// Copyright 2026 bgpgg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::route_generator::{
    generate_peer_routes, AttributeConfig, OverlapConfig, PeerRouteSet, PrefixLengthDistribution,
    RouteGenConfig,
};
use crate::{
    calculate_expected_best_paths, proto_path_to_rib_path, transform_path_for_ebgp_export,
};
use bgpgg::grpc::proto::bgp_service_client::BgpServiceClient;
use bgpgg::grpc::proto::route;
use bgpgg::net::IpNetwork;
use bgpgg::rib::Path;
use conf::bgp::BgpConfig;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tonic::transport::Channel;

type BgpClient = BgpServiceClient<Channel>;

// Memory cap for bgpggd in load tests.
const BGPGGD_AS_LIMIT_BYTES: u64 = 6 * 1024 * 1024 * 1024;

// === Load Test Configuration ===
// Ingestion test: just tests route ingestion and loc-rib best path selection
const INGESTION_UPSTREAM_PEERS: usize = 10;
const INGESTION_TOTAL_ROUTES: usize = 1_000_000;
const INGESTION_TIMEOUT_SECS: u64 = 300;
const INGESTION_POLL_INTERVAL_SECS: u64 = 10;

// Convergence test: tests ingestion + propagation to downstream peers
const CONVERGENCE_UPSTREAM_PEERS: usize = 10;
const CONVERGENCE_DOWNSTREAM_PEERS: usize = 2;
const CONVERGENCE_TOTAL_ROUTES: usize = 1_000_000;
const CONVERGENCE_TIMEOUT_SECS: u64 = 600;
const CONVERGENCE_POLL_INTERVAL_SECS: u64 = 10;

// Shared configuration
const ROUTES_PER_UPDATE: usize = 100; // Routes per BGP UPDATE message
const ROUTE_GEN_SEED: u64 = 12345; // Reproducible route generation

// === Helper Functions ===

/// Create policies for eBGP load testing (RFC 8212 requires explicit policies).
async fn create_load_test_policies(client: &mut BgpClient) {
    tracing::info!("Creating load test policies...");
    client
        .add_policy(bgpgg::grpc::proto::AddPolicyRequest {
            name: "reject-all".to_string(),
            statements: vec![bgpgg::grpc::proto::StatementConfig {
                conditions: None,
                actions: Some(bgpgg::grpc::proto::ActionsConfig {
                    reject: Some(true),
                    ..Default::default()
                }),
            }],
        })
        .await
        .expect("Failed to create reject-all policy");

    client
        .add_policy(bgpgg::grpc::proto::AddPolicyRequest {
            name: "accept-all".to_string(),
            statements: vec![bgpgg::grpc::proto::StatementConfig {
                conditions: None,
                actions: Some(bgpgg::grpc::proto::ActionsConfig {
                    accept: Some(true),
                    ..Default::default()
                }),
            }],
        })
        .await
        .expect("Failed to create accept-all policy");
}

/// Generate routes and calculate expected best paths
fn generate_routes_and_best_paths(
    total_routes: usize,
    num_peers: usize,
) -> (Vec<PeerRouteSet>, HashMap<IpNetwork, Path>) {
    let config = RouteGenConfig {
        total_routes,
        num_peers,
        seed: ROUTE_GEN_SEED,
        prefix_len_dist: PrefixLengthDistribution::default(),
        overlap_config: OverlapConfig::default(),
        attr_config: AttributeConfig::default(),
    };

    tracing::info!("Generating routes with best path selection diversity...");
    tracing::info!(
        "  Overlap policy: {}% single-peer, {}% 2-3 peers, {}% 4+ peers",
        config.overlap_config.single_peer_pct,
        config.overlap_config.two_three_peer_pct,
        config.overlap_config.heavy_peer_pct
    );
    tracing::info!(
        "  Prefix distribution: {}% /24, {}% /22-23, {}% /20-21, {}% /16-19",
        config.prefix_len_dist.len_24,
        config.prefix_len_dist.len_22_23,
        config.prefix_len_dist.len_20_21,
        config.prefix_len_dist.len_16_19
    );
    tracing::info!(
        "  AS_PATH length: {}-{} (avg {})",
        config.attr_config.as_path_min_len,
        config.attr_config.as_path_max_len,
        config.attr_config.as_path_avg_len
    );
    tracing::info!(
        "  Origin mix: {}% IGP, {}% INCOMPLETE, {}% EGP",
        config.attr_config.origin_igp_pct,
        config.attr_config.origin_incomplete_pct,
        config.attr_config.origin_egp_pct
    );

    let peer_route_sets = generate_peer_routes(config);
    tracing::info!("Generated {} route sets", peer_route_sets.len());
    for (i, peer_set) in peer_route_sets.iter().enumerate() {
        tracing::info!("  Peer {}: {} routes", i, peer_set.routes.len());
    }

    let expected_best_paths = calculate_expected_best_paths(&peer_route_sets);
    tracing::info!(
        "Expected {} unique prefixes with best paths selected",
        expected_best_paths.len()
    );

    (peer_route_sets, expected_best_paths)
}

/// Verify peers are established and log their status
async fn verify_peers_established(client: &mut BgpClient, description: &str) {
    sleep(Duration::from_secs(1)).await;

    let peers_response = client
        .list_peers(bgpgg::grpc::proto::ListPeersRequest {})
        .await
        .unwrap();
    let peers = peers_response.into_inner().peers;
    tracing::info!("{}: {} peers", description, peers.len());

    for peer in &peers {
        tracing::info!(
            "  Peer: {} (AS{}, state={})",
            peer.address,
            peer.asn,
            peer.state
        );
    }
}

/// Establish upstream peer connections with reject-all export policy
async fn establish_upstream_peers(
    bgp_addr: &str,
    client: &mut BgpClient,
    num_peers: usize,
) -> Vec<crate::sender::SenderConnection> {
    tracing::info!("Establishing {} upstream peer connections...", num_peers);
    let mut connections = Vec::new();

    for i in 0..num_peers {
        let target: SocketAddr = bgp_addr.parse().unwrap();
        let sender_asn = 65001 + i as u16;
        let sender_router_id = Ipv4Addr::new(2, 0, 0, 1 + i as u8);
        let bind_addr: SocketAddr = format!("127.0.0.{}:0", 1 + i).parse().unwrap();

        tracing::info!(
            "Connecting upstream peer {} (AS{}) from {}...",
            i,
            sender_asn,
            bind_addr.ip()
        );

        // Add peer via gRPC first (passive mode - we initiate connection)
        client
            .add_peer(bgpgg::grpc::proto::AddPeerRequest {
                address: bind_addr.ip().to_string(),
                config: Some(bgpgg::grpc::proto::SessionConfig {
                    passive_mode: Some(true),
                    ..Default::default()
                }),
            })
            .await
            .expect("Failed to add peer");

        match crate::sender::establish_connection(
            target,
            sender_asn,
            sender_router_id,
            65000,
            sender_router_id,
            Some(bind_addr),
        )
        .await
        {
            Ok(conn) => {
                tracing::info!("Upstream peer {} connected", i);

                // Upstream: accept all imports, reject all exports
                client
                    .set_policy_assignment(bgpgg::grpc::proto::SetPolicyAssignmentRequest {
                        peer_address: bind_addr.ip().to_string(),
                        afi: 1,
                        safi: 1,
                        direction: "import".to_string(),
                        policy_names: vec!["accept-all".to_string()],
                        default_action: None,
                    })
                    .await
                    .expect("Failed to set import policy");
                client
                    .set_policy_assignment(bgpgg::grpc::proto::SetPolicyAssignmentRequest {
                        peer_address: bind_addr.ip().to_string(),
                        afi: 1,
                        safi: 1,
                        direction: "export".to_string(),
                        policy_names: vec!["reject-all".to_string()],
                        default_action: None,
                    })
                    .await
                    .expect("Failed to set export policy");

                connections.push(conn);
            }
            Err(e) => {
                tracing::error!("Failed to connect upstream peer {}: {:?}", i, e);
            }
        }
    }

    tracing::info!("{} upstream peers connected", connections.len());
    verify_peers_established(client, "Verifying upstream peers").await;
    connections
}

/// Send routes from all upstream peers in parallel
async fn send_routes_from_peers(
    connections: Vec<crate::sender::SenderConnection>,
    peer_route_sets: Vec<PeerRouteSet>,
    num_peers: usize,
) -> Vec<crate::sender::SenderConnection> {
    tracing::info!("Sending routes from {} peers...", connections.len());

    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel::<(
        usize,
        Result<crate::sender::SenderStats, std::io::Error>,
        Option<crate::sender::SenderConnection>,
    )>(num_peers);

    for (conn, peer_set) in connections.into_iter().zip(peer_route_sets) {
        let tx = result_tx.clone();
        let peer_index = peer_set.peer_index;
        let routes = peer_set.routes;

        tokio::spawn(async move {
            let result = match crate::sender::send_routes(conn, routes, ROUTES_PER_UPDATE).await {
                Ok((returned_conn, stats)) => (peer_index, Ok(stats), Some(returned_conn)),
                Err(e) => (peer_index, Err(e), None),
            };
            let _ = tx.send(result).await;
        });
    }
    drop(result_tx);

    let mut live_connections = Vec::new();
    while let Some((i, result, conn_opt)) = result_rx.recv().await {
        match result {
            Ok(stats) => {
                tracing::info!(
                    "Peer {} sent {} routes in {:?} ({:.0} routes/sec)",
                    i,
                    stats.routes_sent,
                    stats.duration,
                    stats.routes_sent as f64 / stats.duration.as_secs_f64()
                );
                if let Some(conn) = conn_opt {
                    live_connections.push(conn);
                }
            }
            Err(e) => {
                tracing::error!("Peer {} failed to send routes: {:?}", i, e);
            }
        }
    }

    live_connections
}

/// Wait for loc-rib to converge and verify best paths
async fn wait_and_verify_loc_rib(
    client: &mut BgpClient,
    expected_best_paths: &HashMap<IpNetwork, Path>,
    poll_interval_secs: u64,
    timeout_secs: u64,
) {
    tracing::info!("Waiting for loc-rib to converge and verifying best paths...");
    let processing_start = Instant::now();
    let mut last_count = 0;

    while processing_start.elapsed().as_secs() < timeout_secs {
        match client
            .get_server_info(bgpgg::grpc::proto::GetServerInfoRequest {})
            .await
        {
            Ok(response) => {
                let info = response.into_inner();
                let count = info.num_routes;
                tracing::info!("Current route count in loc-rib: {}", count);

                if count == expected_best_paths.len() as u64 {
                    tracing::info!(
                        "Loc-rib has expected number of routes, verifying best paths..."
                    );
                    verify_loc_rib(client, expected_best_paths).await;
                    tracing::info!("All {} best paths verified correctly!", count);
                    return;
                }

                if count < last_count {
                    tracing::warn!("Route count decreased from {} to {}", last_count, count);
                } else if count == last_count && last_count > 0 {
                    tracing::info!("Route count stable at {}, waiting...", count);
                }
                last_count = count;
            }
            Err(e) => {
                tracing::warn!("Failed to get server info: {:?}", e);
            }
        }
        sleep(Duration::from_secs(poll_interval_secs)).await;
    }

    panic!(
        "Timeout after {} seconds: expected {} routes, got {}",
        timeout_secs,
        expected_best_paths.len(),
        last_count
    );
}

/// Verify loc-rib contents match expected best paths
async fn verify_loc_rib(client: &mut BgpClient, expected_best_paths: &HashMap<IpNetwork, Path>) {
    use tokio_stream::StreamExt;

    let mut stream = client
        .list_routes_stream(bgpgg::grpc::proto::ListRoutesRequest {
            rib_type: Some(bgpgg::grpc::proto::RibType::Global as i32),
            peer_address: None,
            afi: None,
            safi: None,
        })
        .await
        .expect("Failed to start route stream")
        .into_inner();

    let mut routes = Vec::new();
    while let Some(route) = stream.next().await {
        routes.push(route.expect("Failed to read route from stream"));
    }
    tracing::info!("Retrieved {} routes from loc-rib", routes.len());

    let mut mismatches = Vec::new();
    for route in &routes {
        let prefix_str = match &route.key {
            Some(route::Key::Prefix(p)) => p.as_str(),
            _ => continue,
        };
        let prefix: IpNetwork = prefix_str.parse().expect("Failed to parse prefix");

        if let Some(expected_path) = expected_best_paths.get(&prefix) {
            if route.paths.is_empty() {
                mismatches.push(format!("Prefix {} has no paths in loc-rib", prefix));
                continue;
            }

            let proto_path = &route.paths[0];
            let actual_path = match proto_path_to_rib_path(proto_path) {
                Ok(p) => p,
                Err(e) => {
                    mismatches.push(format!("Prefix {}: failed to convert path: {}", prefix, e));
                    continue;
                }
            };

            if actual_path.attrs != expected_path.attrs {
                mismatches.push(format!(
                    "Prefix {}: best path mismatch\n  Expected: {:?}\n  Got: {:?}",
                    prefix, expected_path, actual_path
                ));
            }
        } else {
            mismatches.push(format!(
                "Prefix {} found in loc-rib but not in expected best paths",
                prefix
            ));
        }
    }

    if !mismatches.is_empty() {
        tracing::error!(
            "Found {} mismatches in best path selection:",
            mismatches.len()
        );
        for (i, mismatch) in mismatches.iter().take(10).enumerate() {
            tracing::error!("  {}: {}", i + 1, mismatch);
        }
        if mismatches.len() > 10 {
            tracing::error!("  ... and {} more", mismatches.len() - 10);
        }
        panic!(
            "Best path verification failed with {} mismatches",
            mismatches.len()
        );
    }
}

/// Helper to spawn bgpggd binary with a config file
struct BgpggProcess {
    process: Child,
    _config_file: tempfile::NamedTempFile,
    _runtime_dir: tempfile::TempDir,
    bgp_port: u16,
    grpc_addr: String,
}

impl BgpggProcess {
    async fn spawn(asn: u16, router_id: Ipv4Addr) -> std::io::Result<Self> {
        // Create temporary config file
        use std::io::Write;
        let mut config_file = tempfile::NamedTempFile::new()?;
        let runtime_dir = tempfile::tempdir()?;

        // Use port 0 for dynamic BGP port, but fixed gRPC port for easy connection
        let grpc_port = 50051 + (asn - 65000); // Offset by ASN to avoid conflicts
        let grpc_addr = format!("127.0.0.1:{}", grpc_port);

        let config = BgpConfig {
            asn: asn as u32,
            listen_addr: "127.0.0.1:0".to_string(),
            router_id,
            grpc_listen_addr: grpc_addr.clone(),
            hold_time_secs: 3600, // 1 hour for long-running load tests
            connect_retry_secs: 30,
            peers: Vec::new(),
            bmp_servers: vec![],
            rpki_caches: vec![],
            defined_sets: Default::default(),
            policy_definitions: vec![],
            sys_name: None,
            sys_descr: None,
            log_level: "error".to_string(),
            cluster_id: None,
            llgr: None,
            enhanced_rr_stale_ttl: Some(360),
            bgp_ls: Default::default(),
            originate: Vec::new(),
        };

        config_file.write_all(config.to_conf_str().as_bytes())?;
        config_file.flush()?;

        let mut command = Command::new("../../target/release/bgpggd");
        command
            .arg("--config")
            .arg(config_file.path())
            .arg("--runtime-dir")
            .arg(runtime_dir.path());
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: BGPGGD_AS_LIMIT_BYTES as libc::rlim_t,
                    rlim_max: BGPGGD_AS_LIMIT_BYTES as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let process = command.spawn()?;

        // Wait a bit for server to start
        sleep(Duration::from_millis(500)).await;

        Ok(Self {
            process,
            _config_file: config_file,
            _runtime_dir: runtime_dir,
            bgp_port: 0, // Will be populated after connecting
            grpc_addr: format!("http://{}", grpc_addr),
        })
    }

    async fn connect_grpc(&mut self) -> Result<BgpClient, Box<dyn std::error::Error>> {
        // Try to connect to gRPC with retries
        for _ in 0..10 {
            match BgpClient::connect(self.grpc_addr.clone()).await {
                Ok(client) => {
                    // Get server info to find out the BGP port
                    let mut c = client.clone();
                    let info = c
                        .get_server_info(bgpgg::grpc::proto::GetServerInfoRequest {})
                        .await?;
                    self.bgp_port = info.into_inner().listen_port as u16;
                    return Ok(client);
                }
                Err(_) => {
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Err("Failed to connect to gRPC".into())
    }

    fn kill(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Drop for BgpggProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

#[tokio::test]
async fn test_route_ingestion_load() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    tracing::info!(
        "Starting load test: {} peers, {} total routes",
        INGESTION_UPSTREAM_PEERS,
        INGESTION_TOTAL_ROUTES
    );

    // Setup: Spawn bgpggd and connect
    let mut bgpgg = BgpggProcess::spawn(65000, Ipv4Addr::new(1, 1, 1, 1))
        .await
        .expect("Failed to spawn bgpggd");
    let mut client = bgpgg
        .connect_grpc()
        .await
        .expect("Failed to connect to gRPC");
    let bgp_addr = format!("127.0.0.1:{}", bgpgg.bgp_port);
    tracing::info!("bgpggd listening on BGP port {}", bgpgg.bgp_port);

    // Create reject-all export policy
    create_load_test_policies(&mut client).await;

    // Generate routes and calculate expected best paths
    let (peer_route_sets, expected_best_paths) =
        generate_routes_and_best_paths(INGESTION_TOTAL_ROUTES, INGESTION_UPSTREAM_PEERS);
    let total_routes_to_send: usize = peer_route_sets.iter().map(|ps| ps.routes.len()).sum();
    tracing::info!(
        "Total routes to send: {} (across {} peers)",
        total_routes_to_send,
        peer_route_sets.len()
    );

    // PHASE 1: Establish upstream peer connections (includes verification)
    tracing::info!(
        "Phase 1: Establishing {} peer connections...",
        INGESTION_UPSTREAM_PEERS
    );
    let connections =
        establish_upstream_peers(&bgp_addr, &mut client, INGESTION_UPSTREAM_PEERS).await;

    // PHASE 2: Send routes from all peers in parallel
    tracing::info!(
        "Phase 2: Blasting {} routes from {} peers...",
        INGESTION_TOTAL_ROUTES,
        connections.len()
    );
    let start_time = Instant::now();
    let _live_connections =
        send_routes_from_peers(connections, peer_route_sets, INGESTION_UPSTREAM_PEERS).await;
    let ingestion_time = Instant::now() - start_time;
    tracing::info!("All peers completed sending in {:?}", ingestion_time);

    // PHASE 3: Wait for loc-rib to converge and verify best paths
    tracing::info!("Phase 3: Waiting for bgpgg to process routes...");
    let processing_start = Instant::now();
    wait_and_verify_loc_rib(
        &mut client,
        &expected_best_paths,
        INGESTION_POLL_INTERVAL_SECS,
        INGESTION_TIMEOUT_SECS,
    )
    .await;
    let processing_time = Instant::now() - processing_start;

    // Note: With overlapping routes, we can't verify expected UPDATE count per peer
    // as each peer may send different amounts based on overlap distribution
    let peers_response = client
        .list_peers(bgpgg::grpc::proto::ListPeersRequest {})
        .await
        .unwrap();
    let peers = peers_response.into_inner().peers;
    tracing::info!("Verifying {} peers", peers.len());

    for peer in &peers {
        let peer_response = client
            .get_peer(bgpgg::grpc::proto::GetPeerRequest {
                address: peer.address.clone(),
            })
            .await
            .unwrap();
        let peer_info = peer_response.into_inner();

        if let Some(stats) = peer_info.statistics {
            tracing::info!(
                "Peer {}: received {} UPDATEs",
                peer.address,
                stats.update_received
            );
        }
    }

    // Report final statistics
    tracing::info!("\n=== Test Results ===");
    tracing::info!("Route send time: {:?}", ingestion_time);
    tracing::info!("Route processing time: {:?}", processing_time);
    tracing::info!("Total test time: {:?}", ingestion_time + processing_time);

    bgpgg.kill();
}

#[tokio::test]
async fn test_route_convergence() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init()
        .ok();

    tracing::info!(
        "Starting convergence test: {} upstream peers, {} routes, {} downstream peers",
        CONVERGENCE_UPSTREAM_PEERS,
        CONVERGENCE_TOTAL_ROUTES,
        CONVERGENCE_DOWNSTREAM_PEERS
    );

    // Setup: Spawn bgpggd and connect
    let mut bgpgg = BgpggProcess::spawn(65000, Ipv4Addr::new(1, 1, 1, 1))
        .await
        .expect("Failed to spawn bgpggd");
    let mut client = bgpgg
        .connect_grpc()
        .await
        .expect("Failed to connect to gRPC");
    let bgp_addr = format!("127.0.0.1:{}", bgpgg.bgp_port);
    tracing::info!("bgpggd listening on BGP port {}", bgpgg.bgp_port);

    // Create reject-all export policy
    create_load_test_policies(&mut client).await;

    // Generate routes and calculate expected best paths
    let (peer_route_sets, expected_best_paths) =
        generate_routes_and_best_paths(CONVERGENCE_TOTAL_ROUTES, CONVERGENCE_UPSTREAM_PEERS);

    // PHASE 1: Establish downstream peer connections (will receive routes)
    tracing::info!(
        "Phase 1: Establishing {} downstream peer connections...",
        CONVERGENCE_DOWNSTREAM_PEERS
    );
    let mut downstream_connections = Vec::new();

    for i in 0..CONVERGENCE_DOWNSTREAM_PEERS {
        let target: SocketAddr = bgp_addr.parse().unwrap();
        let downstream_asn = 65100 + i as u16;
        let downstream_router_id = Ipv4Addr::new(3, 0, 0, 1 + i as u8);
        let bind_addr: SocketAddr = format!("127.0.0.{}:0", 21 + i).parse().unwrap();

        // Add peer via gRPC first (passive mode - we initiate connection)
        client
            .add_peer(bgpgg::grpc::proto::AddPeerRequest {
                address: bind_addr.ip().to_string(),
                config: Some(bgpgg::grpc::proto::SessionConfig {
                    passive_mode: Some(true),
                    ..Default::default()
                }),
            })
            .await
            .expect("Failed to add downstream peer");

        match crate::sender::establish_connection(
            target,
            downstream_asn,
            downstream_router_id,
            65000,
            downstream_router_id,
            Some(bind_addr),
        )
        .await
        {
            Ok(conn) => {
                tracing::info!("Downstream peer {} connected from {}", i, bind_addr.ip());
                // Downstream: accept-all export so routes propagate
                client
                    .set_policy_assignment(bgpgg::grpc::proto::SetPolicyAssignmentRequest {
                        peer_address: bind_addr.ip().to_string(),
                        afi: 1,
                        safi: 1,
                        direction: "export".to_string(),
                        policy_names: vec!["accept-all".to_string()],
                        default_action: None,
                    })
                    .await
                    .expect("Failed to set downstream export policy");
                downstream_connections.push(conn);
            }
            Err(e) => {
                tracing::error!("Failed to connect downstream peer {}: {:?}", i, e);
            }
        }
    }

    tracing::info!(
        "{} downstream peers connected",
        downstream_connections.len()
    );

    // PHASE 2: Verify downstream peers are established
    verify_peers_established(&mut client, "Phase 2: Downstream peers established").await;

    // PHASE 3: Establish upstream peer connections (includes verification)
    let connections =
        establish_upstream_peers(&bgp_addr, &mut client, CONVERGENCE_UPSTREAM_PEERS).await;

    // PHASE 4: Start convergence timer and send routes
    tracing::info!("Phase 4: Sending routes from upstream peers...");
    let convergence_start = Instant::now();

    // Keep downstream connections alive throughout the test
    let _live_downstream_connections = downstream_connections;

    let _live_connections =
        send_routes_from_peers(connections, peer_route_sets, CONVERGENCE_UPSTREAM_PEERS).await;

    // PHASE 5: Verify loc-rib has correct best paths
    tracing::info!("Phase 5: Waiting for loc-rib to converge and verifying best paths...");
    wait_and_verify_loc_rib(
        &mut client,
        &expected_best_paths,
        CONVERGENCE_POLL_INTERVAL_SECS,
        CONVERGENCE_TIMEOUT_SECS,
    )
    .await;

    // PHASE 6: Verify downstream peers' adj-rib-out matches loc-rib (with eBGP transformations)
    // Strategy: Fully verify peer 0, then hash-compare the rest
    tracing::info!("Phase 6: Verifying downstream peers' adj-rib-out...");
    let expected_route_count = expected_best_paths.len();
    let phase6_start = Instant::now();

    // First, wait for all peers to have the expected route count
    tracing::info!("Waiting for all peers to receive routes...");
    let mut all_converged = false;
    while phase6_start.elapsed().as_secs() < CONVERGENCE_TIMEOUT_SECS {
        let mut counts = Vec::new();
        for i in 0..CONVERGENCE_DOWNSTREAM_PEERS {
            let peer_addr = format!("127.0.0.{}", 21 + i);
            use tokio_stream::StreamExt;
            let mut stream = client
                .list_routes_stream(bgpgg::grpc::proto::ListRoutesRequest {
                    rib_type: Some(bgpgg::grpc::proto::RibType::AdjOut as i32),
                    peer_address: Some(peer_addr.clone()),
                    afi: None,
                    safi: None,
                })
                .await
                .expect("Failed to start adj-rib-out stream")
                .into_inner();

            let mut count = 0;
            while (stream.next().await).is_some() {
                count += 1;
            }
            counts.push(count);
        }

        tracing::info!("Peer route counts: {:?}", counts);

        if counts.iter().all(|&c| c >= expected_route_count) {
            tracing::info!("All peers have expected route count");
            all_converged = true;
            break;
        }

        sleep(Duration::from_secs(10)).await;
    }

    if !all_converged {
        tracing::error!("Phase 6 timeout: not all peers converged");
        bgpgg.kill();
        panic!("Phase 6 timeout after {} seconds", CONVERGENCE_TIMEOUT_SECS);
    }

    // Verify all downstream peers' adj-rib-out
    tracing::info!("Verifying all downstream peers' adj-rib-out...");
    use tokio_stream::StreamExt;
    for i in 0..CONVERGENCE_DOWNSTREAM_PEERS {
        let peer_addr = format!("127.0.0.{}", 21 + i);
        let mut stream = client
            .list_routes_stream(bgpgg::grpc::proto::ListRoutesRequest {
                rib_type: Some(bgpgg::grpc::proto::RibType::AdjOut as i32),
                peer_address: Some(peer_addr.clone()),
                afi: None,
                safi: None,
            })
            .await
            .expect("Failed to start adj-rib-out stream")
            .into_inner();

        let mut routes = Vec::new();
        while let Some(route) = stream.next().await {
            routes.push(route.expect("Failed to read route"));
        }

        let mut mismatches = Vec::new();
        for route in &routes {
            let prefix_str = match &route.key {
                Some(route::Key::Prefix(p)) => p.as_str(),
                _ => continue,
            };
            let prefix: bgpgg::net::IpNetwork = prefix_str.parse().expect("Failed to parse prefix");

            if let Some(expected_path) = expected_best_paths.get(&prefix) {
                if route.paths.is_empty() {
                    mismatches.push(format!("Prefix {} has no paths", prefix));
                    continue;
                }

                let proto_path = &route.paths[0];
                let actual_path = match proto_path_to_rib_path(proto_path) {
                    Ok(p) => p,
                    Err(e) => {
                        mismatches.push(format!("Prefix {}: {}", prefix, e));
                        continue;
                    }
                };

                let expected_exported = transform_path_for_ebgp_export(
                    expected_path,
                    65000,
                    Ipv4Addr::new(127, 0, 0, 1),
                );

                if actual_path.attrs != expected_exported.attrs {
                    mismatches.push(format!(
                        "Prefix {}: path mismatch\n  Expected: {:?}\n  Got: {:?}",
                        prefix, expected_exported, actual_path
                    ));
                }
            } else {
                mismatches.push(format!("Prefix {} not in expected best paths", prefix));
            }
        }

        if !mismatches.is_empty() {
            tracing::error!("Peer {} has {} mismatches:", i, mismatches.len());
            for mismatch in mismatches.iter().take(5) {
                tracing::error!("  {}", mismatch);
            }

            bgpgg.kill();
            panic!("Verification failed for peer {}", i);
        }

        tracing::info!("Peer {} verified correctly ({} routes)", i, routes.len());
    }

    let convergence_end = Instant::now();
    let convergence_time = convergence_end - convergence_start;

    tracing::info!("\n=== Convergence Test Results ===");
    tracing::info!("Total routes: {}", CONVERGENCE_TOTAL_ROUTES);
    tracing::info!("Unique prefixes: {}", expected_best_paths.len());
    tracing::info!("Upstream peers: {}", CONVERGENCE_UPSTREAM_PEERS);
    tracing::info!("Downstream peers: {}", CONVERGENCE_DOWNSTREAM_PEERS);
    tracing::info!("Convergence time (end-to-end): {:?}", convergence_time);
    tracing::info!("Loc-rib verified with correct best paths!");
    tracing::info!(
        "All {} downstream peers' adj-rib-out verified!",
        CONVERGENCE_DOWNSTREAM_PEERS
    );

    bgpgg.kill();
}
