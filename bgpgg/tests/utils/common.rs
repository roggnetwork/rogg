// Copyright 2025 bgpgg Authors
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

//! Common test utilities for BGP server testing

use tracing_subscriber::EnvFilter;

/// Initialize tracing for tests. Call at the start of each test.
/// Uses RUST_LOG env var, defaulting to debug for bgpgg only.
/// Safe to call multiple times - only first call takes effect.
pub fn init_test_logging() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "bgpgg=debug".to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_test_writer()
        .try_init();
}

use std::collections::{HashMap, HashSet};

use bgpgg::bgp::msg::{
    read_bgp_message, AddPathMask, BgpMessage, Message, MessageFormat, MessageType, BGP_MARKER,
    PRE_OPEN_FORMAT,
};
use bgpgg::bgp::msg_keepalive::KeepaliveMessage;
use bgpgg::bgp::msg_notification::NotificationMessage;
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::bgp::msg_update::UpdateMessage;
use bgpgg::bgp::msg_update_types::AS_TRANS;
use bgpgg::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use bgpgg::grpc::proto::bgp_service_server::BgpServiceServer;
use bgpgg::grpc::proto::{
    add_route_request, defined_set_config, route, ActionsConfig, AddIpRouteRequest,
    AddLsRouteRequest, AddPathSendMode, AddRouteRequest, AdminState, AfiSafiConfig, Aggregator,
    AsPathSegment, AsPathSegmentType, BgpState, ConditionsConfig, DefinedSetConfig,
    ExtendedCommunity, GracefulRestartConfig, LargeCommunity, ListRoutesRequest,
    LlgrConfig as ProtoLlgrConfig, LsAttribute, LsNlri, Origin, Path, Peer, PeerStatistics,
    PrefixMatch, PrefixSetData, RibType, Route, SessionConfig, StatementConfig, UnknownAttribute,
};
use bgpgg::grpc::proto_community::{internal_to_proto_large_community, u64_to_proto_extcomm};
use bgpgg::grpc::{BgpClient, BgpGrpcService};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use bgpgg::net::apply_gtsm;
use bgpgg::server::BgpServer;
use conf::bgp::BgpConfig;
use conf::testutil::TempDir;
use std::fs;
use std::net::Ipv4Addr;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
pub use tokio::time::Duration;
use tokio::time::{sleep, timeout};

/// Extract the IP prefix string from a Route's key. Panics if not an IP route.
pub fn route_prefix(route: &Route) -> &str {
    match &route.key {
        Some(route::Key::Prefix(p)) => p.as_str(),
        _ => panic!("expected IP prefix key, got {:?}", route.key),
    }
}

/// Returns a hashable string key for any route (IP prefix or LS NLRI debug repr).
fn route_key_string(route: &Route) -> String {
    match &route.key {
        Some(route::Key::Prefix(p)) => p.clone(),
        Some(route::Key::LsNlri(n)) => format!("ls:{:?}", n),
        None => "none".to_string(),
    }
}

/// Check if a Route has a given IP prefix.
pub fn route_has_prefix(route: &Route, prefix: &str) -> bool {
    matches!(&route.key, Some(route::Key::Prefix(p)) if p == prefix)
}

/// Test server handle that includes runtime for killing the server
pub struct TestServer {
    pub client: BgpClient,
    pub bgp_port: u16,
    pub asn: u32,
    pub address: std::net::IpAddr, // IP address the server is bound to (no port)
    pub config: BgpConfig,
    runtime: Option<tokio::runtime::Runtime>,
    /// Tempdir backing `rogg.conf`. Held so it isn't deleted mid-test.
    config_dir: TempDir,
}

impl TestServer {
    /// Parse the on-disk rogg.conf this server commits to. Panics if missing
    /// or unparseable -- both are bugs in commit_config.
    pub fn read_conf(&self) -> BgpConfig {
        let path = self.config_dir.path().join("rogg.conf");
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        BgpConfig::from_conf_str(&text)
            .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
    }

    /// True if `rogg.conf` exists on disk for this server.
    pub fn rogg_conf_exists(&self) -> bool {
        self.config_dir.path().join("rogg.conf").exists()
    }

    /// Path to snapshot file at `index` (e.g. `rogg.1.conf`).
    pub fn snapshot_path(&self, index: u32) -> PathBuf {
        self.config_dir.path().join(format!("rogg.{}.conf", index))
    }

    /// True if snapshot `index` exists on disk.
    pub fn snapshot_exists(&self, index: u32) -> bool {
        self.snapshot_path(index).exists()
    }

    /// Parse the snapshot at `index`. Panics if missing or unparseable.
    pub fn read_snapshot(&self, index: u32) -> BgpConfig {
        let path = self.snapshot_path(index);
        let text =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        BgpConfig::from_conf_str(&text)
            .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
    }

    /// Kill the BGP server by shutting down its runtime (simulates process death)
    pub fn kill(&mut self) {
        // Shutdown the runtime - this kills ALL tasks in it (simulates process death)
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }

    /// Path to the sibling `<config>.lock` file.
    pub fn lock_path(&self) -> PathBuf {
        conf::fs::lock_path_for(&self.config_dir.path().join("rogg.conf"))
    }

    /// Take EX flock, write UUID, run closure, release. Mimics
    /// `ggsh configure` for tests calling `save_config` / `commit_config`.
    pub async fn with_session_lock<F, Fut, T>(&self, f: F) -> T
    where
        F: FnOnce(uuid::Uuid) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        use std::io::Write;
        let lock_path = self.lock_path();
        let session_uuid = conf::fs::make_session_uuid();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&lock_path)
            .expect("open lock file");
        file.lock().expect("acquire EX flock");
        write!(file, "{}", session_uuid).expect("write UUID to lock file");
        file.flush().expect("flush lock file");
        let result = f(session_uuid).await;
        drop(file);
        let _ = std::fs::remove_file(&lock_path);
        result
    }

    pub async fn save_config(&self) -> Result<(), tonic::Status> {
        self.with_session_lock(|uuid| async move { self.client.save_config(uuid).await })
            .await
    }

    pub async fn commit_config(&self, text: String) -> Result<(), tonic::Status> {
        self.with_session_lock(|uuid| async move { self.client.commit_config(text, uuid).await })
            .await
    }

    pub async fn rollback_config(&self, index: u32) -> Result<(), tonic::Status> {
        self.with_session_lock(|uuid| async move { self.client.rollback_config(index, uuid).await })
            .await
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Shutdown runtime in background when TestServer is dropped
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl TestServer {
    /// Converts a TestServer to a Peer struct for use in test assertions.
    /// ASN is only known after OPEN exchange, so it's 0 for non-Established states.
    pub fn to_peer(&self, state: BgpState) -> Peer {
        Peer {
            address: self.address.to_string(),
            asn: if state == BgpState::Established {
                self.asn
            } else {
                0
            },
            state: state.into(),
            admin_state: AdminState::Up.into(),
            import_policies: vec![],
            export_policies: vec![],
            session_config: None,
        }
    }

    /// Add a peer to this server
    pub async fn add_peer(&self, peer: &TestServer) {
        self.add_peer_with_config(peer, SessionConfig::default())
            .await;
    }

    /// Add a peer to this server with custom session config.
    /// Port is always set from the peer's BGP port.
    pub async fn add_peer_with_config(&self, peer: &TestServer, mut config: SessionConfig) {
        config.port = Some(peer.bgp_port as u32);
        self.client
            .add_peer(peer.address.to_string(), Some(config))
            .await
            .unwrap();
    }

    /// Remove a peer from this server
    pub async fn remove_peer(&self, peer: &TestServer) {
        self.client
            .remove_peer(peer.address.to_string())
            .await
            .unwrap();
    }
}

/// Helper to check if peer is in a specific BGP state
pub fn peer_in_state(peer: &Peer, state: BgpState) -> bool {
    peer.state == state as i32
}

/// Configuration for peer setup helpers
#[derive(Default, Clone)]
pub struct PeerConfig {
    pub hold_timer_secs: Option<u16>,
    pub graceful_restart: Option<GracefulRestartConfig>,
    pub llgr: Option<ProtoLlgrConfig>,
    pub idle_hold_time_secs: Option<u64>,
    pub min_route_advertisement_interval_secs: Option<u64>,
    pub add_path_send: Option<bool>,
    pub add_path_receive: Option<bool>,
    pub send_rpki_community: Option<bool>,
    pub afi_safis: Vec<AfiSafiConfig>,
}

/// Helper to convert a flat AS list to AS_SEQUENCE segment
pub fn as_sequence(asns: Vec<u32>) -> AsPathSegment {
    AsPathSegment {
        segment_type: AsPathSegmentType::AsSequence.into(),
        asns,
    }
}

/// Helper to create an AS_SET segment
pub fn as_set(asns: Vec<u32>) -> AsPathSegment {
    AsPathSegment {
        segment_type: AsPathSegmentType::AsSet.into(),
        asns,
    }
}

pub fn afi_safi_ipv4_unicast() -> AfiSafiConfig {
    AfiSafiConfig {
        afi: 1,
        safi: 1,
        ..Default::default()
    }
}

pub fn afi_safi_ipv6_unicast() -> AfiSafiConfig {
    AfiSafiConfig {
        afi: 2,
        safi: 1,
        ..Default::default()
    }
}

pub fn afi_safi_link_state() -> AfiSafiConfig {
    AfiSafiConfig {
        afi: 16388,
        safi: 71,
        ..Default::default()
    }
}

/// Create SessionConfig with custom graceful restart timer
pub fn session_config_with_gr_timer(restart_time_secs: u32) -> SessionConfig {
    SessionConfig {
        graceful_restart: Some(GracefulRestartConfig {
            enabled: Some(true),
            restart_time_secs: Some(restart_time_secs),
        }),
        ..Default::default()
    }
}

/// Parameters for building a Path in test assertions
#[derive(Default, Clone)]
pub struct PathParams {
    pub as_path: Vec<AsPathSegment>,
    pub next_hop: String,
    pub peer_address: String,
    pub origin: Option<Origin>,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub atomic_aggregate: bool,
    pub unknown_attributes: Vec<UnknownAttribute>,
    pub communities: Vec<u32>,
    pub extended_communities: Vec<ExtendedCommunity>,
    pub large_communities: Vec<LargeCommunity>,
    /// RFC 4456: ORIGINATOR_ID (IPv4 address as string)
    pub originator_id: Option<String>,
    /// RFC 4456: CLUSTER_LIST (list of IPv4 addresses as strings)
    pub cluster_list: Vec<String>,
    /// RFC 7911: locally assigned path ID (None = not in loc-rib)
    pub local_path_id: Option<u32>,
    /// RFC 7911: path ID received from peer
    pub remote_path_id: Option<u32>,
    pub aggregator: Option<Aggregator>,
    /// RFC 6811: RPKI origin validation state
    pub rpki_validation: i32,
    /// RFC 9552: BGP-LS attribute (type 29)
    pub ls_attribute: Option<LsAttribute>,
    /// RFC 2545: link-local IPv6 next-hop
    pub link_local_next_hop: Option<String>,
}

impl PathParams {
    /// Build PathParams for a route received from an eBGP peer:
    /// next_hop rewritten to peer address, AS prepended, local_pref 100.
    pub fn from_peer(peer: &TestServer) -> Self {
        PathParams {
            next_hop: peer.address.to_string(),
            peer_address: peer.address.to_string(),
            as_path: vec![as_sequence(vec![peer.asn])],
            local_pref: Some(100),
            ..Default::default()
        }
    }
}

pub enum ExpectedRouteKey {
    Prefix(String),
    Ls(Box<LsNlri>),
}

impl From<&str> for ExpectedRouteKey {
    fn from(prefix: &str) -> Self {
        ExpectedRouteKey::Prefix(prefix.to_string())
    }
}

impl From<&String> for ExpectedRouteKey {
    fn from(prefix: &String) -> Self {
        ExpectedRouteKey::Prefix(prefix.clone())
    }
}

impl From<&&str> for ExpectedRouteKey {
    fn from(prefix: &&str) -> Self {
        ExpectedRouteKey::Prefix((*prefix).to_string())
    }
}

impl From<LsNlri> for ExpectedRouteKey {
    fn from(nlri: LsNlri) -> Self {
        ExpectedRouteKey::Ls(Box::new(nlri))
    }
}

/// Build a single-path Route for test assertions.
/// Accepts `&str` (IP prefix) or `LsNlri` (BGP-LS) as key.
pub fn expected_route(key: impl Into<ExpectedRouteKey>, params: PathParams) -> Route {
    let key = match key.into() {
        ExpectedRouteKey::Prefix(p) => route::Key::Prefix(p),
        ExpectedRouteKey::Ls(n) => route::Key::LsNlri(n),
    };
    Route {
        paths: vec![build_path(params)],
        key: Some(key),
    }
}

/// Helper to build a Path from PathParams (new way - preferred for new tests)
pub fn build_path(params: PathParams) -> Path {
    Path {
        origin: params.origin.unwrap_or(Origin::Igp).into(),
        as_path: params.as_path,
        next_hop: params.next_hop,
        peer_address: params.peer_address,
        local_pref: params.local_pref,
        med: params.med,
        atomic_aggregate: params.atomic_aggregate,
        unknown_attributes: params.unknown_attributes,
        communities: params.communities,
        extended_communities: params.extended_communities,
        large_communities: params.large_communities,
        originator_id: params.originator_id,
        cluster_list: params.cluster_list,
        local_path_id: params.local_path_id,
        remote_path_id: params.remote_path_id,
        aggregator: params.aggregator,
        rpki_validation: params.rpki_validation,
        ls_attribute: params.ls_attribute,
        link_local_next_hop: params.link_local_next_hop,
    }
}

/// Strip path IDs from a proto Path for attribute comparison.
/// Path IDs are allocation metadata, not BGP attributes.
fn strip_path_ids(path: &Path) -> Path {
    let mut stripped = path.clone();
    stripped.local_path_id = None;
    stripped.remote_path_id = None;
    stripped
}

fn strip_route_path_ids(route: &Route) -> Route {
    Route {
        paths: route.paths.iter().map(strip_path_ids).collect(),
        key: route.key.clone(),
    }
}

/// Controls path ID validation and comparison strategy in routes_match.
#[derive(Clone, Copy)]
pub enum ExpectPathId {
    /// Don't check path IDs, compare best path only (adj-rib-in/out)
    Ignore,
    /// Assert local_path_id is Some, compare best path only (loc-rib)
    Present,
    /// Assert Some + distinct per prefix, compare all paths (ADD-PATH)
    Distinct,
}

fn assert_path_ids_present(routes: &[Route]) {
    for route in routes {
        for path in &route.paths {
            assert!(
                path.local_path_id.is_some(),
                "path for key {:?} from peer {} missing local_path_id",
                route.key,
                path.peer_address
            );
        }
    }
}

fn assert_path_ids_distinct(routes: &[Route]) {
    for route in routes {
        let ids: Vec<u32> = route.paths.iter().filter_map(|p| p.local_path_id).collect();
        let unique: HashSet<u32> = ids.iter().copied().collect();
        assert_eq!(
            ids.len(),
            unique.len(),
            "duplicate local_path_ids for key {:?}: {:?}",
            route.key,
            ids
        );
    }
}

/// Compare actual routes against expected.
///
/// - Ignore: compare best path only, no path ID checks (adj-rib-in/out)
/// - Present: compare best path only, assert path IDs present (loc-rib)
/// - Distinct: compare all paths, assert path IDs present + distinct (ADD-PATH)
///
/// Always strips path IDs before attribute comparison — tests don't predict
/// allocator values.
pub fn routes_match(actual: &[Route], expected: &[Route], expect: ExpectPathId) -> bool {
    match expect {
        ExpectPathId::Ignore => {}
        ExpectPathId::Present => assert_path_ids_present(actual),
        ExpectPathId::Distinct => {
            assert_path_ids_present(actual);
            assert_path_ids_distinct(actual);
        }
    }

    if matches!(expect, ExpectPathId::Distinct) {
        let actual_map: HashMap<_, _> = actual
            .iter()
            .map(|r| (route_key_string(r), &r.paths))
            .collect();
        let expected_map: HashMap<_, _> = expected
            .iter()
            .map(|r| (route_key_string(r), &r.paths))
            .collect();

        if actual_map.len() != expected_map.len() {
            return false;
        }

        for (key, expected_paths) in &expected_map {
            let Some(actual_paths) = actual_map.get(key) else {
                return false;
            };
            if actual_paths.len() != expected_paths.len() {
                return false;
            }
            let actual_stripped: Vec<Path> = actual_paths.iter().map(strip_path_ids).collect();
            let expected_stripped: Vec<Path> = expected_paths.iter().map(strip_path_ids).collect();
            for expected_path in &expected_stripped {
                if !actual_stripped.contains(expected_path) {
                    return false;
                }
            }
        }
        true
    } else {
        let routes_map: HashMap<_, _> = actual
            .iter()
            .map(|r| {
                (
                    route_key_string(r),
                    strip_route_path_ids(r).paths.first().cloned(),
                )
            })
            .collect();
        let expected_map: HashMap<_, _> = expected
            .iter()
            .map(|r| {
                (
                    route_key_string(r),
                    strip_route_path_ids(r).paths.first().cloned(),
                )
            })
            .collect();

        routes_map == expected_map
    }
}

/// Helper to create a standard test config with sane defaults
pub fn test_config(asn: u32, ip_last_octet: u8) -> BgpConfig {
    let ip = format!("127.0.0.{}", ip_last_octet);
    let mut config = BgpConfig::new(
        asn,
        &format!("{}:0", ip),
        Ipv4Addr::new(ip_last_octet, ip_last_octet, ip_last_octet, ip_last_octet),
        90,
    );
    config.sys_name = Some(format!("test-bgpgg-{}", ip));
    config.sys_descr = Some("test bgpgg router".to_string());
    config
}

/// Starts a single BGP server with gRPC interface for testing
pub async fn start_test_server(mut config: BgpConfig) -> TestServer {
    use tokio::net::TcpListener;

    init_test_logging();

    // Use fast connect retry for tests (default 30s is too slow).
    // If the caller explicitly set a value, preserve it.
    if config.connect_retry_secs == BgpConfig::default().connect_retry_secs {
        config.connect_retry_secs = 1;
    }

    let router_id = config.router_id;
    let asn = config.asn;

    // Parse IP from listen_addr (handles both "IP:port" and "[IPv6]:port")
    let bind_ip: std::net::IpAddr = if config.listen_addr.starts_with('[') {
        let end = config
            .listen_addr
            .find(']')
            .expect("IPv6 address missing ]");
        config.listen_addr[1..end]
            .parse()
            .expect("valid IPv6 address")
    } else {
        config
            .listen_addr
            .split(':')
            .next()
            .unwrap_or("127.0.0.1")
            .parse()
            .expect("valid IPv4 address")
    };

    // Bind gRPC listener to get port (no race - we keep the listener)
    let grpc_listener = TcpListener::bind("[::1]:0").await.unwrap();
    let grpc_port = grpc_listener.local_addr().unwrap().port();
    let grpc_listener = grpc_listener.into_std().unwrap();

    let config_dir = TempDir::new().expect("create config tempdir");
    let config_path = config_dir.path().join("rogg.conf");
    fs::write(&config_path, config.to_conf_str()).expect("write initial rogg.conf");
    let server = BgpServer::new(config_path).expect("valid server config");
    // TestServer.config mirrors what the daemon actually loaded -- not the
    // pre-write input. They diverge whenever the grammar can't round-trip
    // a field; tests should see what the daemon sees.
    let loaded_config = server.config.clone();
    let grpc_service = BgpGrpcService::new(server.mgmt_tx.clone());

    // Create a separate runtime for this server (simulates separate process)
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Spawn BGP server
    runtime.spawn(async move { server.run().await });

    // Spawn gRPC server
    runtime.spawn(async move {
        let grpc_listener = tokio::net::TcpListener::from_std(grpc_listener).unwrap();
        tonic::transport::Server::builder()
            .add_service(BgpServiceServer::new(grpc_service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
                grpc_listener,
            ))
            .await
            .unwrap();
    });

    // Retry connecting to gRPC server until it's ready
    let mut client = None;
    for _ in 0..50 {
        match BgpClient::connect_with_router_id(format!("http://[::1]:{}", grpc_port), router_id)
            .await
        {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }

    let client = client.expect("Failed to connect to gRPC server after retries");

    // Query actual BGP port from server
    let mut bgp_port = 0;
    for _ in 0..50 {
        match client.get_server_info().await {
            Ok((_, port, _)) if port > 0 => {
                bgp_port = port;
                break;
            }
            _ => {
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    assert!(bgp_port > 0, "Failed to get BGP port from server");

    TestServer {
        client,
        bgp_port,
        asn,
        address: bind_ip,
        config: loaded_config,
        runtime: Some(runtime),
        config_dir,
    }
}

/// Insert a passive peer at the given address into the BgpConfig before
/// starting the test server. Uses defaults for everything else; for tests
/// that need extra fields (GR, LLGR, port, ...), build the PeerConfig
/// inline and call `config.insert_peer(...)` directly.
pub fn add_passive_peer(config: &mut BgpConfig, address: &str) {
    config
        .insert_peer(conf::bgp::PeerConfig {
            address: address.to_string(),
            passive_mode: true,
            ..Default::default()
        })
        .unwrap();
}

/// Setup a test server with a passive peer configured (no connection yet).
///
/// Use when you need custom handshake behavior (e.g., partial handshake for OpenConfirm tests).
pub async fn setup_server_with_passive_peer() -> TestServer {
    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
    add_passive_peer(&mut config, "127.0.0.1");
    let server = start_test_server(config).await;
    // FakePeer will be eBGP (ASN 65002): apply accept-all policies
    apply_import_accept_all(&server, "127.0.0.1").await;
    apply_export_accept_all(&server, "127.0.0.1").await;
    server
}

/// Setup a test server with a FakePeer already connected and in Established state.
///
/// Returns (TestServer, FakePeer) with default settings:
/// - Server: ASN 65001, router_id 1.1.1.1, hold_time 300
/// - FakePeer: ASN 65002, router_id 2.2.2.2
pub async fn setup_server_and_fake_peer() -> (TestServer, FakePeer) {
    let server = setup_server_with_passive_peer().await;
    let peer =
        FakePeer::connect_and_handshake(None, &server, 65002, Ipv4Addr::new(2, 2, 2, 2), None)
            .await;
    (server, peer)
}

/// Sets up two BGP servers with peering established
///
/// Server1 (AS65001) <-----> Server2 (AS65001)
///
/// # Arguments
/// * `config` - Peer configuration (hold timer, GR, etc). Defaults to hold_timer=90s if not specified.
///
/// Bidirectional peering of two servers with default config, waits for Established.
pub async fn peer_servers(server1: &TestServer, server2: &TestServer) {
    peer_servers_with_config(server1, server2, SessionConfig::default()).await;
}

/// Bidirectional peering of two servers with custom config, waits for Established.
pub async fn peer_servers_with_config(
    server1: &TestServer,
    server2: &TestServer,
    config: SessionConfig,
) {
    server1.add_peer_with_config(server2, config.clone()).await;
    server2.add_peer_with_config(server1, config).await;

    // RFC 8212: eBGP peers need explicit accept-all policies
    if server1.asn != server2.asn {
        apply_permit_all_routes(server1, server2).await;
    }

    let peer_addr = server2.address.to_string();
    poll_until(
        || async {
            server1.client.get_peers().await.is_ok_and(|peers| {
                peers.iter().any(|peer| {
                    peer.address == peer_addr && peer.state == BgpState::Established as i32
                })
            })
        },
        &format!(
            "Timeout waiting for AS{} <-> AS{} to establish",
            server1.asn, server2.asn
        ),
    )
    .await;
}

/// Returns (server1, server2) TestServer instances for each server.
/// Both servers will be in Established state when this function returns.
pub async fn setup_two_peered_servers(config: PeerConfig) -> (TestServer, TestServer) {
    let hold = config.hold_timer_secs.unwrap_or(90) as u64;
    let [server1, server2] = chain_servers(
        [
            start_test_server(BgpConfig::new(
                65001,
                "127.0.0.1:0",
                Ipv4Addr::new(1, 1, 1, 1),
                hold,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65002,
                "127.0.0.2:0",
                Ipv4Addr::new(2, 2, 2, 2),
                hold,
            ))
            .await,
        ],
        config,
    )
    .await;

    (server1, server2)
}

/// Sets up three BGP servers in a full mesh topology
///
///     Server1 (AS65001)
///       /  \
///      /    \
/// Server2 -- Server3
/// (AS65002)  (AS65003)
///
/// # Arguments
/// * `hold_timer_secs` - BGP hold timer in seconds (defaults to 3 seconds if None)
///
/// Returns (server1, server2, server3) TestServer instances for each server.
/// All servers will have 2 peers each in Established state when this function returns.
pub async fn setup_three_meshed_servers(
    config: PeerConfig,
) -> (TestServer, TestServer, TestServer) {
    let hold = config.hold_timer_secs.unwrap_or(90) as u64;
    let [server1, server2, server3] = mesh_servers(
        [
            start_test_server(BgpConfig::new(
                65001,
                "127.0.0.1:0",
                Ipv4Addr::new(1, 1, 1, 1),
                hold,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65002,
                "127.0.0.2:0",
                Ipv4Addr::new(2, 2, 2, 2),
                hold,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65003,
                "127.0.0.3:0",
                Ipv4Addr::new(3, 3, 3, 3),
                hold,
            ))
            .await,
        ],
        config,
    )
    .await;

    (server1, server2, server3)
}

/// Sets up four BGP servers in a full mesh topology
///
/// (AS65001) (AS65002)
///     S1----S2
///      |\   /|
///      | \ / |
///      | / \ |
///      |/   \|
///     S3----S4
/// (AS65003) (AS65004)
///
/// # Arguments
/// * `hold_timer_secs` - BGP hold timer in seconds (defaults to 3 seconds if None)
///
/// Returns (server1, server2, server3, server4) TestServer instances for each server.
/// All servers will have 3 peers each in Established state when this function returns.
pub async fn setup_four_meshed_servers(
    config: PeerConfig,
) -> (TestServer, TestServer, TestServer, TestServer) {
    let hold = config.hold_timer_secs.unwrap_or(90) as u64;
    let [server1, server2, server3, server4] = mesh_servers(
        [
            start_test_server(BgpConfig::new(
                65001,
                "127.0.0.1:0",
                Ipv4Addr::new(1, 1, 1, 1),
                hold,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65002,
                "127.0.0.2:0",
                Ipv4Addr::new(2, 2, 2, 2),
                hold,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65003,
                "127.0.0.3:0",
                Ipv4Addr::new(3, 3, 3, 3),
                hold,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65004,
                "127.0.0.4:0",
                Ipv4Addr::new(4, 4, 4, 4),
                hold,
            ))
            .await,
        ],
        config,
    )
    .await;

    (server1, server2, server3, server4)
}

/// Sets up a hub-and-spoke BGP topology.
///
/// The hub connects to each spoke; spokes are not connected to each other.
/// All sessions use the same `config`. Returns when all sessions are Established.
///
/// Hub ASN and spoke ASNs are auto-assigned IPs (127.0.0.1 for hub, 127.0.0.2+ for spokes).
///
/// # Example
/// ```
/// // S1 (AS65001) connected to S2 (AS65002), S3 (AS65003), S4 (AS65001 iBGP)
/// let (s1, [s2, s3, s4]) = setup_hub_spoke_servers(65001, [65002, 65003, 65001], PeerConfig::default()).await;
/// ```
pub async fn setup_hub_spoke_servers<const N: usize>(
    hub_asn: u32,
    spoke_asns: [u32; N],
    config: PeerConfig,
) -> (TestServer, [TestServer; N]) {
    let hold = config.hold_timer_secs.unwrap_or(90) as u64;
    let hub = start_test_server(BgpConfig::new(
        hub_asn,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        hold,
    ))
    .await;
    let mut spokes = Vec::new();
    for (i, &asn) in spoke_asns.iter().enumerate() {
        let octet = (i + 2) as u8;
        spokes.push(
            start_test_server(BgpConfig::new(
                asn,
                &format!("127.0.0.{}:0", octet),
                Ipv4Addr::new(octet, octet, octet, octet),
                hold,
            ))
            .await,
        );
    }
    let spokes_array: [TestServer; N] = match spokes.try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Failed to convert Vec to array"),
    };
    hub_spoke_servers(hub, spokes_array, config).await
}

/// Polls until each server's full RIB matches the expected routes exactly
pub async fn poll_rib(expectations: &[(&TestServer, Vec<Route>)]) {
    poll_rib_with_timeout(expectations, Duration::from_secs(10)).await;
}

/// Polls until each server's RIB matches expected routes using ADD-PATH comparison.
/// Uses ExpectPathId::Distinct to assert multiple paths per prefix with distinct path_ids.
pub async fn poll_rib_addpath(expectations: &[(&TestServer, Vec<Route>)]) {
    poll_until(
        || async {
            for (server, expected_routes) in expectations {
                let Ok(routes) = server
                    .client
                    .list_routes(ListRoutesRequest::default())
                    .await
                else {
                    return false;
                };
                if !routes_match(&routes, expected_routes, ExpectPathId::Distinct) {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for ADD-PATH routes to propagate",
    )
    .await;
}

/// Polls until each server's full RIB matches exactly, with custom timeout
pub async fn poll_rib_with_timeout(expectations: &[(&TestServer, Vec<Route>)], timeout: Duration) {
    poll_until_with_timeout(
        || async {
            for (server, expected_routes) in expectations {
                let Ok(routes) = server
                    .client
                    .list_routes(ListRoutesRequest::default())
                    .await
                else {
                    return false;
                };

                if !routes_match(&routes, expected_routes, ExpectPathId::Present) {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for routes to propagate",
        timeout,
    )
    .await;
}

/// Polls until a specific route exists in a server's RIB, then asserts path attributes
/// Check if a prefix exists in a server's RIB.
pub async fn has_route(server: &TestServer, prefix: &str) -> bool {
    server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .is_ok_and(|routes| routes.iter().any(|r| route_has_prefix(r, prefix)))
}

/// Check if a server's adj-rib-out toward a peer contains a specific prefix.
pub async fn has_adj_out_route(server: &TestServer, peer: &TestServer, prefix: &str) -> bool {
    server
        .client
        .list_routes(ListRoutesRequest {
            rib_type: Some(RibType::AdjOut as i32),
            peer_address: Some(peer.address.to_string()),
            ..Default::default()
        })
        .await
        .is_ok_and(|routes| routes.iter().any(|r| route_has_prefix(r, prefix)))
}

pub async fn poll_route_exists(server: &TestServer, expected: Route) {
    poll_until(
        || async {
            let Ok(routes) = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
            else {
                return false;
            };
            let actual: Vec<Route> = routes
                .into_iter()
                .filter(|r| r.key == expected.key)
                .collect();
            routes_match(
                &actual,
                std::slice::from_ref(&expected),
                ExpectPathId::Present,
            )
        },
        &format!(
            "Timeout waiting for route {:?} on server {}",
            expected.key, server.address
        ),
    )
    .await;
}

/// Expected peer statistics for polling. None means don't check that field.
/// Uses `==` for exact match, `>=` for `min_*` fields.
#[derive(Default, Clone, Copy)]
pub struct ExpectedStats {
    pub open_sent: Option<u64>,
    pub open_received: Option<u64>,
    pub update_sent: Option<u64>,
    pub update_received: Option<u64>,
    pub notification_sent: Option<u64>,
    pub notification_received: Option<u64>,
    pub min_update_sent: Option<u64>,
    pub min_update_received: Option<u64>,
    pub min_keepalive_sent: Option<u64>,
    pub min_keepalive_received: Option<u64>,
    pub min_notification_sent: Option<u64>,
    pub min_notification_received: Option<u64>,
}

impl ExpectedStats {
    pub fn is_met_by(&self, s: &PeerStatistics) -> bool {
        self.open_sent.is_none_or(|e| s.open_sent == e)
            && self.open_received.is_none_or(|e| s.open_received == e)
            && self.update_sent.is_none_or(|e| s.update_sent == e)
            && self.update_received.is_none_or(|e| s.update_received == e)
            && self
                .notification_sent
                .is_none_or(|e| s.notification_sent == e)
            && self
                .notification_received
                .is_none_or(|e| s.notification_received == e)
            && self.min_update_sent.is_none_or(|e| s.update_sent >= e)
            && self
                .min_update_received
                .is_none_or(|e| s.update_received >= e)
            && self
                .min_keepalive_sent
                .is_none_or(|e| s.keepalive_sent >= e)
            && self
                .min_keepalive_received
                .is_none_or(|e| s.keepalive_received >= e)
            && self
                .min_notification_sent
                .is_none_or(|e| s.notification_sent >= e)
            && self
                .min_notification_received
                .is_none_or(|e| s.notification_received >= e)
    }
}

/// Poll until peer statistics meet expected thresholds.
pub async fn poll_peer_stats(server: &TestServer, peer_addr: &str, expected: ExpectedStats) {
    poll_until(
        || async {
            let Ok((_, stats)) = server.client.get_peer(peer_addr.to_string()).await else {
                eprintln!("poll_peer_stats: get_peer failed");
                return false;
            };
            let Some(s) = stats else {
                eprintln!("poll_peer_stats: stats is None");
                return false;
            };
            if !expected.is_met_by(&s) {
                eprintln!(
                    "poll_peer_stats: notification_sent={} (expecting >= {:?})",
                    s.notification_sent, expected.min_notification_sent
                );
                return false;
            }
            true
        },
        "Timeout waiting for peer statistics",
    )
    .await;
}

/// Wait for routes and peer stats to converge.
pub async fn wait_convergence(
    route_expectations: &[(&TestServer, Vec<Route>)],
    stats_expectations: &[(&TestServer, &TestServer, ExpectedStats)],
) {
    poll_until(
        || async {
            for (server, expected_routes) in route_expectations {
                let Ok(routes) = server
                    .client
                    .list_routes(ListRoutesRequest::default())
                    .await
                else {
                    return false;
                };
                if !routes_match(&routes, expected_routes, ExpectPathId::Present) {
                    return false;
                }
            }
            for (server, peer, expected) in stats_expectations {
                let Ok((_, stats)) = server.client.get_peer(peer.address.to_string()).await else {
                    return false;
                };
                let Some(s) = stats else {
                    return false;
                };
                if !expected.is_met_by(&s) {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for route convergence",
    )
    .await;
}

/// Polls for route withdrawal from multiple servers
///
/// # Arguments
/// * `servers` - Slice of TestServer instances to check
pub async fn poll_route_withdrawal(servers: &[&TestServer]) {
    poll_until(
        || async {
            for server in servers.iter() {
                let Ok(routes) = server
                    .client
                    .list_routes(ListRoutesRequest::default())
                    .await
                else {
                    return false;
                };
                if !routes.is_empty() {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for route withdrawal",
    )
    .await;
}

/// Generic polling helper that retries until a condition is met
///
/// # Arguments
/// * `check` - Async function that returns true when condition is met
/// * `timeout_message` - Message to display if timeout occurs
/// * `timeout` - Maximum time to wait before panicking
pub async fn poll_until_with_timeout<F, Fut>(check: F, timeout_message: &str, timeout: Duration)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if check().await {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }

    panic!("{}", timeout_message);
}

/// Generic polling helper that retries until a condition is met (default 10s timeout)
pub async fn poll_until<F, Fut>(check: F, timeout_message: &str)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    poll_until_with_timeout(check, timeout_message, Duration::from_secs(10)).await;
}

/// Poll to verify a condition stays true for a duration.
/// Panics immediately if condition becomes false.
pub async fn poll_while<F, Fut>(check: F, duration: Duration, fail_message: &str)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < duration {
        assert!(check().await, "{}", fail_message);
        sleep(Duration::from_millis(100)).await;
    }
}

/// Wait until condition becomes true, then verify it stays stable for a duration.
/// Combines poll_until + poll_while to prevent race conditions.
pub async fn poll_until_stable<F, Fut>(check: F, stable_duration: Duration, fail_message: &str)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    poll_until(&check, fail_message).await;
    poll_while(check, stable_duration, fail_message).await;
}

/// Verify peer statistics
///
/// # Arguments
/// * `server` - Server to query for peer statistics
/// * `peer_addr` - Address of the peer to check
/// * `expected_open_sent` - Expected number of OPEN messages sent
/// * `expected_open_received` - Expected number of OPEN messages received
/// * `expected_update_sent` - Expected number of UPDATE messages sent
pub async fn verify_peer_statistics(
    server: &TestServer,
    peer_addr: String,
    expected_open_sent: u64,
    expected_open_received: u64,
    expected_update_sent: u64,
) {
    let (peer, stats) = server
        .client
        .get_peer(peer_addr.clone())
        .await
        .expect("Failed to get peer");

    assert!(peer.is_some(), "Peer {} should exist", peer_addr);
    let stats = stats.expect("Statistics should be present");

    assert_eq!(
        stats.open_sent, expected_open_sent,
        "Peer {} should send OPEN {} time(s), got {}",
        peer_addr, expected_open_sent, stats.open_sent
    );
    assert_eq!(
        stats.open_received, expected_open_received,
        "Peer {} should receive OPEN {} time(s), got {}",
        peer_addr, expected_open_received, stats.open_received
    );
    assert_eq!(
        stats.update_sent, expected_update_sent,
        "Peer {} should send UPDATE {} time(s), got {}",
        peer_addr, expected_update_sent, stats.update_sent
    );
}

/// Parameters for announcing a route.
///
/// ```
/// // IP route
/// announce_route(server, RouteParams::Ip(Box::new(IpRouteParams {
///     prefix: "10.0.0.0/24".to_string(),
///     next_hop: "192.168.1.1".to_string(),
///     ..Default::default()
/// }))).await;
///
/// // BGP-LS route
/// announce_route(server, RouteParams::Ls(LsRouteParams {
///     nlri: Some(nlri),
///     attribute: Some(attr),
///     ..Default::default()
/// })).await;
/// ```
pub enum RouteParams {
    Ip(Box<IpRouteParams>),
    Ls(Box<LsRouteParams>),
}

#[derive(Default)]
pub struct IpRouteParams {
    pub prefix: String,
    pub next_hop: String,
    pub origin: Option<Origin>,
    pub as_path: Vec<AsPathSegment>,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub atomic_aggregate: bool,
    pub communities: Vec<u32>,
    pub extended_communities: Vec<u64>,
    pub large_communities: Vec<bgpgg::bgp::msg_update_types::LargeCommunity>,
    pub originator_id: Option<String>,
    pub cluster_list: Vec<String>,
}

#[derive(Default)]
pub struct LsRouteParams {
    pub nlri: Option<LsNlri>,
    pub attribute: Option<LsAttribute>,
    pub next_hop: Option<String>,
}

pub async fn announce_route(server: &TestServer, params: RouteParams) {
    let request = match params {
        RouteParams::Ip(ip) => AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: ip.prefix,
                next_hop: ip.next_hop,
                origin: ip.origin.unwrap_or(Origin::Igp) as i32,
                as_path: ip.as_path,
                local_pref: ip.local_pref,
                med: ip.med,
                atomic_aggregate: ip.atomic_aggregate,
                communities: ip.communities,
                extended_communities: ip
                    .extended_communities
                    .iter()
                    .map(|ec| u64_to_proto_extcomm(*ec))
                    .collect(),
                large_communities: ip
                    .large_communities
                    .iter()
                    .map(internal_to_proto_large_community)
                    .collect(),
                originator_id: ip.originator_id,
                cluster_list: ip.cluster_list,
            }))),
        },
        RouteParams::Ls(ls) => AddRouteRequest {
            route: Some(add_route_request::Route::Ls(Box::new(AddLsRouteRequest {
                nlri: ls.nlri,
                attribute: ls.attribute,
                next_hop: ls.next_hop,
            }))),
        },
    };
    server.client.add_route(request).await.unwrap();
}

/// Chains BGP servers together in a linear topology (active-active peering)
/// Both sides of each peering call add_peer() on each other.
///
/// # Arguments
/// * `servers` - Array of servers to chain together
///
/// # Returns
/// The same array of servers after chaining is complete
///
/// # Example
/// ```
/// let [s1, s2, s3] = chain_servers([
///     start_test_server(65001, ...).await,
///     start_test_server(65002, ...).await,
///     start_test_server(65002, ...).await,
/// ]).await;
/// ```
pub async fn chain_servers<const N: usize>(
    servers: [TestServer; N],
    config: PeerConfig,
) -> [TestServer; N] {
    let session_config = SessionConfig {
        graceful_restart: config.graceful_restart,
        llgr: config.llgr,
        idle_hold_time_secs: config.idle_hold_time_secs,
        min_route_advertisement_interval_secs: config.min_route_advertisement_interval_secs,
        add_path_send: config.add_path_send.map(|v| {
            if v {
                AddPathSendMode::AddPathSendAll
            } else {
                AddPathSendMode::AddPathSendDisabled
            }
            .into()
        }),
        add_path_receive: config.add_path_receive,
        send_rpki_community: config.send_rpki_community,
        afi_safis: config.afi_safis.clone(),
        ..Default::default()
    };

    // Active-active: both sides call add_peer() on each other
    // Chain: s0 <-> s1 <-> s2 <-> ...
    for i in 0..servers.len() - 1 {
        let curr_port = servers[i].bgp_port;
        let curr_address = servers[i].address.to_string();
        let next_port = servers[i + 1].bgp_port;
        let next_address = servers[i + 1].address.to_string();

        // Server i adds server i+1
        let mut cfg = session_config.clone();
        cfg.port = Some(next_port as u32);
        servers[i]
            .client
            .add_peer(next_address, Some(cfg))
            .await
            .unwrap_or_else(|_| panic!("Failed to add peer {} to server {}", i + 1, i));

        // Server i+1 adds server i
        let mut cfg = session_config.clone();
        cfg.port = Some(curr_port as u32);
        servers[i + 1]
            .client
            .add_peer(curr_address, Some(cfg))
            .await
            .unwrap_or_else(|_| panic!("Failed to add peer {} to server {}", i, i + 1));

        // RFC 8212: eBGP peers need explicit accept-all policies
        if servers[i].asn != servers[i + 1].asn {
            apply_permit_all_routes(&servers[i], &servers[i + 1]).await;
        }
    }

    // Wait for all peers to reach Established
    poll_until(
        || async {
            for (i, server) in servers.iter().enumerate() {
                let mut expected_peers = Vec::new();

                if i > 0 {
                    expected_peers.push(servers[i - 1].to_peer(BgpState::Established));
                }

                if i < servers.len() - 1 {
                    expected_peers.push(servers[i + 1].to_peer(BgpState::Established));
                }

                if !verify_peers(server, expected_peers).await {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for chain topology to establish",
    )
    .await;

    servers
}

/// Create chain of servers with given ASNs, auto-generating IPs and router IDs
///
/// This helper reduces boilerplate for tests that need servers with specific ASNs.
/// IPs are auto-assigned as 127.0.0.N where N is the server index (1-based).
/// Router IDs are auto-assigned as N.N.N.N.
///
/// # Arguments
/// * `asns` - Array of AS numbers for the servers
/// * `hold_timer` - Optional hold timer in seconds (defaults to 90 if None)
///
/// # Example
/// ```
/// let [s1, s2] = create_asn_chain([4200000001, 4200000002], None).await;
/// let [s1, s2, s3] = create_asn_chain([65001, 65002, 65003], Some(300)).await;
/// ```
pub async fn create_asn_chain<const N: usize>(
    asns: [u32; N],
    hold_timer: Option<u64>,
) -> [TestServer; N] {
    let hold = hold_timer.unwrap_or(90);
    let mut servers = Vec::new();
    for (i, asn) in asns.iter().enumerate() {
        let octet = (i + 1) as u8;
        servers.push(
            start_test_server(BgpConfig::new(
                *asn,
                &format!("127.0.0.{}:0", octet),
                Ipv4Addr::new(octet, octet, octet, octet),
                hold,
            ))
            .await,
        );
    }
    let servers_array: [TestServer; N] = match servers.try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("Failed to convert Vec to array"),
    };
    chain_servers(servers_array, PeerConfig::default()).await
}

/// Announce route from source and verify it propagates to destinations
///
/// Reduces boilerplate for route propagation tests by handling the announce + verify pattern.
/// Supports both single and multiple destinations.
///
/// # Arguments
/// * `source` - Server that announces the route
/// * `dests` - Slice of servers that should receive the route
/// * `announce_params` - RouteParams for announcement (prefix, next_hop, communities, etc.)
/// * `expected_path` - Expected PathParams after propagation (caller sets ALL fields)
///
/// # Examples
/// ```
/// // eBGP: next_hop rewritten, AS prepended, local_pref set
/// announce_and_verify_route(
///     &mut s1,
///     &[&s2],
///     RouteParams::Ip(Box::new(IpRouteParams { prefix: "10.0.0.0/24".to_string(), next_hop: "192.168.1.1".to_string(), ..Default::default() })),
///     PathParams {
///         as_path: vec![as_sequence(vec![65001])],
///         next_hop: s1.address.to_string(),
///         peer_address: s1.address.to_string(),
///         local_pref: Some(100),
///         origin: Some(Origin::Igp),
///         ..Default::default()
///     }
/// ).await;
///
/// // iBGP: next_hop preserved, no AS prepend
/// announce_and_verify_route(
///     &mut s1,
///     &[&s2],
///     RouteParams::Ip(Box::new(IpRouteParams { prefix: "10.0.0.0/24".to_string(), next_hop: "192.168.1.1".to_string(), ..Default::default() })),
///     PathParams {
///         as_path: vec![],
///         next_hop: "192.168.1.1".to_string(),
///         peer_address: s1.address.to_string(),
///         local_pref: Some(100),
///         origin: Some(Origin::Igp),
///         ..Default::default()
///     }
/// ).await;
///
/// // Multiple destinations with same expected path
/// announce_and_verify_route(
///     &mut s1,
///     &[&s2, &s3, &s4],
///     RouteParams::Ip(Box::new(IpRouteParams { prefix: "10.1.0.0/24".to_string(), ..Default::default() })),
///     PathParams {
///         as_path: vec![as_sequence(vec![65001])],
///         next_hop: s1.address.to_string(),
///         peer_address: s1.address.to_string(),
///         local_pref: Some(100),
///         origin: Some(Origin::Igp),
///         ..Default::default()
///     }
/// ).await;
/// ```
pub async fn announce_and_verify_route(
    source: &TestServer,
    dests: &[&TestServer],
    announce_params: RouteParams,
    expected_path: PathParams,
) {
    let key = match &announce_params {
        RouteParams::Ip(ip) => route::Key::Prefix(ip.prefix.clone()),
        RouteParams::Ls(ls) => {
            route::Key::LsNlri(Box::new(ls.nlri.clone().expect("ls_nlri required")))
        }
    };
    announce_route(source, announce_params).await;

    let mut expectations = Vec::new();
    for dest in dests {
        expectations.push((
            *dest,
            vec![Route {
                paths: vec![build_path(expected_path.clone())],
                key: Some(key.clone()),
            }],
        ));
    }

    poll_rib(&expectations).await;
}

/// Meshes BGP servers together in a full mesh topology (active-active peering)
///
/// Both sides of each peering call add_peer() on each other, representing real-world
/// active-active BGP configurations.
///
/// # Arguments
/// * `servers` - Array of servers to mesh together
///
/// # Returns
/// The same array of servers after meshing is complete
///
/// # Example
/// ```
/// let [s1, s2, s3] = mesh_servers([
///     start_test_server(65001, ...).await,
///     start_test_server(65002, ...).await,
///     start_test_server(65003, ...).await,
/// ]).await;
/// // All three servers are now connected to each other
/// ```
pub async fn mesh_servers<const N: usize>(
    servers: [TestServer; N],
    config: PeerConfig,
) -> [TestServer; N] {
    let session_config = SessionConfig {
        graceful_restart: config.graceful_restart,
        llgr: config.llgr,
        idle_hold_time_secs: config.idle_hold_time_secs,
        min_route_advertisement_interval_secs: config.min_route_advertisement_interval_secs,
        add_path_send: config.add_path_send.map(|v| {
            if v {
                AddPathSendMode::AddPathSendAll
            } else {
                AddPathSendMode::AddPathSendDisabled
            }
            .into()
        }),
        add_path_receive: config.add_path_receive,
        send_rpki_community: config.send_rpki_community,
        ..Default::default()
    };

    // Active-active: both sides call add_peer() on each other
    for i in 0..servers.len() {
        for j in (i + 1)..servers.len() {
            let i_port = servers[i].bgp_port;
            let i_address = servers[i].address.to_string();
            let j_port = servers[j].bgp_port;
            let j_address = servers[j].address.to_string();

            // Server i adds server j
            let mut cfg = session_config.clone();
            cfg.port = Some(j_port as u32);
            servers[i]
                .client
                .add_peer(j_address, Some(cfg))
                .await
                .unwrap_or_else(|_| panic!("Failed to add peer {} to server {}", j, i));

            // Server j adds server i
            let mut cfg = session_config.clone();
            cfg.port = Some(i_port as u32);
            servers[j]
                .client
                .add_peer(i_address, Some(cfg))
                .await
                .unwrap_or_else(|_| panic!("Failed to add peer {} to server {}", i, j));

            // RFC 8212: eBGP peers need explicit accept-all policies
            if servers[i].asn != servers[j].asn {
                apply_permit_all_routes(&servers[i], &servers[j]).await;
            }
        }
    }

    // Wait for all peers to reach Established
    poll_until(
        || async {
            for (i, server) in servers.iter().enumerate() {
                let mut expected_peers = Vec::new();

                for (j, other_server) in servers.iter().enumerate() {
                    if i != j {
                        // Expect peer in Established state
                        expected_peers.push(other_server.to_peer(BgpState::Established));
                    }
                }

                if !verify_peers(server, expected_peers).await {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for mesh topology to establish",
    )
    .await;

    servers
}

/// Connect a hub server to N spoke servers (spokes not connected to each other).
/// Waits for all N hub-spoke sessions to reach Established.
pub async fn hub_spoke_servers<const N: usize>(
    hub: TestServer,
    spokes: [TestServer; N],
    config: PeerConfig,
) -> (TestServer, [TestServer; N]) {
    let session_config = SessionConfig {
        graceful_restart: config.graceful_restart,
        llgr: config.llgr,
        idle_hold_time_secs: config.idle_hold_time_secs,
        min_route_advertisement_interval_secs: config.min_route_advertisement_interval_secs,
        add_path_send: config.add_path_send.map(|v| {
            if v {
                AddPathSendMode::AddPathSendAll
            } else {
                AddPathSendMode::AddPathSendDisabled
            }
            .into()
        }),
        add_path_receive: config.add_path_receive,
        send_rpki_community: config.send_rpki_community,
        ..Default::default()
    };

    for spoke in &spokes {
        let mut cfg = session_config.clone();
        cfg.port = Some(spoke.bgp_port as u32);
        hub.client
            .add_peer(spoke.address.to_string(), Some(cfg))
            .await
            .unwrap_or_else(|e| panic!("hub failed to add spoke: {}", e));

        let mut cfg = session_config.clone();
        cfg.port = Some(hub.bgp_port as u32);
        spoke
            .client
            .add_peer(hub.address.to_string(), Some(cfg))
            .await
            .unwrap_or_else(|e| panic!("spoke failed to add hub: {}", e));
    }

    poll_until(
        || async {
            for spoke in &spokes {
                if !verify_peers(spoke, vec![hub.to_peer(BgpState::Established)]).await {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for hub-spoke topology to establish",
    )
    .await;

    (hub, spokes)
}

/// Sets up route reflector topology with bidirectional peering and waits for Established.
///
/// - `clients_per_rr[i]` are added to `rrs[i]` with `rr_client=true`
/// - `non_clients` connect to every RR as regular peers
/// - RRs peer with each other as non-clients
///
/// # Examples
/// ```
/// // Single RR with 2 clients
/// setup_rr(vec![&rr], vec![vec![&client1, &client2]], vec![]).await;
///
/// // Mixed: 1 client, 2 non-clients
/// setup_rr(vec![&rr], vec![vec![&c1]], vec![&nc1, &nc2]).await;
///
/// // Dual RR chain: RRs auto-peer as non-clients
/// setup_rr(vec![&rr1, &rr2], vec![vec![&client1], vec![&client2]], vec![]).await;
/// ```
pub async fn setup_rr(
    rrs: Vec<&TestServer>,
    clients_per_rr: Vec<Vec<&TestServer>>,
    non_clients: Vec<&TestServer>,
    client_config: SessionConfig,
) {
    assert_eq!(
        rrs.len(),
        clients_per_rr.len(),
        "each RR must have a clients list"
    );

    let rr_client_cfg = SessionConfig {
        rr_client: Some(true),
        ..client_config.clone()
    };

    for (rr, rr_clients) in rrs.iter().zip(clients_per_rr.iter()) {
        for client in rr_clients {
            rr.add_peer_with_config(client, rr_client_cfg.clone()).await;
            client.add_peer_with_config(rr, client_config.clone()).await;
            if rr.asn != client.asn {
                apply_permit_all_routes(rr, client).await;
            }
        }

        for nc in &non_clients {
            rr.add_peer_with_config(nc, client_config.clone()).await;
            nc.add_peer_with_config(rr, client_config.clone()).await;
            if rr.asn != nc.asn {
                apply_permit_all_routes(rr, nc).await;
            }
        }
    }

    // RRs peer with each other as non-clients
    for i in 0..rrs.len() {
        for j in (i + 1)..rrs.len() {
            rrs[i].add_peer(rrs[j]).await;
            rrs[j].add_peer(rrs[i]).await;
            if rrs[i].asn != rrs[j].asn {
                apply_permit_all_routes(rrs[i], rrs[j]).await;
            }
        }
    }

    // Wait for Established on all RRs
    for (rr, rr_clients) in rrs.iter().zip(clients_per_rr.iter()) {
        let mut expected: Vec<_> = rr_clients
            .iter()
            .map(|c| c.to_peer(BgpState::Established))
            .collect();
        expected.extend(
            non_clients
                .iter()
                .map(|nc| nc.to_peer(BgpState::Established)),
        );
        for other_rr in &rrs {
            if !std::ptr::eq(*rr, *other_rr) {
                expected.push(other_rr.to_peer(BgpState::Established));
            }
        }
        poll_until(
            || async { verify_peers(rr, expected.clone()).await },
            "Timeout waiting for RR peers to reach Established",
        )
        .await;
    }
}

/// Helper to check if server has expected peers (returns bool, suitable for poll_until)
pub async fn verify_peers(server: &TestServer, mut expected_peers: Vec<Peer>) -> bool {
    let Ok(mut peers) = server.client.get_peers().await else {
        return false;
    };

    // Sort both by address for consistent comparison
    peers.sort_by(|a, b| a.address.cmp(&b.address));
    expected_peers.sort_by(|a, b| a.address.cmp(&b.address));

    if peers.len() != expected_peers.len() {
        eprintln!(
            "verify_peers: count mismatch: actual={} expected={}",
            peers.len(),
            expected_peers.len()
        );
        return false;
    }

    for (i, (actual, expected)) in peers.iter().zip(expected_peers.iter()).enumerate() {
        if actual.address != expected.address
            || actual.asn != expected.asn
            || actual.state != expected.state
            || actual.admin_state != expected.admin_state
        {
            eprintln!(
                "verify_peers mismatch at peer {}:\n  actual:   addr={} asn={} state={} admin={}\n  expected: addr={} asn={} state={} admin={}",
                i, actual.address, actual.asn, actual.state, actual.admin_state,
                expected.address, expected.asn, expected.state, expected.admin_state,
            );
            return false;
        }
    }

    true
}

/// Poll until server has expected peers
pub async fn poll_peers(server: &TestServer, expected_peers: Vec<Peer>) {
    poll_until(
        || async { verify_peers(server, expected_peers.clone()).await },
        "Timeout waiting for peers to match expected state",
    )
    .await;
}

pub async fn poll_peers_with_timeout(
    server: &TestServer,
    expected_peers: Vec<Peer>,
    timeout: Duration,
) {
    poll_until_with_timeout(
        || async { verify_peers(server, expected_peers.clone()).await },
        "Timeout waiting for peers to match expected state",
        timeout,
    )
    .await;
}

/// Wait for a specific peer address to reach Established on a server.
pub async fn poll_peer_established(server: &TestServer, peer_addr: &str) {
    let addr = peer_addr.to_string();
    poll_until(
        || async {
            server.client.get_peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .any(|p| p.address == addr && p.state == BgpState::Established as i32)
            })
        },
        &format!("Timeout waiting for peer {addr} to establish"),
    )
    .await;
}

/// Wait for a specific peer to leave Established state.
pub async fn poll_peer_not_established(server: &TestServer, peer_addr: &str) {
    let addr = peer_addr.to_string();
    poll_until(
        || async {
            server.client.get_peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .any(|p| p.address == addr && p.state != BgpState::Established as i32)
            })
        },
        &format!("Timeout waiting for peer {addr} to leave Established"),
    )
    .await;
}

/// Verify server info matches expected values
pub async fn verify_server_info(
    server: &TestServer,
    expected_addr: Ipv4Addr,
    expected_port: u16,
    expected_num_routes: u64,
) {
    let (listen_addr, listen_port, num_routes) = server
        .client
        .get_server_info()
        .await
        .expect("Failed to get server info");

    assert_eq!(listen_addr, expected_addr, "listen_addr mismatch");
    assert_eq!(listen_port, expected_port, "listen_port mismatch");
    assert_eq!(num_routes, expected_num_routes, "num_routes mismatch");
}

/// Fake BGP peer for testing error handling
///
/// This allows sending raw/malformed BGP messages to test error handling.
/// Use a long hold timer (e.g., 300s) to avoid needing KEEPALIVE management.
pub struct FakePeer {
    pub stream: Option<TcpStream>,
    pub address: String,
    pub asn: u32,
    pub listener: Option<TcpListener>,
    /// Whether this peer advertised 4-byte ASN capability
    pub supports_4byte_asn: bool,
    /// ADD-PATH mask for parsing incoming UPDATEs from the remote peer.
    pub add_path: AddPathMask,
}

impl FakePeer {
    /// Connect TCP only. Use local_ip to bind to specific address.
    pub async fn connect(local_ip: Option<&str>, peer: &TestServer) -> Self {
        use std::net::SocketAddr;
        use tokio::net::TcpSocket;

        let local_ip = local_ip.unwrap_or("0.0.0.0");
        let local_addr: SocketAddr = format!("{}:0", local_ip).parse().unwrap();
        let peer_addr: SocketAddr = format!("{}:{}", peer.address, peer.bgp_port)
            .parse()
            .unwrap();

        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(local_addr).unwrap();
        let stream = socket.connect(peer_addr).await.unwrap();

        let address = stream.local_addr().unwrap().ip().to_string();
        FakePeer {
            stream: Some(stream),
            address,
            asn: 0,
            listener: None,
            supports_4byte_asn: false,
            add_path: AddPathMask::NONE,
        }
    }

    /// Connect with GTSM: sets IP_MINTTL before connect() to simulate peers that
    /// enforce TTL security from the outset. The TCP handshake will fail if the
    /// listener sends SYN-ACKs with TTL below min_ttl.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub async fn connect_with_min_ttl(
        local_ip: Option<&str>,
        peer: &TestServer,
        min_ttl: u8,
    ) -> Self {
        use std::net::SocketAddr;
        use tokio::net::TcpSocket;

        let local_ip = local_ip.unwrap_or("0.0.0.0");
        let local_addr: SocketAddr = format!("{}:0", local_ip).parse().unwrap();
        let peer_addr: SocketAddr = format!("{}:{}", peer.address, peer.bgp_port)
            .parse()
            .unwrap();

        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(local_addr).unwrap();

        // Set IP_MINTTL before connect() — connect() fails if the listener
        // does not send SYN-ACK with TTL >= min_ttl.
        apply_gtsm(socket.as_raw_fd(), peer_addr.ip(), min_ttl).expect("apply_gtsm failed");

        let stream = socket.connect(peer_addr).await.unwrap();
        let address = stream.local_addr().unwrap().ip().to_string();
        FakePeer {
            stream: Some(stream),
            address,
            asn: 0,
            listener: None,
            supports_4byte_asn: false,
            add_path: AddPathMask::NONE,
        }
    }

    /// Connect and complete handshake with custom OPEN message
    pub async fn connect_with_open(
        local_ip: Option<&str>,
        peer: &TestServer,
        asn: u16,
        router_id: u32,
        open_options: RawOpenOptions,
    ) -> Self {
        // TCP connect
        let mut fake_peer = Self::connect(local_ip, peer).await;

        // Read server's OPEN
        let _server_open = fake_peer.read_open().await;

        // Send our custom OPEN
        let custom_open = build_raw_open(asn, 180, router_id, open_options);
        fake_peer.send_raw(&custom_open).await;

        // Complete handshake
        let _keepalive = fake_peer.read_keepalive().await;
        fake_peer.send_keepalive().await;

        fake_peer.asn = asn as u32;
        fake_peer
    }

    /// Create a FakePeer. Call accept() to accept the connection.
    pub async fn new(bind_addr: &str, local_asn: u32) -> Self {
        let listener = TcpListener::bind(bind_addr).await.unwrap();
        let address = listener.local_addr().unwrap().ip().to_string();
        FakePeer {
            stream: None,
            address,
            asn: local_asn,
            listener: Some(listener),
            supports_4byte_asn: false,
            add_path: AddPathMask::NONE,
        }
    }

    /// Get the port this FakePeer is listening on.
    pub fn port(&self) -> u16 {
        self.listener.as_ref().unwrap().local_addr().unwrap().port()
    }

    /// Accept a TCP connection on the listener (no BGP handshake).
    pub async fn accept(&mut self) {
        let listener = self.listener.as_ref().unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        self.stream = Some(stream);
    }

    /// Scan raw capabilities for ADD-PATH (code 69) entries where we advertised
    /// receive (mode bit 0). Returns an AddPathMask for those AFI/SAFIs.
    fn parse_addpath_receive(caps: &[Vec<u8>]) -> AddPathMask {
        let mut mask = AddPathMask::NONE;
        for cap in caps {
            if cap.len() >= 6 && cap[0] == 69 {
                let data = &cap[2..];
                for chunk in data.chunks_exact(4) {
                    let afi = u16::from_be_bytes([chunk[0], chunk[1]]);
                    let safi = chunk[2];
                    let mode = chunk[3];
                    // Bit 0 = receive: we told the peer we can receive ADD-PATH
                    if mode & 1 != 0 {
                        if let (Ok(afi), Ok(safi)) = (Afi::try_from(afi), Safi::try_from(safi)) {
                            mask = mask.with(&AfiSafi::new(afi, safi));
                        }
                    }
                }
            }
        }
        mask
    }

    /// Returns the MessageFormat based on negotiated capabilities.
    fn message_format(&self) -> MessageFormat {
        MessageFormat {
            use_4byte_asn: self.supports_4byte_asn,
            add_path: self.add_path,
            is_ebgp: false,
            enhanced_rr: false,
        }
    }

    /// Exchange OPEN messages with peer (ends up in OpenConfirm state).
    /// For outgoing connections: sends OPEN then reads OPEN.
    pub async fn handshake_open(&mut self, asn: u32, router_id: Ipv4Addr, hold_time: u16) {
        self.asn = asn;

        // Send our OPEN
        let open = OpenMessage::new(asn, hold_time, u32::from(router_id));
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&open.serialize())
            .await
            .expect("Failed to send OPEN");

        // Read their OPEN
        let msg = read_bgp_message(self.stream.as_mut().unwrap(), PRE_OPEN_FORMAT)
            .await
            .expect("Failed to read OPEN");
        match msg {
            BgpMessage::Open(_) => {}
            _ => panic!("Expected OPEN message"),
        }
    }

    /// Exchange OPEN messages for accepted connections (ends up in OpenConfirm state).
    /// For incoming connections: reads OPEN then sends OPEN.
    pub async fn accept_handshake_open(&mut self, asn: u32, router_id: Ipv4Addr, hold_time: u16) {
        self.asn = asn;

        // Read their OPEN (they connected, they send first)
        let msg = read_bgp_message(self.stream.as_mut().unwrap(), PRE_OPEN_FORMAT)
            .await
            .expect("Failed to read OPEN");
        match msg {
            BgpMessage::Open(_) => {}
            _ => panic!("Expected OPEN message"),
        }

        // Send our OPEN
        let open = OpenMessage::new(asn, hold_time, u32::from(router_id));
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&open.serialize())
            .await
            .expect("Failed to send OPEN");
    }

    /// Exchange KEEPALIVE messages to complete handshake (reaches Established state).
    pub async fn handshake_keepalive(&mut self) {
        let keepalive = KeepaliveMessage {};
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&keepalive.serialize())
            .await
            .expect("Failed to send KEEPALIVE");

        let format = self.message_format();
        let msg = read_bgp_message(self.stream.as_mut().unwrap(), format)
            .await
            .expect("Failed to read KEEPALIVE");
        match msg {
            BgpMessage::Keepalive(_) => {}
            _ => panic!("Expected KEEPALIVE message during handshake"),
        }
    }

    /// Accept incoming connection and complete full BGP handshake.
    /// Mirrors connect_and_handshake but for incoming connections (FakePeer listens).
    /// Without capabilities: uses OpenMessage::new (plain OPEN).
    /// With capabilities: uses build_raw_open (custom OPEN with capabilities).
    pub async fn accept_and_handshake(
        &mut self,
        asn: u32,
        router_id: Ipv4Addr,
        capabilities: Option<Vec<Vec<u8>>>,
    ) {
        self.accept().await;
        self.asn = asn;

        // Read their OPEN
        let _server_open = self.read_open().await;

        // Send our OPEN
        if let Some(caps) = &capabilities {
            let asn_2byte = if asn > 65535 { AS_TRANS } else { asn as u16 };
            self.supports_4byte_asn = true;
            self.add_path = Self::parse_addpath_receive(caps);
            let open = build_raw_open(
                asn_2byte,
                300,
                u32::from(router_id),
                RawOpenOptions {
                    capabilities: Some(caps.clone()),
                    ..Default::default()
                },
            );
            self.send_raw(&open).await;
        } else {
            let open = OpenMessage::new(asn, 300, u32::from(router_id));
            self.stream
                .as_mut()
                .unwrap()
                .write_all(&open.serialize())
                .await
                .expect("Failed to send OPEN");
        }

        // Exchange KEEPALIVEs
        self.send_keepalive().await;
        self.read_keepalive().await;
    }

    pub fn to_peer(&self, state: BgpState) -> Peer {
        Peer {
            address: self.address.clone(),
            asn: self.asn,
            state: state.into(),
            admin_state: AdminState::Up.into(),
            import_policies: vec![],
            export_policies: vec![],
            session_config: None,
        }
    }

    /// Send raw bytes to the peer
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.stream
            .as_mut()
            .unwrap()
            .write_all(bytes)
            .await
            .expect("Failed to send raw bytes");
    }

    /// Send a KEEPALIVE message
    pub async fn send_keepalive(&mut self) {
        let keepalive = KeepaliveMessage {};
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&keepalive.serialize())
            .await
            .expect("Failed to send KEEPALIVE");
    }

    /// Send an OPEN message
    pub async fn send_open(&mut self, asn: u32, router_id: Ipv4Addr, hold_time: u16) {
        let open = OpenMessage::new(asn, hold_time, u32::from(router_id));
        self.stream
            .as_mut()
            .unwrap()
            .write_all(&open.serialize())
            .await
            .unwrap();
    }

    /// Send an OPEN message with Graceful Restart capability
    pub async fn send_open_with_gr(
        &mut self,
        asn: u32,
        router_id: Ipv4Addr,
        hold_time: u16,
        gr_time: u16,
        restart_flag: bool,
    ) {
        self.send_open_with_gr_fbit(asn, router_id, hold_time, gr_time, restart_flag, true)
            .await;
    }

    /// Send an OPEN message with Graceful Restart capability and configurable F-bit
    pub async fn send_open_with_gr_fbit(
        &mut self,
        asn: u32,
        router_id: Ipv4Addr,
        hold_time: u16,
        gr_time: u16,
        restart_flag: bool,
        forwarding_flag: bool,
    ) {
        let gr_cap = build_gr_capability_with_fbit(gr_time, restart_flag, forwarding_flag);
        let mp_cap = build_multiprotocol_capability_ipv4_unicast();
        let open = build_raw_open(
            asn as u16,
            hold_time,
            u32::from(router_id),
            RawOpenOptions {
                capabilities: Some(vec![mp_cap, gr_cap]),
                ..Default::default()
            },
        );
        self.send_raw(&open).await;
    }

    /// Send an OPEN message with GR + LLGR capabilities for IPv4 Unicast
    pub async fn send_open_with_llgr(
        &mut self,
        asn: u32,
        router_id: Ipv4Addr,
        hold_time: u16,
        gr_time: u16,
        llst_secs: u32,
    ) {
        let gr_cap = build_gr_capability(gr_time, false);
        let llgr_cap = build_llgr_capability(false, llst_secs);
        let mp_cap = build_multiprotocol_capability_ipv4_unicast();
        let open = build_raw_open(
            asn as u16,
            hold_time,
            u32::from(router_id),
            RawOpenOptions {
                capabilities: Some(vec![mp_cap, gr_cap, llgr_cap]),
                ..Default::default()
            },
        );
        self.send_raw(&open).await;
    }

    /// Send an OPEN message with Route Refresh + Enhanced Route Refresh capabilities (RFC 7313)
    pub async fn send_open_with_enhanced_rr(
        &mut self,
        asn: u32,
        router_id: Ipv4Addr,
        hold_time: u16,
    ) {
        let mp_cap = build_multiprotocol_capability_ipv4_unicast();
        let rr_cap = vec![2, 0]; // Route Refresh capability (code 2, length 0)
        let err_cap = build_enhanced_route_refresh_capability();
        let asn_cap = build_capability_4byte_asn(asn);
        let open = build_raw_open(
            if asn > 65535 { AS_TRANS } else { asn as u16 },
            hold_time,
            u32::from(router_id),
            RawOpenOptions {
                capabilities: Some(vec![mp_cap, rr_cap, err_cap, asn_cap]),
                ..Default::default()
            },
        );
        self.send_raw(&open).await;
    }

    /// Read and discard an OPEN message
    pub async fn read_open(&mut self) -> OpenMessage {
        let msg = read_bgp_message(self.stream.as_mut().unwrap(), PRE_OPEN_FORMAT)
            .await
            .unwrap();
        match msg {
            BgpMessage::Open(open) => open,
            _ => panic!("Expected OPEN message"),
        }
    }

    /// Read and discard a KEEPALIVE message
    pub async fn read_keepalive(&mut self) {
        let format = self.message_format();
        let msg = read_bgp_message(self.stream.as_mut().unwrap(), format)
            .await
            .unwrap();
        assert!(matches!(msg, BgpMessage::Keepalive(_)));
    }

    /// Read a NOTIFICATION message (skips any KEEPALIVEs) with 5s timeout
    pub async fn read_notification(&mut self) -> NotificationMessage {
        let format = self.message_format();
        let result = timeout(Duration::from_secs(5), async {
            loop {
                let msg = read_bgp_message(self.stream.as_mut().unwrap(), format)
                    .await
                    .expect("Failed to read message");

                match msg {
                    BgpMessage::Notification(notif) => return notif,
                    BgpMessage::Keepalive(_) => continue, // Skip KEEPALIVEs sent by peer
                    _ => panic!("Expected NOTIFICATION, got unexpected message type"),
                }
            }
        })
        .await;

        match result {
            Ok(notif) => notif,
            Err(_) => panic!("Timeout waiting for NOTIFICATION message"),
        }
    }

    /// Read an UPDATE message (skips any KEEPALIVEs) with 5s timeout
    pub async fn read_update(&mut self) -> UpdateMessage {
        let format = self.message_format();
        let result = timeout(Duration::from_secs(5), async {
            loop {
                let msg = read_bgp_message(self.stream.as_mut().unwrap(), format)
                    .await
                    .expect("Failed to read UPDATE");

                match msg {
                    BgpMessage::Update(update) => return update,
                    BgpMessage::Keepalive(_) => continue, // Skip KEEPALIVEs sent by peer
                    _ => panic!("Expected UPDATE, got {:?}", msg),
                }
            }
        })
        .await;

        match result {
            Ok(update) => update,
            Err(_) => panic!("Timeout waiting for UPDATE message"),
        }
    }

    /// Read the next non-KEEPALIVE BGP message from the stream.
    pub async fn read_message(&mut self) -> BgpMessage {
        let format = self.message_format();
        let result = timeout(Duration::from_secs(5), async {
            loop {
                let msg = read_bgp_message(self.stream.as_mut().unwrap(), format)
                    .await
                    .expect("Failed to read message");
                match msg {
                    BgpMessage::Keepalive(_) => continue,
                    other => return other,
                }
            }
        })
        .await;
        match result {
            Ok(msg) => msg,
            Err(_) => panic!("Timeout waiting for BGP message"),
        }
    }

    /// Connect and complete BGP handshake with custom capabilities
    ///
    /// # Arguments
    /// * `local_ip` - Optional local IP to bind to
    /// * `server` - Server to connect to
    /// * `asn` - AS number (use value > 65535 to require capability 65)
    /// * `router_id` - BGP router ID
    /// * `capabilities` - Optional BGP capabilities (e.g., Some(vec![build_capability_4byte_asn(asn)]))
    ///
    /// # Examples
    /// ```
    /// // RFC 6793 OLD speaker (no capability 65)
    /// FakePeer::connect_and_handshake(None, &server, 65002, router_id, None).await;
    ///
    /// // RFC 6793 NEW speaker (with capability 65)
    /// FakePeer::connect_and_handshake(
    ///     None, &server, 4200000002, router_id,
    ///     Some(vec![build_capability_4byte_asn(4200000002)])
    /// ).await;
    /// ```
    pub async fn connect_and_handshake(
        local_ip: Option<&str>,
        server: &TestServer,
        asn: u32,
        router_id: Ipv4Addr,
        capabilities: Option<Vec<Vec<u8>>>,
    ) -> Self {
        let mut peer = Self::connect(local_ip, server).await;

        // Read server's OPEN
        let _server_open = peer.read_open().await;

        // Determine 2-byte ASN field value
        // RFC 6793: Use AS_TRANS if ASN > 65535 and using capability 65
        let asn_2byte = if asn > 65535 && capabilities.is_some() {
            AS_TRANS
        } else if asn > 65535 {
            panic!("ASN {} requires capability 65 (4-byte ASN support)", asn)
        } else {
            asn as u16
        };

        // Check if we're advertising 4-byte ASN capability
        let supports_4byte_asn = capabilities.is_some();

        // Send OPEN
        let open = build_raw_open(
            asn_2byte,
            300,
            u32::from(router_id),
            RawOpenOptions {
                capabilities,
                ..Default::default()
            },
        );
        peer.send_raw(&open).await;

        // Exchange KEEPALIVEs
        peer.send_raw(&build_raw_keepalive(None)).await;
        peer.read_keepalive().await;

        peer.asn = asn;
        peer.supports_4byte_asn = supports_4byte_asn;
        peer
    }

    /// Connect and complete GR+LLGR handshake for IPv4 Unicast.
    pub async fn connect_and_handshake_llgr(
        local_ip: Option<&str>,
        server: &TestServer,
        asn: u32,
        router_id: Ipv4Addr,
        gr_time: u16,
        llst: u32,
    ) -> Self {
        let mut peer = Self::connect(local_ip, server).await;
        peer.read_open().await;
        peer.send_open_with_llgr(asn, router_id, 90, gr_time, llst)
            .await;
        peer.asn = asn;
        peer.send_keepalive().await;
        peer.read_keepalive().await;
        peer
    }

    /// Connect and complete Enhanced Route Refresh handshake for IPv4 Unicast.
    pub async fn connect_and_handshake_enhanced_rr(
        local_ip: Option<&str>,
        server: &TestServer,
        asn: u32,
        router_id: Ipv4Addr,
    ) -> Self {
        let mut peer = Self::connect(local_ip, server).await;
        peer.read_open().await;
        peer.send_open_with_enhanced_rr(asn, router_id, 90).await;
        peer.asn = asn;
        peer.supports_4byte_asn = true;
        peer.send_keepalive().await;
        peer.read_keepalive().await;
        peer
    }

    /// Initiate new connection to server from same IP as this peer.
    /// Returns raw TcpStream (no OPEN sent).
    pub async fn connect_to(&self, server: &TestServer) -> TcpStream {
        use std::net::SocketAddr;
        use tokio::net::TcpSocket;

        let local_addr: SocketAddr = format!("{}:0", self.address).parse().unwrap();
        let server_addr: SocketAddr = format!("{}:{}", server.address, server.bgp_port)
            .parse()
            .unwrap();

        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(local_addr).unwrap();
        socket.connect(server_addr).await.unwrap()
    }
}

// Build raw BGP message from components
pub fn build_raw_message(
    marker: [u8; 16],
    length_override: Option<u16>,
    msg_type: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut msg = marker.to_vec();
    msg.extend_from_slice(&[0x00, 0x00]); // Placeholder for length
    msg.push(msg_type);
    msg.extend_from_slice(body);

    // Fix the length field (unless overridden)
    let len = length_override.unwrap_or(msg.len() as u16);
    msg[16] = (len >> 8) as u8;
    msg[17] = (len & 0xff) as u8;

    msg
}

/// Send a raw UPDATE via FakePeer announcing a prefix and wait for it in the RIB.
pub async fn fake_announce_prefix(
    server: &TestServer,
    fake: &mut FakePeer,
    prefix_nlri: &[u8],
    prefix_str: &str,
) {
    let next_hop: Ipv4Addr = fake.address.parse().unwrap();
    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(next_hop),
            &attr_local_pref(100),
        ],
        prefix_nlri,
        None,
    );
    fake.send_raw(&update).await;

    let prefix_owned = prefix_str.to_string();
    poll_until(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.iter().any(|r| route_has_prefix(r, &prefix_owned)))
        },
        &format!("Timeout waiting for route {prefix_str}"),
    )
    .await;
}

// Build a raw update message.
pub fn build_raw_update(
    withdrawn: &[u8],
    attrs: &[&[u8]],
    nlri: &[u8],
    total_attr_len_override: Option<u16>,
) -> Vec<u8> {
    let mut body = Vec::new();

    // Withdrawn routes
    body.extend_from_slice(&(withdrawn.len() as u16).to_be_bytes());
    body.extend_from_slice(withdrawn);

    // Total path attributes length - use override if provided, else calculate correctly
    let total_attr_len = total_attr_len_override
        .unwrap_or_else(|| attrs.iter().map(|a| a.len()).sum::<usize>() as u16);
    body.extend_from_slice(&total_attr_len.to_be_bytes());

    // Path attributes
    for attr in attrs {
        body.extend_from_slice(attr);
    }

    // NLRI
    body.extend_from_slice(nlri);

    build_raw_message(BGP_MARKER, None, MessageType::Update.as_u8(), &body)
}

// Build raw attribute bytes
pub fn build_attr_bytes(flags: u8, attr_type: u8, length: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![flags, attr_type, length];
    bytes.extend_from_slice(value);
    bytes
}

// Pre-built common path attributes for error tests
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code, Origin as MsgOrigin};

pub fn attr_origin_igp() -> Vec<u8> {
    build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::ORIGIN,
        1,
        &[MsgOrigin::IGP as u8],
    )
}

pub fn attr_as_path_empty() -> Vec<u8> {
    build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::AS_PATH, 0, &[])
}

pub fn attr_next_hop(ip: Ipv4Addr) -> Vec<u8> {
    let octets = ip.octets();
    build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::NEXT_HOP, 4, &octets)
}

pub fn attr_local_pref(value: u32) -> Vec<u8> {
    build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::LOCAL_PREF,
        4,
        &value.to_be_bytes(),
    )
}

/// Build AGGREGATOR attribute with 4-byte ASN encoding (RFC 6793)
pub fn attr_aggregator(asn: u32, ip: Ipv4Addr) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&asn.to_be_bytes());
    value.extend_from_slice(&ip.octets());
    build_attr_bytes(
        attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
        attr_type_code::AGGREGATOR,
        8,
        &value,
    )
}

pub fn attr_originator_id(ip: Ipv4Addr) -> Vec<u8> {
    build_attr_bytes(
        attr_flags::OPTIONAL,
        attr_type_code::ORIGINATOR_ID,
        4,
        &ip.octets(),
    )
}

pub fn attr_cluster_list(ids: &[Ipv4Addr]) -> Vec<u8> {
    let mut value = Vec::new();
    for id in ids {
        value.extend_from_slice(&id.octets());
    }
    build_attr_bytes(
        attr_flags::OPTIONAL,
        attr_type_code::CLUSTER_LIST,
        value.len() as u8,
        &value,
    )
}

/// Build AS_PATH attribute with 2-byte ASN encoding (legacy/OLD speaker)
pub fn attr_as_path_2byte(asns: Vec<u16>) -> Vec<u8> {
    let mut value = Vec::new();
    value.push(2); // AS_SEQUENCE
    value.push(asns.len() as u8);
    for asn in asns {
        value.extend_from_slice(&asn.to_be_bytes());
    }
    build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::AS_PATH,
        value.len() as u8,
        &value,
    )
}

/// Build AS_PATH attribute with 4-byte ASN encoding (RFC 6793)
pub fn attr_as_path_4byte(asns: Vec<u32>) -> Vec<u8> {
    let mut value = Vec::new();
    value.push(2); // AS_SEQUENCE
    value.push(asns.len() as u8);
    for asn in asns {
        value.extend_from_slice(&asn.to_be_bytes());
    }
    build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::AS_PATH,
        value.len() as u8,
        &value,
    )
}

pub fn attr_communities(communities: &[u32]) -> Vec<u8> {
    let mut value = Vec::new();
    for &comm in communities {
        value.extend_from_slice(&comm.to_be_bytes());
    }
    build_attr_bytes(
        attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
        attr_type_code::COMMUNITIES,
        value.len() as u8,
        &value,
    )
}

/// Build a minimal eBGP UPDATE with the given communities and NLRI prefix.
/// `from_asn` is 2-byte encoded.
pub fn build_ebgp_update_with_communities(
    from_asn: u16,
    next_hop: Ipv4Addr,
    communities: &[u32],
    nlri: &[u8],
) -> Vec<u8> {
    let mut attrs: Vec<Vec<u8>> = vec![
        attr_origin_igp(),
        attr_as_path_2byte(vec![from_asn]),
        attr_next_hop(next_hop),
    ];
    if !communities.is_empty() {
        attrs.push(attr_communities(communities));
    }
    let attr_refs: Vec<&[u8]> = attrs.iter().map(|a| a.as_slice()).collect();
    build_raw_update(&[], &attr_refs, nlri, None)
}

/// Build capability 65 (4-byte ASN support) for use with build_raw_open
pub fn build_capability_4byte_asn(asn: u32) -> Vec<u8> {
    let mut cap = vec![65u8, 4u8]; // Type 65, Length 4
    cap.extend_from_slice(&asn.to_be_bytes());
    cap
}

/// Optional parameters for building raw OPEN messages
#[derive(Default)]
pub struct RawOpenOptions {
    pub version_override: Option<u8>,
    pub marker_override: Option<[u8; 16]>,
    pub length_override: Option<u16>,
    pub msg_type_override: Option<u8>,
    pub capabilities: Option<Vec<Vec<u8>>>,
}

// Build raw OPEN message with optional custom version, marker, length, message type, and capabilities
pub fn build_raw_open(
    asn: u16,
    hold_time: u16,
    router_id: u32,
    options: RawOpenOptions,
) -> Vec<u8> {
    let version = options.version_override.unwrap_or(4);
    let marker = options.marker_override.unwrap_or(BGP_MARKER);
    let msg_type = options
        .msg_type_override
        .unwrap_or(MessageType::Open.as_u8());

    let mut body = Vec::new();
    body.push(version);
    body.extend_from_slice(&asn.to_be_bytes());
    body.extend_from_slice(&hold_time.to_be_bytes());
    body.extend_from_slice(&router_id.to_be_bytes());

    // Build optional parameters for capabilities
    if let Some(caps) = options.capabilities {
        let mut opt_params = Vec::new();
        for cap in caps {
            // Optional parameter type 2 = Capabilities
            opt_params.push(2u8);
            opt_params.push(cap.len() as u8);
            opt_params.extend_from_slice(&cap);
        }
        body.push(opt_params.len() as u8); // Optional parameters length
        body.extend_from_slice(&opt_params);
    } else {
        body.push(0); // Optional parameters length = 0
    }

    build_raw_message(marker, options.length_override, msg_type, &body)
}

// Build raw KEEPALIVE message with optional custom length
pub fn build_raw_keepalive(length_override: Option<u16>) -> Vec<u8> {
    let body = Vec::new(); // KEEPALIVE has no body
    build_raw_message(
        BGP_MARKER,
        length_override,
        MessageType::Keepalive.as_u8(),
        &body,
    )
}

// Build raw NOTIFICATION message with optional custom length
pub fn build_raw_notification(
    error_code: u8,
    error_subcode: u8,
    data: &[u8],
    length_override: Option<u16>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(error_code);
    body.push(error_subcode);
    body.extend_from_slice(data);

    build_raw_message(
        BGP_MARKER,
        length_override,
        MessageType::Notification.as_u8(),
        &body,
    )
}

/// Build GR capability bytes for OPEN message
/// RFC 4724: Restart Flags (4 bits) + Restart Time (12 bits) + AFI/SAFI tuples
pub fn build_gr_capability(restart_time_secs: u16, restart_flag: bool) -> Vec<u8> {
    build_gr_capability_with_fbit(restart_time_secs, restart_flag, true)
}

/// Build GR capability bytes with configurable F-bit (forwarding state)
/// restart_flag: R-bit - indicates speaker is restarting
/// forwarding_flag: F-bit - indicates forwarding state was preserved
pub fn build_gr_capability_with_fbit(
    restart_time_secs: u16,
    restart_flag: bool,
    forwarding_flag: bool,
) -> Vec<u8> {
    let mut cap = vec![64u8]; // Capability code 64 = Graceful Restart
    cap.push(6); // Length: 2 (flags+time) + 4 (one AFI/SAFI tuple)

    // Restart Flags (high 4 bits) + Restart Time (low 12 bits)
    let flags_and_time = if restart_flag {
        0x8000 | (restart_time_secs & 0x0FFF) // R flag = bit 15
    } else {
        restart_time_secs & 0x0FFF
    };
    cap.extend_from_slice(&flags_and_time.to_be_bytes());

    // AFI/SAFI tuple: IPv4 Unicast
    cap.push(0); // AFI high byte
    cap.push(1); // AFI low byte (IPv4)
    cap.push(1); // SAFI (Unicast)
    cap.push(if forwarding_flag { 0x80 } else { 0x00 }); // F-bit

    cap
}

/// Build Multiprotocol Extensions capability (RFC 4760) for IPv4 Unicast
pub fn build_multiprotocol_capability_ipv4_unicast() -> Vec<u8> {
    vec![
        1, // Capability code 1 = Multiprotocol Extensions
        4, // Length: 4 bytes
        0, 1, // AFI = 1 (IPv4)
        0, // Reserved
        1, // SAFI = 1 (Unicast)
    ]
}

/// Build Multiprotocol Extensions capability (RFC 4760) for IPv6 Unicast
pub fn build_multiprotocol_capability_ipv6_unicast() -> Vec<u8> {
    vec![
        1, // Capability code 1 = Multiprotocol Extensions
        4, // Length: 4 bytes
        0, 2, // AFI = 2 (IPv6)
        0, // Reserved
        1, // SAFI = 1 (Unicast)
    ]
}

/// Build ADD-PATH capability (RFC 7911) for IPv4 Unicast, send+receive
pub fn build_addpath_capability_ipv4_unicast() -> Vec<u8> {
    vec![
        69, // Capability code 69 = ADD-PATH
        4,  // Length: 4 bytes
        0, 1, // AFI = 1 (IPv4)
        1, // SAFI = 1 (Unicast)
        3, // Send + Receive
    ]
}

/// Build ADD-PATH capability (RFC 7911) for IPv6 Unicast, send+receive
pub fn build_addpath_capability_ipv6_unicast() -> Vec<u8> {
    vec![
        69, // Capability code 69 = ADD-PATH
        4,  // Length: 4 bytes
        0, 2, // AFI = 2 (IPv6)
        1, // SAFI = 1 (Unicast)
        3, // Send + Receive
    ]
}

/// Build LLGR capability bytes (RFC 9494) for IPv4 Unicast
/// f_bit: forwarding state preserved
/// stale_time_secs: 24-bit LLST value
pub fn build_llgr_capability(f_bit: bool, stale_time_secs: u32) -> Vec<u8> {
    let mut cap = vec![71u8]; // Capability code 71 = LLGR
    cap.push(7); // Length: 7 bytes (one AFI/SAFI tuple)

    // AFI/SAFI tuple: IPv4 Unicast
    cap.push(0); // AFI high byte
    cap.push(1); // AFI low byte (IPv4)
    cap.push(1); // SAFI (Unicast)
    cap.push(if f_bit { 0x80 } else { 0x00 }); // Flags (F-bit)

    // Stale time: 3 bytes big-endian
    cap.push((stale_time_secs >> 16) as u8);
    cap.push((stale_time_secs >> 8) as u8);
    cap.push(stale_time_secs as u8);

    cap
}

/// Create an export policy that rejects matching prefixes and accepts the rest,
/// then assign it to the given peer.
pub async fn apply_export_prefix_reject_policy(
    server: &TestServer,
    peer_addr: &str,
    policy_name: &str,
    prefixes: Vec<(&str, Option<&str>)>,
) {
    server
        .client
        .add_defined_set(
            DefinedSetConfig {
                set_type: "prefix-set".to_string(),
                name: policy_name.to_string(),
                config: Some(defined_set_config::Config::PrefixSet(PrefixSetData {
                    prefixes: prefixes
                        .into_iter()
                        .map(|(prefix, range)| PrefixMatch {
                            prefix: prefix.to_string(),
                            masklength_range: range.map(|s| s.to_string()),
                        })
                        .collect(),
                })),
            },
            false,
        )
        .await
        .unwrap();

    server
        .client
        .add_policy(
            policy_name.to_string(),
            vec![
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        match_prefix_set: Some(bgpgg::grpc::proto::MatchSetRef {
                            set_name: policy_name.to_string(),
                            match_option: "any".to_string(),
                        }),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: None,
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        ..Default::default()
                    }),
                },
            ],
        )
        .await
        .unwrap();

    apply_policy_to_common_families(server, peer_addr, "export", policy_name).await;
}

/// Create an export policy that rejects routes sourced from a specific neighbor and accepts
/// the rest, then assign it to the given peer.
pub async fn apply_export_neighbor_reject_policy(
    server: &TestServer,
    peer_addr: &str,
    policy_name: &str,
    reject_neighbor: &str,
) {
    server
        .client
        .add_policy(
            policy_name.to_string(),
            vec![
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        neighbor: Some(reject_neighbor.to_string()),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: None,
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        ..Default::default()
                    }),
                },
            ],
        )
        .await
        .unwrap();

    apply_policy_to_common_families(server, peer_addr, "export", policy_name).await;
}

/// Build Enhanced Route Refresh capability (RFC 7313, code 70, zero-length)
pub fn build_enhanced_route_refresh_capability() -> Vec<u8> {
    vec![70, 0] // Capability code 70, Length 0
}

/// Build a raw ROUTE-REFRESH message with the given AFI, subtype, and SAFI
pub fn build_raw_route_refresh(afi: u16, subtype: u8, safi: u8) -> Vec<u8> {
    let mut msg = Vec::with_capacity(23);
    msg.extend_from_slice(&[0xff; 16]); // Marker
    msg.extend_from_slice(&23u16.to_be_bytes()); // Length
    msg.push(5); // Type: ROUTE_REFRESH
    msg.extend_from_slice(&afi.to_be_bytes()); // AFI
    msg.push(subtype); // Subtype
    msg.push(safi); // SAFI
    msg
}

/// Write a key to a temporary file for TCP MD5 authentication tests
pub fn write_key_file(suffix: &str, key: &[u8]) -> String {
    use std::io::Write;
    let path = format!("/tmp/bgpgg-test-md5-{}.key", suffix);
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(key).unwrap();
    path
}

/// Apply accept-all import policy on a server for a specific peer.
/// Needed for eBGP peers since RFC 8212 defaults to reject-all.
pub async fn apply_import_accept_all(server: &TestServer, peer_addr: &str) {
    let _ = server
        .client
        .add_policy(
            "permit-all".to_string(),
            vec![StatementConfig {
                conditions: None,
                actions: Some(ActionsConfig {
                    accept: Some(true),
                    ..Default::default()
                }),
            }],
        )
        .await;
    apply_policy_to_common_families(server, peer_addr, "import", "permit-all").await;
}

/// Apply accept-all export policy on a server for a specific peer.
/// Needed for eBGP peers since RFC 8212 defaults to reject-all.
pub async fn apply_export_accept_all(server: &TestServer, peer_addr: &str) {
    let _ = server
        .client
        .add_policy(
            "permit-all".to_string(),
            vec![StatementConfig {
                conditions: None,
                actions: Some(ActionsConfig {
                    accept: Some(true),
                    ..Default::default()
                }),
            }],
        )
        .await;
    apply_policy_to_common_families(server, peer_addr, "export", "permit-all").await;
}

/// Apply accept-all import and export on a server for a specific peer address.
pub async fn apply_permit_all(server: &TestServer, peer_addr: &str) {
    apply_import_accept_all(server, peer_addr).await;
    apply_export_accept_all(server, peer_addr).await;
}

/// Apply accept-all import and export policies on both sides of a peering.
pub async fn apply_permit_all_routes(server1: &TestServer, server2: &TestServer) {
    apply_permit_all(server1, &server2.address.to_string()).await;
    apply_permit_all(server2, &server1.address.to_string()).await;
}

/// Attach `policy_name` to the peer's IPv4-unicast, IPv6-unicast, and BGP-LS
/// families in `direction`. Tests that need single-family attachment should
/// call `set_policy_assignment` directly with explicit afi/safi.
pub async fn apply_policy_to_common_families(
    server: &TestServer,
    peer_addr: &str,
    direction: &str,
    policy_name: &str,
) {
    use conf::bgp::{Afi, Safi};
    for (afi, safi) in [
        (Afi::Ipv4 as u32, Safi::Unicast as u32),
        (Afi::Ipv6 as u32, Safi::Unicast as u32),
        (Afi::LinkState as u32, Safi::LinkState as u32),
    ] {
        server
            .client
            .set_policy_assignment(
                peer_addr.to_string(),
                afi,
                safi,
                direction.to_string(),
                vec![policy_name.to_string()],
                None,
            )
            .await
            .unwrap();
    }
}
