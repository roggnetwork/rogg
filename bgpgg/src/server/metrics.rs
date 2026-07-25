// Copyright 2026 rogg Authors
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

//! Periodic metrics emitted from the server timer (peer counts, uptime,
//! RIB sizes, process memory), and the snapshot the Prometheus endpoint
//! reads over `ServerOp::GetMetricsSnapshot`.

use super::BgpServer;
use crate::bgp::multiprotocol::AfiSafi;
use crate::metrics;
use crate::peer::{BgpState, PeerOp, PeerStatistics};
use std::net::IpAddr;
use std::time::Duration;
use telemetry::{metric, Unit};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout_at, Instant};

/// Server-owned gauge state, collected synchronously in the server loop.
#[derive(Debug)]
pub struct MetricsSnapshot {
    pub peer_total: usize,
    pub peers: Vec<PeerMetricsSnapshot>,
    pub loc_rib_families: Vec<(AfiSafi, usize)>,
    pub rss_bytes: Option<u64>,
}

#[derive(Debug)]
pub struct PeerMetricsSnapshot {
    pub peer_ip: IpAddr,
    /// Most-progressed FSM state across the peer's connections.
    pub state: BgpState,
    /// Set for established sessions only.
    pub uptime_secs: Option<u64>,
    pub adj_rib_in_total: usize,
    pub adj_rib_out_total: usize,
    pub adj_rib_in_families: Vec<(AfiSafi, usize)>,
    pub adj_rib_out_families: Vec<(AfiSafi, usize)>,
    /// Channel to the peer task, for counter fan-out outside the server
    /// loop. Set for established sessions only.
    pub peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
}

impl BgpServer {
    /// Collect all server-owned gauges. Pure read, no emission.
    pub(crate) fn collect_metrics_snapshot(&self) -> MetricsSnapshot {
        let mut peer_metrics: Vec<PeerMetricsSnapshot> = self
            .peers
            .iter()
            .map(|(peer_ip, peer)| {
                let established = peer.established_conn();
                PeerMetricsSnapshot {
                    peer_ip: *peer_ip,
                    state: peer.max_state().1,
                    uptime_secs: established
                        .and_then(|conn| conn.state_changed_at)
                        .map(|at| at.elapsed().as_secs()),
                    adj_rib_in_total: peer.adj_rib_in.prefix_count(),
                    adj_rib_out_total: peer.adj_rib_out.route_count(),
                    adj_rib_in_families: peer.adj_rib_in.family_counts().to_vec(),
                    adj_rib_out_families: peer.adj_rib_out.family_counts().to_vec(),
                    peer_tx: established.and_then(|conn| conn.peer_tx.clone()),
                }
            })
            .collect();
        peer_metrics.sort_by_key(|peer| peer.peer_ip);
        MetricsSnapshot {
            peer_total: self.peers.len(),
            peers: peer_metrics,
            loc_rib_families: self.loc_rib.family_counts().to_vec(),
            rss_bytes: process_rss_bytes(),
        }
    }

    /// Emit the periodic gauges. Called from the server loop timer; the
    /// message counters need a peer-task fan-out and are emitted by
    /// `emit_message_counter_metrics` on a spawned task instead.
    pub(crate) fn emit_periodic_metrics(&self, snapshot: &MetricsSnapshot) {
        metric(
            metrics::PEER_COUNT,
            snapshot.peer_total,
            Unit::Count,
            &[],
            &[],
            &[],
        );

        for peer in &snapshot.peers {
            let peer_ip = &peer.peer_ip;
            metric(
                metrics::SESSION_STATE,
                peer.state.code() as u32,
                Unit::Count,
                &[("peer", peer_ip)],
                &[&["peer"]],
                &[],
            );
            if let Some(uptime) = peer.uptime_secs {
                metric(
                    metrics::SESSION_UPTIME_SECONDS,
                    uptime,
                    Unit::Seconds,
                    &[("peer", peer_ip)],
                    &[&["peer"]],
                    &[],
                );
            }

            metric(
                metrics::ADJ_RIB_IN_ROUTE_COUNT,
                peer.adj_rib_in_total,
                Unit::Count,
                &[("peer", peer_ip)],
                &[&["peer"]],
                &[],
            );
            metric(
                metrics::ADJ_RIB_OUT_ROUTE_COUNT,
                peer.adj_rib_out_total,
                Unit::Count,
                &[("peer", peer_ip)],
                &[&["peer"]],
                &[],
            );

            for (afi_safi, count) in &peer.adj_rib_in_families {
                metric(
                    metrics::ADJ_RIB_IN_AFI_SAFI_ROUTE_COUNT,
                    *count,
                    Unit::Count,
                    &[("peer", peer_ip), ("afi_safi", afi_safi)],
                    &[&["afi_safi"], &["peer", "afi_safi"]],
                    &[],
                );
            }
            for (afi_safi, count) in &peer.adj_rib_out_families {
                metric(
                    metrics::ADJ_RIB_OUT_AFI_SAFI_ROUTE_COUNT,
                    *count,
                    Unit::Count,
                    &[("peer", peer_ip), ("afi_safi", afi_safi)],
                    &[&["afi_safi"], &["peer", "afi_safi"]],
                    &[],
                );
            }
        }

        for (afi_safi, count) in &snapshot.loc_rib_families {
            metric(
                metrics::LOC_RIB_ROUTE_COUNT,
                *count,
                Unit::Count,
                &[("afi_safi", afi_safi)],
                &[&["afi_safi"]],
                &[],
            );
        }

        if let Some(rss) = snapshot.rss_bytes {
            metric(
                metrics::PROCESS_MEMORY_BYTES,
                rss,
                Unit::Bytes,
                &[],
                &[],
                &[],
            );
        }
    }
}

/// Cap on how long one collection waits for peer-task statistics replies.
const STATS_FANOUT_TIMEOUT: Duration = Duration::from_secs(2);

/// Fan out `PeerOp::GetStatistics` to every established peer. Requests are
/// all sent up front and replies awaited against one shared deadline, so a
/// stuck peer task cannot stall the collection; its stats are omitted.
pub(crate) async fn collect_peer_statistics(
    peers: &[PeerMetricsSnapshot],
) -> Vec<(IpAddr, PeerStatistics)> {
    let mut pending = Vec::new();
    for peer in peers {
        let Some(peer_tx) = &peer.peer_tx else {
            continue;
        };
        let (stats_tx, stats_rx) = oneshot::channel();
        if peer_tx.send(PeerOp::GetStatistics(stats_tx)).is_ok() {
            pending.push((peer.peer_ip, stats_rx));
        }
    }
    let deadline = Instant::now() + STATS_FANOUT_TIMEOUT;
    let mut stats = Vec::with_capacity(pending.len());
    for (peer_ip, stats_rx) in pending {
        if let Ok(Ok(peer_stats)) = timeout_at(deadline, stats_rx).await {
            stats.push((peer_ip, peer_stats));
        }
    }
    stats
}

/// Emit cumulative per-peer message counters (one metric per message type
/// and direction). Runs on a spawned task each stats tick -- the peer-task
/// fan-out must not block the server loop.
pub(crate) async fn emit_message_counter_metrics(peers: Vec<PeerMetricsSnapshot>) {
    for (peer_ip, stats) in collect_peer_statistics(&peers).await {
        let received: [(&str, u64); 5] = [
            ("open", stats.open_received),
            ("keepalive", stats.keepalive_received),
            ("update", stats.update_received),
            ("notification", stats.notification_received),
            ("route_refresh", stats.route_refresh_received),
        ];
        let sent: [(&str, u64); 5] = [
            ("open", stats.open_sent),
            ("keepalive", stats.keepalive_sent),
            ("update", stats.update_sent),
            ("notification", stats.notification_sent),
            ("route_refresh", stats.route_refresh_sent),
        ];
        for (name, counts) in [
            (metrics::MESSAGES_RECEIVED_TOTAL, received),
            (metrics::MESSAGES_SENT_TOTAL, sent),
        ] {
            for (msg_type, count) in counts {
                metric(
                    name,
                    count,
                    Unit::Count,
                    &[("peer", &peer_ip), ("type", &msg_type)],
                    &[&["type"], &["peer", "type"]],
                    &[],
                );
            }
        }
    }
}

/// Resident set size of this process in bytes, from /proc/self/status VmRSS.
#[cfg(target_os = "linux")]
fn process_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let vm_rss = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kilobytes: u64 = vm_rss.split_whitespace().nth(1)?.parse().ok()?;
    Some(kilobytes * 1024)
}

#[cfg(not(target_os = "linux"))]
fn process_rss_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::{emit_message_counter_metrics, PeerMetricsSnapshot};
    use crate::peer::{BgpState, PeerOp, PeerStatistics};
    use crate::server::{BgpServer, ConnectionState, PeerInfo};
    use conf::bgp::BgpConfig;
    use conf::testutil::TempDir;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Instant;
    use telemetry::{CaptureSink, Telemetry, Value};
    use tokio::sync::mpsc;

    #[test]
    fn test_emit_periodic_metrics() {
        let config = BgpConfig::new(65000, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 180);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rogg.conf");
        std::fs::write(&path, config.to_conf_str()).unwrap();
        let mut server = BgpServer::new(path).expect("valid config");

        let capture = CaptureSink::new();
        server.telemetry.set_sink(Some(Arc::new(capture.clone())));
        telemetry::bind(server.telemetry.clone());

        let peer_ip: IpAddr = "10.99.99.1".parse().unwrap();
        let mut peer_info = PeerInfo::new(false, None, None);
        let mut conn = ConnectionState::new(None);
        conn.state = BgpState::Established;
        conn.state_changed_at = Some(Instant::now());
        peer_info.outgoing = Some(conn);
        server.peers.insert(peer_ip, peer_info);

        let snapshot = server.collect_metrics_snapshot();
        server.emit_periodic_metrics(&snapshot);

        let total = capture.find("peer_count", &[]);
        assert_eq!(total.len(), 1);
        assert_eq!(total[0].value, Value::UInt(1));

        let state = capture.find("session_state", &[("peer", "10.99.99.1")]);
        assert_eq!(state.len(), 1);
        assert_eq!(state[0].value, Value::UInt(6));

        let uptime = capture.find("session_uptime_seconds", &[("peer", "10.99.99.1")]);
        assert_eq!(uptime.len(), 1);

        let adj_in_total = capture.find("adj_rib_in_route_count", &[("peer", "10.99.99.1")]);
        assert_eq!(adj_in_total.len(), 1);
        assert_eq!(adj_in_total[0].value, Value::UInt(0));

        let adj_in = capture.find(
            "adj_rib_in_afi_safi_route_count",
            &[("peer", "10.99.99.1"), ("afi_safi", "IPv4/Unicast")],
        );
        assert_eq!(adj_in.len(), 1);
        assert_eq!(adj_in[0].value, Value::UInt(0));

        let adj_out_total = capture.find("adj_rib_out_route_count", &[("peer", "10.99.99.1")]);
        assert_eq!(adj_out_total.len(), 1);

        let adj_out = capture.find(
            "adj_rib_out_afi_safi_route_count",
            &[("peer", "10.99.99.1"), ("afi_safi", "IPv4/Unicast")],
        );
        assert_eq!(adj_out.len(), 1);

        assert!(!capture
            .find("loc_rib_route_count", &[("afi_safi", "IPv4/Unicast")])
            .is_empty());

        #[cfg(target_os = "linux")]
        assert!(!capture.find("process_memory_bytes", &[]).is_empty());
    }

    #[tokio::test]
    async fn test_emit_message_counter_metrics() {
        let telemetry = Telemetry::new("1.1.1.1");
        let capture = CaptureSink::new();
        telemetry.set_sink(Some(Arc::new(capture.clone())));
        telemetry::bind(telemetry);

        // Fake peer task: answer one GetStatistics request.
        let (peer_tx, mut peer_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            if let Some(PeerOp::GetStatistics(response)) = peer_rx.recv().await {
                let _ = response.send(PeerStatistics {
                    open_received: 1,
                    update_received: 7,
                    keepalive_sent: 3,
                    ..Default::default()
                });
            }
        });

        let peer_ip: IpAddr = "10.99.99.2".parse().unwrap();
        emit_message_counter_metrics(vec![PeerMetricsSnapshot {
            peer_ip,
            state: BgpState::Established,
            uptime_secs: Some(1),
            adj_rib_in_total: 0,
            adj_rib_out_total: 0,
            adj_rib_in_families: vec![],
            adj_rib_out_families: vec![],
            peer_tx: Some(peer_tx),
        }])
        .await;

        let received = capture.find(
            "messages_received_total",
            &[("peer", "10.99.99.2"), ("type", "update")],
        );
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].value, Value::UInt(7));

        let sent = capture.find(
            "messages_sent_total",
            &[("peer", "10.99.99.2"), ("type", "keepalive")],
        );
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].value, Value::UInt(3));

        // All five types emitted per direction.
        assert_eq!(capture.find("messages_received_total", &[]).len(), 5);
        assert_eq!(capture.find("messages_sent_total", &[]).len(), 5);
    }
}
