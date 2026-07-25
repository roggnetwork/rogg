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
//! RIB sizes, process memory).

use super::BgpServer;
use crate::metrics;
use telemetry::{metric, Unit};

impl BgpServer {
    /// Emit all periodic metrics. Called from the server loop timer.
    pub(crate) fn emit_periodic_metrics(&self) {
        metric(
            metrics::PEER_TOTAL_COUNT,
            self.peers.len(),
            Unit::Count,
            &[],
            &[],
            &[],
        );

        for (peer_ip, peer) in &self.peers {
            // Uptime only for established sessions.
            if let Some(state_changed_at) = peer
                .established_conn()
                .and_then(|conn| conn.state_changed_at)
            {
                metric(
                    metrics::SESSION_UPTIME_SEC,
                    state_changed_at.elapsed().as_secs(),
                    Unit::Seconds,
                    &[("peer", peer_ip)],
                    &[&["peer"]],
                    &[],
                );
            }

            metric(
                metrics::ADJ_RIB_IN_ROUTE_COUNT,
                peer.adj_rib_in.prefix_count(),
                Unit::Count,
                &[("peer", peer_ip)],
                &[&["peer"]],
                &[],
            );
            metric(
                metrics::ADJ_RIB_OUT_ROUTE_COUNT,
                peer.adj_rib_out.route_count(),
                Unit::Count,
                &[("peer", peer_ip)],
                &[&["peer"]],
                &[],
            );

            for (afi_safi, count) in peer.adj_rib_in.family_counts() {
                metric(
                    metrics::ADJ_RIB_IN_AFI_SAFI_ROUTE_COUNT,
                    count,
                    Unit::Count,
                    &[("peer", peer_ip), ("afi_safi", &afi_safi)],
                    &[&["afi_safi"], &["peer", "afi_safi"]],
                    &[],
                );
            }
            for (afi_safi, count) in peer.adj_rib_out.family_counts() {
                metric(
                    metrics::ADJ_RIB_OUT_AFI_SAFI_ROUTE_COUNT,
                    count,
                    Unit::Count,
                    &[("peer", peer_ip), ("afi_safi", &afi_safi)],
                    &[&["afi_safi"], &["peer", "afi_safi"]],
                    &[],
                );
            }
        }

        for (afi_safi, count) in self.loc_rib.family_counts() {
            metric(
                metrics::LOC_RIB_ROUTE_COUNT,
                count,
                Unit::Count,
                &[("afi_safi", &afi_safi)],
                &[&["afi_safi"]],
                &[],
            );
        }

        if let Some(rss) = process_rss_bytes() {
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
    use crate::peer::BgpState;
    use crate::server::{BgpServer, ConnectionState, PeerInfo};
    use conf::bgp::BgpConfig;
    use conf::testutil::TempDir;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Instant;
    use telemetry::{CaptureSink, Value};

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

        server.emit_periodic_metrics();

        let total = capture.find("peer_total_count", &[]);
        assert_eq!(total.len(), 1);
        assert_eq!(total[0].value, Value::UInt(1));

        let uptime = capture.find("session_uptime_sec", &[("peer", "10.99.99.1")]);
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
}
