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

//! Prometheus scrape endpoint. The listener task requests a
//! `MetricsSnapshot` from the server loop, fans out per-peer statistics
//! requests to the peer tasks, and renders text exposition format.
//! Identity (`instance`/`job`) is the scraper's job; no router_id label.

use super::metrics::{collect_peer_statistics, MetricsSnapshot, PeerMetricsSnapshot};
use super::{BgpServer, ServerOp};
use crate::bgp::multiprotocol::AfiSafi;
use crate::metrics::{self, prometheus_name};
use crate::peer::PeerStatistics;
use conf::bgp::BgpConfig;
use std::net::{IpAddr, SocketAddr};
use telemetry::prometheus::{serve, MetricFamily, MetricType, Sample};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};

impl BgpServer {
    /// Spawn the scrape listener if `telemetry { prometheus { ... } }` is
    /// configured. Invalid listen address logs an error and skips.
    pub(crate) fn init_configured_prometheus(&mut self) {
        let Some(prometheus) = self
            .config
            .telemetry
            .as_ref()
            .and_then(|telemetry| telemetry.prometheus.as_ref())
        else {
            return;
        };
        let Ok(addr) = prometheus.listen.parse::<SocketAddr>() else {
            error!(addr = %prometheus.listen, "invalid prometheus listen address in config");
            return;
        };
        let task = tokio::spawn(run_listener(addr, self.op_tx.clone()));
        self.prometheus_listener = Some((addr, task));
        info!(%addr, "prometheus endpoint configured");
    }

    /// Diff the configured prometheus listen address and restart the
    /// listener on change. Called by `commit_config`.
    pub(crate) fn reconfigure_prometheus(&mut self, new: &BgpConfig) -> Result<(), String> {
        let new_addr = match new
            .telemetry
            .as_ref()
            .and_then(|telemetry| telemetry.prometheus.as_ref())
        {
            Some(prometheus) => Some(prometheus.listen.parse::<SocketAddr>().map_err(|e| {
                format!(
                    "invalid prometheus listen address '{}': {}",
                    prometheus.listen, e
                )
            })?),
            None => None,
        };
        let old_addr = self.prometheus_listener.as_ref().map(|(addr, _)| *addr);
        // Respawn a dead listener (e.g. bind failed) even on an unchanged
        // address, so a commit retries instead of leaving the endpoint down.
        let listener_dead = self
            .prometheus_listener
            .as_ref()
            .is_some_and(|(_, task)| task.is_finished());
        if new_addr == old_addr && !listener_dead {
            return Ok(());
        }
        if let Some((addr, task)) = self.prometheus_listener.take() {
            task.abort();
            info!(%addr, "prometheus endpoint stopped");
        }
        if let Some(addr) = new_addr {
            let task = tokio::spawn(run_listener(addr, self.op_tx.clone()));
            self.prometheus_listener = Some((addr, task));
            info!(%addr, "prometheus endpoint configured");
        }
        Ok(())
    }
}

/// Listener task body: bind and serve scrapes until aborted.
async fn run_listener(addr: SocketAddr, op_tx: mpsc::UnboundedSender<ServerOp>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(%addr, error = %e, "failed to bind prometheus listener");
            return;
        }
    };
    serve(listener, move || {
        let op_tx = op_tx.clone();
        async move { scrape(&op_tx).await }
    })
    .await;
}

/// One scrape: snapshot from the server loop, then per-peer statistics
/// fan-out. None (-> 503) when the server is gone.
async fn scrape(op_tx: &mpsc::UnboundedSender<ServerOp>) -> Option<Vec<MetricFamily>> {
    let (tx, rx) = oneshot::channel();
    op_tx
        .send(ServerOp::GetMetricsSnapshot { response: tx })
        .ok()?;
    let snapshot = rx.await.ok()?;
    let stats = collect_peer_statistics(&snapshot.peers).await;
    Some(build_families(&snapshot, &stats))
}

fn peer_label(peer_ip: &IpAddr) -> (String, String) {
    ("peer".to_string(), peer_ip.to_string())
}

fn gauge(name: String, samples: Vec<Sample>) -> MetricFamily {
    MetricFamily {
        name,
        metric_type: MetricType::Gauge,
        samples,
    }
}

/// Map the snapshot and per-peer statistics to exposition families.
fn build_families(
    snapshot: &MetricsSnapshot,
    stats: &[(IpAddr, PeerStatistics)],
) -> Vec<MetricFamily> {
    let mut families = vec![gauge(
        prometheus_name(metrics::PEER_COUNT),
        vec![Sample {
            labels: vec![],
            value: snapshot.peer_total as f64,
        }],
    )];

    families.push(gauge(
        prometheus_name(metrics::SESSION_STATE),
        snapshot
            .peers
            .iter()
            .map(|peer| Sample {
                labels: vec![peer_label(&peer.peer_ip)],
                value: peer.state.code() as f64,
            })
            .collect(),
    ));

    families.push(gauge(
        prometheus_name(metrics::SESSION_UPTIME_SECONDS),
        snapshot
            .peers
            .iter()
            .filter_map(|peer| {
                peer.uptime_secs.map(|uptime| Sample {
                    labels: vec![peer_label(&peer.peer_ip)],
                    value: uptime as f64,
                })
            })
            .collect(),
    ));

    families.push(gauge(
        prometheus_name(metrics::LOC_RIB_ROUTE_COUNT),
        snapshot
            .loc_rib_families
            .iter()
            .map(|(afi_safi, count)| Sample {
                labels: vec![("afi_safi".to_string(), afi_safi.to_string())],
                value: *count as f64,
            })
            .collect(),
    ));

    let per_peer_total = |select: fn(&PeerMetricsSnapshot) -> usize| {
        snapshot
            .peers
            .iter()
            .map(|peer| Sample {
                labels: vec![peer_label(&peer.peer_ip)],
                value: select(peer) as f64,
            })
            .collect::<Vec<_>>()
    };
    let per_peer_family = |select: fn(&PeerMetricsSnapshot) -> &Vec<(AfiSafi, usize)>| {
        snapshot
            .peers
            .iter()
            .flat_map(|peer| {
                select(peer).iter().map(|(afi_safi, count)| Sample {
                    labels: vec![
                        peer_label(&peer.peer_ip),
                        ("afi_safi".to_string(), afi_safi.to_string()),
                    ],
                    value: *count as f64,
                })
            })
            .collect::<Vec<_>>()
    };

    families.push(gauge(
        prometheus_name(metrics::ADJ_RIB_IN_ROUTE_COUNT),
        per_peer_total(|peer| peer.adj_rib_in_total),
    ));
    families.push(gauge(
        prometheus_name(metrics::ADJ_RIB_IN_AFI_SAFI_ROUTE_COUNT),
        per_peer_family(|peer| &peer.adj_rib_in_families),
    ));
    families.push(gauge(
        prometheus_name(metrics::ADJ_RIB_OUT_ROUTE_COUNT),
        per_peer_total(|peer| peer.adj_rib_out_total),
    ));
    families.push(gauge(
        prometheus_name(metrics::ADJ_RIB_OUT_AFI_SAFI_ROUTE_COUNT),
        per_peer_family(|peer| &peer.adj_rib_out_families),
    ));

    families.push(gauge(
        prometheus_name(metrics::PROCESS_MEMORY_BYTES),
        snapshot
            .rss_bytes
            .map(|rss| Sample {
                labels: vec![],
                value: rss as f64,
            })
            .into_iter()
            .collect(),
    ));

    let message_samples = |select: fn(&PeerStatistics) -> [(&'static str, u64); 5]| {
        stats
            .iter()
            .flat_map(|(peer_ip, peer_stats)| {
                select(peer_stats).map(|(msg_type, count)| Sample {
                    labels: vec![
                        peer_label(peer_ip),
                        ("message_type".to_string(), msg_type.to_string()),
                    ],
                    value: count as f64,
                })
            })
            .collect::<Vec<_>>()
    };
    families.push(MetricFamily {
        name: prometheus_name(metrics::MESSAGES_RECEIVED_TOTAL),
        metric_type: MetricType::Counter,
        samples: message_samples(|peer_stats| {
            [
                ("open", peer_stats.open_received),
                ("keepalive", peer_stats.keepalive_received),
                ("update", peer_stats.update_received),
                ("notification", peer_stats.notification_received),
                ("route_refresh", peer_stats.route_refresh_received),
            ]
        }),
    });
    families.push(MetricFamily {
        name: prometheus_name(metrics::MESSAGES_SENT_TOTAL),
        metric_type: MetricType::Counter,
        samples: message_samples(|peer_stats| {
            [
                ("open", peer_stats.open_sent),
                ("keepalive", peer_stats.keepalive_sent),
                ("update", peer_stats.update_sent),
                ("notification", peer_stats.notification_sent),
                ("route_refresh", peer_stats.route_refresh_sent),
            ]
        }),
    });

    families
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::multiprotocol::{Afi, Safi};
    use crate::peer::BgpState;
    use telemetry::prometheus::render;

    #[test]
    fn test_build_families() {
        let v4 = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let snapshot = MetricsSnapshot {
            peer_total: 1,
            peers: vec![PeerMetricsSnapshot {
                peer_ip,
                state: BgpState::Established,
                uptime_secs: Some(30),
                adj_rib_in_total: 5,
                adj_rib_out_total: 2,
                adj_rib_in_families: vec![(v4, 5)],
                adj_rib_out_families: vec![(v4, 2)],
                peer_tx: None,
            }],
            loc_rib_families: vec![(v4, 5)],
            rss_bytes: Some(4096),
        };
        let stats = [(
            peer_ip,
            PeerStatistics {
                open_received: 1,
                keepalive_received: 3,
                update_received: 5,
                open_sent: 1,
                keepalive_sent: 4,
                ..Default::default()
            },
        )];

        assert_eq!(
            render(&build_families(&snapshot, &stats)),
            "\
# TYPE bgpgg_peer_count gauge
bgpgg_peer_count 1
# TYPE bgpgg_session_state gauge
bgpgg_session_state{peer=\"10.0.0.1\"} 6
# TYPE bgpgg_session_uptime_seconds gauge
bgpgg_session_uptime_seconds{peer=\"10.0.0.1\"} 30
# TYPE bgpgg_loc_rib_route_count gauge
bgpgg_loc_rib_route_count{afi_safi=\"IPv4/Unicast\"} 5
# TYPE bgpgg_adj_rib_in_route_count gauge
bgpgg_adj_rib_in_route_count{peer=\"10.0.0.1\"} 5
# TYPE bgpgg_adj_rib_in_afi_safi_route_count gauge
bgpgg_adj_rib_in_afi_safi_route_count{peer=\"10.0.0.1\",afi_safi=\"IPv4/Unicast\"} 5
# TYPE bgpgg_adj_rib_out_route_count gauge
bgpgg_adj_rib_out_route_count{peer=\"10.0.0.1\"} 2
# TYPE bgpgg_adj_rib_out_afi_safi_route_count gauge
bgpgg_adj_rib_out_afi_safi_route_count{peer=\"10.0.0.1\",afi_safi=\"IPv4/Unicast\"} 2
# TYPE bgpgg_process_memory_bytes gauge
bgpgg_process_memory_bytes 4096
# TYPE bgpgg_messages_received_total counter
bgpgg_messages_received_total{peer=\"10.0.0.1\",type=\"open\"} 1
bgpgg_messages_received_total{peer=\"10.0.0.1\",type=\"keepalive\"} 3
bgpgg_messages_received_total{peer=\"10.0.0.1\",type=\"update\"} 5
bgpgg_messages_received_total{peer=\"10.0.0.1\",type=\"notification\"} 0
bgpgg_messages_received_total{peer=\"10.0.0.1\",type=\"route_refresh\"} 0
# TYPE bgpgg_messages_sent_total counter
bgpgg_messages_sent_total{peer=\"10.0.0.1\",type=\"open\"} 1
bgpgg_messages_sent_total{peer=\"10.0.0.1\",type=\"keepalive\"} 4
bgpgg_messages_sent_total{peer=\"10.0.0.1\",type=\"update\"} 0
bgpgg_messages_sent_total{peer=\"10.0.0.1\",type=\"notification\"} 0
bgpgg_messages_sent_total{peer=\"10.0.0.1\",type=\"route_refresh\"} 0
"
        );
    }

    #[test]
    fn test_build_families_empty_server() {
        let snapshot = MetricsSnapshot {
            peer_total: 0,
            peers: vec![],
            loc_rib_families: vec![],
            rss_bytes: None,
        };
        let rendered = render(&build_families(&snapshot, &[]));
        assert_eq!(
            rendered,
            "# TYPE bgpgg_peer_count gauge\nbgpgg_peer_count 0\n"
        );
    }
}
