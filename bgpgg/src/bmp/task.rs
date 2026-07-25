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

use super::destination::BmpDestination;
use super::msg::BmpMessage;
use super::msg_initiation::InitiationMessage;
use super::msg_peer_down::PeerDownMessage;
use super::msg_peer_up::PeerUpMessage;
use super::msg_route_monitoring::RouteMonitoringMessage;
use super::msg_statistics::{StatType, StatisticsReportMessage, StatisticsTlv};
use super::msg_termination::{TerminationMessage, TerminationReason};
use super::utils::PeerDistinguisher;
use crate::log::info;
use crate::server::ops::ServerOp;
use crate::server::BmpOp;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

// Batching constants
const MAX_BATCH_SIZE: usize = 100;
const MAX_BATCH_TIME: Duration = Duration::from_millis(100);

/// Individual BMP task handling one destination
pub struct BmpTask {
    addr: SocketAddr,
    destination: BmpDestination,
    rx: mpsc::UnboundedReceiver<Arc<BmpOp>>,
    server_tx: mpsc::UnboundedSender<ServerOp>,
    statistics_timeout: Option<u64>,

    // Batching state
    batch: Vec<BmpMessage>,
    last_flush: Instant,
}

impl BmpTask {
    pub fn new(
        addr: SocketAddr,
        destination: BmpDestination,
        rx: mpsc::UnboundedReceiver<Arc<BmpOp>>,
        server_tx: mpsc::UnboundedSender<ServerOp>,
        statistics_timeout: Option<u64>,
    ) -> Self {
        Self {
            addr,
            destination,
            rx,
            server_tx,
            statistics_timeout,
            batch: Vec::new(),
            last_flush: Instant::now(),
        }
    }

    pub async fn run(mut self, sys_name: String, sys_descr: String) {
        info!(addr = %self.addr, "BMP task starting");

        // Send Initiation message
        let initiation = BmpMessage::Initiation(InitiationMessage::new(&sys_name, &sys_descr, &[]));
        self.destination.send(&initiation).await;

        // Main event loop
        self.event_loop().await;

        // Flush any pending batched messages before sending Termination
        if !self.batch.is_empty() {
            self.flush().await;
        }

        // Send Termination message before exiting
        let termination = BmpMessage::Termination(TerminationMessage::new(
            TerminationReason::PermanentlyAdminClose,
            &[],
        ));
        self.destination.send(&termination).await;

        info!(addr = %self.addr, "BMP task exiting");
    }

    async fn event_loop(&mut self) {
        let mut stats_interval = self.statistics_timeout.and_then(|timeout_secs| {
            if timeout_secs > 0 {
                Some(tokio::time::interval(Duration::from_secs(timeout_secs)))
            } else {
                None
            }
        });

        loop {
            tokio::select! {
                op = self.rx.recv() => {
                    match op {
                        Some(op) => {
                            if let Some(msg) = self.convert_to_bmp(&op) {
                                self.batch.push(msg);

                                // Flush if batch full
                                if self.batch.len() >= MAX_BATCH_SIZE {
                                    self.flush().await;
                                }
                            }
                        }
                        None => break, // Channel closed, exit
                    }
                }
                _ = async {
                    match &mut stats_interval {
                        Some(interval) => interval.tick().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.send_statistics().await;
                }
                // Periodic flush on timeout
                _ = tokio::time::sleep_until(self.last_flush + MAX_BATCH_TIME) => {
                    if !self.batch.is_empty() {
                        self.flush().await;
                    }
                }
            }
        }
    }

    async fn flush(&mut self) {
        if self.batch.is_empty() {
            return;
        }

        info!(addr = %self.addr, count = self.batch.len(), "BMP: Flushing batch");
        self.destination.send_batch(&self.batch).await;
        self.batch.clear();
        self.last_flush = Instant::now();
    }

    fn convert_to_bmp(&self, op: &BmpOp) -> Option<BmpMessage> {
        match op {
            BmpOp::PeerUp {
                peer_ip,
                peer_as,
                peer_bgp_id,
                local_address,
                local_port,
                remote_port,
                sent_open,
                received_open,
                use_4byte_asn,
            } => {
                info!(peer_ip = %peer_ip, "BMP: Peer Up");
                Some(BmpMessage::PeerUp(PeerUpMessage::new(
                    PeerDistinguisher::Global,
                    *peer_ip,
                    *peer_as,
                    *peer_bgp_id,
                    false, // post_policy
                    *use_4byte_asn,
                    Some(SystemTime::now()),
                    *local_address,
                    *local_port,
                    *remote_port,
                    sent_open.clone(),
                    received_open.clone(),
                    &[],
                )))
            }
            BmpOp::PeerDown {
                peer_ip,
                peer_as,
                peer_bgp_id,
                reason,
                use_4byte_asn,
            } => {
                info!(peer_ip = %peer_ip, "BMP: Peer Down");
                Some(BmpMessage::PeerDown(PeerDownMessage::new(
                    PeerDistinguisher::Global,
                    *peer_ip,
                    *peer_as,
                    *peer_bgp_id,
                    false, // post_policy
                    *use_4byte_asn,
                    Some(SystemTime::now()),
                    reason.clone(),
                )))
            }
            BmpOp::RouteMonitoring {
                peer_ip,
                peer_as,
                peer_bgp_id,
                update,
            } => Some(BmpMessage::RouteMonitoring(RouteMonitoringMessage::new(
                PeerDistinguisher::Global,
                *peer_ip,
                *peer_as,
                *peer_bgp_id,
                false, // post_policy
                update.use_4byte_asn(),
                Some(SystemTime::now()),
                update.clone(),
            ))),
        }
    }

    async fn send_statistics(&mut self) {
        let (tx, rx) = oneshot::channel();
        if self
            .server_tx
            .send(ServerOp::GetBmpStatistics { response: tx })
            .is_err()
        {
            return;
        }

        let Ok(stats) = rx.await else { return };

        for peer_stat in stats {
            let tlvs = vec![StatisticsTlv::new_counter64(
                StatType::RoutesInAdjRibIn,
                peer_stat.adj_rib_in_count,
            )];

            let msg = BmpMessage::StatisticsReport(StatisticsReportMessage::new(
                PeerDistinguisher::Global,
                peer_stat.peer_ip,
                peer_stat.peer_as,
                peer_stat.peer_bgp_id,
                true, // use_4byte_asn - statistics messages always use 4-byte ASN encoding
                Some(SystemTime::now()),
                tlvs,
            ));

            self.destination.send(&msg).await;
        }
    }
}
