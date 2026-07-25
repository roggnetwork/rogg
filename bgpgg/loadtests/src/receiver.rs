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

use crate::bgp_handshake;
use bgpgg::bgp::msg::{AddPathMask, BgpMessage, MessageFormat};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub struct ReceiverStats {
    pub routes_received: usize,
    pub first_route_time: Option<Instant>,
    pub last_route_time: Option<Instant>,
    pub duration: Option<Duration>,
}

/// Run a lightweight BGP receiver that logs route arrival timestamps
pub async fn run_receiver(
    listen_addr: SocketAddr,
    local_asn: u16,
    local_router_id: Ipv4Addr,
    peer_asn: u16,
    expected_routes: usize,
) -> io::Result<ReceiverStats> {
    // Bind and listen
    let listener = TcpListener::bind(listen_addr).await?;

    // Accept connection from bgpgg
    let (mut stream, _peer_addr) = listener.accept().await?;

    // Perform BGP handshake
    bgp_handshake(&mut stream, local_asn, local_router_id, peer_asn, 180).await?;

    // Read incoming BGP messages and count routes
    let mut stats = ReceiverStats {
        routes_received: 0,
        first_route_time: None,
        last_route_time: None,
        duration: None,
    };

    loop {
        match bgpgg::bgp::msg::read_bgp_message(
            &mut stream,
            MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
                enhanced_rr: false,
            },
        )
        .await
        {
            Ok(BgpMessage::Update(update)) => {
                let nlri_count = update.nlri_prefixes().len();

                if nlri_count > 0 {
                    let now = Instant::now();

                    if stats.first_route_time.is_none() {
                        stats.first_route_time = Some(now);
                    }

                    stats.last_route_time = Some(now);
                    stats.routes_received += nlri_count;

                    if stats.routes_received >= expected_routes {
                        if let Some(first) = stats.first_route_time {
                            stats.duration = Some(now - first);
                        }
                        return Ok(stats);
                    }
                }
            }
            Ok(BgpMessage::Keepalive(_)) => {
                // Ignore KEEPALIVEs
                continue;
            }
            Ok(msg) => {
                tracing::warn!("Received unexpected message: {:?}", msg);
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to read BGP message: {:?}", e),
                ));
            }
        }
    }
}
