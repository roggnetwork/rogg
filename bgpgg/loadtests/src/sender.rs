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

use crate::route_generator::PeerRoute;
use crate::{bgp_handshake, create_update_message};
use bgpgg::bgp::msg_update::Origin;
use bgpgg::net::IpNetwork;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub struct SenderConnection {
    pub stream: TcpStream,
    pub local_asn: u16,
    pub next_hop: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct SenderStats {
    pub routes_sent: usize,
    pub duration: Duration,
    pub start_time: Instant,
    pub end_time: Instant,
}

/// Establish BGP connection without sending routes
pub async fn establish_connection(
    target_addr: SocketAddr,
    local_asn: u16,
    local_router_id: Ipv4Addr,
    peer_asn: u16,
    next_hop: Ipv4Addr,
    bind_addr: Option<SocketAddr>,
) -> io::Result<SenderConnection> {
    use tokio::net::TcpSocket;

    let mut stream = if let Some(bind) = bind_addr {
        // Bind to specific local address
        let socket = if bind.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(bind)?;
        socket.connect(target_addr).await?
    } else {
        TcpStream::connect(target_addr).await?
    };

    // Use very long hold time (3600s = 1 hour) so we don't need to send KEEPALIVEs during test
    bgp_handshake(&mut stream, local_asn, local_router_id, peer_asn, 3600).await?;

    Ok(SenderConnection {
        stream,
        local_asn,
        next_hop,
    })
}

/// Send routes on an already-established connection
/// Returns the connection so caller can keep it alive
pub async fn send_routes(
    mut conn: SenderConnection,
    routes: Vec<PeerRoute>,
    batch_size: usize,
) -> io::Result<(SenderConnection, SenderStats)> {
    if routes.is_empty() {
        return Ok((
            conn,
            SenderStats {
                routes_sent: 0,
                duration: Duration::from_secs(0),
                start_time: Instant::now(),
                end_time: Instant::now(),
            },
        ));
    }

    // Group routes by their attributes (since BGP UPDATE messages share attributes across all NLRIs)
    use std::collections::HashMap;

    #[derive(Hash, Eq, PartialEq, Clone)]
    struct RouteAttributes {
        as_path: Vec<u16>,
        origin: Origin,
        med: Option<u32>,
        communities: Vec<u32>,
    }

    let mut routes_by_attrs: HashMap<RouteAttributes, Vec<IpNetwork>> = HashMap::new();
    for route in &routes {
        let attrs = RouteAttributes {
            as_path: route.as_path.clone(),
            origin: route.origin,
            med: route.med,
            communities: route.communities.clone(),
        };
        routes_by_attrs.entry(attrs).or_default().push(route.prefix);
    }

    // Pre-serialize UPDATE messages, batching prefixes with the same attributes
    let mut update_messages = Vec::new();
    for (attrs, prefixes) in routes_by_attrs {
        // Batch prefixes with same attributes into UPDATE messages
        for chunk in prefixes.chunks(batch_size) {
            let msg = create_update_message(
                chunk.to_vec(),
                conn.next_hop,
                attrs.as_path.clone(),
                attrs.origin,
                attrs.med,
                None, // local_pref
                attrs.communities.clone(),
            );
            update_messages.push(msg);
        }
    }

    // Start timer and blast all UPDATEs
    let start_time = Instant::now();

    for msg in &update_messages {
        conn.stream.write_all(msg).await?;
    }

    conn.stream.flush().await?;

    let end_time = Instant::now();

    let stats = SenderStats {
        routes_sent: routes.len(),
        duration: end_time - start_time,
        start_time,
        end_time,
    };

    Ok((conn, stats))
}
