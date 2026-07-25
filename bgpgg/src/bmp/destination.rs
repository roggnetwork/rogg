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

use super::msg::BmpMessage;
use crate::log::{error, info};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// TCP client for sending BMP messages to external collectors
pub struct BmpTcpClient {
    addr: SocketAddr,
    conn: Option<TcpStream>,
    reconnect_delay: Duration,
}

impl BmpTcpClient {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            conn: None,
            reconnect_delay: Duration::from_secs(1),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    async fn ensure_connected(&mut self) -> bool {
        if self.conn.is_some() {
            return true;
        }

        match TcpStream::connect(self.addr).await {
            Ok(stream) => {
                info!(addr = %self.addr, "BMP: Connected to collector");
                self.conn = Some(stream);
                self.reconnect_delay = Duration::from_secs(1); // Reset delay
                true
            }
            Err(e) => {
                error!(addr = %self.addr, error = %e, "BMP: Failed to connect to collector");
                // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s (max)
                self.reconnect_delay =
                    std::cmp::min(self.reconnect_delay * 2, Duration::from_secs(30));
                false
            }
        }
    }

    async fn send_raw(&mut self, data: &[u8]) -> bool {
        if !self.ensure_connected().await {
            return false;
        }

        if let Some(conn) = &mut self.conn {
            match conn.write_all(data).await {
                Ok(_) => true,
                Err(e) => {
                    error!(addr = %self.addr, error = %e, "BMP: Write failed");
                    self.conn = None; // Trigger reconnect
                    false
                }
            }
        } else {
            false
        }
    }
}

/// BMP message destinations (TCP collectors, SQLite, etc.)
pub enum BmpDestination {
    TcpClient(BmpTcpClient),
}

impl BmpDestination {
    /// Send a single BMP message to the destination
    pub async fn send(&mut self, msg: &BmpMessage) {
        match self {
            Self::TcpClient(client) => {
                let data = msg.serialize();
                client.send_raw(&data).await;
            }
        }
    }

    /// Send a batch of BMP messages to the destination
    pub async fn send_batch(&mut self, msgs: &[BmpMessage]) {
        // Serialize all messages into one buffer
        let mut buffer = Vec::new();
        for msg in msgs {
            buffer.extend_from_slice(&msg.serialize());
        }

        // Single write_all() syscall
        match self {
            Self::TcpClient(client) => {
                client.send_raw(&buffer).await;
            }
        }
    }
}
