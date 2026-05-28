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

//! CacheSession: manages a single RTR (RFC 8210) connection to an RPKI cache server.
//!
//! Handles TCP and SSH connections, RTR protocol state machine, sync cycles,
//! timer management, backoff, and error reporting.

use crate::log::{debug, error, info, warn};
use crate::net::set_tcp_keepalive;
use crate::net::IpNetwork;
use crate::rpki::manager::{CacheEvent, RtrCacheConfig, RtrTransport, SshTransport, VrpBatch};
use crate::rpki::rtr::{
    self, CacheResponse, EndOfData, ErrorCode, ErrorReport, Message, ResetQuery, RtrReadError,
    RtrReader, Serial, SerialNotify, SerialQuery, DEFAULT_EXPIRE_INTERVAL,
    DEFAULT_REFRESH_INTERVAL, DEFAULT_RETRY_INTERVAL,
};
use crate::rpki::vrp::Vrp;
use russh::client::{self, AuthResult, Handle, Msg};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::ChannelStream;
use std::collections::HashSet;
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self as tokio_io, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, Instant};

/// Maximum backoff for reconnection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// SSH subsystem name for RTR (RFC 8210 Section 10).
const RTR_SSH_SUBSYSTEM: &str = "rpki-rtr";

/// Manages a single RTR connection to an RPKI cache server.
pub struct CacheSession {
    config: RtrCacheConfig,
    manager_tx: mpsc::UnboundedSender<CacheEvent>,
    shutdown_rx: oneshot::Receiver<()>,
    /// RTR session ID from the cache (set after first CacheResponse).
    session_id: Option<u16>,
    /// Serial number from the last successful EndOfData.
    serial_number: Option<Serial>,
    /// Timer intervals (from EndOfData or config override).
    refresh_interval: u64,
    retry_interval: u64,
    expire_interval: u64,
    /// Reconnection backoff.
    reconnect_delay: Duration,
    /// VRPs currently known from this cache (for withdrawal-of-unknown detection).
    local_vrps: HashSet<Vrp>,
    /// True when inside a CacheResponse..EndOfData sync cycle.
    syncing: bool,
    /// Pending announcements in current sync cycle.
    pending_announced: HashSet<Vrp>,
    /// Pending withdrawals in current sync cycle.
    pending_withdrawn: HashSet<Vrp>,
    /// Next refresh query deadline.
    refresh_deadline: Instant,
    /// Data expiry deadline.
    expire_deadline: Instant,
}

impl CacheSession {
    pub fn new(
        config: RtrCacheConfig,
        manager_tx: mpsc::UnboundedSender<CacheEvent>,
        shutdown_rx: oneshot::Receiver<()>,
    ) -> Self {
        let refresh_interval = config.refresh_interval.unwrap_or(DEFAULT_REFRESH_INTERVAL);
        let retry_interval = config.retry_interval.unwrap_or(DEFAULT_RETRY_INTERVAL);
        let expire_interval = config.expire_interval.unwrap_or(DEFAULT_EXPIRE_INTERVAL);

        CacheSession {
            config,
            manager_tx,
            shutdown_rx,
            session_id: None,
            serial_number: None,
            refresh_interval,
            retry_interval,
            expire_interval,
            reconnect_delay: Duration::from_secs(1),
            local_vrps: HashSet::new(),
            syncing: false,
            pending_announced: HashSet::new(),
            pending_withdrawn: HashSet::new(),
            refresh_deadline: Instant::now() + Duration::from_secs(refresh_interval),
            expire_deadline: Instant::now() + Duration::from_secs(expire_interval),
        }
    }

    /// Outer reconnect loop. Connects, runs protocol, reconnects on failure.
    pub async fn run(mut self) {
        let addr = self.config.address;
        info!(%addr, "cache session starting");

        loop {
            let result = match &self.config.transport {
                RtrTransport::Tcp => match self.connect_tcp().await {
                    Ok((reader, writer)) => self.run_session(reader, writer).await,
                    Err(err) => err,
                },
                RtrTransport::Ssh(ssh) => {
                    let ssh = ssh.clone();
                    match self.connect_ssh(&ssh).await {
                        Ok((reader, writer, _handle)) => self.run_session(reader, writer).await,
                        Err(err) => err,
                    }
                }
            };

            if self.handle_disconnect(result).await {
                return;
            }
        }
    }

    /// Log disconnect reason, notify manager, backoff. Returns true if shutdown.
    async fn handle_disconnect(&mut self, result: SessionResult) -> bool {
        let addr = self.config.address;
        match result {
            SessionResult::Shutdown => {
                info!(%addr, "cache session shutdown requested");
                return true;
            }
            SessionResult::Disconnected => {
                info!(%addr, delay = ?self.reconnect_delay, "cache disconnected, reconnecting");
            }
            SessionResult::FatalError(msg) => {
                error!(%addr, error = %msg, "fatal RTR error, reconnecting");
            }
        }

        let _ = self.manager_tx.send(CacheEvent::Disconnected(addr));

        tokio::select! {
            _ = time::sleep(self.reconnect_delay) => {
                self.reconnect_delay = (self.reconnect_delay * 2).min(MAX_BACKOFF);
                false
            }
            _ = &mut self.shutdown_rx => {
                info!(%addr, "cache session shutdown during backoff");
                true
            }
        }
    }

    /// Establish a TCP connection to the cache server.
    async fn connect_tcp(&mut self) -> Result<(OwnedReadHalf, OwnedWriteHalf), SessionResult> {
        let addr = self.config.address;

        let stream = tokio::select! {
            result = TcpStream::connect(addr) => {
                match result {
                    Ok(stream) => stream,
                    Err(err) => {
                        warn!(%addr, %err, "TCP connect failed");
                        return Err(SessionResult::Disconnected);
                    }
                }
            }
            _ = &mut self.shutdown_rx => {
                return Err(SessionResult::Shutdown);
            }
        };

        // RFC 8210 Section 7: enable TCP keep-alive
        if let Err(err) = set_tcp_keepalive(stream.as_raw_fd()) {
            warn!(%addr, %err, "failed to set TCP keepalive");
        }

        info!(%addr, "connected to RTR cache");
        self.reconnect_delay = Duration::from_secs(1);

        Ok(stream.into_split())
    }

    /// Establish an SSH connection to the cache server and request the rpki-rtr subsystem.
    ///
    /// Returns the channel stream split into read/write halves plus the SSH handle.
    /// The handle must be kept alive for the channel to function.
    async fn connect_ssh(
        &mut self,
        ssh: &SshTransport,
    ) -> Result<
        (
            tokio_io::ReadHalf<ChannelStream<Msg>>,
            tokio_io::WriteHalf<ChannelStream<Msg>>,
            Handle<SshHandler>,
        ),
        SessionResult,
    > {
        let addr = self.config.address;

        // Load private key from file.
        let key = match load_secret_key(&ssh.private_key_file, None) {
            Ok(key) => Arc::new(key),
            Err(err) => {
                error!(%addr, %err, path = %ssh.private_key_file, "failed to load SSH private key");
                return Err(SessionResult::FatalError(format!(
                    "SSH key load failed: {err}"
                )));
            }
        };

        let config = client::Config {
            keepalive_interval: Some(Duration::from_secs(30)),
            ..Default::default()
        };

        let handler = SshHandler {
            host: addr.ip().to_string(),
            port: addr.port(),
            known_hosts_file: ssh.known_hosts_file.clone(),
        };

        // Connect via SSH.
        let mut handle = tokio::select! {
            result = client::connect(Arc::new(config), addr, handler) => {
                match result {
                    Ok(handle) => handle,
                    Err(err) => {
                        warn!(%addr, %err, "SSH connect failed");
                        return Err(SessionResult::Disconnected);
                    }
                }
            }
            _ = &mut self.shutdown_rx => {
                return Err(SessionResult::Shutdown);
            }
        };

        // Authenticate with public key.
        let key_with_alg = PrivateKeyWithHashAlg::new(key, None);
        match handle
            .authenticate_publickey(&ssh.username, key_with_alg)
            .await
        {
            Ok(AuthResult::Success) => {}
            Ok(AuthResult::Failure { .. }) => {
                error!(%addr, user = %ssh.username, "SSH authentication rejected");
                return Err(SessionResult::FatalError(
                    "SSH authentication rejected".into(),
                ));
            }
            Err(err) => {
                error!(%addr, %err, "SSH authentication error");
                return Err(SessionResult::FatalError(format!(
                    "SSH authentication error: {err}"
                )));
            }
        }

        // Open session channel and request rpki-rtr subsystem.
        let channel = match handle.channel_open_session().await {
            Ok(channel) => channel,
            Err(err) => {
                error!(%addr, %err, "SSH channel open failed");
                return Err(SessionResult::FatalError(format!(
                    "SSH channel open failed: {err}"
                )));
            }
        };

        if let Err(err) = channel.request_subsystem(true, RTR_SSH_SUBSYSTEM).await {
            error!(%addr, %err, "SSH rpki-rtr subsystem request failed");
            return Err(SessionResult::FatalError(format!(
                "SSH subsystem request failed: {err}"
            )));
        }

        let stream = channel.into_stream();
        let (reader, writer) = tokio_io::split(stream);

        info!(%addr, "connected to RTR cache via SSH");
        self.reconnect_delay = Duration::from_secs(1);

        Ok((reader, writer, handle))
    }

    /// Run the RTR protocol over an established connection.
    /// Generic over reader/writer to support both TCP and SSH transport.
    async fn run_session<R, W>(&mut self, reader: R, mut writer: W) -> SessionResult
    where
        R: tokio::io::AsyncRead + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let addr = self.config.address;

        // Send initial query
        let query = self.build_query();
        if let Err(err) = writer.write_all(&query.serialize()).await {
            warn!(%addr, %err, "failed to send initial query");
            return SessionResult::Disconnected;
        }

        let mut rtr_reader = RtrReader::new(reader);
        self.syncing = false;
        self.refresh_deadline = Instant::now() + Duration::from_secs(self.refresh_interval);
        self.expire_deadline = Instant::now() + Duration::from_secs(self.expire_interval);

        loop {
            tokio::select! {
                result = rtr_reader.next_message() => {
                    match result {
                        Ok(msg) => {
                            if let Some(result) = self.handle_message(msg, &mut writer).await {
                                return result;
                            }
                        }
                        Err(RtrReadError::Eof) => {
                            info!(%addr, "cache closed connection");
                            return SessionResult::Disconnected;
                        }
                        Err(RtrReadError::Io(err)) => {
                            warn!(%addr, %err, "read error");
                            return SessionResult::Disconnected;
                        }
                        Err(RtrReadError::Parse(err)) => {
                            error!(%addr, ?err, "RTR parse error");
                            self.send_error_report(&mut writer, ErrorCode::CorruptData, None, &format!("{:?}", err)).await;
                            return SessionResult::FatalError(format!("parse error: {:?}", err));
                        }
                        Err(RtrReadError::MessageTooLarge(msg_len)) => {
                            error!(%addr, msg_len, "message exceeds max size");
                            return SessionResult::FatalError("message too large".into());
                        }
                    }
                }

                // Refresh timer -> send Serial Query
                _ = time::sleep_until(self.refresh_deadline) => {
                    if let (Some(session_id), Some(serial)) = (self.session_id, self.serial_number) {
                        let query = Message::SerialQuery(SerialQuery { session_id, serial });
                        if let Err(err) = writer.write_all(&query.serialize()).await {
                            warn!(%addr, %err, "failed to send serial query");
                            return SessionResult::Disconnected;
                        }
                        self.syncing = false;
                        debug!(%addr, ?serial, "sent refresh serial query");
                    }
                    self.refresh_deadline = Instant::now() + Duration::from_secs(self.refresh_interval);
                }

                // Expire timer -> data is stale
                _ = time::sleep_until(self.expire_deadline) => {
                    warn!(%addr, "expire timer fired");
                    self.local_vrps.clear();
                    let _ = self.manager_tx.send(CacheEvent::Expired(self.config.address));
                    self.expire_deadline = Instant::now() + Duration::from_secs(self.expire_interval);
                }

                _ = &mut self.shutdown_rx => {
                    return SessionResult::Shutdown;
                }
            }
        }
    }

    /// Build the initial RTR query message.
    fn build_query(&self) -> Message {
        match (self.session_id, self.serial_number) {
            (Some(session_id), Some(serial)) => {
                info!(addr = %self.config.address, session_id, ?serial, "sending serial query");
                Message::SerialQuery(SerialQuery { session_id, serial })
            }
            _ => {
                info!(addr = %self.config.address, "sending reset query");
                Message::ResetQuery(ResetQuery)
            }
        }
    }

    /// Handle a single RTR message. Returns Some to stop the session, None to continue.
    async fn handle_message<W: AsyncWriteExt + Unpin>(
        &mut self,
        msg: Message,
        writer: &mut W,
    ) -> Option<SessionResult> {
        match msg {
            Message::SerialNotify(notify) => self.handle_msg_serial_notify(notify, writer).await,
            Message::CacheResponse(resp) => self.handle_msg_cache_response(resp, writer).await,
            Message::Ipv4Prefix(pfx) => {
                let vrp =
                    make_ip_network(IpAddr::V4(pfx.prefix), pfx.prefix_length).map(|prefix| Vrp {
                        prefix,
                        max_length: pfx.max_length,
                        origin_as: pfx.asn,
                    });
                self.handle_msg_prefix(writer, pfx.is_announcement(), vrp)
                    .await
            }
            Message::Ipv6Prefix(pfx) => {
                let vrp =
                    make_ip_network(IpAddr::V6(pfx.prefix), pfx.prefix_length).map(|prefix| Vrp {
                        prefix,
                        max_length: pfx.max_length,
                        origin_as: pfx.asn,
                    });
                self.handle_msg_prefix(writer, pfx.is_announcement(), vrp)
                    .await
            }
            Message::EndOfData(eod) => self.handle_msg_end_of_data(eod, writer).await,
            Message::CacheReset(_) => self.handle_msg_cache_reset(writer).await,
            Message::ErrorReport(report) => self.handle_msg_error_report(report),
            Message::RouterKey(_) => {
                debug!(addr = %self.config.address, "router key received (ignored, no BGPsec)");
                None
            }
            Message::ResetQuery(_) | Message::SerialQuery(_) => {
                warn!(addr = %self.config.address, "received unexpected router-to-cache message");
                None
            }
        }
    }

    async fn handle_msg_serial_notify<W: AsyncWriteExt + Unpin>(
        &mut self,
        notify: SerialNotify,
        writer: &mut W,
    ) -> Option<SessionResult> {
        let addr = self.config.address;
        debug!(%addr, serial = ?notify.serial, "serial notify received");

        if let Some(our_serial) = self.serial_number {
            if our_serial >= notify.serial {
                debug!(%addr, "serial notify is not newer, ignoring");
                return None;
            }
        }

        let query = self.build_query();
        if let Err(err) = writer.write_all(&query.serialize()).await {
            warn!(%addr, %err, "failed to send query after serial notify");
            self.reset_session();
            return Some(SessionResult::Disconnected);
        }
        self.syncing = false;
        None
    }

    async fn handle_msg_cache_response<W: AsyncWriteExt + Unpin>(
        &mut self,
        resp: CacheResponse,
        writer: &mut W,
    ) -> Option<SessionResult> {
        let addr = self.config.address;

        if let Some(expected) = self.session_id {
            if resp.session_id != expected {
                error!(%addr, expected, got = resp.session_id, "session ID mismatch");
                return self
                    .protocol_error(writer, ErrorCode::CorruptData, "session ID mismatch")
                    .await;
            }
        } else {
            self.session_id = Some(resp.session_id);
            info!(%addr, session_id = resp.session_id, "new RTR session");
        }

        if self.syncing {
            error!(%addr, "CacheResponse while sync already in progress");
            return self
                .protocol_error(
                    writer,
                    ErrorCode::CorruptData,
                    "CacheResponse while sync already in progress",
                )
                .await;
        }

        self.syncing = true;
        self.pending_announced.clear();
        self.pending_withdrawn.clear();
        None
    }

    async fn handle_msg_prefix<W: AsyncWriteExt + Unpin>(
        &mut self,
        writer: &mut W,
        is_announcement: bool,
        vrp: Option<Vrp>,
    ) -> Option<SessionResult> {
        let addr = self.config.address;
        if !self.syncing {
            error!(%addr, "prefix PDU outside of sync cycle");
            return self
                .protocol_error(
                    writer,
                    ErrorCode::CorruptData,
                    "prefix PDU outside of sync cycle",
                )
                .await;
        }

        let vrp = match vrp {
            Some(vrp) => vrp,
            None => {
                warn!(%addr, "invalid prefix in PDU");
                return None;
            }
        };

        if is_announcement {
            if !self.pending_announced.insert(vrp.clone()) {
                warn!(%addr, ?vrp, "duplicate announcement in sync cycle");
                return self
                    .protocol_error(
                        writer,
                        ErrorCode::DuplicateAnnouncementReceived,
                        "duplicate announcement in sync cycle",
                    )
                    .await;
            }
            // RFC 8210 Section 5.6: router SHOULD raise error if it already
            // holds this VRP from a previous sync (incremental only).
            if self.has_serial() && self.local_vrps.contains(&vrp) {
                warn!(%addr, ?vrp, "duplicate announcement of existing VRP");
                return self
                    .protocol_error(
                        writer,
                        ErrorCode::DuplicateAnnouncementReceived,
                        "duplicate announcement of existing VRP",
                    )
                    .await;
            }
        } else {
            if !self.has_serial() {
                warn!(%addr, ?vrp, "withdrawal in reset response, expected announcements only");
                return self
                    .protocol_error(
                        writer,
                        ErrorCode::CorruptData,
                        "withdrawal in reset response, expected announcements only",
                    )
                    .await;
            }

            if !self.local_vrps.contains(&vrp) {
                warn!(%addr, ?vrp, "withdrawal of unknown record");
                return self
                    .protocol_error(
                        writer,
                        ErrorCode::WithdrawalOfUnknownRecord,
                        "withdrawal of unknown record",
                    )
                    .await;
            }

            self.pending_withdrawn.insert(vrp);
        }

        None
    }

    async fn handle_msg_end_of_data<W: AsyncWriteExt + Unpin>(
        &mut self,
        eod: EndOfData,
        writer: &mut W,
    ) -> Option<SessionResult> {
        let addr = self.config.address;

        if !self.syncing {
            error!(%addr, "EndOfData outside of sync cycle");
            return self
                .protocol_error(
                    writer,
                    ErrorCode::CorruptData,
                    "EndOfData outside of sync cycle",
                )
                .await;
        }
        self.syncing = false;

        let (refresh, retry, expire) = eod.get_timers();
        self.refresh_interval = self.config.refresh_interval.unwrap_or(refresh);
        self.retry_interval = self.config.retry_interval.unwrap_or(retry);
        self.expire_interval = self.config.expire_interval.unwrap_or(expire);

        // Update local VRP tracking before setting serial
        if !self.has_serial() {
            // Reset response: announced set is the complete state
            self.local_vrps = self.pending_announced.clone();
        } else {
            // Incremental: apply deltas
            self.local_vrps
                .extend(self.pending_announced.iter().cloned());
            for vrp in &self.pending_withdrawn {
                self.local_vrps.remove(vrp);
            }
        }

        self.serial_number = Some(eod.serial);
        self.pending_announced.clear();
        self.pending_withdrawn.clear();

        info!(%addr, session_id = eod.session_id, serial = ?eod.serial,
              total_vrps = self.local_vrps.len(), "sync cycle complete");

        let _ = self.manager_tx.send(CacheEvent::Batch(VrpBatch {
            cache_addr: self.config.address,
            session_id: eod.session_id,
            serial: eod.serial,
            vrps: self.local_vrps.clone(),
        }));

        // Reset timers
        self.refresh_deadline = Instant::now() + Duration::from_secs(self.refresh_interval);
        self.expire_deadline = Instant::now() + Duration::from_secs(self.expire_interval);

        None
    }

    fn handle_msg_error_report(&self, report: ErrorReport) -> Option<SessionResult> {
        let addr = self.config.address;
        // Never send Error Report in response to Error Report (RFC 8210)
        match report.error_code {
            ErrorCode::NoDataAvailable => {
                info!(%addr, "cache has no data available, will retry");
                None
            }
            _ => {
                error!(%addr, code = ?report.error_code, text = %report.error_text,
                       "fatal error from cache");
                Some(SessionResult::FatalError(format!(
                    "error report from cache: {:?} - {}",
                    report.error_code, report.error_text
                )))
            }
        }
    }

    /// RFC 8210 Section 8.3: Cache Reset received in response to Serial Query.
    /// Send Reset Query on the same connection to get a full re-sync.
    async fn handle_msg_cache_reset<W: AsyncWriteExt + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Option<SessionResult> {
        let addr = self.config.address;
        info!(%addr, "cache reset received, sending reset query on same connection");

        self.local_vrps.clear();
        self.reset_session();

        let query = Message::ResetQuery(ResetQuery);
        if let Err(err) = writer.write_all(&query.serialize()).await {
            warn!(%addr, %err, "failed to send reset query after cache reset");
            return Some(SessionResult::Disconnected);
        }
        self.syncing = false;
        None
    }

    /// Send an Error Report PDU to the cache.
    async fn send_error_report<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
        code: ErrorCode,
        erroneous_pdu: Option<Vec<u8>>,
        text: &str,
    ) {
        let msg = Message::ErrorReport(rtr::ErrorReport {
            error_code: code,
            erroneous_pdu,
            error_text: text.to_string(),
        });
        if let Err(err) = writer.write_all(&msg.serialize()).await {
            warn!(addr = %self.config.address, %err, "failed to send error report");
        }
    }

    /// True if we have a serial from a prior sync. When false, the current
    /// sync is a full dump (no withdrawals allowed, local_vrps gets replaced).
    fn has_serial(&self) -> bool {
        self.serial_number.is_some()
    }

    /// Clear session state for reconnection with a fresh Reset Query.
    fn reset_session(&mut self) {
        self.session_id = None;
        self.serial_number = None;
    }

    /// Send error report, reset session, and return Disconnected.
    async fn protocol_error<W: AsyncWriteExt + Unpin>(
        &mut self,
        writer: &mut W,
        code: ErrorCode,
        text: &str,
    ) -> Option<SessionResult> {
        self.send_error_report(writer, code, None, text).await;
        self.reset_session();
        Some(SessionResult::Disconnected)
    }
}

/// Result of a single session or connection attempt.
enum SessionResult {
    Shutdown,
    Disconnected,
    FatalError(String),
}

/// Create an IpNetwork from an IP address and prefix length.
fn make_ip_network(addr: IpAddr, prefix_len: u8) -> Option<IpNetwork> {
    match addr {
        IpAddr::V4(v4) => {
            if prefix_len > 32 {
                return None;
            }
            let net = format!("{}/{}", v4, prefix_len);
            net.parse::<IpNetwork>().ok()
        }
        IpAddr::V6(v6) => {
            if prefix_len > 128 {
                return None;
            }
            let net = format!("{}/{}", v6, prefix_len);
            net.parse::<IpNetwork>().ok()
        }
    }
}

/// SSH client handler for RTR cache connections.
///
/// Handles host key verification. All other callbacks use defaults.
pub struct SshHandler {
    host: String,
    port: u16,
    known_hosts_file: Option<String>,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match &self.known_hosts_file {
            Some(path) => {
                match russh::keys::known_hosts::check_known_hosts_path(
                    &self.host,
                    self.port,
                    server_public_key,
                    path,
                ) {
                    Ok(found) => {
                        if !found {
                            warn!(
                                path = %path,
                                host = %self.host,
                                "SSH server key not found in known_hosts"
                            );
                        }
                        Ok(found)
                    }
                    Err(err) => {
                        error!(path = %path, %err, "SSH known_hosts verification failed");
                        Ok(false)
                    }
                }
            }
            None => {
                warn!(
                    "accepting SSH host key without verification (no known-hosts-file configured)"
                );
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_ip_network() {
        // Valid IPv4
        let net = make_ip_network(IpAddr::V4("10.0.0.0".parse().unwrap()), 8);
        assert!(net.is_some());

        // Valid IPv6
        let net = make_ip_network(IpAddr::V6("2001:db8::".parse().unwrap()), 32);
        assert!(net.is_some());

        // Invalid prefix length
        let net = make_ip_network(IpAddr::V4("10.0.0.0".parse().unwrap()), 33);
        assert!(net.is_none());

        let net = make_ip_network(IpAddr::V6("2001:db8::".parse().unwrap()), 129);
        assert!(net.is_none());
    }
}
