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

use crate::bgp::msg::{AddPathMask, BgpMessage, Message, MessageFormat, PRE_OPEN_FORMAT};
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_open_types::{AddPathCapability, GracefulRestartCapability, LlgrCapability};
use crate::bgp::msg_route_refresh::RouteRefreshSubtype;
use crate::bgp::msg_update::UpdateMessage;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::bgp::utils::ParserError;
use crate::log::{debug, error, info};
use crate::rib::{RouteKey, RoutePath, Withdrawal};
use crate::server::ops::ServerOp;
use crate::server::ConnectionType;
use crate::types::PeerDownReason;
use conf::bgp::{LlgrConfig, PeerConfig};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, Error};
use std::net::{IpAddr, SocketAddr};

use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Runtime Graceful Restart state for a peer (RFC 4724)
#[derive(Debug)]
pub struct GracefulRestartState {
    /// Per-AFI/SAFI restart state (true = in restart for this AFI/SAFI)
    pub in_restart: HashMap<AfiSafi, bool>,
    /// Restart timer task handle
    pub restart_timer: Option<JoinHandle<()>>,
    /// End-of-RIB markers received (per AFI/SAFI)
    pub eor_received: HashSet<AfiSafi>,
    /// AFI/SAFIs the peer advertised GR support for
    pub afi_safis: HashSet<AfiSafi>,
    /// End-of-RIB markers sent (per AFI/SAFI) - restarting speaker mode
    pub eor_sent: HashSet<AfiSafi>,
    /// Track if loc-rib has been received per AFI/SAFI (triggers EOR sending)
    pub loc_rib_received: HashMap<AfiSafi, bool>,
}

/// BGP capabilities negotiated between peers
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCapabilities {
    /// Multiprotocol extensions (RFC 4760)
    pub multiprotocol: HashSet<AfiSafi>,
    /// Route Refresh capability (RFC 2918)
    pub route_refresh: bool,
    /// Enhanced Route Refresh capability (RFC 7313)
    pub enhanced_route_refresh: bool,
    /// Four-Octet ASN capability (RFC 6793)
    /// Contains the peer's 4-byte ASN if advertised
    pub four_octet_asn: Option<u32>,
    /// Graceful Restart capability (RFC 4724)
    /// Contains what the peer advertised in their OPEN message
    pub graceful_restart: Option<GracefulRestartCapability>,
    /// ADD-PATH capability (RFC 7911)
    /// Contains the negotiated ADD-PATH send/receive per AFI/SAFI
    pub add_path: Option<AddPathCapability>,
    /// Long-Lived Graceful Restart capability (RFC 9494)
    pub llgr: Option<LlgrCapability>,
}

impl PeerCapabilities {
    /// Check if a specific AFI/SAFI is negotiated
    pub fn supports_afi_safi(&self, afi_safi: &AfiSafi) -> bool {
        self.multiprotocol.contains(afi_safi)
    }

    /// Check if peer supports 4-byte ASNs (RFC 6793)
    pub fn supports_four_octet_asn(&self) -> bool {
        self.four_octet_asn.is_some()
    }

    /// Get Graceful Restart AFI/SAFIs (empty if not advertised)
    pub fn gr_afi_safis(&self) -> Vec<AfiSafi> {
        self.graceful_restart
            .as_ref()
            .map(|gr_cap| gr_cap.afi_safis())
            .unwrap_or_default()
    }

    /// Check if ADD-PATH send is negotiated for a specific AFI/SAFI
    pub fn add_path_send_negotiated(&self, afi_safi: &AfiSafi) -> bool {
        self.add_path
            .as_ref()
            .map(|ap| {
                ap.entries
                    .iter()
                    .any(|(entry_afi_safi, mode)| entry_afi_safi == afi_safi && mode.can_send())
            })
            .unwrap_or(false)
    }

    /// Negotiated AFI/SAFIs. RFC 4760: if multiprotocol is not negotiated,
    /// IPv4 Unicast is assumed.
    pub fn afi_safis(&self) -> Vec<AfiSafi> {
        if self.multiprotocol.is_empty() {
            vec![AfiSafi::new(Afi::Ipv4, Safi::Unicast)]
        } else {
            self.multiprotocol.iter().copied().collect()
        }
    }

    /// MessageFormat for parsing incoming UPDATEs from this peer.
    /// Includes ADD-PATH for all AFI/SAFIs where receive is negotiated.
    pub fn receive_format(&self, session_type: Option<SessionType>) -> MessageFormat {
        let mut add_path = AddPathMask::NONE;
        if let Some(ap) = &self.add_path {
            for (afi_safi, mode) in &ap.entries {
                if mode.can_receive() {
                    add_path = add_path.with(afi_safi);
                }
            }
        }
        MessageFormat {
            use_4byte_asn: self.supports_four_octet_asn(),
            add_path,
            is_ebgp: session_type == Some(SessionType::Ebgp),
            enhanced_rr: self.enhanced_route_refresh,
        }
    }

    /// Build MessageFormat for encoding outgoing messages to this peer.
    /// Includes ADD-PATH for all AFI/SAFIs where send is negotiated.
    pub fn send_format(&self, session_type: Option<SessionType>) -> MessageFormat {
        let mut add_path = AddPathMask::NONE;
        if let Some(ap) = &self.add_path {
            for (afi_safi, mode) in &ap.entries {
                if mode.can_send() {
                    add_path = add_path.with(afi_safi);
                }
            }
        }
        MessageFormat {
            use_4byte_asn: self.supports_four_octet_asn(),
            add_path,
            is_ebgp: session_type == Some(SessionType::Ebgp),
            enhanced_rr: self.enhanced_route_refresh,
        }
    }

    /// Check if ADD-PATH receive is negotiated for a specific AFI/SAFI
    pub fn add_path_receive_negotiated(&self, afi_safi: &AfiSafi) -> bool {
        self.add_path
            .as_ref()
            .map(|ap| {
                ap.entries
                    .iter()
                    .any(|(entry_afi_safi, mode)| entry_afi_safi == afi_safi && mode.can_receive())
            })
            .unwrap_or(false)
    }

    /// Check if ADD-PATH receive is negotiated for any AFI/SAFI
    pub fn add_path_receive(&self) -> bool {
        self.add_path
            .as_ref()
            .map(|ap| ap.entries.iter().any(|(_, mode)| mode.can_receive()))
            .unwrap_or(false)
    }
}

/// Parameters from received BGP OPEN message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpOpenParams {
    pub peer_asn: u32,
    pub peer_hold_time: u16,
    pub peer_bgp_id: u32,
    pub local_asn: u32,
    pub local_hold_time: u16,
    pub peer_capabilities: PeerCapabilities,
}

/// Local router configuration passed to each peer
#[derive(Debug, Clone)]
pub struct LocalConfig {
    pub asn: u32,
    pub bgp_id: std::net::Ipv4Addr,
    pub hold_time: u16,
    pub addr: SocketAddr,
    pub cluster_id: std::net::Ipv4Addr,
    /// Resolved LLGR config (server + peer merged). None = disabled.
    pub llgr: Option<LlgrConfig>,
}

/// A pending route announcement or withdrawal awaiting flush to server.
#[derive(Debug, Clone)]
pub enum PendingRoute {
    Announce(RoutePath),
    Withdraw(Withdrawal),
}

impl PendingRoute {
    pub fn route_key(&self) -> RouteKey {
        match self {
            PendingRoute::Announce(route_path) => route_path.key.clone(),
            PendingRoute::Withdraw((key, _)) => key.clone(),
        }
    }

    /// Split a slice into separate announced and withdrawn lists.
    pub fn split(routes: &[PendingRoute]) -> (Vec<RoutePath>, Vec<Withdrawal>) {
        let mut announced = Vec::new();
        let mut withdrawn = Vec::new();
        for route in routes {
            match route {
                PendingRoute::Announce(route_path) => announced.push(route_path.clone()),
                PendingRoute::Withdraw(withdrawal) => withdrawn.push(withdrawal.clone()),
            }
        }
        (announced, withdrawn)
    }
}

/// (announced routes, withdrawn routes)
pub(super) type RouteChanges = (Vec<RoutePath>, Vec<Withdrawal>);

mod fsm;
mod incoming;
mod messages;
mod state_active;
mod state_connect;
mod state_established;
mod state_idle;
mod state_openconfirm;
mod state_opensent;
mod states;

pub mod outgoing;

// Re-export FSM types so they can be used from outside the peer module
pub use fsm::{BgpState, Fsm, FsmEvent, FsmTimers};

/// Errors that can occur during peer FSM event processing
#[derive(Debug)]
pub enum PeerError {
    /// FSM protocol error - unexpected event in current state
    FsmError,
    /// Automatic stop requested with cease subcode
    AutomaticStop(CeaseSubcode),
    /// BGP UPDATE message validation error
    UpdateError,
    /// I/O error during message send/receive
    IoError(Error),
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerError::FsmError => write!(f, "FSM protocol error"),
            PeerError::AutomaticStop(subcode) => write!(f, "automatic stop: {:?}", subcode),
            PeerError::UpdateError => write!(f, "UPDATE message error"),
            PeerError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl From<Error> for PeerError {
    fn from(e: Error) -> Self {
        PeerError::IoError(e)
    }
}

impl From<PeerError> for Error {
    fn from(e: PeerError) -> Self {
        match e {
            PeerError::IoError(io_err) => io_err,
            _ => Error::other(e.to_string()),
        }
    }
}

/// RFC 4271 8.1.1: Maximum IdleHoldTime for DampPeerOscillations backoff.
const MAX_IDLE_HOLD_TIME: Duration = Duration::from_secs(120);

/// Operations that can be sent to a peer task
pub enum PeerOp {
    SendUpdate(Vec<u8>),
    SendRouteRefresh {
        afi: Afi,
        safi: Safi,
        subtype: RouteRefreshSubtype,
    },
    GetStatistics(oneshot::Sender<PeerStatistics>),
    GetNegotiatedCapabilities(oneshot::Sender<PeerCapabilities>),
    /// Graceful shutdown - sends CEASE NOTIFICATION with given subcode and closes connection
    Shutdown(CeaseSubcode),
    /// Hard reset - sends CEASE/ADMINISTRATIVE_RESET, closes connection, but keeps task alive
    /// Peer will auto-reconnect after idle hold timer
    HardReset,
    /// RFC 4271 Event 1: ManualStart - admin starts the peer connection
    ManualStart,
    /// RFC 4271 Event 2: ManualStop - admin stops the peer connection
    ManualStop,
    /// RFC 4271 Event 3: AutomaticStart - system automatically starts (non-passive)
    AutomaticStart,
    /// RFC 4271 Event 4: ManualStart_with_PassiveTcpEstablishment
    ManualStartPassive,
    /// RFC 4271 Event 5: AutomaticStartPassive - system automatically starts (passive)
    AutomaticStartPassive,
    /// Incoming TCP connection accepted - peer should transition to OpenSent
    TcpConnectionAccepted {
        tcp_tx: OwnedWriteHalf,
        tcp_rx: OwnedReadHalf,
    },
    /// Server notifies that loc-rib has been sent for an AFI/SAFI
    LocalRibSent {
        afi_safi: crate::bgp::multiprotocol::AfiSafi,
    },
    /// Server detected collision, this connection lost. Send NOTIFICATION and close.
    CollisionLost,
}

/// Type of BGP session based on AS relationship
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// External BGP session (different AS)
    Ebgp,
    /// Internal BGP session (same AS)
    Ibgp,
}

/// Statistics for BGP messages
#[derive(Debug, Clone, Default)]
pub struct PeerStatistics {
    pub open_sent: u64,
    pub keepalive_sent: u64,
    pub update_sent: u64,
    pub notification_sent: u64,
    pub open_received: u64,
    pub keepalive_received: u64,
    pub update_received: u64,
    pub notification_received: u64,
    pub route_refresh_received: u64,
    pub route_refresh_sent: u64,
    pub adj_rib_in_count: u64,
}

/// TCP connection state - only present when connected
/// Spawns a dedicated read task to avoid tokio::select! cancellation issues
struct TcpConnection {
    tx: OwnedWriteHalf,
    msg_rx: mpsc::Receiver<Result<Vec<u8>, ParserError>>,
    read_task: JoinHandle<()>,
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        // Abort read task when connection is dropped
        self.read_task.abort();
    }
}

impl TcpConnection {
    /// Creates a new TcpConnection and spawns a dedicated read task
    ///
    /// The read task runs `read_bgp_message_bytes` in a loop, sending raw bytes to a channel.
    /// This ensures the read operation cannot be cancelled mid-execution by tokio::select!,
    /// preventing TCP stream desynchronization.
    /// The Peer task will parse these bytes using negotiated capabilities.
    fn new(tx: OwnedWriteHalf, mut rx: OwnedReadHalf) -> Self {
        use crate::bgp::msg::read_bgp_message_bytes;

        let (msg_tx, msg_rx) = mpsc::channel(16);

        let read_task = tokio::spawn(async move {
            loop {
                match read_bgp_message_bytes(&mut rx).await {
                    Ok(bytes) => {
                        if msg_tx.send(Ok(bytes)).await.is_err() {
                            // Receiver dropped, exit cleanly
                            break;
                        }
                    }
                    Err(e) => {
                        // Send error and exit - connection will be torn down
                        let _ = msg_tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });

        TcpConnection {
            tx,
            msg_rx,
            read_task,
        }
    }
}

pub struct Peer {
    pub addr: IpAddr,
    pub port: u16,
    pub fsm: Fsm,
    pub asn: Option<u32>,
    /// Peer's BGP Router ID from OPEN message
    pub bgp_id: Option<std::net::Ipv4Addr>,
    pub session_type: Option<SessionType>,
    pub statistics: PeerStatistics,
    pub config: PeerConfig,
    /// TCP connection - None when disconnected (Idle/Connect/Active states)
    conn: Option<TcpConnection>,
    peer_rx: mpsc::UnboundedReceiver<PeerOp>,
    server_tx: mpsc::UnboundedSender<ServerOp>,
    /// Local router configuration
    local_config: LocalConfig,
    /// ConnectRetryTime from global config (RFC 4271 8.1.2)
    connect_retry_secs: u64,
    /// Consecutive disconnect count for DampPeerOscillations backoff (RFC 4271 8.1.1)
    consecutive_down_count: u32,
    /// RFC 5492: peer rejected capabilities (NOTIFICATION code 2 subcode 4).
    /// When true, OPEN messages are sent without capabilities.
    capabilities_suppressed: bool,
    /// Connection type for collision detection
    conn_type: ConnectionType,
    /// True if ManualStop was received - disables auto-reconnect until ManualStart
    manually_stopped: bool,
    /// Timestamp when Established state was entered (for stability-based damping reset)
    established_at: Option<Instant>,
    /// RFC 4271 9.2.1.1: Last time we sent an UPDATE
    last_update_sent: Option<Instant>,
    /// Queued serialized UPDATE messages waiting for MRAI timer
    pending_updates: Vec<Vec<u8>>,
    /// MinRouteAdvertisementIntervalTimer from config
    mrai_interval: Duration,
    /// OPEN message sent to peer (for BMP PeerUp)
    sent_open: Option<OpenMessage>,
    /// OPEN message received from peer (for BMP PeerUp)
    received_open: Option<OpenMessage>,
    /// Peer capabilities
    capabilities: PeerCapabilities,
    /// Graceful Restart runtime state (RFC 4724)
    gr_state: Option<GracefulRestartState>,
    /// Accumulated route events awaiting flush to server, in temporal order.
    pending_routes: Vec<PendingRoute>,
}

impl Peer {
    /// Create a new Peer in Idle state (RFC 4271 8.2.2).
    /// Peer starts without TCP connection - use ManualStart to initiate connection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        addr: IpAddr,
        port: u16,
        peer_rx: mpsc::UnboundedReceiver<PeerOp>,
        server_tx: mpsc::UnboundedSender<ServerOp>,
        local_config: LocalConfig,
        config: PeerConfig,
        connect_retry_secs: u64,
        conn_type: ConnectionType,
    ) -> Self {
        Peer {
            addr,
            port,
            fsm: Fsm::new(config.delay_open_time(), config.passive_mode),
            conn: None,
            asn: None,
            bgp_id: None,
            session_type: None,
            statistics: PeerStatistics::default(),
            mrai_interval: Duration::from_secs(
                config.min_route_advertisement_interval_secs.unwrap_or(0),
            ),
            last_update_sent: None,
            pending_updates: Vec::new(),
            config,
            peer_rx,
            server_tx,
            local_config,
            connect_retry_secs,
            consecutive_down_count: 0,
            capabilities_suppressed: false,
            conn_type,
            manually_stopped: false,
            established_at: None,
            sent_open: None,
            received_open: None,
            capabilities: PeerCapabilities::default(),
            gr_state: None,
            pending_routes: Vec::new(),
        }
    }

    fn pending_route_count(&self) -> usize {
        self.pending_routes.len()
    }

    /// Flush accumulated route events to the server in temporal order.
    fn flush_pending_routes(&mut self) {
        let _ = self.server_tx.send(ServerOp::PeerUpdate {
            peer_ip: self.addr,
            routes: std::mem::take(&mut self.pending_routes),
        });
    }

    /// Main peer task - handles the full lifecycle of a BGP peer.
    /// Runs forever, handling all FSM states including Idle, Connect, Active.
    pub async fn run(mut self) {
        let peer_ip = self.addr;
        debug!(peer_ip = %peer_ip, "starting peer task");

        loop {
            match self.fsm.state() {
                BgpState::Idle => {
                    if self.handle_idle_state().await {
                        return; // Shutdown requested
                    }
                }
                BgpState::Connect => {
                    self.handle_connect_state().await;
                }
                BgpState::Active => {
                    self.handle_active_state().await;
                }
                BgpState::OpenSent | BgpState::OpenConfirm => {
                    if self.handle_open_states().await {
                        return; // Shutdown requested
                    }
                }
                BgpState::Established => {
                    if self.handle_established().await {
                        return; // Shutdown requested
                    }
                }
            }
        }
    }

    /// Check if routes should be preserved with Graceful Restart (RFC 4724)
    /// Returns true if GR is enabled and peer advertised a restart time > 0
    fn should_preserve_routes_with_gr(&self, reason: &PeerDownReason) -> bool {
        // RFC 4724 Section 5: NOTIFICATION always deletes routes, even with GR
        // Only TcpConnectionFails preserves routes when GR is active
        match reason {
            PeerDownReason::RemoteNotification(_) | PeerDownReason::LocalNotification(_) => {
                return false;
            }
            _ => {}
        }

        // Only preserve routes if we're in Established state and have GR negotiated
        if self.fsm.state() != BgpState::Established {
            return false;
        }

        if let Some(gr_cap) = &self.capabilities.graceful_restart {
            if gr_cap.afi_safi_list.is_empty() {
                return false;
            }
            if gr_cap.restart_time > 0 {
                return true;
            }
            // RFC 9494 Section 4.2: restart_time=0 with nonzero LLST still preserves routes
            if let Some(llgr_cap) = &self.capabilities.llgr {
                return llgr_cap.entries.iter().any(|e| e.stale_time > 0);
            }
        }
        false
    }

    /// Start Graceful Restart timer (RFC 4724)
    fn start_gr_restart_timer(&mut self) {
        let Some(gr_cap) = &self.capabilities.graceful_restart else {
            return;
        };

        let restart_time = gr_cap.restart_time;

        // Use the AFI/SAFIs the peer advertised for GR
        let gr_afi_safis: HashSet<_> = gr_cap.afi_safis().into_iter().collect();

        if gr_afi_safis.is_empty() {
            return;
        }

        // RFC 9494: Collect LLGR-capable AFI/SAFIs and their stale times from peer cap
        let llgr_afi_safis: Vec<(AfiSafi, u32)> = self
            .capabilities
            .llgr
            .as_ref()
            .map(|cap| {
                cap.entries
                    .iter()
                    .map(|entry| (entry.afi_safi, entry.stale_time))
                    .collect()
            })
            .unwrap_or_default();

        // Cancel existing timer if any
        if let Some(state) = &mut self.gr_state {
            if let Some(timer) = state.restart_timer.take() {
                timer.abort();
            }
        }

        let peer_ip = self.addr;
        let server_tx = self.server_tx.clone();

        // Spawn restart timer. restart_time=0 with LLGR yields once to let
        // PeerDisconnected mark routes stale before firing (RFC 9494 Section 4.2).
        let timer = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(restart_time as u64)).await;
            let _ = server_tx.send(ServerOp::GracefulRestartTimerExpired {
                peer_ip,
                llgr_afi_safis,
            });
        });

        // Initialize or update GR state
        let mut in_restart = HashMap::new();
        for afi_safi in &gr_afi_safis {
            in_restart.insert(*afi_safi, true);
        }

        self.gr_state = Some(GracefulRestartState {
            in_restart,
            restart_timer: Some(timer),
            eor_received: HashSet::new(),
            afi_safis: gr_afi_safis,
            eor_sent: HashSet::new(),
            loc_rib_received: HashMap::new(),
        });

        info!(peer_ip = %peer_ip, restart_time = restart_time,
              "started Graceful Restart timer (Receiving Speaker mode)");
    }

    /// Disconnect TCP and transition FSM.
    fn disconnect(&mut self, apply_damping: bool, reason: PeerDownReason) {
        let had_connection = self.conn.is_some();

        // RFC 4724: Extract GR AFI/SAFIs if routes should be preserved
        let gr_afi_safis = if self.should_preserve_routes_with_gr(&reason) {
            self.capabilities.gr_afi_safis()
        } else {
            vec![]
        };

        self.conn = None;
        self.established_at = None;
        self.fsm.timers.stop_hold_timer();
        self.fsm.timers.stop_keepalive_timer();
        self.fsm.timers.stop_delay_open_timer();

        if had_connection {
            if apply_damping {
                self.consecutive_down_count += 1;
            }

            // Start GR timer if applicable
            if !gr_afi_safis.is_empty() {
                self.start_gr_restart_timer();
            }

            let _ = self.server_tx.send(ServerOp::PeerDisconnected {
                peer_ip: self.addr,
                reason,
                gr_afi_safis,
                conn_type: self.conn_type,
            });
        }
    }

    /// Compute idle hold time with DampPeerOscillations backoff (RFC 4271 8.1.1).
    /// Returns None if automatic restart is disabled.
    fn get_idle_hold_time(&self) -> Option<Duration> {
        let cfg = &self.config;
        let base = Duration::from_secs(cfg.idle_hold_time_secs?);
        if !cfg.damp_peer_oscillations || self.consecutive_down_count == 0 {
            Some(base)
        } else {
            let exp = self.consecutive_down_count.min(6);
            let backoff = base * 2u32.pow(exp);
            Some(backoff.min(MAX_IDLE_HOLD_TIME))
        }
    }

    /// Notify server of state change.
    fn notify_state_change(&self) {
        let _ = self.server_tx.send(ServerOp::PeerStateChanged {
            peer_ip: self.addr,
            state: self.fsm.state(),
            conn_type: self.conn_type,
        });
    }

    /// Get current BGP state
    pub fn state(&self) -> BgpState {
        self.fsm.state()
    }

    /// Handle End-of-RIB marker received (RFC 4724)
    pub(super) async fn handle_eor_received(&mut self, afi_safi: AfiSafi) {
        let Some(gr_state) = &mut self.gr_state else {
            debug!(peer_ip = %self.addr, %afi_safi, "EOR received but no GR state");
            return;
        };

        if !gr_state.afi_safis.contains(&afi_safi) {
            debug!(peer_ip = %self.addr, %afi_safi, "EOR received for non-GR AFI/SAFI");
            return;
        }

        if gr_state.eor_received.insert(afi_safi) {
            info!(peer_ip = %self.addr, %afi_safi, "End-of-RIB received");

            // Mark this AFI/SAFI as no longer in restart
            gr_state.in_restart.insert(afi_safi, false);

            // Cancel restart timer if all expected EORs received
            let all_eors_received = gr_state
                .afi_safis
                .iter()
                .all(|afi_safi| gr_state.eor_received.contains(afi_safi));

            if all_eors_received {
                info!(peer_ip = %self.addr, "all EORs received - Graceful Restart complete");
                if let Some(timer) = gr_state.restart_timer.take() {
                    timer.abort();
                }
            }

            // Flush any pending route updates so the server processes them
            // before the stale sweep triggered by GracefulRestartComplete.
            self.flush_pending_routes();

            // Notify server to remove stale routes for this AFI/SAFI
            let _ = self.server_tx.send(ServerOp::GracefulRestartComplete {
                peer_ip: self.addr,
                afi_safi,
            });
        }
    }

    /// Send End-of-RIB markers for specified AFI/SAFIs (RFC 4724)
    /// RFC 4724: "The End-of-RIB marker MUST be sent by a BGP speaker to its peer once
    /// it completes the initial routing update for an address family after the BGP session
    /// is established." This helps routing convergence in general, not just for GR.
    async fn send_eor_markers(&mut self, afi_safis: &[AfiSafi]) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(std::io::ErrorKind::NotConnected, "no TCP connection"))?;

        let gr_state = self
            .gr_state
            .as_mut()
            .ok_or_else(|| io::Error::other("no GR state"))?;

        for afi_safi in afi_safis {
            // Skip if already sent
            if gr_state.eor_sent.contains(afi_safi) {
                continue;
            }

            // Only send for negotiated AFI/SAFIs
            if !gr_state.afi_safis.contains(afi_safi) {
                continue;
            }

            // Create EOR message
            let format = self.capabilities.send_format(self.session_type);
            let eor_msg = UpdateMessage::new_eor(afi_safi.afi, afi_safi.safi, format);

            // Send EOR
            conn.tx.write_all(&eor_msg.serialize()).await?;
            gr_state.eor_sent.insert(*afi_safi);
            info!(peer_ip = %self.addr, %afi_safi, "sent End-of-RIB marker");
        }

        Ok(())
    }

    /// Check if NOTIFICATION can be sent (RFC 4271 8.2.1.5).
    fn can_send_notification(&self) -> bool {
        self.conn.is_some()
            && (self.config.send_notification_without_open || self.statistics.open_sent > 0)
    }

    /// Parse BGP message from raw bytes received from TCP connection.
    ///
    /// RFC 4271 Section 4.1: BGP header is 19 bytes, message type at byte 18.
    ///
    /// # Arguments
    /// * `bytes` - Complete BGP message including header
    /// * `format` - Message encoding format based on negotiated capabilities
    ///
    /// # Note on format during OPEN exchange
    /// During OPEN message exchange, `format` MUST have `use_4byte_asn: false` because:
    /// - RFC 6793: OPEN messages always use 2-byte ASN encoding
    /// - If peer ASN > 65535, OPEN uses AS_TRANS (23456) and real ASN goes in capability
    /// - Only after OPEN negotiation can we determine if peer supports 4-byte ASNs
    fn parse_bgp_message(bytes: &[u8], format: MessageFormat) -> Result<BgpMessage, ParserError> {
        let message_type = bytes[18];
        let body = bytes[19..].to_vec();
        BgpMessage::from_bytes(message_type, body, bytes, format)
    }

    /// Convert BGP parse error to FSM event for error handling.
    ///
    /// RFC 4271 Events 21, 22: Different error types trigger different FSM events.
    fn parse_error_to_fsm_event(error: &ParserError) -> FsmEvent {
        if let Some(notif) = NotificationMessage::from_parser_error(error) {
            match notif.error() {
                BgpError::MessageHeaderError(_) => FsmEvent::BgpHeaderErr(notif),
                BgpError::OpenMessageError(_) => FsmEvent::BgpOpenMsgErr(notif),
                _ => FsmEvent::TcpConnectionFails,
            }
        } else {
            FsmEvent::TcpConnectionFails
        }
    }

    /// Handle received message during DelayOpen timer wait.
    ///
    /// Common logic for both Active and Connect states while waiting for DelayOpenTimer.
    /// Handles OPEN, NOTIFICATION, parse errors, and connection failures.
    ///
    /// RFC 4271 Section 8: DelayOpen optional session attribute allows delaying
    /// OPEN message to reduce resource consumption from connection collisions.
    async fn handle_delay_open_message(&mut self, result: Option<Result<Vec<u8>, ParserError>>) {
        match result {
            Some(Ok(bytes)) => match Self::parse_bgp_message(&bytes, PRE_OPEN_FORMAT) {
                Ok(BgpMessage::Open(open)) => {
                    debug!(peer_ip = %self.addr, "OPEN received while DelayOpen running");
                    self.fsm.timers.stop_delay_open_timer();
                    let event = FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
                        peer_asn: open.asn,
                        peer_hold_time: open.hold_time,
                        local_asn: self.local_config.asn,
                        local_hold_time: self.local_config.hold_time,
                        peer_capabilities: PeerCapabilities::default(),
                        peer_bgp_id: open.bgp_identifier,
                    });
                    if let Err(e) = self.process_event(&event).await {
                        error!(peer_ip = %self.addr, error = %e, "failed to send response to OPEN");
                        self.disconnect(true, PeerDownReason::LocalNoNotification(event));
                    }
                }
                Ok(BgpMessage::Notification(notif)) => {
                    self.handle_notification_received(&notif).await;
                }
                Ok(_) => {
                    error!(peer_ip = %self.addr, "unexpected message while waiting for DelayOpen");
                    self.disconnect(true, PeerDownReason::RemoteNoNotification);
                }
                Err(e) => {
                    debug!(peer_ip = %self.addr, error = ?e, "parse error while waiting for DelayOpen");
                    let event = Self::parse_error_to_fsm_event(&e);
                    self.try_process_event(&event).await;
                }
            },
            Some(Err(e)) => {
                // Header validation error from read task
                debug!(peer_ip = %self.addr, error = %e, "connection error while waiting for DelayOpen");
                let event = Self::parse_error_to_fsm_event(&e);
                self.try_process_event(&event).await;
            }
            None => {
                // Read task exited without error - connection failure
                debug!(peer_ip = %self.addr, "read task exited unexpectedly");
                self.try_process_event(&FsmEvent::TcpConnectionFails).await;
            }
        }
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use crate::net::ipv4;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    pub async fn create_test_peer_with_state(state: BgpState) -> Peer {
        // Create a test TCP connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn task to accept connection and drain data
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (mut rx, _tx) = stream.into_split();
                let mut buf = vec![0u8; 4096];
                while rx.read(&mut buf).await.is_ok() {}
            }
        });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (tcp_rx, tcp_tx) = client.into_split();

        // Create dummy channels for testing
        let (server_tx, _server_rx) = mpsc::unbounded_channel();
        let (_peer_tx, peer_rx) = mpsc::unbounded_channel();

        // Create peer directly for testing
        let local_ip = ipv4(127, 0, 0, 1);
        let local_config = LocalConfig {
            asn: 65000,
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
            hold_time: 180,
            addr: SocketAddr::new(local_ip, 0),
            cluster_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
            llgr: None,
        };
        Peer {
            addr: addr.ip(),
            port: addr.port(),
            fsm: Fsm::with_state(state, false),
            conn: Some(TcpConnection::new(tcp_tx, tcp_rx)),
            asn: Some(65001),
            bgp_id: Some(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            session_type: Some(SessionType::Ebgp),
            statistics: PeerStatistics::default(),
            config: PeerConfig::default(),
            peer_rx,
            server_tx,
            local_config,
            connect_retry_secs: 120,
            consecutive_down_count: 0,
            capabilities_suppressed: false,
            conn_type: ConnectionType::Outgoing,
            manually_stopped: false,
            established_at: None,
            mrai_interval: Duration::from_secs(0),
            last_update_sent: None,
            pending_updates: Vec::new(),
            sent_open: None,
            received_open: None,
            capabilities: PeerCapabilities::default(),
            gr_state: None,
            pending_routes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;

    #[tokio::test]
    async fn test_get_idle_hold_time() {
        // (idle_hold_secs, damping, down_count, expected_secs)
        let cases = [
            (Some(30), true, 0, Some(30)),   // No downs -> base
            (Some(30), true, 1, Some(60)),   // 1 down -> 30*2
            (Some(30), true, 2, Some(120)),  // 2 downs -> 30*4, capped at 120
            (Some(30), true, 3, Some(120)),  // 3 downs -> 30*8=240, capped at 120
            (Some(30), false, 5, Some(30)),  // Damping disabled -> base
            (Some(10), true, 1, Some(20)),   // 10*2
            (Some(10), true, 3, Some(80)),   // 10*8
            (Some(10), true, 6, Some(120)),  // 10*64=640, capped at 120
            (Some(10), true, 10, Some(120)), // exp capped at 6 -> 10*64=640, capped at 120
            (None, true, 0, None),           // Disabled -> None
            (None, true, 5, None),           // Disabled with damping -> still None
        ];
        for (idle, damp, count, expected) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Idle).await;
            peer.config.idle_hold_time_secs = idle;
            peer.config.damp_peer_oscillations = damp;
            peer.consecutive_down_count = count;
            assert_eq!(
                peer.get_idle_hold_time(),
                expected.map(Duration::from_secs),
                "idle={:?}, damp={}, count={}",
                idle,
                damp,
                count
            );
        }
    }
}
