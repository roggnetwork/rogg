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

pub(crate) mod config;
pub(crate) mod ops;
pub(crate) mod ops_mgmt;
pub(crate) mod propagate;

use crate::bgp::msg::{AddPathMask, Message, MessageFormat, PRE_OPEN_FORMAT};
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_update::{NextHopAddr, Origin, UpdateMessage};
use crate::bgp::multiprotocol::AfiSafi;
use crate::bmp::destination::{BmpDestination, BmpTcpClient};
use crate::bmp::task::BmpTask;
use crate::log::{error, info, warn};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::net::apply_gtsm;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::net::apply_tcp_md5;
#[cfg(target_os = "freebsd")]
use crate::net::remove_tcp_md5;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::net::set_ttl_max;
use crate::net::{bind_addr_from_ip, peer_ip, IpNetwork};
use crate::peer::BgpState;
use crate::peer::{LocalConfig, Peer, PeerCapabilities, PeerOp, PeerStatistics};
use crate::policy::{AfiSafiPolicies, Policy, PolicyContext};
use crate::rib::rib_in::AdjRibIn;
use crate::rib::rib_loc::{LocRib, LocRibConfig};
use crate::rib::{AdjRibOut, PathAttrs, RouteKey, RouteSource};
use crate::rpki::manager::{RpkiOp, RtrCacheConfig, RtrManager, RtrTransport, SshTransport};
use crate::rpki::vrp::VrpTable;
use crate::types::PeerDownReason;
use conf::bgp::{get_peer_llgr, BgpConfig, BmpConfig, PeerConfig, RpkiCacheConfig, TransportType};
use conf::language_bgp::OriginateRoute;
use ops::ServerOp;
use ops_mgmt::MgmtOp;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// PathAttrs for a configured `originate` entry. Locally-sourced, IGP origin,
/// empty AS_PATH, default local-pref 100. Used by both startup-time
/// initialization and runtime commit.
fn originate_path_attrs(next_hop: NextHopAddr) -> PathAttrs {
    PathAttrs {
        origin: Origin::IGP,
        as_path: vec![],
        next_hop,
        source: RouteSource::Local,
        local_pref: Some(100),
        med: None,
        atomic_aggregate: false,
        aggregator: None,
        communities: vec![],
        extended_communities: vec![],
        large_communities: vec![],
        unknown_attrs: vec![],
        originator_id: None,
        cluster_list: vec![],
        ls_attr: None,
    }
}

/// Parse a CIDR prefix and forwarding next-hop address into runtime types.
pub(crate) fn parse_prefix_and_nexthop(
    prefix_str: &str,
    nh_str: &str,
) -> Result<(IpNetwork, NextHopAddr), String> {
    let prefix = IpNetwork::from_str(prefix_str)
        .map_err(|err| format!("invalid prefix '{}': {}", prefix_str, err))?;
    let nh_addr: IpAddr = nh_str
        .parse()
        .map_err(|_| format!("invalid nexthop '{}'", nh_str))?;
    let next_hop = match nh_addr {
        IpAddr::V4(v4) => NextHopAddr::Ipv4(v4),
        IpAddr::V6(v6) => NextHopAddr::Ipv6(v6),
    };
    Ok((prefix, next_hop))
}

/// Convert RPKI cache transport config to runtime RtrTransport.
fn rpki_cache_to_transport(config: &RpkiCacheConfig) -> Result<RtrTransport, String> {
    match config.transport {
        TransportType::Tcp => Ok(RtrTransport::Tcp),
        TransportType::Ssh => {
            let username = config
                .ssh_username
                .as_ref()
                .ok_or("SSH transport requires ssh-username")?;
            let private_key_file = config
                .ssh_private_key_file
                .as_ref()
                .ok_or("SSH transport requires ssh-private-key-file")?;
            Ok(RtrTransport::Ssh(SshTransport {
                username: username.clone(),
                private_key_file: private_key_file.clone(),
                known_hosts_file: config.ssh_known_hosts_file.clone(),
            }))
        }
    }
}

/// Errors that can occur during server initialization or operation.
#[derive(Debug)]
pub enum ServerError {
    InvalidListenAddr(String),
    BindError(io::Error),
    IoError(io::Error),
    ConfigParse(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::InvalidListenAddr(addr) => write!(f, "Invalid listen address: {}", addr),
            ServerError::BindError(e) => write!(f, "Failed to bind listener: {}", e),
            ServerError::IoError(e) => write!(f, "I/O error: {}", e),
            ServerError::ConfigParse(msg) => write!(f, "Failed to parse rogg.conf: {}", msg),
        }
    }
}

impl std::error::Error for ServerError {}

/// TCP connection initiator for collision detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Incoming,
    Outgoing,
}

/// Administrative state of a peer, controls auto-reconnect behavior.
/// Only reconnect when Up.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum AdminState {
    /// Normal operation, auto-reconnect enabled
    #[default]
    Up,
    /// Manually disabled by admin
    Down,
    /// Disabled due to prefix limit exceeded
    PrefixLimitReached,
}

/// Reset type for peer reset operations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResetType {
    SoftIn,  // Send ROUTE_REFRESH to peer
    SoftOut, // Resend our routes
    Soft,    // Both
    Hard,    // Send CEASE/ADMINISTRATIVE_RESET and reconnect
}

#[derive(Debug, Clone)]
pub struct GetPeersResponse {
    pub address: String,
    pub asn: Option<u32>,
    pub state: BgpState,
    pub admin_state: AdminState,
    pub import_policies: Vec<String>,
    pub export_policies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GetPeerResponse {
    pub address: String,
    pub asn: Option<u32>,
    pub state: BgpState,
    pub admin_state: AdminState,
    pub import_policies: Vec<String>,
    pub export_policies: Vec<String>,
    pub statistics: PeerStatistics,
    pub config: PeerConfig,
}

#[derive(Debug, Clone)]
pub struct BmpPeerStats {
    pub peer_ip: IpAddr,
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    pub adj_rib_in_count: u64,
}

/// Policy direction (import or export)
#[derive(Debug, Clone, Copy)]
pub enum PolicyDirection {
    Import,
    Export,
}

// Re-exported from ops_mgmt where the handler lives

// BMP operations sent from server to BMP sender task
pub enum BmpOp {
    PeerUp {
        peer_ip: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        local_address: IpAddr,
        local_port: u16,
        remote_port: u16,
        sent_open: OpenMessage,
        received_open: OpenMessage,
        use_4byte_asn: bool,
    },
    PeerDown {
        peer_ip: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        reason: PeerDownReason,
        use_4byte_asn: bool,
    },
    RouteMonitoring {
        peer_ip: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        update: UpdateMessage,
    },
}

/// BMP task tracking info (one per BMP destination)
pub struct BmpTaskInfo {
    pub addr: SocketAddr,
    pub statistics_timeout: Option<u64>,
    pub task_tx: mpsc::UnboundedSender<Arc<BmpOp>>,
}

impl BmpTaskInfo {
    pub fn new(
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
        task_tx: mpsc::UnboundedSender<Arc<BmpOp>>,
    ) -> Self {
        Self {
            addr,
            statistics_timeout,
            task_tx,
        }
    }
}

/// Connection info (stored only while peer is Established)
#[derive(Clone)]
pub struct ConnectionInfo {
    pub sent_open: OpenMessage,
    pub received_open: OpenMessage,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    /// Link-local IPv6 address of the local interface (for 32-byte next-hop encoding)
    pub local_link_local: Option<Ipv6Addr>,
}

/// Connection-specific state.
/// Direction is determined by which slot (outgoing/incoming) contains this state.
#[derive(Default)]
pub struct ConnectionState {
    pub peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
    pub state: BgpState,
    pub asn: Option<u32>,
    pub bgp_id: Option<u32>,
    pub conn_info: Option<ConnectionInfo>,
    pub capabilities: Option<PeerCapabilities>,
}

impl ConnectionState {
    pub fn new(peer_tx: Option<mpsc::UnboundedSender<PeerOp>>) -> Self {
        Self {
            peer_tx,
            state: BgpState::Idle,
            asn: None,
            bgp_id: None,
            conn_info: None,
            capabilities: None,
        }
    }

    pub fn supports_four_octet_asn(&self) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.supports_four_octet_asn())
    }

    pub fn has_enhanced_route_refresh(&self) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.enhanced_route_refresh)
    }

    pub fn add_path_send_negotiated(&self, afi_safi: &AfiSafi) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.add_path_send_negotiated(afi_safi))
    }

    pub fn add_path_receive_negotiated(&self, afi_safi: &AfiSafi) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.add_path_receive_negotiated(afi_safi))
    }

    pub fn add_path_receive(&self) -> bool {
        self.capabilities
            .as_ref()
            .is_some_and(|caps| caps.add_path_receive())
    }

    /// Returns the negotiated multiprotocol AFI/SAFIs, or empty set if none negotiated.
    /// An empty set signals IPv4/Unicast-only fallback (RFC 4760).
    pub fn negotiated_afi_safis(&self) -> HashSet<AfiSafi> {
        self.capabilities
            .as_ref()
            .map(|caps| caps.multiprotocol.clone())
            .unwrap_or_default()
    }

    /// MessageFormat for encoding outgoing messages to this peer
    pub fn send_format(&self) -> MessageFormat {
        self.capabilities
            .as_ref()
            .map(|caps| caps.send_format(None))
            .unwrap_or(PRE_OPEN_FORMAT)
    }

    /// MessageFormat for parsing incoming messages from this peer
    pub fn receive_format(&self) -> MessageFormat {
        self.capabilities
            .as_ref()
            .map(|caps| caps.receive_format(None))
            .unwrap_or(PRE_OPEN_FORMAT)
    }
}

/// Peer configuration and state stored in server's HashMap.
/// The peer IP is the HashMap key.
///
/// Connection slots: Direction is determined by which slot a connection occupies
/// (outgoing vs incoming), not by a conn_type field.
pub struct PeerInfo {
    pub admin_state: AdminState,
    /// Resolved import policies. Populated from `BgpConfig.peers[ip].afi_safis`
    /// at handshake.
    pub import_policies: AfiSafiPolicies,
    /// Resolved export policies. Populated from `BgpConfig.peers[ip].afi_safis`
    /// at handshake.
    pub export_policies: AfiSafiPolicies,
    /// Outgoing connection slot (we initiated)
    pub outgoing: Option<ConnectionState>,
    /// Incoming connection slot (peer initiated)
    pub incoming: Option<ConnectionState>,
    /// Per-peer adj-rib-in: routes received from this peer before import policy.
    pub adj_rib_in: AdjRibIn,
    /// Per-peer adj-rib-out: tracks routes actually exported to this peer.
    pub adj_rib_out: AdjRibOut,
    /// AFI/SAFIs disabled due to non-negotiated UPDATE (RFC 4760 Section 7)
    pub disabled_afi_safi: HashSet<AfiSafi>,
    /// RFC 9494: Running LLGR stale timers per AFI/SAFI
    pub llgr_timers: ServerOpTimers<AfiSafi>,
    /// RFC 7313: Running enhanced route refresh stale timers per AFI/SAFI
    pub rr_stale_timers: ServerOpTimers<AfiSafi>,
}

/// Keyed timer map. Each key has at most one running timer that sends a
/// ServerOp on expiry. Used for LLGR (RFC 9494) and enhanced RR (RFC 7313).
pub struct ServerOpTimers<K: Eq + Hash + Copy> {
    timers: HashMap<K, JoinHandle<()>>,
}

impl<K: Eq + Hash + Copy> Default for ServerOpTimers<K> {
    fn default() -> Self {
        Self {
            timers: HashMap::new(),
        }
    }
}

impl<K: Eq + Hash + Copy> ServerOpTimers<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a timer that sends `op` after `duration_secs`.
    /// Cancels any existing timer for the same key first.
    pub fn run(
        &mut self,
        key: K,
        duration_secs: u64,
        op: ServerOp,
        server_tx: mpsc::UnboundedSender<ServerOp>,
    ) {
        self.cancel(&key);
        self.timers.insert(
            key,
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(duration_secs)).await;
                let _ = server_tx.send(op);
            }),
        );
    }

    /// Cancel a running timer. No-op if not running.
    pub fn cancel(&mut self, key: &K) {
        if let Some(handle) = self.timers.remove(key) {
            handle.abort();
        }
    }

    /// Cancel all running timers.
    pub fn cancel_all(&mut self) {
        for (_, handle) in self.timers.drain() {
            handle.abort();
        }
    }

    /// Keys with running timers.
    pub fn keys(&self) -> Vec<K> {
        self.timers.keys().copied().collect()
    }
}

impl PeerInfo {
    pub fn new(
        admin_down: bool,
        peer_tx: Option<mpsc::UnboundedSender<PeerOp>>,
        conn_type: Option<ConnectionType>,
    ) -> Self {
        let conn_state = ConnectionState::new(peer_tx);
        let (outgoing, incoming) = match conn_type {
            Some(ConnectionType::Outgoing) => (Some(conn_state), None),
            Some(ConnectionType::Incoming) => (None, Some(conn_state)),
            None => (None, None),
        };
        let admin_state = if admin_down {
            AdminState::Down
        } else {
            AdminState::Up
        };
        Self {
            admin_state,
            import_policies: HashMap::new(),
            export_policies: HashMap::new(),
            outgoing,
            incoming,
            adj_rib_in: AdjRibIn::new(),
            adj_rib_out: AdjRibOut::new(),
            disabled_afi_safi: HashSet::new(),
            llgr_timers: ServerOpTimers::new(),
            rr_stale_timers: ServerOpTimers::new(),
        }
    }

    /// Get the established connection (only one can be Established)
    pub fn established_conn(&self) -> Option<&ConnectionState> {
        [self.outgoing.as_ref(), self.incoming.as_ref()]
            .into_iter()
            .flatten()
            .find(|c| c.state == BgpState::Established)
    }

    /// Get mutable reference to the established connection
    pub fn established_conn_mut(&mut self) -> Option<&mut ConnectionState> {
        [self.outgoing.as_mut(), self.incoming.as_mut()]
            .into_iter()
            .flatten()
            .find(|c| c.state == BgpState::Established)
    }

    /// Get reference to slot by connection type
    pub fn slot(&self, conn_type: ConnectionType) -> Option<&ConnectionState> {
        match conn_type {
            ConnectionType::Outgoing => self.outgoing.as_ref(),
            ConnectionType::Incoming => self.incoming.as_ref(),
        }
    }

    /// Get mutable reference to slot by connection type
    pub fn slot_mut(&mut self, conn_type: ConnectionType) -> &mut Option<ConnectionState> {
        match conn_type {
            ConnectionType::Outgoing => &mut self.outgoing,
            ConnectionType::Incoming => &mut self.incoming,
        }
    }

    /// Get connection state. Returns the most-progressed connection during collision.
    pub fn max_state(&self) -> (Option<u32>, BgpState) {
        // Prefer established
        if let Some(conn) = self.established_conn() {
            return (conn.asn, conn.state);
        }
        // Pick most-progressed during collision
        [self.outgoing.as_ref(), self.incoming.as_ref()]
            .into_iter()
            .flatten()
            .max_by_key(|c| c.state as u8)
            .map(|c| (c.asn, c.state))
            .unwrap_or((None, BgpState::Idle))
    }

    /// Send operation to all active peer tasks (both incoming and outgoing slots)
    pub fn send_to_all(&self, mut make_op: impl FnMut() -> PeerOp) {
        for conn in [&self.outgoing, &self.incoming].into_iter().flatten() {
            if let Some(peer_tx) = &conn.peer_tx {
                let _ = peer_tx.send(make_op());
            }
        }
    }

    /// Find any connection with a peer_tx (for handing off incoming connections)
    pub fn any_peer_tx(&self) -> Option<&mpsc::UnboundedSender<PeerOp>> {
        // Check outgoing first (passive mode typically has outgoing task waiting)
        self.outgoing
            .as_ref()
            .and_then(|c| c.peer_tx.as_ref())
            .or_else(|| self.incoming.as_ref().and_then(|c| c.peer_tx.as_ref()))
    }

    pub async fn get_statistics(&self) -> Option<PeerStatistics> {
        let peer_tx = self.established_conn()?.peer_tx.as_ref()?;
        let (tx, rx) = oneshot::channel();
        peer_tx.send(PeerOp::GetStatistics(tx)).ok()?;
        rx.await.ok()
    }

    /// Import policies attached to the given family. Empty if no entry.
    pub fn policy_in_for(&self, family: AfiSafi) -> &[Arc<Policy>] {
        self.import_policies
            .get(&family)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Export policies attached to the given family. Empty if no entry.
    pub fn policy_out_for(&self, family: AfiSafi) -> &[Arc<Policy>] {
        self.export_policies
            .get(&family)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn supports_4byte_asn(&self) -> bool {
        self.established_conn()
            .and_then(|c| c.capabilities.as_ref())
            .map(|caps| caps.supports_four_octet_asn())
            .unwrap_or(true)
    }

    pub fn add_path_receive_mask(&self) -> AddPathMask {
        self.established_conn()
            .map(|conn| conn.receive_format().add_path)
            .unwrap_or(AddPathMask::NONE)
    }
}

pub struct BgpServer {
    pub(crate) peers: HashMap<IpAddr, PeerInfo>,
    pub(crate) loc_rib: LocRib,
    pub config: BgpConfig,
    pub(crate) policy_ctx: PolicyContext,
    local_bgp_id: u32,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
    pub mgmt_tx: mpsc::Sender<MgmtOp>,
    mgmt_rx: mpsc::Receiver<MgmtOp>,
    pub(crate) op_tx: mpsc::UnboundedSender<ServerOp>,
    op_rx: mpsc::UnboundedReceiver<ServerOp>,
    pub(crate) bmp_tasks: HashMap<SocketAddr, BmpTaskInfo>,
    /// Channel to send operations to the RtrManager (RPKI).
    pub(crate) rpki_tx: Option<mpsc::UnboundedSender<RpkiOp>>,
    /// RPKI VRP table for origin validation (RFC 6811).
    pub(crate) vrp_table: VrpTable,
    /// Raw fd of the listener socket, stored for TCP MD5 setup on new peers
    pub(crate) listener_fd: Option<i32>,
    /// Path to rogg.conf. Commits write here.
    pub(crate) config_path: PathBuf,
}

impl BgpServer {
    /// Read and parse `rogg.conf` from `config_path`, then construct the server.
    /// `config_path` is the single source of truth -- the daemon owns the read,
    /// not the caller.
    pub fn new(config_path: PathBuf) -> Result<Self, ServerError> {
        let config = BgpConfig::from_conf_file(&config_path)
            .map_err(|e| ServerError::ConfigParse(e.to_string()))?;
        let local_bgp_id = u32::from(config.router_id);
        let sock_addr: SocketAddr = config
            .listen_addr
            .parse()
            .map_err(|_| ServerError::InvalidListenAddr(config.listen_addr.clone()))?;
        let local_addr = sock_addr.ip();

        let (mgmt_tx, mgmt_rx) = mpsc::channel(100);
        let (op_tx, op_rx) = mpsc::unbounded_channel();

        let policy_ctx = PolicyContext::from_config(&config)
            .map_err(|e| ServerError::IoError(io::Error::new(io::ErrorKind::InvalidData, e)))?;

        Ok(BgpServer {
            peers: HashMap::new(),
            loc_rib: LocRib::new(LocRibConfig {
                max_ls_entries: config.bgp_ls.max_ls_entries,
            }),
            config,
            policy_ctx,
            local_bgp_id,
            local_addr,
            local_port: sock_addr.port(),
            mgmt_tx,
            mgmt_rx,
            op_tx,
            op_rx,
            bmp_tasks: HashMap::new(),
            rpki_tx: None,
            vrp_table: VrpTable::new(),
            listener_fd: None,
            config_path,
        })
    }

    /// Resolve policies for a peer: user-configured first, then session-type fallback.
    /// RFC 8212: eBGP peers get reject-all fallback, iBGP peers get accept-all.
    pub(crate) fn resolve_policies(
        &self,
        policy_names: &[String],
        is_ebgp: bool,
    ) -> Vec<Arc<Policy>> {
        let mut policies = Vec::new();

        for name in policy_names {
            if let Some(policy) = self.policy_ctx.policies.get(name).cloned() {
                policies.push(policy);
            } else {
                error!(policy = name, "policy not found");
            }
        }

        let fallback = if is_ebgp {
            Policy::deny_all()
        } else {
            Policy::permit_all()
        };
        policies.push(Arc::new(fallback));

        policies
    }

    /// Check if a peer should be accepted (must be pre-configured).
    fn should_accept_peer(&self, peer_ip: IpAddr) -> bool {
        self.peers.contains_key(&peer_ip)
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    fn setup_listener_tcp_md5(&mut self, listener: &TcpListener) {
        let fd = listener.as_raw_fd();
        self.listener_fd = Some(fd);
        for peer_cfg in &self.config.peers {
            let Ok(addr) = peer_cfg.socket_addr() else {
                continue;
            };
            if let Some(key) = peer_cfg.read_md5_key() {
                if let Err(e) = apply_tcp_md5(fd, addr.ip(), &key) {
                    error!(peer = %addr, error = %e, "failed to set TCP MD5 on listener");
                }
            }
        }
    }

    pub async fn run(mut self) -> Result<(), ServerError> {
        info!(listen_addr = %self.config.listen_addr, "BGP server starting");

        let listener = TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(ServerError::BindError)?;
        self.local_port = listener.local_addr().map_err(ServerError::IoError)?.port();

        // Set outgoing TTL=255 on the listener so SYN-ACKs are sent with TTL=255.
        // Remote peers that enforce GTSM by setting IP_MINTTL before connect() will
        // otherwise drop our SYN-ACK (which arrives with the OS default TTL of 64).
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        if let Err(e) = set_ttl_max(listener.as_raw_fd(), self.local_addr) {
            warn!(error = %e, "failed to set TTL=255 on listener");
        }

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        self.setup_listener_tcp_md5(&listener);

        let bind_addr = bind_addr_from_ip(self.local_addr);
        self.init_configured_peers(bind_addr);
        self.init_configured_bmp_servers();
        self.init_configured_rpki_caches();
        self.init_configured_originate_routes();

        loop {
            tokio::select! {
                // Handle incoming BGP connections
                Ok((stream, _)) = listener.accept() => {
                    self.accept_peer(stream).await;
                }

                // Handle management requests
                Some(req) = self.mgmt_rx.recv() => {
                    self.handle_mgmt_op(req, bind_addr).await;
                }

                // Handle server operations from peers
                Some(op) = self.op_rx.recv() => {
                    self.handle_server_op(op).await;
                }
            }
        }
    }

    /// Initialize configured peers from `self.config.peers` and spawn their
    /// tasks. Per-peer config stays in `self.config.peers` for the lifetime
    /// of the server; `PeerInfo` only carries runtime state.
    fn init_configured_peers(&mut self, bind_addr: SocketAddr) {
        let peer_specs: Vec<PeerConfig> = self.config.peers.clone();
        for peer_cfg in peer_specs {
            let Ok(peer_addr) = peer_cfg.socket_addr() else {
                error!(addr = %peer_cfg.address, "invalid peer address in config");
                continue;
            };
            let peer_ip = peer_addr.ip();
            let passive = peer_cfg.passive_mode;
            let admin_down = peer_cfg.admin_down;
            let allow_auto_start = peer_cfg.allow_automatic_start();

            // Passive mode peers only accept incoming connections
            let conn_type = if passive {
                ConnectionType::Incoming
            } else {
                ConnectionType::Outgoing
            };

            let peer_tx = self.spawn_peer(peer_addr, peer_cfg, bind_addr, conn_type);

            // Create peer with connection in the appropriate slot
            let mut entry = PeerInfo::new(admin_down, None, None);
            let conn_state = ConnectionState::new(Some(peer_tx.clone()));
            match conn_type {
                ConnectionType::Outgoing => entry.outgoing = Some(conn_state),
                ConnectionType::Incoming => entry.incoming = Some(conn_state),
            }
            self.peers.insert(peer_ip, entry);

            // RFC 4271: AutomaticStart for configured peers (if allowed and not admin-down)
            if allow_auto_start && !admin_down {
                if passive {
                    let _ = peer_tx.send(PeerOp::AutomaticStartPassive);
                } else {
                    let _ = peer_tx.send(PeerOp::AutomaticStart);
                }
            }
            info!(%peer_ip, passive, admin_down, "configured peer");
        }
    }

    /// Diff `self.config.peers` (the running peer set) vs `new.peers` and
    /// apply: spawn added, drop removed, restart modified. Called by
    /// `commit_config` BEFORE `self.config` is replaced with `new`.
    pub(crate) async fn reconfigure_peers(&mut self, new: &BgpConfig, bind_addr: SocketAddr) {
        let old_ips: Vec<IpAddr> = self
            .config
            .peers
            .iter()
            .filter_map(|cfg| cfg.ip())
            .collect();
        let new_ips: HashSet<IpAddr> = new.peers.iter().filter_map(|cfg| cfg.ip()).collect();

        for ip in &old_ips {
            if !new_ips.contains(ip) {
                self.shutdown_and_remove_peer(*ip).await;
            }
        }

        for new_cfg in &new.peers {
            let Some(ip) = new_cfg.ip() else {
                continue;
            };
            match self.config.find_peer(ip) {
                None => self.spawn_and_start_peer(ip, new_cfg.clone(), bind_addr),
                Some(old_cfg) if old_cfg != new_cfg => {
                    info!(%ip, "peer config changed -- restarting session");
                    self.shutdown_and_remove_peer(ip).await;
                    self.spawn_and_start_peer(ip, new_cfg.clone(), bind_addr);
                }
                Some(_) => {}
            }
        }
    }

    fn init_configured_bmp_servers(&mut self) {
        for bmp_cfg in &self.config.bmp_servers.clone() {
            let Ok(addr) = bmp_cfg.address.parse::<SocketAddr>() else {
                error!(addr = %bmp_cfg.address, "invalid BMP server address in config");
                continue;
            };

            let task_tx = self.spawn_bmp_task(addr, bmp_cfg.statistics_timeout);
            let task_info = BmpTaskInfo::new(addr, bmp_cfg.statistics_timeout, task_tx);
            self.bmp_tasks.insert(addr, task_info);

            info!(%addr, "configured BMP server");
        }
    }

    /// Diff `old.bmp_servers` vs `new.bmp_servers` by address; spawn added,
    /// drop removed, restart on statistics-timeout change. Called by
    /// `commit_config`.
    pub(crate) async fn reconfigure_bmp_servers(
        &mut self,
        old: &BgpConfig,
        new: &BgpConfig,
    ) -> Result<(), String> {
        let mut new_by_addr: HashMap<SocketAddr, &BmpConfig> = HashMap::new();
        for cfg in &new.bmp_servers {
            let addr = cfg
                .address
                .parse::<SocketAddr>()
                .map_err(|e| format!("invalid BMP server address '{}': {}", cfg.address, e))?;
            new_by_addr.insert(addr, cfg);
        }
        let old_by_addr: HashMap<SocketAddr, &BmpConfig> = old
            .bmp_servers
            .iter()
            .filter_map(|c| c.address.parse::<SocketAddr>().ok().map(|a| (a, c)))
            .collect();

        for addr in old_by_addr.keys() {
            if !new_by_addr.contains_key(addr) {
                self.stop_single_bmp_task(*addr);
            }
        }

        for (addr, cfg) in &new_by_addr {
            let stats = cfg.statistics_timeout;
            let needs_spawn = match old_by_addr.get(addr) {
                None => true,
                Some(old_cfg) => old_cfg.statistics_timeout != stats,
            };
            if !needs_spawn {
                continue;
            }
            self.spawn_single_bmp_task(*addr, stats);
        }
        Ok(())
    }

    /// Spawn (or restart) a BMP task for `addr` with the given statistics
    /// timeout. Sends the established-peer initial state once spawned so the
    /// remote sees existing peers immediately. Used by both
    /// `reconfigure_bmp_servers` and `handle_add_bmp_server`.
    pub(crate) fn spawn_single_bmp_task(
        &mut self,
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
    ) {
        if let Some(task_info) = self.bmp_tasks.remove(&addr) {
            drop(task_info.task_tx);
        }
        let task_tx = self.spawn_bmp_task(addr, statistics_timeout);
        self.bmp_tasks
            .insert(addr, BmpTaskInfo::new(addr, statistics_timeout, task_tx));
        info!(%addr, "BMP task spawned");
        let established = self.get_established_peers();
        if let Some(info_ref) = self.bmp_tasks.get(&addr) {
            ops_mgmt::send_initial_bmp_state(&info_ref.task_tx, established);
        }
    }

    /// Drop the BMP task for `addr` if running. Idempotent.
    pub(crate) fn stop_single_bmp_task(&mut self, addr: SocketAddr) {
        if let Some(task_info) = self.bmp_tasks.remove(&addr) {
            drop(task_info.task_tx);
            info!(%addr, "BMP task stopped");
        }
    }

    /// Diff `old.rpki_caches` vs `new.rpki_caches` by address. Spawns the RTR
    /// manager on first addition; sends `AddCache`/`RemoveCache` for deltas.
    pub(crate) async fn reconfigure_rpki_caches(
        &mut self,
        old: &BgpConfig,
        new: &BgpConfig,
    ) -> Result<(), String> {
        let mut new_by_addr: HashMap<SocketAddr, &RpkiCacheConfig> = HashMap::new();
        for cfg in &new.rpki_caches {
            let addr = cfg
                .address
                .parse::<SocketAddr>()
                .map_err(|e| format!("invalid RPKI cache address '{}': {}", cfg.address, e))?;
            rpki_cache_to_transport(cfg)?;
            new_by_addr.insert(addr, cfg);
        }
        let old_by_addr: HashMap<SocketAddr, &RpkiCacheConfig> = old
            .rpki_caches
            .iter()
            .filter_map(|c| c.address.parse::<SocketAddr>().ok().map(|a| (a, c)))
            .collect();

        if new_by_addr.is_empty() && old_by_addr.is_empty() {
            return Ok(());
        }

        for addr in old_by_addr.keys() {
            if !new_by_addr.contains_key(addr) {
                self.stop_single_rpki_cache(*addr)?;
            }
        }

        for (addr, cfg) in &new_by_addr {
            if old_by_addr.contains_key(addr) {
                continue;
            }
            self.spawn_single_rpki_cache(cfg)?;
            let _ = addr;
        }
        Ok(())
    }

    /// Send `AddCache` to the RTR manager for `cfg`, spawning the manager if
    /// it isn't running yet. Used by both `reconfigure_rpki_caches` and
    /// `handle_add_rpki_cache`.
    pub(crate) fn spawn_single_rpki_cache(&mut self, cfg: &RpkiCacheConfig) -> Result<(), String> {
        let addr: SocketAddr = cfg
            .address
            .parse()
            .map_err(|e| format!("invalid RPKI cache address '{}': {}", cfg.address, e))?;
        let transport = rpki_cache_to_transport(cfg)?;
        let rpki_tx = match &self.rpki_tx {
            Some(tx) => tx.clone(),
            None => self.spawn_rtr_manager(),
        };
        let cache_config = RtrCacheConfig {
            address: addr,
            preference: cfg.preference,
            transport,
            retry_interval: cfg.retry_interval,
            refresh_interval: cfg.refresh_interval,
            expire_interval: cfg.expire_interval,
        };
        if rpki_tx.send(RpkiOp::AddCache(cache_config)).is_err() {
            return Err("RPKI manager not running".to_string());
        }
        info!(%addr, "RPKI cache added");
        Ok(())
    }

    /// Send `RemoveCache` to the RTR manager. Returns Err if the manager isn't
    /// running.
    pub(crate) fn stop_single_rpki_cache(&mut self, addr: SocketAddr) -> Result<(), String> {
        let Some(rpki_tx) = &self.rpki_tx else {
            return Err("RPKI manager not running".to_string());
        };
        if rpki_tx.send(RpkiOp::RemoveCache(addr)).is_err() {
            return Err("RPKI manager not running".to_string());
        }
        info!(%addr, "RPKI cache removed");
        Ok(())
    }

    fn init_configured_rpki_caches(&mut self) {
        if self.config.rpki_caches.is_empty() {
            return;
        }

        let rpki_tx = self.spawn_rtr_manager();

        for rpki_cfg in &self.config.rpki_caches.clone() {
            let Ok(addr) = rpki_cfg.address.parse::<SocketAddr>() else {
                error!(addr = %rpki_cfg.address, "invalid RPKI cache address in config");
                continue;
            };

            let transport = match rpki_cache_to_transport(rpki_cfg) {
                Ok(transport) => transport,
                Err(err) => {
                    error!(%addr, %err, "invalid RPKI cache transport config");
                    continue;
                }
            };

            let cache_config = RtrCacheConfig {
                address: addr,
                preference: rpki_cfg.preference,
                transport,
                retry_interval: rpki_cfg.retry_interval,
                refresh_interval: rpki_cfg.refresh_interval,
                expire_interval: rpki_cfg.expire_interval,
            };
            let _ = rpki_tx.send(RpkiOp::AddCache(cache_config));
            info!(%addr, "configured RPKI cache");
        }
    }

    fn init_configured_originate_routes(&mut self) {
        let routes = self.config.originate.clone();
        for entry in &routes {
            let (prefix, next_hop) = match parse_prefix_and_nexthop(&entry.prefix, &entry.nexthop) {
                Ok(parsed) => parsed,
                Err(err) => {
                    warn!(prefix = %entry.prefix, nexthop = %entry.nexthop, %err,
                              "skipping invalid originate entry");
                    continue;
                }
            };
            match self
                .loc_rib
                .add_local_route(RouteKey::Prefix(prefix), originate_path_attrs(next_hop))
            {
                Ok(_) => info!(prefix = %entry.prefix, nexthop = %entry.nexthop,
                               "originated static route"),
                Err(err) => warn!(prefix = %entry.prefix, ?err,
                                  "loc-rib rejected static originate entry"),
            }
        }
    }

    /// Diff `old.originate` vs `new.originate` and apply the change to the
    /// loc-RIB plus propagate. Called by `commit_config` after originate
    /// entries have been pre-validated. A changed nexthop counts as
    /// remove + add. Same prefix+nexthop is a no-op.
    pub(crate) async fn reconfigure_originate_routes(&mut self, old: &BgpConfig, new: &BgpConfig) {
        let new_by_prefix: HashMap<&str, &OriginateRoute> = new
            .originate
            .iter()
            .map(|entry| (entry.prefix.as_str(), entry))
            .collect();
        let old_by_prefix: HashMap<&str, &OriginateRoute> = old
            .originate
            .iter()
            .map(|entry| (entry.prefix.as_str(), entry))
            .collect();

        for entry in &old.originate {
            let needs_remove = match new_by_prefix.get(entry.prefix.as_str()) {
                Some(new_entry) => new_entry.nexthop != entry.nexthop,
                None => true,
            };
            if !needs_remove {
                continue;
            }
            let prefix = match parse_prefix_and_nexthop(&entry.prefix, &entry.nexthop) {
                Ok((prefix, _)) => prefix,
                Err(err) => {
                    warn!(prefix = %entry.prefix, nexthop = %entry.nexthop, %err,
                          "skipping originate removal: invalid entry");
                    continue;
                }
            };
            let delta = self.loc_rib.remove_local_route(&RouteKey::Prefix(prefix));
            self.propagate_routes(delta, None).await;
            info!(prefix = %entry.prefix, "withdrew configured originate");
        }

        for entry in &new.originate {
            let needs_add = match old_by_prefix.get(entry.prefix.as_str()) {
                Some(old_entry) => old_entry.nexthop != entry.nexthop,
                None => true,
            };
            if !needs_add {
                continue;
            }
            let (prefix, next_hop) = match parse_prefix_and_nexthop(&entry.prefix, &entry.nexthop) {
                Ok(parsed) => parsed,
                Err(err) => {
                    warn!(prefix = %entry.prefix, nexthop = %entry.nexthop, %err,
                          "skipping originate add: invalid entry (should have been caught at validate)");
                    continue;
                }
            };
            match self
                .loc_rib
                .add_local_route(RouteKey::Prefix(prefix), originate_path_attrs(next_hop))
            {
                Ok(delta) => {
                    self.propagate_routes(delta, None).await;
                    info!(prefix = %entry.prefix, nexthop = %entry.nexthop,
                          "originated configured route");
                }
                Err(err) => {
                    warn!(prefix = %entry.prefix, ?err,
                          "loc-rib rejected configured originate");
                }
            }
        }
    }

    fn spawn_rtr_manager(&mut self) -> mpsc::UnboundedSender<RpkiOp> {
        let (rpki_tx, rpki_rx) = mpsc::unbounded_channel();
        let manager = RtrManager::new(rpki_rx, self.op_tx.clone());

        tokio::spawn(async move {
            manager.run().await;
        });

        self.rpki_tx = Some(rpki_tx.clone());
        rpki_tx
    }

    /// Spawn a new Peer task in Idle state
    pub(crate) fn spawn_peer(
        &self,
        addr: SocketAddr,
        config: PeerConfig,
        bind_addr: SocketAddr,
        conn_type: ConnectionType,
    ) -> mpsc::UnboundedSender<PeerOp> {
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();

        let llgr = get_peer_llgr(&self.config.llgr, &config.llgr);
        let local_config = LocalConfig {
            asn: self.config.asn,
            bgp_id: Ipv4Addr::from(self.local_bgp_id.to_be_bytes()),
            hold_time: self.config.hold_time_secs as u16,
            addr: bind_addr,
            cluster_id: self.config.cluster_id(),
            llgr,
        };
        let peer = Peer::new(
            addr.ip(),
            addr.port(),
            peer_rx,
            self.op_tx.clone(),
            local_config,
            config,
            self.config.connect_retry_secs,
            conn_type,
        );

        tokio::spawn(async move {
            peer.run().await;
        });

        peer_tx
    }

    /// Spawn a peer task and start it. Honors `config.admin_down`: the task is
    /// spawned but no Start op is sent.
    pub(crate) fn spawn_and_start_peer(
        &mut self,
        peer_ip: IpAddr,
        config: PeerConfig,
        bind_addr: SocketAddr,
    ) {
        let peer_addr = SocketAddr::new(peer_ip, config.port);

        let conn_type = if config.passive_mode {
            ConnectionType::Incoming
        } else {
            ConnectionType::Outgoing
        };

        let peer_tx = self.spawn_peer(peer_addr, config.clone(), bind_addr, conn_type);

        self.peers.insert(
            peer_ip,
            PeerInfo::new(config.admin_down, Some(peer_tx.clone()), Some(conn_type)),
        );

        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        if let (Some(fd), Some(key)) = (self.listener_fd, config.read_md5_key()) {
            if let Err(e) = apply_tcp_md5(fd, peer_ip, &key) {
                error!(peer = %peer_ip, error = %e, "failed to set TCP MD5 on listener for new peer");
            }
        }

        if !config.admin_down {
            if config.passive_mode {
                let _ = peer_tx.send(PeerOp::ManualStartPassive);
            } else {
                let _ = peer_tx.send(PeerOp::ManualStart);
            }
        }

        info!(%peer_ip, passive = config.passive_mode, admin_down = config.admin_down, total_peers = self.peers.len(), "peer added");
    }

    /// Tear down a peer session and drop it.
    pub(crate) async fn shutdown_and_remove_peer(&mut self, peer_ip: IpAddr) {
        let Some(entry) = self.peers.get(&peer_ip) else {
            return;
        };

        entry.send_to_all(|| PeerOp::Shutdown(CeaseSubcode::PeerDeconfigured));

        if let Some(conn) = entry.established_conn() {
            if let (Some(asn), Some(bgp_id)) = (conn.asn, conn.bgp_id) {
                let use_4byte_asn = entry.supports_4byte_asn();
                self.broadcast_bmp(BmpOp::PeerDown {
                    peer_ip,
                    peer_as: asn,
                    peer_bgp_id: bgp_id,
                    reason: PeerDownReason::PeerDeConfigured,
                    use_4byte_asn,
                });
            }
        }

        #[cfg(target_os = "freebsd")]
        if let (Some(fd), Some(cfg)) = (self.listener_fd, self.config.find_peer(peer_ip)) {
            if cfg.md5_key_file.is_some() {
                if let Err(e) = remove_tcp_md5(fd, peer_ip) {
                    error!(peer = %peer_ip, error = %e, "failed to remove TCP MD5 from listener");
                }
            }
        }

        if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
            peer_info.llgr_timers.cancel_all();
            peer_info.rr_stale_timers.cancel_all();
        }

        self.peers.remove(&peer_ip);

        let delta = self.loc_rib.remove_routes_from_peer(peer_ip);
        self.propagate_routes(delta, None).await;

        info!(%peer_ip, "peer removed");
    }

    async fn accept_peer(&mut self, stream: TcpStream) {
        let Some(peer_ip) = peer_ip(&stream) else {
            error!("failed to get peer address");
            return;
        };

        info!(%peer_ip, "new peer connection");

        if !self.should_accept_peer(peer_ip) {
            info!(%peer_ip, "rejecting unconfigured peer");
            Self::send_rejection(stream);
            return;
        }

        // RFC 4271 6.8: Collision detection handled at OpenConfirm via check_collision()
        self.accept_incoming_connection(stream, peer_ip);
        info!(%peer_ip, state = "Idle", total_peers = self.peers.len(), "peer added");
    }

    /// Accept an incoming TCP connection for a configured peer.
    /// RFC 4271 6.8: If peer already has an active outgoing connection, this becomes
    /// a collision candidate in the incoming slot.
    /// Caller must ensure peer is pre-configured (via should_accept_peer check).
    pub(crate) fn accept_incoming_connection(&mut self, stream: TcpStream, peer_ip: IpAddr) {
        let Some(peer_cfg) = self.config.find_peer(peer_ip).cloned() else {
            // This should not happen - should_accept_peer should have rejected
            error!(%peer_ip, "accept_incoming_connection called for unconfigured peer");
            return;
        };
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            error!(%peer_ip, "accept_incoming_connection: PeerInfo missing");
            return;
        };

        // Apply GTSM on the accepted socket if configured
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        if let Some(min_ttl) = peer_cfg.ttl_min {
            if let Err(e) = apply_gtsm(stream.as_raw_fd(), peer_ip, min_ttl) {
                warn!(%peer_ip, error = %e, "failed to apply GTSM on incoming connection");
            }
        }

        // Passive mode with existing task: send connection to existing task
        if peer_cfg.passive_mode {
            if let Some(peer_tx) = peer
                .slot(ConnectionType::Incoming)
                .and_then(|c| c.peer_tx.as_ref())
            {
                let (tcp_rx, tcp_tx) = stream.into_split();
                let _ = peer_tx.send(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx });
                info!(%peer_ip, "sent incoming connection to passive peer");
                return;
            }
        }

        // Already have an incoming connection - reject third connection
        if peer.incoming.is_some() {
            info!(%peer_ip, "rejecting: incoming slot already occupied");
            Self::send_rejection(stream);
            return;
        }

        // Check if outgoing is Established with GR capability
        let outgoing_established = peer
            .outgoing
            .as_ref()
            .is_some_and(|out| out.state == BgpState::Established);
        let outgoing_has_gr = peer
            .outgoing
            .as_ref()
            .and_then(|out| out.capabilities.as_ref())
            .and_then(|caps| caps.graceful_restart.as_ref())
            .is_some_and(|gr| !gr.afi_safi_list.is_empty());

        // Handle Established outgoing connection
        if outgoing_established {
            if outgoing_has_gr {
                // RFC 4724: New connection from restarting peer - trigger GR
                info!(%peer_ip, "GR reconnection: closing stale Established, accepting new");
                if let Some(peer_tx) = peer.outgoing.as_ref().and_then(|out| out.peer_tx.clone()) {
                    let _ = peer_tx.send(PeerOp::ManualStop);
                }
                peer.outgoing = None;
            } else {
                info!(%peer_ip, "rejecting: outgoing already Established (no GR)");
                Self::send_rejection(stream);
                return;
            }
        }

        // Spawn incoming connection - let check_collision() decide winner
        let (peer_tx, peer_rx) = mpsc::unbounded_channel();
        peer.incoming = Some(ConnectionState::new(Some(peer_tx.clone())));
        self.spawn_incoming_with_stream(peer_rx, &peer_tx, stream, peer_ip, peer_cfg);
        info!(%peer_ip, "spawned incoming connection");
    }

    /// Send rejection notification in background task.
    /// Non-blocking to avoid stalling the server's event loop on socket writes.
    fn send_rejection(mut stream: TcpStream) {
        tokio::spawn(async move {
            let notif =
                NotificationMessage::new(BgpError::Cease(CeaseSubcode::ConnectionRejected), vec![]);
            let _ = stream.write_all(&notif.serialize()).await;
        });
    }

    /// Spawn incoming peer task with pre-created channel.
    ///
    /// Caller must set up the incoming slot with peer_tx BEFORE calling this,
    /// to avoid race where task sends PeerStateChanged before slot exists.
    fn spawn_incoming_with_stream(
        &self,
        peer_rx: mpsc::UnboundedReceiver<PeerOp>,
        peer_tx: &mpsc::UnboundedSender<PeerOp>,
        stream: TcpStream,
        peer_ip: IpAddr,
        config: PeerConfig,
    ) {
        // Use port 0 (ephemeral) so this peer can make outgoing connections if needed
        // (e.g., after collision resolution or hard reset when passive_mode=false).
        // Using stream.local_addr() would give us the server's listening port, which
        // would cause EADDRINUSE when trying to reconnect.
        let local_addr = bind_addr_from_ip(
            stream
                .local_addr()
                .map(|a| a.ip())
                .unwrap_or(self.local_addr),
        );

        let (tcp_rx, tcp_tx) = stream.into_split();

        let llgr = get_peer_llgr(&self.config.llgr, &config.llgr);
        let local_config = LocalConfig {
            asn: self.config.asn,
            bgp_id: Ipv4Addr::from(self.local_bgp_id.to_be_bytes()),
            hold_time: self.config.hold_time_secs as u16,
            addr: local_addr,
            cluster_id: self.config.cluster_id(),
            llgr,
        };
        let peer = Peer::new(
            peer_ip,
            config.port,
            peer_rx,
            self.op_tx.clone(),
            local_config,
            config.clone(),
            self.config.connect_retry_secs,
            ConnectionType::Incoming,
        );

        tokio::spawn(async move {
            peer.run().await;
        });

        // RFC 4271 8.2.2: Send start event only if AllowAutomaticStart is true
        // If false, FSM stays in Idle and will refuse the connection per RFC 4271 8.2.2
        if config.allow_automatic_start() {
            if config.passive_mode {
                let _ = peer_tx.send(PeerOp::AutomaticStartPassive);
            } else {
                let _ = peer_tx.send(PeerOp::AutomaticStart);
            }
        }

        // Always send TCP connection - let FSM decide what to do with it
        let _ = peer_tx.send(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx });
    }

    /// Spawn a BMP task for a destination
    pub(crate) fn spawn_bmp_task(
        &self,
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
    ) -> mpsc::UnboundedSender<Arc<BmpOp>> {
        let (task_tx, task_rx) = mpsc::unbounded_channel();

        let destination = BmpDestination::TcpClient(BmpTcpClient::new(addr));

        let task = BmpTask::new(
            addr,
            destination,
            task_rx,
            self.op_tx.clone(),
            statistics_timeout,
        );

        let sys_name = self.config.sys_name();
        let sys_descr = self.config.sys_descr();

        tokio::spawn(async move {
            task.run(sys_name, sys_descr).await;
        });

        task_tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Policy, DEFAULT_DENY_ALL, DEFAULT_PERMIT_ALL};
    use conf::testutil::TempDir;
    use std::net::Ipv4Addr;

    fn peer_info() -> PeerInfo {
        PeerInfo::new(false, None, None)
    }

    /// Returns the server plus the TempDir guard. The caller must keep the
    /// guard alive for the test's lifetime; dropping it removes rogg.conf.
    fn make_server() -> (BgpServer, TempDir) {
        let config = BgpConfig::new(65000, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 180);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rogg.conf");
        std::fs::write(&path, config.to_conf_str()).unwrap();
        let server = BgpServer::new(path).expect("valid config");
        (server, dir)
    }

    #[test]
    fn test_should_accept_peer() {
        let peer_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Unconfigured peer -> reject
        let (server, _dir) = make_server();
        assert!(!server.should_accept_peer(peer_ip));

        // Configured peer -> accept
        let (mut server, _dir) = make_server();
        server.peers.insert(peer_ip, peer_info());
        assert!(server.should_accept_peer(peer_ip));
    }

    #[test]
    fn test_resolve_policies() {
        struct TestCase {
            desc: &'static str,
            user_policies: Vec<&'static str>,
            is_ebgp: bool,
            expected_names: Vec<&'static str>,
        }

        let cases = vec![
            TestCase {
                desc: "eBGP with user policy -> user first, reject-all fallback",
                user_policies: vec!["my-export"],
                is_ebgp: true,
                expected_names: vec!["my-export", DEFAULT_DENY_ALL],
            },
            TestCase {
                desc: "eBGP no user policy -> reject-all only (RFC 8212)",
                user_policies: vec![],
                is_ebgp: true,
                expected_names: vec![DEFAULT_DENY_ALL],
            },
            TestCase {
                desc: "iBGP with user policy -> user first, accept-all fallback",
                user_policies: vec!["my-import"],
                is_ebgp: false,
                expected_names: vec!["my-import", DEFAULT_PERMIT_ALL],
            },
            TestCase {
                desc: "iBGP no user policy -> accept-all only",
                user_policies: vec![],
                is_ebgp: false,
                expected_names: vec![DEFAULT_PERMIT_ALL],
            },
        ];

        for tc in cases {
            let (mut server, _dir) = make_server();

            for name in &tc.user_policies {
                server
                    .policy_ctx
                    .policies
                    .insert(name.to_string(), Arc::new(Policy::new(name.to_string())));
            }

            let policy_names: Vec<String> =
                tc.user_policies.iter().map(|n| n.to_string()).collect();
            let resolved = server.resolve_policies(&policy_names, tc.is_ebgp);
            let names: Vec<&str> = resolved.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, tc.expected_names, "failed: {}", tc.desc);
        }
    }

    #[test]
    fn test_has_enhanced_route_refresh() {
        // No capabilities -> false
        let conn = ConnectionState::new(None);
        assert!(!conn.has_enhanced_route_refresh());

        // Capabilities without enhanced RR -> false
        let mut conn = ConnectionState::new(None);
        conn.capabilities = Some(PeerCapabilities::default());
        assert!(!conn.has_enhanced_route_refresh());

        // Capabilities with enhanced RR -> true
        let mut conn = ConnectionState::new(None);
        conn.capabilities = Some(PeerCapabilities {
            enhanced_route_refresh: true,
            ..PeerCapabilities::default()
        });
        assert!(conn.has_enhanced_route_refresh());
    }
}
