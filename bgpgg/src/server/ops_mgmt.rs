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

use super::config::{commit_config, save_config};
use super::{
    AdminState, BgpServer, BmpOp, BmpPeerStats, GetPeerResponse, GetPeersResponse, PeerInfo,
    PolicyDirection, ResetType,
};
use crate::bgp::msg_route_refresh::RouteRefreshSubtype;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::log::info;
use crate::net::IpNetwork;
use crate::peer::PeerOp;
use crate::policy::sets::{
    AsPathSet, CommunitySet, ExtCommunitySet, LargeCommunitySet, NeighborSet, PrefixMatch,
    PrefixSet,
};
use crate::policy::{DefinedSetType, Policy};
use crate::rib::{PathAttrs, Route, RouteKey};
use conf::bgp::{
    afi_safi_entry_mut, AsPathSetConfig, BgpConfig, BmpConfig, CommunitySetConfig,
    DefinedSetConfig, NeighborSetConfig, PeerConfig, PolicyDefinitionConfig, PrefixMatchConfig,
    PrefixSetConfig, RpkiCacheConfig, StatementConfig,
};

use conf::fs::{list_snapshots, load_snapshot, SnapshotInfo, SNAPSHOT_COUNT};
use regex::Regex;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use crate::grpc::proto::RibType;
use crate::rpki::manager::{RpkiCacheState, RpkiOp};
use crate::rpki::vrp::{RpkiValidation, Vrp};

/// Map a DefinedSetConfig to its DefinedSetType.
fn defined_set_type(set: &DefinedSetConfig) -> DefinedSetType {
    match set {
        DefinedSetConfig::PrefixSet(_) => DefinedSetType::PrefixSet,
        DefinedSetConfig::NeighborSet(_) => DefinedSetType::NeighborSet,
        DefinedSetConfig::AsPathSet(_) => DefinedSetType::AsPathSet,
        DefinedSetConfig::CommunitySet(_) => DefinedSetType::CommunitySet,
        DefinedSetConfig::ExtCommunitySet(_) => DefinedSetType::ExtCommunitySet,
        DefinedSetConfig::LargeCommunitySet(_) => DefinedSetType::LargeCommunitySet,
    }
}

// Management operations that can be sent to the BGP server
pub enum MgmtOp {
    AddPeer {
        addr: String,
        config: PeerConfig,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemovePeer {
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    DisablePeer {
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    EnablePeer {
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    ResetPeer {
        addr: String,
        reset_type: ResetType,
        afi: Option<Afi>,
        safi: Option<Safi>,
        response: oneshot::Sender<Result<(), String>>,
    },
    AddRoute {
        key: Box<RouteKey>,
        attrs: Box<PathAttrs>,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemoveRoute {
        key: Box<RouteKey>,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetPeers {
        response: oneshot::Sender<Vec<GetPeersResponse>>,
    },
    GetPeer {
        addr: String,
        response: oneshot::Sender<Option<GetPeerResponse>>,
    },
    GetRoutes {
        rib_type: Option<i32>,
        peer_address: Option<String>,
        afi: Option<u32>,
        safi: Option<u32>,
        response: oneshot::Sender<Result<Vec<Route>, String>>,
    },
    GetRoutesStream {
        rib_type: Option<i32>,
        peer_address: Option<String>,
        afi: Option<u32>,
        safi: Option<u32>,
        tx: mpsc::UnboundedSender<Route>,
    },
    GetPeersStream {
        tx: mpsc::UnboundedSender<GetPeersResponse>,
    },
    GetServerInfo {
        response: oneshot::Sender<(IpAddr, u16, u64)>,
    },
    AddBmpServer {
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemoveBmpServer {
        addr: SocketAddr,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetBmpServers {
        response: oneshot::Sender<Vec<String>>,
    },
    // Policy Management
    AddDefinedSet {
        set: DefinedSetConfig,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemoveDefinedSet {
        set_type: DefinedSetType,
        name: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    ListDefinedSets {
        set_type: Option<DefinedSetType>,
        name: Option<String>,
        response: oneshot::Sender<Vec<DefinedSetConfig>>,
    },
    AddPolicy {
        name: String,
        statements: Vec<StatementConfig>,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemovePolicy {
        name: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    ListPolicies {
        name: Option<String>,
        response: oneshot::Sender<Vec<PolicyInfoResponse>>,
    },
    SetPolicyAssignment {
        peer_addr: IpAddr,
        family: AfiSafi,
        direction: PolicyDirection,
        policy_names: Vec<String>,
        default_action: Option<crate::policy::PolicyResult>,
        response: oneshot::Sender<Result<(), String>>,
    },
    SetPeerGracefulShutdown {
        addr: String,
        enabled: bool,
        response: oneshot::Sender<Result<(), String>>,
    },
    // RPKI Cache Management
    AddRpkiCache {
        config: RpkiCacheConfig,
        response: oneshot::Sender<Result<(), String>>,
    },
    RemoveRpkiCache {
        addr: SocketAddr,
        response: oneshot::Sender<Result<(), String>>,
    },
    GetRpkiCaches {
        response: oneshot::Sender<(Vec<RpkiCacheState>, usize)>,
    },
    GetRpkiValidation {
        prefix: IpNetwork,
        origin_as: u32,
        response: oneshot::Sender<(RpkiValidation, Vec<Vrp>)>,
    },
    // Config-mode management (ggsh configure/commit flow).
    GetRunningConfig {
        response: oneshot::Sender<String>,
    },
    /// Apply the candidate config text supplied by the caller.
    /// `session_uuid` must match the per-session UUID written by the
    /// operator (ggsh) into `<config>.lock` on `configure`.
    CommitConfig {
        text: String,
        session_uuid: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Persist the daemon's current `self.config` to `rogg.conf`.
    /// `CommitConfig` already persists; this exists for callers that
    /// mutated state via AddPeer/etc. and want the result on disk.
    SaveConfig {
        session_uuid: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Load `rogg.<index>.conf`, parse, commit it. The rollback itself
    /// becomes a new commit (forward history preserved). Same
    /// `session_uuid` rule.
    RollbackConfig {
        index: u32,
        session_uuid: String,
        response: oneshot::Sender<Result<(), String>>,
    },
    /// Return metadata for each stored snapshot that currently exists.
    ListConfigSnapshots {
        response: oneshot::Sender<Vec<SnapshotInfo>>,
    },
}

#[derive(Debug, Clone)]
pub struct PolicyInfoResponse {
    pub name: String,
    pub statements: Vec<StatementConfig>,
}

impl BgpServer {
    pub(crate) async fn handle_mgmt_op(&mut self, req: MgmtOp, bind_addr: SocketAddr) {
        match req {
            MgmtOp::AddPeer {
                addr,
                config,
                response,
            } => {
                self.handle_add_peer(addr, config, response, bind_addr)
                    .await;
            }
            MgmtOp::RemovePeer { addr, response } => {
                self.handle_remove_peer(addr, response, bind_addr).await;
            }
            MgmtOp::DisablePeer { addr, response } => {
                self.handle_disable_peer(addr, response);
            }
            MgmtOp::EnablePeer { addr, response } => {
                self.handle_enable_peer(addr, response);
            }
            MgmtOp::ResetPeer {
                addr,
                reset_type,
                afi,
                safi,
                response,
            } => {
                self.handle_reset_peer(addr, reset_type, afi, safi, response)
                    .await;
            }
            MgmtOp::AddRoute {
                key,
                attrs,
                response,
            } => {
                self.handle_add_route(*key, *attrs, response).await;
            }
            MgmtOp::RemoveRoute { key, response } => {
                self.handle_remove_route(*key, response).await;
            }
            MgmtOp::GetPeers { response } => {
                self.handle_get_peers(response);
            }
            MgmtOp::GetPeer { addr, response } => {
                self.handle_get_peer(addr, response).await;
            }
            MgmtOp::GetRoutes {
                rib_type,
                peer_address,
                afi,
                safi,
                response,
            } => {
                self.handle_get_routes(rib_type, peer_address, afi, safi, response)
                    .await;
            }
            MgmtOp::GetRoutesStream {
                rib_type,
                peer_address,
                afi,
                safi,
                tx,
            } => {
                self.handle_get_routes_stream(rib_type, peer_address, afi, safi, tx)
                    .await;
            }
            MgmtOp::GetPeersStream { tx } => {
                self.handle_get_peers_stream(tx);
            }
            MgmtOp::GetServerInfo { response } => {
                let num_routes = self.loc_rib.routes_len() as u64;
                let _ = response.send((self.local_addr, self.local_port, num_routes));
            }
            MgmtOp::AddBmpServer {
                addr,
                statistics_timeout,
                response,
            } => {
                self.handle_add_bmp_server(addr, statistics_timeout, response, bind_addr)
                    .await;
            }
            MgmtOp::RemoveBmpServer { addr, response } => {
                self.handle_remove_bmp_server(addr, response, bind_addr)
                    .await;
            }
            MgmtOp::GetBmpServers { response } => {
                self.handle_get_bmp_servers(response);
            }
            MgmtOp::AddDefinedSet { set, response } => {
                self.handle_add_defined_set(set, response);
            }
            MgmtOp::RemoveDefinedSet {
                set_type,
                name,
                response,
            } => {
                self.handle_remove_defined_set(set_type, name, response);
            }
            MgmtOp::ListDefinedSets {
                set_type,
                name,
                response,
            } => {
                self.handle_list_defined_sets(set_type, name, response);
            }
            MgmtOp::AddPolicy {
                name,
                statements,
                response,
            } => {
                self.handle_add_policy(name, statements, response);
            }
            MgmtOp::RemovePolicy { name, response } => {
                self.handle_remove_policy(name, response);
            }
            MgmtOp::ListPolicies { name, response } => {
                self.handle_list_policies(name, response);
            }
            MgmtOp::SetPolicyAssignment {
                peer_addr,
                family,
                direction,
                policy_names,
                default_action,
                response,
            } => {
                self.handle_set_policy_assignment(
                    peer_addr,
                    family,
                    direction,
                    policy_names,
                    default_action,
                    response,
                );
            }
            MgmtOp::SetPeerGracefulShutdown {
                addr,
                enabled,
                response,
            } => {
                self.handle_set_peer_graceful_shutdown(addr, enabled, response);
            }
            MgmtOp::AddRpkiCache { config, response } => {
                self.handle_add_rpki_cache(config, response, bind_addr)
                    .await;
            }
            MgmtOp::RemoveRpkiCache { addr, response } => {
                self.handle_remove_rpki_cache(addr, response, bind_addr)
                    .await;
            }
            MgmtOp::GetRpkiCaches { response } => {
                self.handle_get_rpki_caches(response).await;
            }
            MgmtOp::GetRpkiValidation {
                prefix,
                origin_as,
                response,
            } => {
                self.handle_get_rpki_validation(prefix, origin_as, response);
            }
            MgmtOp::GetRunningConfig { response } => {
                let _ = response.send(self.config.to_conf_str());
            }
            MgmtOp::CommitConfig {
                text,
                session_uuid,
                response,
            } => {
                self.handle_commit_config(text, session_uuid, response, bind_addr)
                    .await;
            }
            MgmtOp::SaveConfig {
                session_uuid,
                response,
            } => {
                let _ = response.send(self.handle_save_config(&session_uuid));
            }
            MgmtOp::RollbackConfig {
                index,
                session_uuid,
                response,
            } => {
                self.handle_rollback_config(index, session_uuid, response, bind_addr)
                    .await;
            }
            MgmtOp::ListConfigSnapshots { response } => {
                let _ = response.send(list_snapshots(&self.config_path, SNAPSHOT_COUNT));
            }
        }
    }

    fn verify_session_uuid(&self, session_uuid: &str) -> Result<(), String> {
        let parsed = uuid::Uuid::parse_str(session_uuid)
            .map_err(|_| "session_uuid is not a valid UUID".to_string())?;
        match conf::fs::read_session_uuid(&self.config_path) {
            Ok(Some(file_uuid)) => {
                if file_uuid == parsed {
                    Ok(())
                } else {
                    Err("session UUID mismatch".into())
                }
            }
            Ok(None) => Err("no active configure session (lock file missing or empty)".into()),
            Err(e) => Err(format!("failed to read session UUID: {}", e)),
        }
    }

    fn handle_save_config(&self, session_uuid: &str) -> Result<(), String> {
        self.verify_session_uuid(session_uuid)?;
        save_config(self)
    }

    /// Load `rogg.<index>.conf` from disk, parse it, run `commit_config`.
    /// The rollback itself goes through the normal snapshot-rotate flow — the
    /// current `rogg.conf` becomes the new `rogg.1.conf`, so a subsequent
    /// rollback can recover from a bad rollback.
    async fn handle_rollback_config(
        &mut self,
        index: u32,
        session_uuid: String,
        response: oneshot::Sender<Result<(), String>>,
        bind_addr: SocketAddr,
    ) {
        if let Err(e) = self.verify_session_uuid(&session_uuid) {
            let _ = response.send(Err(e));
            return;
        }
        let text = match load_snapshot(&self.config_path, index) {
            Ok(text) => text,
            Err(e) => {
                let _ = response.send(Err(format!("failed to read snapshot {}: {}", index, e)));
                return;
            }
        };
        let new_config = match BgpConfig::from_conf_str(&text) {
            Ok(cfg) => cfg,
            Err(e) => {
                let _ = response.send(Err(format!("failed to parse snapshot {}: {}", index, e)));
                return;
            }
        };
        let _ = response.send(commit_config(self, new_config, bind_addr).await);
    }

    async fn handle_commit_config(
        &mut self,
        text: String,
        session_uuid: String,
        response: oneshot::Sender<Result<(), String>>,
        bind_addr: SocketAddr,
    ) {
        if let Err(e) = self.verify_session_uuid(&session_uuid) {
            let _ = response.send(Err(e));
            return;
        }
        let new_config = match BgpConfig::from_conf_str(&text) {
            Ok(cfg) => cfg,
            Err(e) => {
                let _ = response.send(Err(format!("failed to parse candidate config: {}", e)));
                return;
            }
        };
        let _ = response.send(commit_config(self, new_config, bind_addr).await);
    }

    async fn handle_add_peer(
        &mut self,
        addr: String,
        mut config: PeerConfig,
        response: oneshot::Sender<Result<(), String>>,
        bind_addr: SocketAddr,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        info!(peer_addr = %addr, "adding peer via request");

        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        if self.peers.contains_key(&peer_ip) {
            let _ = response.send(Err(format!("peer {} already exists", peer_ip)));
            return;
        }

        config.address = addr;
        if let Err(e) = config.validate() {
            let _ = response.send(Err(e));
            return;
        }

        self.config.peers.push(config.clone());
        self.spawn_and_start_peer(peer_ip, config, bind_addr);
        let _ = response.send(Ok(()));
    }

    async fn handle_remove_peer(
        &mut self,
        addr: String,
        response: oneshot::Sender<Result<(), String>>,
        _bind_addr: SocketAddr,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        info!(peer_ip = %addr, "removing peer via request");

        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        if !self.peers.contains_key(&peer_ip) {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        }

        self.shutdown_and_remove_peer(peer_ip).await;
        self.config.remove_peer(peer_ip);
        let _ = response.send(Ok(()));
    }

    fn handle_disable_peer(&mut self, addr: String, response: oneshot::Sender<Result<(), String>>) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        let Some(entry) = self.peers.get_mut(&peer_ip) else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        };

        entry.admin_state = AdminState::Down;
        entry.send_to_all(|| PeerOp::ManualStop);

        if let Some(cfg) = self.config.find_peer_mut(peer_ip) {
            cfg.admin_down = true;
        }

        let _ = response.send(Ok(()));
    }

    fn handle_enable_peer(&mut self, addr: String, response: oneshot::Sender<Result<(), String>>) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        let passive = self
            .config
            .find_peer(peer_ip)
            .is_some_and(|cfg| cfg.passive_mode);

        let Some(entry) = self.peers.get_mut(&peer_ip) else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        };

        entry.admin_state = AdminState::Up;
        // RFC 4271: ManualStart for admin-enabled peers (send to all tasks)
        entry.send_to_all(|| {
            if passive {
                PeerOp::ManualStartPassive
            } else {
                PeerOp::ManualStart
            }
        });

        if let Some(cfg) = self.config.find_peer_mut(peer_ip) {
            cfg.admin_down = false;
        }

        let _ = response.send(Ok(()));
    }

    async fn handle_reset_peer(
        &mut self,
        addr: String,
        reset_type: ResetType,
        afi: Option<Afi>,
        safi: Option<Safi>,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        let Some(entry) = self.peers.get(&peer_ip) else {
            let _ = response.send(Err(format!("peer {} not found", addr)));
            return;
        };

        // Only allow soft reset on Established peers
        if entry.established_conn().is_none() {
            let _ = response.send(Err(format!("peer {} not in Established state", addr)));
            return;
        }

        // Query negotiated capabilities
        let negotiated = match self.get_negotiated_capabilities(entry).await {
            Ok(caps) => caps,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };

        // Determine which AFI/SAFIs to reset based on parameters
        let afi_safis: Vec<AfiSafi> = match (afi, safi) {
            // Both specified: validate it's negotiated
            (Some(afi), Some(safi)) => {
                let requested = AfiSafi::new(afi, safi);
                if !negotiated.contains(&requested) {
                    let _ = response.send(Err(format!(
                        "AFI/SAFI {:?}/{:?} not negotiated with peer {}",
                        afi, safi, addr
                    )));
                    return;
                }
                vec![requested]
            }

            // Any parameter unset: filter negotiated capabilities
            _ => negotiated
                .into_iter()
                .filter(|cap| {
                    afi.is_none_or(|a| cap.afi == a) && safi.is_none_or(|s| cap.safi == s)
                })
                .collect(),
        };

        match reset_type {
            ResetType::SoftIn => {
                self.handle_reset_soft_in(peer_ip, &afi_safis, Some(response));
            }
            ResetType::SoftOut => {
                self.handle_reset_soft_out(peer_ip, &afi_safis, response);
            }
            ResetType::Soft => {
                self.handle_reset_soft_in(peer_ip, &afi_safis, None);
                self.handle_reset_soft_out(peer_ip, &afi_safis, response);
            }
            ResetType::Hard => {
                self.handle_reset_hard(peer_ip, response);
            }
        }
    }

    fn handle_reset_hard(
        &mut self,
        peer_ip: IpAddr,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let Some(peer) = self.peers.get(&peer_ip) else {
            let _ = response.send(Err(format!("peer {} not found", peer_ip)));
            return;
        };

        // Hard reset only applies to the established connection
        let Some(conn) = peer.established_conn() else {
            let _ = response.send(Err(format!("peer {} has no active task", peer_ip)));
            return;
        };

        let Some(peer_tx) = &conn.peer_tx else {
            let _ = response.send(Err(format!("peer {} has no active task", peer_ip)));
            return;
        };

        if peer_tx.send(PeerOp::HardReset).is_err() {
            let _ = response.send(Err(format!(
                "failed to send hard reset to peer {}",
                peer_ip
            )));
            return;
        }

        info!(%peer_ip, "hard reset initiated");
        let _ = response.send(Ok(()));
    }

    fn handle_reset_soft_in(
        &mut self,
        peer_ip: IpAddr,
        afi_safis: &[AfiSafi],
        response: Option<oneshot::Sender<Result<(), String>>>,
    ) {
        if let Some(peer_tx) = self
            .peers
            .get(&peer_ip)
            .and_then(|p| p.established_conn())
            .and_then(|c| c.peer_tx.as_ref())
        {
            for afi_safi in afi_safis {
                let _ = peer_tx.send(PeerOp::SendRouteRefresh {
                    afi: afi_safi.afi,
                    safi: afi_safi.safi,
                    subtype: RouteRefreshSubtype::Normal,
                });
            }
        }
        if let Some(resp) = response {
            let _ = resp.send(Ok(()));
        }
    }

    fn handle_reset_soft_out(
        &mut self,
        peer_ip: IpAddr,
        afi_safis: &[AfiSafi],
        response: oneshot::Sender<Result<(), String>>,
    ) {
        for afi_safi in afi_safis {
            self.resend_routes_to_peer(peer_ip, afi_safi.afi, afi_safi.safi);
        }
        let _ = response.send(Ok(()));
    }

    /// Helper to query negotiated capabilities from peer
    async fn get_negotiated_capabilities(
        &self,
        peer_info: &PeerInfo,
    ) -> Result<Vec<AfiSafi>, String> {
        let conn = peer_info
            .established_conn()
            .ok_or_else(|| "peer not established".to_string())?;
        let peer_tx = conn
            .peer_tx
            .as_ref()
            .ok_or_else(|| "peer task not available".to_string())?;

        let (tx, rx) = oneshot::channel();
        peer_tx
            .send(PeerOp::GetNegotiatedCapabilities(tx))
            .map_err(|_| "failed to query peer capabilities".to_string())?;

        let caps = rx
            .await
            .map_err(|_| "failed to get peer capabilities".to_string())?;

        if caps.multiprotocol.is_empty() {
            Err("no negotiated capabilities".to_string())
        } else {
            Ok(caps.multiprotocol.into_iter().collect())
        }
    }

    fn handle_set_peer_graceful_shutdown(
        &mut self,
        addr: String,
        enabled: bool,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(e) => {
                let _ = response.send(Err(format!("invalid peer address: {}", e)));
                return;
            }
        };

        if !self.peers.contains_key(&peer_ip) {
            let _ = response.send(Err(format!("peer not found: {}", addr)));
            return;
        }

        // Collect afi_safis before mutating so we avoid double-borrow.
        let afi_safis: Vec<AfiSafi> = self
            .peers
            .get(&peer_ip)
            .and_then(|p| p.established_conn())
            .map(|conn| conn.negotiated_afi_safis().into_iter().collect())
            .unwrap_or_default();

        if let Some(cfg) = self.config.find_peer_mut(peer_ip) {
            cfg.graceful_shutdown = enabled;
        }
        info!(%peer_ip, enabled, "set graceful_shutdown");

        // Resend all routes so the updated community list is propagated.
        // Same pattern as handle_reset_soft_out.
        for afi_safi in afi_safis {
            self.resend_routes_to_peer(peer_ip, afi_safi.afi, afi_safi.safi);
        }

        let _ = response.send(Ok(()));
    }

    async fn handle_add_route(
        &mut self,
        mut key: RouteKey,
        attrs: PathAttrs,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        // RFC 9552 Section 8.2.3: apply configured Instance-ID to locally originated LS NLRIs.
        let instance_id = self.config.bgp_ls.instance_id;
        if let RouteKey::LinkState(ref mut nlri) = key {
            nlri.set_identifier(instance_id);
        }

        info!(?key, next_hop = ?attrs.next_hop, "adding route via request");

        match self.loc_rib.add_local_route(key, attrs) {
            Ok(delta) => {
                self.propagate_routes(delta, None).await;
                let _ = response.send(Ok(()));
            }
            Err(err) => {
                let _ = response.send(Err(format!("{err:?}")));
            }
        }
    }

    async fn handle_remove_route(
        &mut self,
        key: RouteKey,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        info!(?key, "removing route via request");

        let delta = self.loc_rib.remove_local_route(&key);
        self.propagate_routes(delta, None).await;

        let _ = response.send(Ok(()));
    }

    fn handle_get_peers(&self, response: oneshot::Sender<Vec<GetPeersResponse>>) {
        let peers: Vec<GetPeersResponse> = self
            .peers
            .iter()
            .map(|(addr, entry)| {
                let (asn, state) = entry.max_state();
                let cfg = self.config.find_peer(*addr);
                GetPeersResponse {
                    address: addr.to_string(),
                    asn: asn.or_else(|| cfg.and_then(|c| c.asn)),
                    state,
                    admin_state: entry.admin_state,
                    import_policies: cfg.map(|c| c.import_policy_names()).unwrap_or_default(),
                    export_policies: cfg.map(|c| c.export_policy_names()).unwrap_or_default(),
                }
            })
            .collect();
        let _ = response.send(peers);
    }

    async fn handle_get_peer(
        &self,
        addr: String,
        response: oneshot::Sender<Option<GetPeerResponse>>,
    ) {
        let peer_ip: IpAddr = match addr.parse() {
            Ok(ip) => ip,
            Err(_) => {
                let _ = response.send(None);
                return;
            }
        };

        let Some(entry) = self.peers.get(&peer_ip) else {
            let _ = response.send(None);
            return;
        };
        let Some(cfg) = self.config.find_peer(peer_ip) else {
            let _ = response.send(None);
            return;
        };

        let mut stats = entry.get_statistics().await.unwrap_or_default();
        stats.adj_rib_in_count = entry.adj_rib_in.prefix_count() as u64;
        let (asn, state) = entry.max_state();

        let _ = response.send(Some(GetPeerResponse {
            address: addr,
            asn: asn.or(cfg.asn),
            state,
            admin_state: entry.admin_state,
            import_policies: cfg.import_policy_names(),
            export_policies: cfg.export_policy_names(),
            statistics: stats,
            config: cfg.clone(),
        }));
    }

    async fn handle_get_routes(
        &self,
        rib_type: Option<i32>,
        peer_address: Option<String>,
        afi: Option<u32>,
        safi: Option<u32>,
        response: oneshot::Sender<Result<Vec<Route>, String>>,
    ) {
        let rib_type_enum = match rib_type {
            Some(t) => RibType::try_from(t).unwrap_or(RibType::Global),
            None => RibType::Global,
        };

        let afi_safi = AfiSafi::from_raw(afi, safi);
        let result = match rib_type_enum {
            RibType::Global => Ok(self
                .loc_rib
                .get_routes(afi_safi)
                .into_iter()
                .cloned()
                .collect()),
            RibType::AdjIn => self.get_adj_rib_in(peer_address, afi_safi),
            RibType::AdjOut => self.get_adj_rib_out(peer_address, afi_safi),
        };

        let _ = response.send(result);
    }

    async fn handle_get_routes_stream(
        &self,
        rib_type: Option<i32>,
        peer_address: Option<String>,
        afi: Option<u32>,
        safi: Option<u32>,
        tx: mpsc::UnboundedSender<Route>,
    ) {
        let rib_type_enum = match rib_type {
            Some(t) => RibType::try_from(t).unwrap_or(RibType::Global),
            None => RibType::Global,
        };

        let afi_safi = AfiSafi::from_raw(afi, safi);
        let routes = match rib_type_enum {
            RibType::Global => Ok(self
                .loc_rib
                .get_routes(afi_safi)
                .into_iter()
                .cloned()
                .collect()),
            RibType::AdjIn => self.get_adj_rib_in(peer_address, afi_safi),
            RibType::AdjOut => self.get_adj_rib_out(peer_address, afi_safi),
        };

        if let Ok(routes) = routes {
            for route in routes {
                if tx.send(route).is_err() {
                    break;
                }
            }
        }
    }

    fn handle_get_peers_stream(&self, tx: mpsc::UnboundedSender<GetPeersResponse>) {
        for (addr, entry) in self.peers.iter() {
            let (asn, state) = entry.max_state();
            let cfg = self.config.find_peer(*addr);
            let peer = GetPeersResponse {
                address: addr.to_string(),
                asn: asn.or_else(|| cfg.and_then(|c| c.asn)),
                state,
                admin_state: entry.admin_state,
                import_policies: cfg.map(|c| c.import_policy_names()).unwrap_or_default(),
                export_policies: cfg.map(|c| c.export_policy_names()).unwrap_or_default(),
            };
            if tx.send(peer).is_err() {
                break;
            }
        }
    }

    async fn handle_add_bmp_server(
        &mut self,
        addr: SocketAddr,
        statistics_timeout: Option<u64>,
        response: oneshot::Sender<Result<(), String>>,
        _bind_addr: SocketAddr,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        if self.bmp_tasks.contains_key(&addr) {
            let _ = response.send(Err(format!("BMP server {} already exists", addr)));
            return;
        }
        self.config.bmp_servers.push(BmpConfig {
            address: addr.to_string(),
            statistics_timeout,
        });
        self.spawn_single_bmp_task(addr, statistics_timeout);
        let _ = response.send(Ok(()));
    }

    async fn handle_remove_bmp_server(
        &mut self,
        addr: SocketAddr,
        response: oneshot::Sender<Result<(), String>>,
        _bind_addr: SocketAddr,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        if !self.bmp_tasks.contains_key(&addr) {
            let _ = response.send(Err(format!("BMP server not found: {}", addr)));
            return;
        }
        self.config
            .bmp_servers
            .retain(|c| c.address.parse::<SocketAddr>().ok() != Some(addr));
        self.stop_single_bmp_task(addr);
        let _ = response.send(Ok(()));
    }

    fn handle_get_bmp_servers(&self, response: oneshot::Sender<Vec<String>>) {
        let addrs: Vec<String> = self.bmp_tasks.keys().map(|a| a.to_string()).collect();
        let _ = response.send(addrs);
    }

    pub(super) fn handle_get_bmp_statistics(&self, response: oneshot::Sender<Vec<BmpPeerStats>>) {
        let mut stats = Vec::new();

        for (peer_ip, peer_info) in self.get_established_peers() {
            let Some(conn) = peer_info.established_conn() else {
                continue;
            };
            let Some(asn) = conn.asn else {
                continue;
            };
            let Some(bgp_id) = conn.bgp_id else {
                continue;
            };

            stats.push(BmpPeerStats {
                peer_ip,
                peer_as: asn,
                peer_bgp_id: bgp_id,
                adj_rib_in_count: peer_info.adj_rib_in.prefix_count() as u64,
            });
        }

        let _ = response.send(stats);
    }

    async fn handle_add_rpki_cache(
        &mut self,
        config: RpkiCacheConfig,
        response: oneshot::Sender<Result<(), String>>,
        _bind_addr: SocketAddr,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        let addr: SocketAddr = match config.address.parse() {
            Ok(a) => a,
            Err(e) => {
                let _ = response.send(Err(format!(
                    "invalid RPKI cache address '{}': {}",
                    config.address, e
                )));
                return;
            }
        };
        if self
            .config
            .rpki_caches
            .iter()
            .any(|c| c.address.parse::<SocketAddr>().ok() == Some(addr))
        {
            let _ = response.send(Err(format!("RPKI cache {} already exists", addr)));
            return;
        }
        if let Err(e) = self.spawn_single_rpki_cache(&config) {
            let _ = response.send(Err(e));
            return;
        }
        self.config.rpki_caches.push(config);
        let _ = response.send(Ok(()));
    }

    async fn handle_remove_rpki_cache(
        &mut self,
        addr: SocketAddr,
        response: oneshot::Sender<Result<(), String>>,
        _bind_addr: SocketAddr,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        let before = self.config.rpki_caches.len();
        self.config
            .rpki_caches
            .retain(|c| c.address.parse::<SocketAddr>().ok() != Some(addr));
        if self.config.rpki_caches.len() == before {
            let _ = response.send(Err(format!("RPKI cache {} not found", addr)));
            return;
        }
        if let Err(e) = self.stop_single_rpki_cache(addr) {
            let _ = response.send(Err(e));
            return;
        }
        let _ = response.send(Ok(()));
    }

    async fn handle_get_rpki_caches(
        &self,
        response: oneshot::Sender<(Vec<RpkiCacheState>, usize)>,
    ) {
        let vrp_table_len = self.vrp_table.len();

        let Some(rpki_tx) = &self.rpki_tx else {
            let _ = response.send((vec![], vrp_table_len));
            return;
        };

        let (state_tx, state_rx) = oneshot::channel();
        if rpki_tx
            .send(RpkiOp::GetState { response: state_tx })
            .is_err()
        {
            let _ = response.send((vec![], vrp_table_len));
            return;
        }

        match state_rx.await {
            Ok(state) => {
                let _ = response.send((state.caches, vrp_table_len));
            }
            Err(_) => {
                let _ = response.send((vec![], vrp_table_len));
            }
        }
    }

    fn handle_get_rpki_validation(
        &self,
        prefix: IpNetwork,
        origin_as: u32,
        response: oneshot::Sender<(RpkiValidation, Vec<Vrp>)>,
    ) {
        let validation = self.vrp_table.validate(prefix, origin_as);
        let covering = self.vrp_table.covering_vrps(prefix);
        let _ = response.send((validation, covering));
    }

    fn handle_add_defined_set(
        &mut self,
        set: DefinedSetConfig,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        // Clone current defined sets (clone-on-write pattern)
        let mut new_sets = (*self.policy_ctx.defined_sets).clone();

        // Fail if set already exists
        if new_sets.contains(defined_set_type(&set), set.name()) {
            let _ = response.send(Err(format!("defined set '{}' already exists", set.name())));
            return;
        }

        // Add the set - convert config to runtime type
        match &set {
            DefinedSetConfig::PrefixSet(config) => {
                let mut prefix_matches = Vec::new();
                for pm_config in &config.prefixes {
                    match PrefixMatch::new(pm_config) {
                        Ok(pm) => prefix_matches.push(pm),
                        Err(e) => {
                            let _ = response.send(Err(format!("invalid prefix: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.prefix_sets.insert(
                    config.name.clone(),
                    PrefixSet {
                        name: config.name.clone(),
                        prefixes: prefix_matches,
                    },
                );
            }
            DefinedSetConfig::AsPathSet(config) => {
                let mut regexes = Vec::new();
                for pattern in &config.patterns {
                    match Regex::new(pattern) {
                        Ok(r) => regexes.push(r),
                        Err(e) => {
                            let _ =
                                response.send(Err(format!("invalid regex '{}': {}", pattern, e)));
                            return;
                        }
                    }
                }
                new_sets.as_path_sets.insert(
                    config.name.clone(),
                    AsPathSet {
                        name: config.name.clone(),
                        patterns: regexes,
                    },
                );
            }
            DefinedSetConfig::CommunitySet(config) => {
                let mut community_values = Vec::new();
                for comm_str in &config.communities {
                    match parse_community_str(comm_str) {
                        Ok(val) => community_values.push(val),
                        Err(e) => {
                            let _ = response.send(Err(format!("invalid community: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.community_sets.insert(
                    config.name.clone(),
                    CommunitySet {
                        name: config.name.clone(),
                        communities: community_values,
                    },
                );
            }
            DefinedSetConfig::ExtCommunitySet(config) => {
                use crate::bgp::ext_community::parse_extended_community;
                let mut ext_community_values = Vec::new();
                for ec_str in &config.ext_communities {
                    match parse_extended_community(ec_str) {
                        Ok(val) => ext_community_values.push(val),
                        Err(e) => {
                            let _ =
                                response.send(Err(format!("invalid extended community: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.ext_community_sets.insert(
                    config.name.clone(),
                    ExtCommunitySet {
                        name: config.name.clone(),
                        ext_communities: ext_community_values,
                    },
                );
            }
            DefinedSetConfig::NeighborSet(config) => {
                let mut neighbor_addrs = Vec::new();
                for addr_str in &config.neighbors {
                    match IpAddr::from_str(addr_str) {
                        Ok(addr) => neighbor_addrs.push(addr),
                        Err(e) => {
                            let _ = response.send(Err(format!("invalid IP address: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.neighbor_sets.insert(
                    config.name.clone(),
                    NeighborSet {
                        name: config.name.clone(),
                        neighbors: neighbor_addrs,
                    },
                );
            }
            DefinedSetConfig::LargeCommunitySet(config) => {
                use crate::bgp::msg_update_types::parse_large_community;
                let mut large_community_values = Vec::new();
                for lc_str in &config.large_communities {
                    match parse_large_community(lc_str) {
                        Ok(val) => large_community_values.push(val),
                        Err(e) => {
                            let _ = response.send(Err(format!("invalid large community: {}", e)));
                            return;
                        }
                    }
                }
                new_sets.large_community_sets.insert(
                    config.name.clone(),
                    LargeCommunitySet {
                        name: config.name.clone(),
                        large_communities: large_community_values,
                    },
                );
            }
        }

        // Replace the Arc (atomic update)
        self.policy_ctx.defined_sets = Arc::new(new_sets);

        // Mirror to self.config so SaveConfig persists the addition.
        match set {
            DefinedSetConfig::PrefixSet(c) => self.config.defined_sets.prefix_sets.push(c),
            DefinedSetConfig::AsPathSet(c) => self.config.defined_sets.as_path_sets.push(c),
            DefinedSetConfig::CommunitySet(c) => self.config.defined_sets.community_sets.push(c),
            DefinedSetConfig::ExtCommunitySet(c) => {
                self.config.defined_sets.ext_community_sets.push(c)
            }
            DefinedSetConfig::NeighborSet(c) => self.config.defined_sets.neighbor_sets.push(c),
            DefinedSetConfig::LargeCommunitySet(c) => {
                self.config.defined_sets.large_community_sets.push(c)
            }
        }

        let _ = response.send(Ok(()));
    }

    fn handle_remove_defined_set(
        &mut self,
        set_type: DefinedSetType,
        name: String,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        // Check if any policy references this set
        for (policy_name, policy) in &self.policy_ctx.policies {
            if self.policy_references_set(policy, set_type, &name) {
                let _ = response.send(Err(format!(
                    "cannot remove {}: referenced by policy '{}'",
                    set_type.as_str(),
                    policy_name
                )));
                return;
            }
        }

        // Clone current defined sets (clone-on-write pattern)
        let mut new_sets = (*self.policy_ctx.defined_sets).clone();

        // Delete specific set (idempotent - succeed even if not found)
        new_sets.remove(set_type, &name);
        self.policy_ctx.defined_sets = Arc::new(new_sets);

        // Mirror to self.config so SaveConfig persists the removal.
        match set_type {
            DefinedSetType::PrefixSet => self
                .config
                .defined_sets
                .prefix_sets
                .retain(|s| s.name != name),
            DefinedSetType::AsPathSet => self
                .config
                .defined_sets
                .as_path_sets
                .retain(|s| s.name != name),
            DefinedSetType::CommunitySet => self
                .config
                .defined_sets
                .community_sets
                .retain(|s| s.name != name),
            DefinedSetType::ExtCommunitySet => self
                .config
                .defined_sets
                .ext_community_sets
                .retain(|s| s.name != name),
            DefinedSetType::NeighborSet => self
                .config
                .defined_sets
                .neighbor_sets
                .retain(|s| s.name != name),
            DefinedSetType::LargeCommunitySet => self
                .config
                .defined_sets
                .large_community_sets
                .retain(|s| s.name != name),
        }

        let _ = response.send(Ok(()));
    }

    fn handle_list_defined_sets(
        &self,
        set_type: Option<DefinedSetType>,
        name: Option<String>,
        response: oneshot::Sender<Vec<DefinedSetConfig>>,
    ) {
        let mut results = Vec::new();

        // Collect prefix sets
        if set_type.is_none() || set_type == Some(DefinedSetType::PrefixSet) {
            for (set_name, prefix_set) in &self.policy_ctx.defined_sets.prefix_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let prefixes = prefix_set
                    .prefixes
                    .iter()
                    .map(|pm| PrefixMatchConfig {
                        prefix: pm.network.to_string(),
                        masklength_range: if pm.min_len == pm.max_len {
                            None
                        } else {
                            Some(format!("{}..{}", pm.min_len, pm.max_len))
                        },
                    })
                    .collect();

                results.push(DefinedSetConfig::PrefixSet(PrefixSetConfig {
                    name: set_name.clone(),
                    prefixes,
                }));
            }
        }

        // Collect neighbor sets
        if set_type.is_none() || set_type == Some(DefinedSetType::NeighborSet) {
            for (set_name, neighbor_set) in &self.policy_ctx.defined_sets.neighbor_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let neighbors = neighbor_set
                    .neighbors
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect();

                results.push(DefinedSetConfig::NeighborSet(NeighborSetConfig {
                    name: set_name.clone(),
                    neighbors,
                }));
            }
        }

        // Collect AS path sets
        if set_type.is_none() || set_type == Some(DefinedSetType::AsPathSet) {
            for (set_name, as_path_set) in &self.policy_ctx.defined_sets.as_path_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let patterns = as_path_set
                    .patterns
                    .iter()
                    .map(|r| r.as_str().to_string())
                    .collect();

                results.push(DefinedSetConfig::AsPathSet(AsPathSetConfig {
                    name: set_name.clone(),
                    patterns,
                }));
            }
        }

        // Collect community sets
        if set_type.is_none() || set_type == Some(DefinedSetType::CommunitySet) {
            for (set_name, community_set) in &self.policy_ctx.defined_sets.community_sets {
                if name.is_some() && name.as_ref() != Some(set_name) {
                    continue;
                }
                let communities = community_set
                    .communities
                    .iter()
                    .map(|c| {
                        let high = (*c >> 16) as u16;
                        let low = (*c & 0xFFFF) as u16;
                        format!("{}:{}", high, low)
                    })
                    .collect();

                results.push(DefinedSetConfig::CommunitySet(CommunitySetConfig {
                    name: set_name.clone(),
                    communities,
                }));
            }
        }

        let _ = response.send(results);
    }

    fn handle_add_policy(
        &mut self,
        name: String,
        statements: Vec<StatementConfig>,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        // Reject policy names starting with underscore (reserved for built-in policies)
        if name.starts_with('_') {
            let _ = response.send(Err(
                "policy names cannot start with underscore (reserved for built-in policies)"
                    .to_string(),
            ));
            return;
        }

        // Build PolicyDefinitionConfig directly from received statements
        let policy_def = PolicyDefinitionConfig {
            name: name.clone(),
            statements,
        };

        // Build Policy from definition using current defined_sets
        match Policy::from_config(&policy_def, &self.policy_ctx.defined_sets) {
            Ok(policy) => {
                self.policy_ctx
                    .policies
                    .insert(name.clone(), Arc::new(policy));
                // Mirror to self.config: replace existing or append.
                if let Some(existing) = self
                    .config
                    .policy_definitions
                    .iter_mut()
                    .find(|p| p.name == name)
                {
                    *existing = policy_def;
                } else {
                    self.config.policy_definitions.push(policy_def);
                }
                let _ = response.send(Ok(()));
            }
            Err(e) => {
                let _ = response.send(Err(format!("failed to build policy: {}", e)));
            }
        }
    }

    fn handle_remove_policy(
        &mut self,
        name: String,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };
        // Idempotent - succeed even if policy doesn't exist
        self.policy_ctx.policies.remove(&name);
        self.config.policy_definitions.retain(|p| p.name != name);
        let _ = response.send(Ok(()));
    }

    fn handle_list_policies(
        &self,
        name: Option<String>,
        response: oneshot::Sender<Vec<PolicyInfoResponse>>,
    ) {
        let mut results = Vec::new();

        for (policy_name, policy) in &self.policy_ctx.policies {
            if name.is_some() && name.as_ref() != Some(policy_name) {
                continue;
            }

            // Convert compiled statements back to config format
            let statements = policy
                .statements()
                .iter()
                .map(|stmt| stmt.to_config())
                .collect();

            results.push(PolicyInfoResponse {
                name: policy_name.clone(),
                statements,
            });
        }

        let _ = response.send(results);
    }

    fn handle_set_policy_assignment(
        &mut self,
        peer_addr: IpAddr,
        family: AfiSafi,
        direction: PolicyDirection,
        policy_names: Vec<String>,
        _default_action: Option<crate::policy::PolicyResult>,
        response: oneshot::Sender<Result<(), String>>,
    ) {
        let _lock = match conf::fs::acquire_shared_lock(&self.config_path) {
            Ok(f) => f,
            Err(e) => {
                let _ = response.send(Err(e));
                return;
            }
        };

        // Resolve policy names to Policy objects.
        let mut resolved_policies = Vec::new();
        for name in &policy_names {
            match self.policy_ctx.policies.get(name) {
                Some(policy) => resolved_policies.push(policy.clone()),
                None => {
                    let _ = response.send(Err(format!("policy '{}' not found", name)));
                    return;
                }
            }
        }

        let Some(peer) = self.peers.get_mut(&peer_addr) else {
            let _ = response.send(Err(format!("peer {} not found", peer_addr)));
            return;
        };

        // Update resolved runtime policies for this family.
        match direction {
            PolicyDirection::Import => {
                peer.import_policies.insert(family, resolved_policies);
            }
            PolicyDirection::Export => {
                peer.export_policies.insert(family, resolved_policies);
            }
        }

        // Persist the assignment in the peer's per-family config so it
        // survives session reconnections. Auto-create the family entry if
        // the peer didn't have one for this (afi, safi) yet.
        if let Some(cfg) = self.config.find_peer_mut(peer_addr) {
            let entry = afi_safi_entry_mut(&mut cfg.afi_safis, family.afi, family.safi);
            match direction {
                PolicyDirection::Import => entry.import_policy = policy_names,
                PolicyDirection::Export => entry.export_policy = policy_names,
            }
        }

        let _ = response.send(Ok(()));
    }

    pub(super) fn get_established_peers(&self) -> Vec<(IpAddr, &PeerInfo)> {
        self.peers
            .iter()
            .filter(|(_, peer_info)| peer_info.established_conn().is_some())
            .map(|(peer_ip, peer_info)| (*peer_ip, peer_info))
            .collect()
    }

    fn get_adj_rib_in(
        &self,
        peer_address: Option<String>,
        afi_safi: Option<AfiSafi>,
    ) -> Result<Vec<Route>, String> {
        let peer_addr = peer_address
            .ok_or("peer_address required for ADJ_IN".to_string())?
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid peer address: {}", e))?;

        let peer_info = self
            .peers
            .get(&peer_addr)
            .ok_or(format!("peer {} not found", peer_addr))?;

        if peer_info.established_conn().is_none() {
            return Err("peer not established".to_string());
        }

        Ok(peer_info.adj_rib_in.get_routes(afi_safi))
    }

    fn get_adj_rib_out(
        &self,
        peer_address: Option<String>,
        afi_safi: Option<AfiSafi>,
    ) -> Result<Vec<Route>, String> {
        let peer_addr = peer_address
            .ok_or("peer_address required for ADJ_OUT".to_string())?
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid peer address: {}", e))?;

        let peer_info = self
            .peers
            .get(&peer_addr)
            .ok_or(format!("peer {} not found", peer_addr))?;

        Ok(peer_info.adj_rib_out.get_routes(afi_safi))
    }

    /// Check if a policy references a specific defined set
    fn policy_references_set(
        &self,
        policy: &crate::policy::Policy,
        set_type: DefinedSetType,
        set_name: &str,
    ) -> bool {
        for stmt in policy.statements() {
            let config = stmt.to_config();

            match set_type {
                DefinedSetType::PrefixSet => {
                    if let Some(ref match_set) = config.conditions.match_prefix_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::NeighborSet => {
                    if let Some(ref match_set) = config.conditions.match_neighbor_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::AsPathSet => {
                    if let Some(ref match_set) = config.conditions.match_as_path_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::CommunitySet => {
                    if let Some(ref match_set) = config.conditions.match_community_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::ExtCommunitySet => {
                    if let Some(ref match_set) = config.conditions.match_ext_community_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
                DefinedSetType::LargeCommunitySet => {
                    if let Some(ref match_set) = config.conditions.match_large_community_set {
                        if match_set.set_name == set_name {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }
}

/// Parse community string in format "65000:100" or decimal
fn parse_community_str(s: &str) -> Result<u32, String> {
    // Try decimal format first
    if let Ok(val) = s.parse::<u32>() {
        return Ok(val);
    }

    // Try "65000:100" format
    if let Some((high, low)) = s.split_once(':') {
        let high_val = high
            .parse::<u16>()
            .map_err(|_| format!("invalid high part '{}'", high))?;
        let low_val = low
            .parse::<u16>()
            .map_err(|_| format!("invalid low part '{}'", low))?;
        return Ok((high_val as u32) << 16 | (low_val as u32));
    }

    Err(format!(
        "invalid community format '{}' (expected '65000:100' or decimal)",
        s
    ))
}

/// Send initial BMP messages for existing peers after BMP server connects.
pub(super) fn send_initial_bmp_state(
    task_tx: &mpsc::UnboundedSender<Arc<BmpOp>>,
    established_peers: Vec<(IpAddr, &PeerInfo)>,
) {
    use crate::bgp::msg::MessageFormat;
    use crate::peer::outgoing::batch_announcements;
    use crate::rib::RoutePath;

    // Send all PeerUp messages first
    for (peer_ip, peer_info) in &established_peers {
        let Some(conn) = peer_info.established_conn() else {
            continue;
        };
        if let (Some(asn), Some(bgp_id), Some(conn_info)) = (conn.asn, conn.bgp_id, &conn.conn_info)
        {
            let use_4byte_asn = peer_info.supports_4byte_asn();
            let _ = task_tx.send(Arc::new(BmpOp::PeerUp {
                peer_ip: *peer_ip,
                peer_as: asn,
                peer_bgp_id: bgp_id,
                local_address: conn_info.local_address,
                local_port: conn_info.local_port,
                remote_port: conn_info.remote_port,
                sent_open: conn_info.sent_open.clone(),
                received_open: conn_info.received_open.clone(),
                use_4byte_asn,
            }));
        }
    }

    // Then send all RouteMonitoring messages (read adj-rib-in directly from PeerInfo)
    for (peer_ip, peer_info) in established_peers {
        let Some(conn) = peer_info.established_conn() else {
            continue;
        };
        if let (Some(asn), Some(bgp_id)) = (conn.asn, conn.bgp_id) {
            let routes = peer_info.adj_rib_in.get_routes(None);
            let format = MessageFormat {
                use_4byte_asn: peer_info.supports_4byte_asn(),
                add_path: peer_info.add_path_receive_mask(),
                is_ebgp: false,
                enhanced_rr: false,
            };

            // Build BMP Route Monitoring messages for this peer's routes.
            let announcements: Vec<RoutePath> = routes
                .iter()
                .flat_map(|route| {
                    route.paths.iter().map(|path| RoutePath {
                        key: route.key.clone(),
                        path: Arc::clone(path),
                    })
                })
                .collect();
            let batches = batch_announcements(&announcements);
            for batch in batches {
                let update = batch.to_update(format);
                let _ = task_tx.send(Arc::new(BmpOp::RouteMonitoring {
                    peer_ip,
                    peer_as: asn,
                    peer_bgp_id: bgp_id,
                    update,
                }));
            }
        }
    }
}
