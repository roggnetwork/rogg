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

//! RtrManager: orchestrates RTR cache sessions, computes VRP diffs,
//! manages preference-based failover, and delivers updates to the server.

use crate::log::{info, warn};
use crate::rpki::rtr::Serial;
use crate::rpki::session::CacheSession;
use crate::rpki::vrp::Vrp;
use crate::server::ops::ServerOp;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// SSH transport configuration for RTR cache connections.
#[derive(Clone, Debug)]
pub struct SshTransport {
    pub username: String,
    pub private_key_file: String,
    pub known_hosts_file: Option<String>,
}

/// Transport type for RTR cache connections.
#[derive(Clone, Debug)]
pub enum RtrTransport {
    Tcp,
    Ssh(SshTransport),
}

impl RtrTransport {
    pub fn to_str(&self) -> &'static str {
        match self {
            RtrTransport::Tcp => "tcp",
            RtrTransport::Ssh(_) => "ssh",
        }
    }
}

/// Configuration for a single RTR cache server.
#[derive(Clone, Debug)]
pub struct RtrCacheConfig {
    pub address: SocketAddr,
    /// Lower values are preferred. Only the lowest tier is active at startup.
    pub preference: u8,
    /// Transport to use for cache connection.
    pub transport: RtrTransport,
    /// Override cache-provided retry interval (seconds).
    pub retry_interval: Option<u64>,
    /// Override cache-provided refresh interval (seconds).
    pub refresh_interval: Option<u64>,
    /// Override cache-provided expire interval (seconds).
    pub expire_interval: Option<u64>,
}

/// Snapshot of a single RPKI cache for diagnostics.
pub struct RpkiCacheState {
    pub address: SocketAddr,
    pub preference: u8,
    pub transport_name: &'static str,
    pub session_active: bool,
    pub vrp_count: usize,
}

/// Snapshot of all RPKI manager state for diagnostics.
pub struct RpkiManagerState {
    pub caches: Vec<RpkiCacheState>,
}

/// Operations sent from the server to the RtrManager.
pub enum RpkiOp {
    AddCache(RtrCacheConfig),
    RemoveCache(SocketAddr),
    GetState {
        response: oneshot::Sender<RpkiManagerState>,
    },
}

/// A batch of VRP changes from a single cache sync cycle.
#[derive(Debug)]
/// Complete VRP state from a cache after a sync cycle.
/// The session computes this from protocol-level incremental/reset logic.
/// The manager diffs it against the previous state.
pub struct VrpBatch {
    pub cache_addr: SocketAddr,
    pub session_id: u16,
    pub serial: Serial,
    /// Complete VRP set for this cache after this sync.
    pub vrps: HashSet<Vrp>,
}

/// Events sent from CacheSession to RtrManager.
pub enum CacheEvent {
    /// Successful sync cycle completed.
    Batch(VrpBatch),
    /// TCP connection lost. Data stays until expire.
    Disconnected(SocketAddr),
    /// Expire timer fired -- data from this cache is no longer valid.
    Expired(SocketAddr),
}

/// Handle to a running CacheSession task.
struct CacheSessionHandle {
    config: RtrCacheConfig,
    shutdown_tx: oneshot::Sender<()>,
    /// Held to prevent the spawned task from being detached.
    _join_handle: JoinHandle<()>,
}

/// Manages RTR cache sessions and delivers merged VRP diffs to the server.
pub struct RtrManager {
    /// Receives commands (AddCache, RemoveCache) from the server.
    command_rx: mpsc::UnboundedReceiver<RpkiOp>,
    /// Receives events (Batch, Disconnected, Expired) from cache sessions.
    event_rx: mpsc::UnboundedReceiver<CacheEvent>,
    /// Cloned to each cache session so they can send events back.
    event_tx: mpsc::UnboundedSender<CacheEvent>,
    /// Sends VRP updates to the server.
    server_tx: mpsc::UnboundedSender<ServerOp>,
    sessions: HashMap<SocketAddr, CacheSessionHandle>,
    /// VRPs currently held by each cache, for cross-cache diff computation.
    per_cache_vrps: HashMap<SocketAddr, HashSet<Vrp>>,
    /// All configured caches, keyed by address.
    all_configs: HashMap<SocketAddr, RtrCacheConfig>,
}

impl RtrManager {
    pub fn new(
        command_rx: mpsc::UnboundedReceiver<RpkiOp>,
        server_tx: mpsc::UnboundedSender<ServerOp>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        RtrManager {
            command_rx,
            event_rx,
            event_tx,
            server_tx,
            sessions: HashMap::new(),
            per_cache_vrps: HashMap::new(),
            all_configs: HashMap::new(),
        }
    }

    pub async fn run(mut self) {
        info!("RTR manager started");
        loop {
            tokio::select! {
                rpki_op = self.command_rx.recv() => {
                    match rpki_op {
                        Some(RpkiOp::AddCache(config)) => {
                            self.handle_add_cache(config);
                        }
                        Some(RpkiOp::RemoveCache(addr)) => {
                            self.handle_remove_cache(addr);
                        }
                        Some(RpkiOp::GetState { response }) => {
                            self.handle_get_state(response);
                        }
                        None => {
                            info!("command channel closed, stopping RTR manager");
                            break;
                        }
                    }
                }
                event = self.event_rx.recv() => {
                    match event {
                        Some(CacheEvent::Batch(batch)) => {
                            self.handle_batch(batch);
                        }
                        Some(CacheEvent::Disconnected(addr)) => {
                            self.handle_disconnected(addr);
                        }
                        Some(CacheEvent::Expired(addr)) => {
                            self.handle_expired(addr);
                        }
                        None => {
                            // All senders dropped (shouldn't happen while we hold event_tx)
                            break;
                        }
                    }
                }
            }
        }

        // Shutdown all sessions
        for (addr, handle) in self.sessions.drain() {
            let _ = handle.shutdown_tx.send(());
            info!(%addr, "shut down cache session");
        }
        info!("RTR manager stopped");
    }

    fn handle_add_cache(&mut self, config: RtrCacheConfig) {
        let addr = config.address;
        if self.sessions.contains_key(&addr) {
            warn!(%addr, "cache already exists, ignoring add");
            return;
        }

        self.all_configs.insert(addr, config.clone());

        // Only spawn if this cache is in the lowest preference tier
        let lowest_configured = self.lowest_configured_preference();
        if config.preference <= lowest_configured {
            self.spawn_session(config);
        } else {
            info!(%addr, preference = config.preference, lowest = lowest_configured,
                  "cache configured but not spawned (higher preference tier)");
        }
    }

    fn handle_get_state(&self, response: oneshot::Sender<RpkiManagerState>) {
        let caches = self
            .all_configs
            .values()
            .map(|config| {
                let addr = config.address;
                RpkiCacheState {
                    address: addr,
                    preference: config.preference,
                    transport_name: config.transport.to_str(),
                    session_active: self.sessions.contains_key(&addr),
                    vrp_count: self.per_cache_vrps.get(&addr).map_or(0, |s| s.len()),
                }
            })
            .collect();
        let _ = response.send(RpkiManagerState { caches });
    }

    fn handle_remove_cache(&mut self, addr: SocketAddr) {
        // Shutdown session if running
        if let Some(handle) = self.sessions.remove(&addr) {
            let _ = handle.shutdown_tx.send(());
            info!(%addr, "cache session removed");
        }

        self.all_configs.remove(&addr);

        // Compute diff: VRPs unique to this cache become removals
        let removed = self.compute_removal_diff(addr);
        self.per_cache_vrps.remove(&addr);

        if !removed.is_empty() {
            self.send_vrp_update(vec![], removed);
        }
    }

    fn handle_batch(&mut self, batch: VrpBatch) {
        let addr = batch.cache_addr;
        info!(%addr, session_id = batch.session_id, serial = ?batch.serial,
              vrps = batch.vrps.len(), "received VRP batch");

        let old_vrps = self
            .per_cache_vrps
            .insert(addr, batch.vrps.clone())
            .unwrap_or_default();

        // Diff old vs new, filtering out VRPs covered by other caches
        let mut added = Vec::new();
        let mut removed = Vec::new();

        for vrp in batch.vrps.difference(&old_vrps) {
            if !self.any_other_cache_has(addr, vrp) {
                added.push(vrp.clone());
            }
        }

        for vrp in old_vrps.difference(&self.per_cache_vrps[&addr]) {
            if !self.any_other_cache_has(addr, vrp) {
                removed.push(vrp.clone());
            }
        }

        if !added.is_empty() || !removed.is_empty() {
            self.send_vrp_update(added, removed);
        }

        // Preference-based failover: if this cache recovered at a better preference,
        // kill less-preferred tiers
        if let Some(config) = self.session_config(addr) {
            let pref = config.preference;
            self.kill_less_preferred_tiers(pref);
        }
    }

    fn handle_disconnected(&mut self, addr: SocketAddr) {
        info!(%addr, "cache session disconnected");

        let pref = match self.session_config(addr) {
            Some(config) => config.preference,
            None => return,
        };

        // If no other cache at same preference tier is still connected,
        // preemptively spawn the next tier
        let same_tier_connected = self.sessions.keys().any(|other_addr| {
            *other_addr != addr
                && self
                    .session_config(*other_addr)
                    .is_some_and(|c| c.preference == pref)
        });

        if !same_tier_connected {
            if let Some(next_pref) = self.next_preference_tier(pref) {
                info!(current_pref = pref, next_pref, "spawning fallback tier");
                self.spawn_preference_tier(next_pref);
            }
        }
    }

    fn handle_expired(&mut self, addr: SocketAddr) {
        warn!(%addr, "cache data expired");

        let removed = self.compute_removal_diff(addr);
        self.per_cache_vrps.remove(&addr);

        if !removed.is_empty() {
            // Check if any other cache has data
            let any_cache_has_data = self.per_cache_vrps.values().any(|vrps| !vrps.is_empty());
            if !any_cache_has_data {
                warn!(%addr, "no RPKI cache has data -- routes will be NotFound");
            }
            self.send_vrp_update(vec![], removed);
        }
    }

    // -- Preference tier helpers --

    /// Lowest preference value among all configured caches.
    fn lowest_configured_preference(&self) -> u8 {
        self.all_configs
            .values()
            .map(|c| c.preference)
            .min()
            .unwrap_or(0)
    }

    /// Next preference tier strictly greater than `current`.
    fn next_preference_tier(&self, current: u8) -> Option<u8> {
        self.all_configs
            .values()
            .map(|c| c.preference)
            .filter(|p| *p > current)
            .min()
    }

    /// Spawn sessions for all caches at the given preference level.
    fn spawn_preference_tier(&mut self, pref: u8) {
        let configs: Vec<RtrCacheConfig> = self
            .all_configs
            .values()
            .filter(|c| c.preference == pref)
            .cloned()
            .collect();

        for config in configs {
            if !self.sessions.contains_key(&config.address) {
                self.spawn_session(config);
            }
        }
    }

    /// Kill sessions at preference tiers strictly greater than `pref`,
    /// remove their VRPs, and send diff to server.
    fn kill_less_preferred_tiers(&mut self, pref: u8) {
        let addrs_to_kill: Vec<SocketAddr> = self
            .sessions
            .keys()
            .filter(|addr| {
                self.all_configs
                    .get(addr)
                    .is_some_and(|c| c.preference > pref)
            })
            .copied()
            .collect();

        if addrs_to_kill.is_empty() {
            return;
        }

        let mut all_removed = Vec::new();
        for addr in addrs_to_kill {
            if let Some(handle) = self.sessions.remove(&addr) {
                let _ = handle.shutdown_tx.send(());
                info!(%addr, "killed less-preferred cache session");
            }
            let removed = self.compute_removal_diff(addr);
            self.per_cache_vrps.remove(&addr);
            all_removed.extend(removed);
        }

        if !all_removed.is_empty() {
            self.send_vrp_update(vec![], all_removed);
        }
    }

    // -- Session management --

    fn spawn_session(&mut self, config: RtrCacheConfig) {
        let addr = config.address;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let manager_tx = self.event_tx.clone();

        let session = CacheSession::new(config.clone(), manager_tx, shutdown_rx);
        let join_handle = tokio::spawn(async move {
            session.run().await;
        });

        self.sessions.insert(
            addr,
            CacheSessionHandle {
                config,
                shutdown_tx,
                _join_handle: join_handle,
            },
        );
        info!(%addr, "spawned cache session");
    }

    fn session_config(&self, addr: SocketAddr) -> Option<RtrCacheConfig> {
        self.sessions
            .get(&addr)
            .map(|h| h.config.clone())
            .or_else(|| self.all_configs.get(&addr).cloned())
    }

    // -- VRP diff helpers --

    /// Check if any cache other than `exclude_addr` has this VRP.
    fn any_other_cache_has(&self, exclude_addr: SocketAddr, vrp: &Vrp) -> bool {
        self.per_cache_vrps
            .iter()
            .any(|(addr, vrps)| *addr != exclude_addr && vrps.contains(vrp))
    }

    /// Compute VRPs that would be globally removed if this cache's data were deleted.
    fn compute_removal_diff(&self, addr: SocketAddr) -> Vec<Vrp> {
        let Some(cache_vrps) = self.per_cache_vrps.get(&addr) else {
            return vec![];
        };
        cache_vrps
            .iter()
            .filter(|vrp| !self.any_other_cache_has(addr, vrp))
            .cloned()
            .collect()
    }

    fn send_vrp_update(&self, added: Vec<Vrp>, removed: Vec<Vrp>) {
        info!(
            added = added.len(),
            removed = removed.len(),
            "sending VRP update to server"
        );
        let _ = self.server_tx.send(ServerOp::VrpUpdate { added, removed });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().expect("valid addr")
    }

    fn vrp(prefix: &str, max_length: u8, origin_as: u32) -> Vrp {
        use crate::net::IpNetwork;
        Vrp {
            prefix: prefix.parse::<IpNetwork>().expect("valid prefix"),
            max_length,
            origin_as,
        }
    }

    fn config(port: u16, preference: u8) -> RtrCacheConfig {
        RtrCacheConfig {
            address: addr(port),
            preference,
            transport: RtrTransport::Tcp,
            retry_interval: None,
            refresh_interval: None,
            expire_interval: None,
        }
    }

    // Test diff computation when two caches have overlapping VRPs
    #[tokio::test]
    async fn test_batch_diff_overlapping_vrps() {
        let (rpki_tx, command_rx) = mpsc::unbounded_channel();
        let (server_tx, mut server_op_rx) = mpsc::unbounded_channel();
        let mut manager = RtrManager::new(command_rx, server_tx);

        // Manually set up per_cache_vrps (bypassing session spawn)
        let vrp_a = vrp("10.0.0.0/8", 24, 65001);
        let vrp_b = vrp("192.168.0.0/16", 24, 65002);
        let vrp_shared = vrp("172.16.0.0/12", 24, 65003);

        // Cache 1 has vrp_a and vrp_shared
        let mut cache1_vrps = HashSet::new();
        cache1_vrps.insert(vrp_a.clone());
        cache1_vrps.insert(vrp_shared.clone());
        manager.per_cache_vrps.insert(addr(8282), cache1_vrps);

        // Cache 2 has vrp_b and vrp_shared
        let batch = VrpBatch {
            cache_addr: addr(8283),
            session_id: 1,
            serial: Serial(1),
            vrps: HashSet::from([vrp_b.clone(), vrp_shared.clone()]),
        };

        manager.handle_batch(batch);

        // Only vrp_b should be in the server update (vrp_shared already covered by cache 1)
        let update = server_op_rx.try_recv().expect("should have update");
        match update {
            ServerOp::VrpUpdate { added, removed } => {
                assert_eq!(added.len(), 1);
                assert_eq!(added[0], vrp_b);
                assert!(removed.is_empty());
            }
            _ => panic!("expected VrpUpdate"),
        }

        drop(rpki_tx);
    }

    // Test removal diff when cache is removed but shared VRPs stay
    #[tokio::test]
    async fn test_remove_cache_shared_vrps_stay() {
        let (rpki_tx, command_rx) = mpsc::unbounded_channel();
        let (server_tx, _server_op_rx) = mpsc::unbounded_channel();
        let mut manager = RtrManager::new(command_rx, server_tx);

        let vrp_shared = vrp("10.0.0.0/8", 24, 65001);
        let vrp_unique = vrp("192.168.0.0/16", 24, 65002);

        // Both caches have vrp_shared, only cache 1 has vrp_unique
        let mut cache1 = HashSet::new();
        cache1.insert(vrp_shared.clone());
        cache1.insert(vrp_unique.clone());
        manager.per_cache_vrps.insert(addr(8282), cache1);

        let mut cache2 = HashSet::new();
        cache2.insert(vrp_shared.clone());
        manager.per_cache_vrps.insert(addr(8283), cache2);

        manager.all_configs.insert(addr(8282), config(8282, 0));
        manager.all_configs.insert(addr(8283), config(8283, 0));

        // Remove cache 1
        let removed = manager.compute_removal_diff(addr(8282));
        manager.per_cache_vrps.remove(&addr(8282));

        // Only vrp_unique should be removed (vrp_shared still in cache 2)
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], vrp_unique);

        drop(rpki_tx);
    }

    // Test preference tier logic
    #[test]
    fn test_preference_tier_helpers() {
        let (_, command_rx) = mpsc::unbounded_channel();
        let (server_tx, _) = mpsc::unbounded_channel();
        let mut manager = RtrManager::new(command_rx, server_tx);

        manager.all_configs.insert(addr(8282), config(8282, 0));
        manager.all_configs.insert(addr(8283), config(8283, 0));
        manager.all_configs.insert(addr(8284), config(8284, 1));
        manager.all_configs.insert(addr(8285), config(8285, 2));

        assert_eq!(manager.lowest_configured_preference(), 0);
        assert_eq!(manager.next_preference_tier(0), Some(1));
        assert_eq!(manager.next_preference_tier(1), Some(2));
        assert_eq!(manager.next_preference_tier(2), None);
    }

    // Test that handle_add_cache only spawns lowest preference tier
    #[tokio::test]
    async fn test_add_cache_preference_gating() {
        let (_, command_rx) = mpsc::unbounded_channel();
        let (server_tx, _) = mpsc::unbounded_channel();
        let mut manager = RtrManager::new(command_rx, server_tx);

        // Add pref=0 cache -- should spawn
        manager.handle_add_cache(config(8282, 0));
        assert!(manager.sessions.contains_key(&addr(8282)));

        // Add pref=1 cache -- should NOT spawn (higher than lowest)
        manager.handle_add_cache(config(8283, 1));
        assert!(!manager.sessions.contains_key(&addr(8283)));
        // But it should be in all_configs
        assert_eq!(manager.all_configs.len(), 2);
    }

    // Test expired handling clears VRPs and sends diff
    #[tokio::test]
    async fn test_expired_clears_vrps() {
        let (_, command_rx) = mpsc::unbounded_channel();
        let (server_tx, mut server_op_rx) = mpsc::unbounded_channel();
        let mut manager = RtrManager::new(command_rx, server_tx);

        let vrp1 = vrp("10.0.0.0/8", 24, 65001);
        let mut cache_vrps = HashSet::new();
        cache_vrps.insert(vrp1.clone());
        manager.per_cache_vrps.insert(addr(8282), cache_vrps);

        manager.handle_expired(addr(8282));

        assert!(!manager.per_cache_vrps.contains_key(&addr(8282)));

        let update = server_op_rx.try_recv().expect("should have update");
        match update {
            ServerOp::VrpUpdate { added, removed } => {
                assert!(added.is_empty());
                assert_eq!(removed.len(), 1);
                assert_eq!(removed[0], vrp1);
            }
            _ => panic!("expected VrpUpdate"),
        }
    }

    // Test batch withdrawal removes globally unique VRP
    #[tokio::test]
    async fn test_batch_withdrawal() {
        let (_, command_rx) = mpsc::unbounded_channel();
        let (server_tx, mut server_op_rx) = mpsc::unbounded_channel();
        let mut manager = RtrManager::new(command_rx, server_tx);

        let vrp1 = vrp("10.0.0.0/8", 24, 65001);
        let mut cache_vrps = HashSet::new();
        cache_vrps.insert(vrp1.clone());
        manager.per_cache_vrps.insert(addr(8282), cache_vrps);

        // After withdrawal, cache has no VRPs
        let batch = VrpBatch {
            cache_addr: addr(8282),
            session_id: 1,
            serial: Serial(2),
            vrps: HashSet::new(),
        };

        manager.handle_batch(batch);

        let update = server_op_rx.try_recv().expect("should have update");
        match update {
            ServerOp::VrpUpdate { added, removed } => {
                assert!(added.is_empty());
                assert_eq!(removed.len(), 1);
                assert_eq!(removed[0], vrp1);
            }
            _ => panic!("expected VrpUpdate"),
        }
    }
}
