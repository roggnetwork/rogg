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

use crate::language::{self, Service};
use crate::language_bgp::{
    AddPathSendMode as LangAddPathSendMode, AsPathSetBlock, BgpLsBlock, BgpServiceBody,
    BmpServerBlock, CloudwatchEmfBlock, CommunityOp, CommunityOpKind, CommunitySetBlock,
    Disposition, ExtCommunitySetBlock, FamilyBlock, FamilyDirective, LargeCommunitySetBlock,
    MasklengthRange, MatchClause, MatchOptionKind, MatchSetRef, MaxPrefixActionKind, MedSet,
    NeighborSetBlock, OriginateRoute, PeerBlock, PolicyBlock, PolicyRule, PrefixListBlock,
    PrefixListEntry, RpkiCacheBlock, RpkiValidationKind, SetClause, Setting, StatementBlock,
    TelemetryBlock,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tracing::error;

/// Error returned when an AFI or SAFI numeric value is unrecognized.
#[derive(Debug, Clone)]
pub struct AfiSafiError {
    pub kind: &'static str,
    pub value: u32,
}

impl fmt::Display for AfiSafiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown {}: {}", self.kind, self.value)
    }
}

impl std::error::Error for AfiSafiError {}

/// Address Family Identifier per IANA registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
    LinkState = 16388,
}

impl Serialize for Afi {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(*self as u16)
    }
}

impl<'de> Deserialize<'de> for Afi {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u16::deserialize(deserializer)?;
        Afi::try_from(value).map_err(|_| serde::de::Error::custom(format!("unknown AFI: {value}")))
    }
}

impl fmt::Display for Afi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Afi::Ipv4 => write!(f, "IPv4"),
            Afi::Ipv6 => write!(f, "IPv6"),
            Afi::LinkState => write!(f, "LinkState"),
        }
    }
}

impl TryFrom<u16> for Afi {
    type Error = AfiSafiError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Afi::Ipv4),
            2 => Ok(Afi::Ipv6),
            16388 => Ok(Afi::LinkState),
            _ => Err(AfiSafiError {
                kind: "AFI",
                value: value as u32,
            }),
        }
    }
}

impl std::str::FromStr for Afi {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ipv4" => Ok(Afi::Ipv4),
            "ipv6" => Ok(Afi::Ipv6),
            "ls" => Ok(Afi::LinkState),
            _ => Err(format!("expected ipv4|ipv6|ls, got '{}'", s)),
        }
    }
}

impl Afi {
    /// Lowercase token as accepted by the config parser (inverse of FromStr).
    pub fn as_config_str(&self) -> &'static str {
        match self {
            Afi::Ipv4 => "ipv4",
            Afi::Ipv6 => "ipv6",
            Afi::LinkState => "ls",
        }
    }
}

/// Subsequent Address Family Identifier per IANA registry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    MplsLabel = 4,
    LinkState = 71,
    LinkStateVpn = 72,
}

impl From<Safi> for u8 {
    fn from(safi: Safi) -> u8 {
        safi as u8
    }
}

impl Serialize for Safi {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for Safi {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        Safi::try_from(value)
            .map_err(|_| serde::de::Error::custom(format!("unknown SAFI: {value}")))
    }
}

impl fmt::Display for Safi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Safi::Unicast => write!(f, "Unicast"),
            Safi::Multicast => write!(f, "Multicast"),
            Safi::MplsLabel => write!(f, "MPLS-labeled"),
            Safi::LinkState => write!(f, "LinkState"),
            Safi::LinkStateVpn => write!(f, "LinkState-VPN"),
        }
    }
}

impl std::str::FromStr for Safi {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unicast" => Ok(Safi::Unicast),
            "multicast" => Ok(Safi::Multicast),
            "mpls-label" => Ok(Safi::MplsLabel),
            "link-state" => Ok(Safi::LinkState),
            "link-state-vpn" => Ok(Safi::LinkStateVpn),
            _ => Err(format!(
                "expected unicast|multicast|mpls-label|link-state|link-state-vpn, got '{}'",
                s
            )),
        }
    }
}

impl Safi {
    /// Lowercase token as accepted by the config parser (inverse of FromStr).
    pub fn as_config_str(&self) -> &'static str {
        match self {
            Safi::Unicast => "unicast",
            Safi::Multicast => "multicast",
            Safi::MplsLabel => "mpls-label",
            Safi::LinkState => "link-state",
            Safi::LinkStateVpn => "link-state-vpn",
        }
    }
}

impl TryFrom<u8> for Safi {
    type Error = AfiSafiError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Safi::Unicast),
            2 => Ok(Safi::Multicast),
            4 => Ok(Safi::MplsLabel),
            71 => Ok(Safi::LinkState),
            72 => Ok(Safi::LinkStateVpn),
            _ => Err(AfiSafiError {
                kind: "SAFI",
                value: value as u32,
            }),
        }
    }
}

/// Combined AFI/SAFI for capability tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AfiSafi {
    pub afi: Afi,
    pub safi: Safi,
}

impl AfiSafi {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        AfiSafi { afi, safi }
    }

    /// Try to construct from optional raw numeric AFI/SAFI values.
    /// Returns None if either is absent or unrecognized.
    pub fn from_raw(afi: Option<u32>, safi: Option<u32>) -> Option<Self> {
        let afi = Afi::try_from(afi? as u16).ok()?;
        let safi_val = safi.unwrap_or(1);
        let safi = Safi::try_from(safi_val as u8).ok()?;
        Some(AfiSafi { afi, safi })
    }
}

impl fmt::Display for AfiSafi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.afi, self.safi)
    }
}

/// Default AFI/SAFIs: IPv4 Unicast + IPv6 Unicast
pub fn default_afi_safis() -> Vec<AfiSafi> {
    vec![
        AfiSafi::new(Afi::Ipv4, Safi::Unicast),
        AfiSafi::new(Afi::Ipv6, Safi::Unicast),
    ]
}

/// Action to take when max prefix limit is reached
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MaxPrefixAction {
    /// Send CEASE notification and close the session
    Terminate,
    /// Discard new prefixes but keep the session
    Discard,
}

/// Max prefix limit configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct MaxPrefixSetting {
    pub limit: u32,
    #[serde(default = "default_max_prefix_action")]
    pub action: MaxPrefixAction,
}

fn default_max_prefix_action() -> MaxPrefixAction {
    MaxPrefixAction::Terminate
}

/// Graceful Restart configuration (RFC 4724)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct GracefulRestartConfig {
    /// Enable Graceful Restart (default: true)
    #[serde(default = "default_gr_enabled")]
    pub enabled: bool,
    /// Restart time in seconds (default: 120, max: 4095)
    #[serde(default = "default_gr_restart_time")]
    pub restart_time: u16,
}

fn default_gr_enabled() -> bool {
    true
}

fn default_gr_restart_time() -> u16 {
    120
}

impl Default for GracefulRestartConfig {
    fn default() -> Self {
        Self {
            enabled: default_gr_enabled(),
            restart_time: default_gr_restart_time(),
        }
    }
}

const MAX_LLGR_STALE_TIME: u32 = 0xFFFFFF; // 24-bit max

fn default_llgr_enabled() -> bool {
    true
}

/// RFC 9494: Long-Lived Graceful Restart configuration.
/// Used at both server level and per-peer level.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LlgrConfig {
    /// Enable LLGR (default: true). Set to false to explicitly disable.
    #[serde(default = "default_llgr_enabled")]
    pub enabled: bool,
    /// Long-Lived Stale Time in seconds (24-bit max: 16777215)
    pub stale_time: Option<u32>,
    /// AFI/SAFIs to enable LLGR for. None = use default_afi_safis().
    #[serde(default)]
    pub afi_safis: Option<Vec<AfiSafi>>,
}

/// Resolve LLGR config from server-level and peer-level settings.
/// - No server + no peer = disabled (None)
/// - Server + no peer = inherit server
/// - Peer enabled: false = disabled regardless of server
/// - Peer overrides server fields (stale_time, afi_safis)
pub fn get_peer_llgr(
    server_llgr: &Option<LlgrConfig>,
    peer_llgr: &Option<LlgrConfig>,
) -> Option<LlgrConfig> {
    let effective = match (server_llgr, peer_llgr) {
        (None, None) => return None,
        (Some(server), None) => server,
        (_, Some(peer)) => {
            if !peer.enabled {
                return None;
            }
            peer
        }
    };

    if !effective.enabled {
        return None;
    }

    Some(LlgrConfig {
        enabled: true,
        stale_time: effective.stale_time,
        afi_safis: Some(
            effective
                .afi_safis
                .clone()
                .unwrap_or_else(default_afi_safis),
        ),
    })
}

/// RFC 7911: ADD-PATH send mode
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddPathSend {
    /// Do not send multiple paths (default)
    #[default]
    Disabled,
    /// Send all paths for each prefix
    All,
}

/// Per address-family configuration. Enables the family on the peer and
/// optionally attaches per-family overrides (max-prefix, add-path) and
/// per-family policy attachments (import/export). Policies are scoped to
/// the family — runtime evaluates them only against routes of this AFI/SAFI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AfiSafiConfig {
    pub afi: Afi,
    pub safi: Safi,
    /// Override peer-level max_prefix for this family.
    #[serde(default)]
    pub max_prefix: Option<MaxPrefixSetting>,
    /// Override peer-level add_path_send for this family.
    #[serde(default)]
    pub add_path_send: Option<AddPathSend>,
    /// Import policy names applied to inbound routes for this family.
    #[serde(default)]
    pub import_policy: Vec<String>,
    /// Export policy names applied to outbound routes for this family.
    #[serde(default)]
    pub export_policy: Vec<String>,
}

impl AfiSafiConfig {
    /// Create a config entry with no overrides (just AFI/SAFI enablement).
    pub fn new(afi: Afi, safi: Safi) -> Self {
        Self {
            afi,
            safi,
            max_prefix: None,
            add_path_send: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
        }
    }

    /// Return the plain AfiSafi for protocol-level use.
    pub fn afi_safi(&self) -> AfiSafi {
        AfiSafi::new(self.afi, self.safi)
    }
}

/// Peer configuration in YAML config file.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct PeerConfig {
    /// Peer IP address (IPv4 or IPv6). This IS the peer's identity — the
    /// config language keys peers by address (`peer <ADDR> { ... }`), matching
    /// Cisco/FRR/Junos/GoBGP convention. No separate symbolic name.
    #[serde(default)]
    pub address: String,
    /// Remote BGP port (default: 179).
    #[serde(default = "default_port")]
    pub port: u16,
    /// IdleHoldTime - delay before automatic restart (RFC 4271 8.1.1).
    /// None disables automatic restart. Some(0) = immediate restart. Some(n) = restart after n seconds.
    #[serde(default = "default_idle_hold_time")]
    pub idle_hold_time_secs: Option<u64>,
    #[serde(default = "default_damp_peer_oscillations")]
    pub damp_peer_oscillations: bool,
    #[serde(default = "default_allow_automatic_stop")]
    pub allow_automatic_stop: bool,
    #[serde(default = "default_passive_mode")]
    pub passive_mode: bool,
    /// DelayOpenTime - seconds to wait before sending OPEN (RFC 4271 8.1.1).
    /// None disables DelayOpen, Some(secs) enables it with given delay.
    #[serde(default)]
    pub delay_open_time_secs: Option<u64>,
    #[serde(default)]
    pub max_prefix: Option<MaxPrefixSetting>,
    /// SendNOTIFICATIONwithoutOPEN - allow sending NOTIFICATION before OPEN (RFC 4271 8.2.1.5).
    /// Default false: OPEN must be sent before NOTIFICATION.
    #[serde(default)]
    pub send_notification_without_open: bool,
    /// MinRouteAdvertisementIntervalTimer - minimum seconds between route advertisements (RFC 4271 9.2.1.1).
    /// Default: 30 seconds for eBGP, 5 seconds for iBGP (or disabled for iBGP).
    #[serde(default)]
    pub min_route_advertisement_interval_secs: Option<u64>,
    /// Graceful Restart configuration (RFC 4724)
    #[serde(default)]
    pub graceful_restart: GracefulRestartConfig,
    /// RFC 4456: Mark this peer as a route reflector client
    #[serde(default)]
    pub rr_client: bool,
    /// RFC 7947: Mark this peer as a route server client (transparency mode)
    #[serde(default)]
    pub rs_client: bool,
    /// RFC 4271 Section 6.3: Enforce first AS in AS_PATH matches peer AS (default: true)
    #[serde(default = "default_enforce_first_as")]
    pub enforce_first_as: bool,
    /// RFC 7911: ADD-PATH send mode for this peer
    #[serde(default)]
    pub add_path_send: AddPathSend,
    /// RFC 7911: Whether to accept multiple paths from this peer
    #[serde(default)]
    pub add_path_receive: bool,
    /// Expected peer ASN. When set, OPEN messages with mismatched ASN are rejected.
    #[serde(default)]
    pub asn: Option<u32>,
    /// Path to file containing TCP MD5 key (RFC 2385). File should be chmod 600.
    #[serde(default)]
    pub md5_key_file: Option<String>,
    /// Rewrite NEXT_HOP to local interface address when advertising to this peer.
    /// Useful for iBGP peers that lack a route to the original NEXT_HOP.
    #[serde(default)]
    pub next_hop_self: bool,
    /// RFC 8326: tag outbound routes with GRACEFUL_SHUTDOWN community (65535:0).
    /// Enable before taking the session down to let peers prefer alternate paths.
    #[serde(default)]
    pub graceful_shutdown: bool,
    /// RFC 5082: minimum inbound TTL for GTSM. None = disabled.
    /// 255 = directly connected peer, 254 = 1 hop away, etc.
    #[serde(default)]
    pub ttl_min: Option<u8>,
    /// Network interface for link-local IPv6 peers (e.g., "eth0").
    /// Required when address is a link-local IPv6 address (fe80::/10).
    #[serde(default)]
    pub interface: Option<String>,
    /// RFC 9494: Long-Lived Graceful Restart configuration
    #[serde(default)]
    pub llgr: Option<LlgrConfig>,
    /// RFC 8097: Attach RPKI Origin Validation State extended community on export
    #[serde(default)]
    pub send_rpki_community: bool,
    /// Additional AFI/SAFIs beyond default IPv4/IPv6 unicast (e.g. BGP-LS).
    /// Each entry can optionally override peer-level settings for that family.
    #[serde(default)]
    pub afi_safis: Vec<AfiSafiConfig>,
    /// Administratively shut down. When true the peer task does not auto-start
    /// and active sessions are stopped. Persisted so DisablePeer survives a
    /// SaveConfig + restart cycle.
    #[serde(default)]
    pub admin_down: bool,
}

fn default_idle_hold_time() -> Option<u64> {
    Some(30)
}

fn default_damp_peer_oscillations() -> bool {
    true
}

fn default_allow_automatic_stop() -> bool {
    true
}

fn default_passive_mode() -> bool {
    false
}

fn default_enforce_first_as() -> bool {
    true
}

fn default_enhanced_rr_stale_ttl() -> Option<u64> {
    Some(360)
}

fn default_port() -> u16 {
    179
}

impl PeerConfig {
    /// Returns the parsed peer IP, or None if `address` is not a valid IP.
    pub fn ip(&self) -> Option<IpAddr> {
        self.address.parse().ok()
    }

    /// Returns the socket address (IP + port) for this peer.
    pub fn socket_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        let ip: IpAddr = self.address.parse()?;
        Ok(SocketAddr::new(ip, self.port))
    }

    /// Returns the DelayOpenTime as a Duration, or None if disabled.
    pub fn delay_open_time(&self) -> Option<Duration> {
        self.delay_open_time_secs.map(Duration::from_secs)
    }

    /// RFC 4271 8.1.2: AllowAutomaticStart is true if IdleHoldTimer is configured.
    pub fn allow_automatic_start(&self) -> bool {
        self.idle_hold_time_secs.is_some()
    }

    /// Read MD5 key bytes from file, trimming whitespace/newlines.
    pub fn read_md5_key(&self) -> Option<Vec<u8>> {
        let path = self.md5_key_file.as_ref()?;
        match fs::read_to_string(path) {
            Ok(s) => Some(s.trim().as_bytes().to_vec()),
            Err(e) => {
                error!(peer_ip = %self.address, path = %path, error = %e, "failed to read MD5 key file");
                None
            }
        }
    }

    /// Deduplicated import-policy names across all families, in declaration order.
    pub fn import_policy_names(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for entry in &self.afi_safis {
            for name in &entry.import_policy {
                if seen.insert(name.clone()) {
                    out.push(name.clone());
                }
            }
        }
        out
    }

    /// Deduplicated export-policy names across all families, in declaration order.
    pub fn export_policy_names(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for entry in &self.afi_safis {
            for name in &entry.export_policy {
                if seen.insert(name.clone()) {
                    out.push(name.clone());
                }
            }
        }
        out
    }

    /// Extract plain AfiSafi list for protocol-level use (capability negotiation, etc.).
    pub fn afi_safi_list(&self) -> Vec<AfiSafi> {
        self.afi_safis.iter().map(|c| c.afi_safi()).collect()
    }

    /// Get the effective max_prefix setting for a given address family.
    /// Returns the per-family override if present, else the peer-level default.
    pub fn effective_max_prefix(&self, family: &AfiSafi) -> Option<MaxPrefixSetting> {
        self.afi_safis
            .iter()
            .find(|c| c.afi == family.afi && c.safi == family.safi)
            .and_then(|c| c.max_prefix)
            .or(self.max_prefix)
    }

    /// Import policy names attached to the given family. Empty if the family
    /// is not listed in `afi_safis` or has no import policies.
    pub fn import_policy_for(&self, afi: Afi, safi: Safi) -> &[String] {
        self.afi_safis
            .iter()
            .find(|c| c.afi == afi && c.safi == safi)
            .map(|c| c.import_policy.as_slice())
            .unwrap_or(&[])
    }

    /// Export policy names attached to the given family. Empty if the family
    /// is not listed in `afi_safis` or has no export policies.
    pub fn export_policy_for(&self, afi: Afi, safi: Safi) -> &[String] {
        self.afi_safis
            .iter()
            .find(|c| c.afi == afi && c.safi == safi)
            .map(|c| c.export_policy.as_slice())
            .unwrap_or(&[])
    }

    /// Validate peer configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.rr_client && self.rs_client {
            return Err("Peer cannot be both rr-client and rs-client".to_string());
        }
        // RFC 7947 2.3.2.2.2: Route server enforces send-only ADD-PATH mode with clients.
        if self.rs_client && self.add_path_receive {
            return Err(
                "rs-client peers must not use add-path-receive (route server uses send-only ADD-PATH mode per RFC 7947)".to_string(),
            );
        }
        if let Some(llgr) = &self.llgr {
            if let Some(stale_time) = llgr.stale_time {
                if stale_time > MAX_LLGR_STALE_TIME {
                    return Err(format!(
                        "LLGR stale_time {} exceeds 24-bit maximum ({})",
                        stale_time, MAX_LLGR_STALE_TIME
                    ));
                }
            }
            if llgr.enabled && !self.graceful_restart.enabled {
                return Err(
                    "LLGR requires graceful-restart to be enabled (RFC 9494 Section 4.5)"
                        .to_string(),
                );
            }
        }
        // Reject duplicate AFI/SAFI entries
        let mut seen = HashSet::new();
        for entry in &self.afi_safis {
            if !seen.insert((entry.afi, entry.safi)) {
                return Err(format!(
                    "duplicate afi-safis entry: {}/{}",
                    entry.afi, entry.safi
                ));
            }
        }
        Ok(())
    }
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            address: String::new(),
            port: default_port(),
            idle_hold_time_secs: default_idle_hold_time(),
            damp_peer_oscillations: default_damp_peer_oscillations(),
            allow_automatic_stop: default_allow_automatic_stop(),
            passive_mode: default_passive_mode(),
            delay_open_time_secs: None,
            max_prefix: None,
            send_notification_without_open: false,
            min_route_advertisement_interval_secs: None,
            graceful_restart: GracefulRestartConfig::default(),
            rr_client: false,
            rs_client: false,
            enforce_first_as: default_enforce_first_as(),
            add_path_send: AddPathSend::default(),
            add_path_receive: false,
            asn: None,
            md5_key_file: None,
            next_hop_self: false,
            graceful_shutdown: false,
            ttl_min: None,
            interface: None,
            llgr: None,
            send_rpki_community: false,
            afi_safis: Vec::new(),
            admin_down: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BmpConfig {
    pub address: String,
    /// Statistics reporting interval in seconds. 0 or None disables statistics.
    #[serde(default)]
    pub statistics_timeout: Option<u64>,
}

/// Transport type for RTR cache connections.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TransportType {
    #[default]
    Tcp,
    Ssh,
}

impl TransportType {
    /// Lowercase token as accepted by the config parser (inverse of FromStr).
    pub fn as_config_str(&self) -> &'static str {
        match self {
            TransportType::Tcp => "tcp",
            TransportType::Ssh => "ssh",
        }
    }
}

impl std::str::FromStr for TransportType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(TransportType::Tcp),
            "ssh" => Ok(TransportType::Ssh),
            _ => Err(format!("expected tcp|ssh, got '{}'", s)),
        }
    }
}

/// Configuration for an RPKI cache server (RTR, RFC 8210).
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RpkiCacheConfig {
    /// Address in "host:port" format (e.g. "127.0.0.1:8282").
    pub address: String,
    /// Preference tier. Lower values are preferred; only the lowest tier is active at startup.
    #[serde(default)]
    pub preference: u8,
    /// Transport type: "tcp" (default) or "ssh".
    #[serde(default)]
    pub transport: TransportType,
    /// SSH username (required when transport is "ssh").
    #[serde(default)]
    pub ssh_username: Option<String>,
    /// Path to SSH private key file (required when transport is "ssh").
    #[serde(default)]
    pub ssh_private_key_file: Option<String>,
    /// Path to OpenSSH known_hosts file. If omitted, host key is accepted without verification.
    #[serde(default)]
    pub ssh_known_hosts_file: Option<String>,
    /// Override cache-provided retry interval (seconds).
    #[serde(default)]
    pub retry_interval: Option<u64>,
    /// Override cache-provided refresh interval (seconds).
    #[serde(default)]
    pub refresh_interval: Option<u64>,
    /// Override cache-provided expire interval (seconds).
    #[serde(default)]
    pub expire_interval: Option<u64>,
}

/// Container for all defined sets used in policy matching (YAML representation)
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DefinedSetsConfig {
    #[serde(default)]
    pub prefix_sets: Vec<PrefixSetConfig>,
    #[serde(default)]
    pub neighbor_sets: Vec<NeighborSetConfig>,
    #[serde(default)]
    pub as_path_sets: Vec<AsPathSetConfig>,
    #[serde(default)]
    pub community_sets: Vec<CommunitySetConfig>,
    #[serde(default)]
    pub ext_community_sets: Vec<ExtCommunitySetConfig>,
    #[serde(default)]
    pub large_community_sets: Vec<LargeCommunitySetConfig>,
}

/// Named prefix set with masklength range support (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrefixSetConfig {
    pub name: String,
    pub prefixes: Vec<PrefixMatchConfig>,
}

/// Prefix with optional masklength range (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrefixMatchConfig {
    /// CIDR prefix like "10.0.0.0/8"
    pub prefix: String,
    /// Optional masklength range: "exact", "21..24", or "10.." for "le 10"
    #[serde(default)]
    pub masklength_range: Option<String>,
}

/// Named neighbor (IP address) set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NeighborSetConfig {
    pub name: String,
    pub neighbors: Vec<String>,
}

/// Named AS path set with regex patterns (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AsPathSetConfig {
    pub name: String,
    pub patterns: Vec<String>,
}

/// Named community set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommunitySetConfig {
    pub name: String,
    pub communities: Vec<String>,
}

/// Named extended community set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtCommunitySetConfig {
    pub name: String,
    pub ext_communities: Vec<String>,
}

/// Named large community set (YAML representation)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LargeCommunitySetConfig {
    pub name: String,
    pub large_communities: Vec<String>,
}

/// Enum wrapper for any defined set config type (used in management API)
#[derive(Debug, Clone)]
pub enum DefinedSetConfig {
    PrefixSet(PrefixSetConfig),
    NeighborSet(NeighborSetConfig),
    AsPathSet(AsPathSetConfig),
    CommunitySet(CommunitySetConfig),
    ExtCommunitySet(ExtCommunitySetConfig),
    LargeCommunitySet(LargeCommunitySetConfig),
}

impl DefinedSetConfig {
    pub fn name(&self) -> &str {
        match self {
            DefinedSetConfig::PrefixSet(c) => &c.name,
            DefinedSetConfig::NeighborSet(c) => &c.name,
            DefinedSetConfig::AsPathSet(c) => &c.name,
            DefinedSetConfig::CommunitySet(c) => &c.name,
            DefinedSetConfig::ExtCommunitySet(c) => &c.name,
            DefinedSetConfig::LargeCommunitySet(c) => &c.name,
        }
    }
}

/// Named policy definition from YAML config
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyDefinitionConfig {
    pub name: String,
    pub statements: Vec<StatementConfig>,
}

/// Statement definition from YAML
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatementConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub conditions: ConditionsConfig,
    pub actions: ActionsConfig,
}

/// Conditions that must match for a statement to apply
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConditionsConfig {
    #[serde(default)]
    pub match_prefix_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_neighbor_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_as_path_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_community_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_ext_community_set: Option<MatchSetRefConfig>,
    #[serde(default)]
    pub match_large_community_set: Option<MatchSetRefConfig>,

    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub neighbor: Option<String>,
    #[serde(default)]
    pub has_asn: Option<u32>,
    #[serde(default)]
    pub route_type: Option<String>,
    #[serde(default)]
    pub community: Option<String>,
    #[serde(default)]
    pub rpki_validation: Option<RpkiValidationConfig>,

    #[serde(default)]
    pub afi_safi: Option<String>,

    #[serde(default)]
    pub ls_nlri_type: Option<String>,
    #[serde(default)]
    pub ls_protocol_id: Option<String>,
    #[serde(default)]
    pub ls_instance_id: Option<u64>,
    #[serde(default)]
    pub ls_node_as: Option<u32>,
    #[serde(default)]
    pub ls_node_router_id: Option<String>,
}

/// Reference to a defined set with match option
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MatchSetRefConfig {
    pub set_name: String,
    #[serde(default = "default_match_option")]
    pub match_option: MatchOptionConfig,
}

fn default_match_option() -> MatchOptionConfig {
    MatchOptionConfig::Any
}

/// Match option for set-based conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchOptionConfig {
    /// At least one element in the set must match
    Any,
    /// All elements in the set must match
    All,
    /// No elements in the set must match (invert)
    Invert,
}

/// RFC 6811: RPKI validation state for policy config
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RpkiValidationConfig {
    Valid,
    Invalid,
    NotFound,
}

/// Actions to apply when conditions match
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ActionsConfig {
    #[serde(default)]
    pub accept: Option<bool>,
    #[serde(default)]
    pub reject: Option<bool>,
    #[serde(default)]
    pub local_pref: Option<LocalPrefActionConfig>,
    #[serde(default)]
    pub med: Option<MedActionConfig>,
    #[serde(default)]
    pub community: Option<CommunityActionConfig>,
    #[serde(default)]
    pub ext_community: Option<ExtCommunityActionConfig>,
    #[serde(default)]
    pub large_community: Option<LargeCommunityActionConfig>,
    #[serde(default)]
    pub set_rpki_state: Option<RpkiValidationConfig>,
}

/// Local preference action
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum LocalPrefActionConfig {
    /// Simple set: local-pref: 200
    Set(u32),
    /// Force override: local-pref: { value: 200, force: true }
    Force { value: u32, force: bool },
}

/// MED action
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MedActionConfig {
    /// Simple set: med: 100
    Set(u32),
    /// Remove: med: { remove: true }
    Remove { remove: bool },
}

/// Community action
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommunityActionConfig {
    /// Operation: "add", "remove", "replace"
    pub operation: String,
    /// Community values to add/remove/replace
    pub communities: Vec<String>,
}

/// Extended Community action
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtCommunityActionConfig {
    /// Operation: "add", "remove", "replace"
    pub operation: String,
    /// Extended community values to add/remove/replace
    pub ext_communities: Vec<String>,
}

/// Large Community action
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LargeCommunityActionConfig {
    /// Operation: "add", "remove", "replace"
    pub operation: String,
    /// Large community values to add/remove/replace (format: "GA:LD1:LD2")
    pub large_communities: Vec<String>,
}

/// BGP-LS operational configuration (RFC 9552).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BgpLsConfig {
    /// Maximum number of LS NLRIs in Loc-RIB. 0 = unlimited.
    #[serde(default)]
    pub max_ls_entries: u32,
    /// RFC 9552 Section 8.2.3: BGP-LS Instance-ID applied to locally originated NLRIs.
    #[serde(default)]
    pub instance_id: u64,
}

/// Telemetry (metric emission) configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TelemetryConfig {
    /// Log-emission format for metrics. None = metrics disabled.
    #[serde(default)]
    pub sink: Option<TelemetrySink>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetrySink {
    Json,
    CloudwatchEmf { namespace: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct BgpConfig {
    pub asn: u32,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    pub router_id: Ipv4Addr,
    #[serde(default = "default_grpc_listen_addr")]
    pub grpc_listen_addr: String,
    #[serde(default = "default_hold_time")]
    pub hold_time_secs: u64,
    #[serde(default = "default_connect_retry_time")]
    pub connect_retry_secs: u64,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub bmp_servers: Vec<BmpConfig>,
    /// RPKI cache servers for RTR (RFC 8210).
    #[serde(default)]
    pub rpki_caches: Vec<RpkiCacheConfig>,
    /// BMP sysName (RFC 7854). Defaults to "bgpgg {router_id}".
    #[serde(default)]
    pub sys_name: Option<String>,
    /// BMP sysDescr (RFC 7854). Defaults to "bgpgg version {VERSION}".
    #[serde(default)]
    pub sys_descr: Option<String>,
    /// Log level: "error", "warn", "info" (default), "debug"
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Defined sets for policy matching
    #[serde(default)]
    pub defined_sets: DefinedSetsConfig,
    /// Policy definitions
    #[serde(default)]
    pub policy_definitions: Vec<PolicyDefinitionConfig>,
    /// RFC 4456: Cluster ID for route reflector. Defaults to router_id if not set.
    #[serde(default)]
    pub cluster_id: Option<Ipv4Addr>,
    /// RFC 9494: Server-level LLGR configuration. Peers inherit this unless overridden.
    #[serde(default)]
    pub llgr: Option<LlgrConfig>,
    /// RFC 7313: Max seconds to retain stale routes after BoRR. None = no limit.
    #[serde(default = "default_enhanced_rr_stale_ttl")]
    pub enhanced_rr_stale_ttl: Option<u64>,
    /// BGP-LS operational configuration (RFC 9552).
    #[serde(default)]
    pub bgp_ls: BgpLsConfig,
    /// Static prefixes injected into the loc-rib at startup. Each entry pairs a
    /// prefix with its forwarding next-hop. Validated when the daemon parses
    /// the config; bad entries log a warning and are skipped at injection time.
    #[serde(default)]
    pub originate: Vec<OriginateRoute>,
    /// Metric emission. None = no telemetry.
    #[serde(default)]
    pub telemetry: Option<TelemetryConfig>,
}

fn default_listen_addr() -> String {
    "0.0.0.0:179".to_string()
}

fn default_grpc_listen_addr() -> String {
    "127.0.0.1:50051".to_string()
}

fn default_hold_time() -> u64 {
    180
}

fn default_connect_retry_time() -> u64 {
    30
}

fn default_log_level() -> String {
    "info".to_string()
}

impl BgpConfig {
    /// Create a new configuration
    pub fn new(asn: u32, listen_addr: &str, router_id: Ipv4Addr, hold_time_secs: u64) -> Self {
        BgpConfig {
            asn,
            listen_addr: listen_addr.to_string(),
            router_id,
            grpc_listen_addr: default_grpc_listen_addr(),
            hold_time_secs,
            connect_retry_secs: default_connect_retry_time(),
            peers: Vec::new(),
            bmp_servers: Vec::new(),
            rpki_caches: Vec::new(),
            sys_name: None,
            sys_descr: None,
            log_level: default_log_level(),
            defined_sets: DefinedSetsConfig::default(),
            policy_definitions: Vec::new(),
            cluster_id: None,
            llgr: None,
            enhanced_rr_stale_ttl: default_enhanced_rr_stale_ttl(),
            bgp_ls: BgpLsConfig::default(),
            originate: Vec::new(),
            telemetry: None,
        }
    }

    /// RFC 4456: Get effective cluster_id (defaults to router_id)
    pub fn cluster_id(&self) -> Ipv4Addr {
        self.cluster_id.unwrap_or(self.router_id)
    }

    /// Get BMP sysName (RFC 7854). Returns configured value or default.
    pub fn sys_name(&self) -> String {
        self.sys_name
            .clone()
            .unwrap_or_else(|| format!("bgpgg {}", self.router_id))
    }

    /// Get BMP sysDescr (RFC 7854). Returns configured value or default.
    pub fn sys_descr(&self) -> String {
        self.sys_descr
            .clone()
            .unwrap_or_else(|| format!("bgpgg version {}", env!("CARGO_PKG_VERSION")))
    }

    /// Load configuration from a rogg.conf file.
    pub fn from_conf_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        Self::from_conf_str(&contents)
    }

    /// Append a peer. Errors if the address is not a valid IP or if a
    /// peer with that IP is already present.
    pub fn insert_peer(&mut self, cfg: PeerConfig) -> Result<(), String> {
        let peer_ip: IpAddr = cfg
            .address
            .parse()
            .map_err(|e| format!("peer address '{}' is not a valid IP: {}", cfg.address, e))?;
        if self.find_peer(peer_ip).is_some() {
            return Err(format!("duplicate peer address '{}'", peer_ip));
        }
        self.peers.push(cfg);
        Ok(())
    }

    /// Look up a peer's config by IP. O(N) scan -- peer counts are
    /// small (typically <100, ~1000 for big route reflectors) so this
    /// is cheaper than a HashMap for our use.
    pub fn find_peer(&self, ip: IpAddr) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| p.ip() == Some(ip))
    }

    pub fn find_peer_mut(&mut self, ip: IpAddr) -> Option<&mut PeerConfig> {
        self.peers.iter_mut().find(|p| p.ip() == Some(ip))
    }

    /// Remove a peer by IP. Returns the removed config, or None if absent.
    pub fn remove_peer(&mut self, ip: IpAddr) -> Option<PeerConfig> {
        let pos = self.peers.iter().position(|p| p.ip() == Some(ip))?;
        Some(self.peers.remove(pos))
    }

    /// Parse a rogg.conf string into a BgpConfig.
    pub fn from_conf_str(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let root = language::parse(input)?;
        let Service::Bgp(bgp) = root.services.first().ok_or("missing 'service bgp' block")?;

        let mut config = BgpConfig::default();
        let mut has_asn = false;
        let mut has_router_id = false;

        for setting in &bgp.settings {
            match setting {
                Setting::Asn(val) => {
                    config.asn = *val;
                    has_asn = true;
                }
                Setting::RouterId(val) => {
                    config.router_id = *val;
                    has_router_id = true;
                }
                Setting::ListenAddr(val) => config.listen_addr = val.clone(),
                Setting::GrpcListenAddr(val) => config.grpc_listen_addr = val.clone(),
                Setting::LogLevel(val) => config.log_level = val.clone(),
                Setting::HoldTime(val) => config.hold_time_secs = *val,
                Setting::ConnectRetry(val) => config.connect_retry_secs = *val,
                Setting::ClusterId(val) => config.cluster_id = Some(*val),
                Setting::SysName(val) => config.sys_name = Some(val.clone()),
                Setting::SysDescr(val) => config.sys_descr = Some(val.clone()),
                Setting::EnhancedRrStaleTtl(val) => config.enhanced_rr_stale_ttl = Some(*val),
                Setting::Originate(route) => config.originate.push(route.clone()),
                _ => {}
            }
        }

        if let Some(bgp_ls) = &bgp.bgp_ls {
            config.bgp_ls.instance_id = bgp_ls.instance_id;
        }

        if let Some(telemetry_block) = &bgp.telemetry {
            config.telemetry = Some(telemetry_config_from_block(telemetry_block));
        }

        if !has_asn {
            return Err("missing required field 'asn'".into());
        }
        if !has_router_id {
            return Err("missing required field 'router-id'".into());
        }

        for peer_block in &bgp.peers {
            config.insert_peer(peer_config_from_block(peer_block))?;
        }

        for prefix_list_block in &bgp.prefix_lists {
            config
                .defined_sets
                .prefix_sets
                .push(prefix_list_block_to_set(prefix_list_block));
        }
        for block in &bgp.neighbor_sets {
            config
                .defined_sets
                .neighbor_sets
                .push(neighbor_set_block_to_config(block));
        }
        for block in &bgp.as_path_sets {
            config
                .defined_sets
                .as_path_sets
                .push(as_path_set_block_to_config(block));
        }
        for block in &bgp.community_sets {
            config
                .defined_sets
                .community_sets
                .push(community_set_block_to_config(block));
        }
        for block in &bgp.ext_community_sets {
            config
                .defined_sets
                .ext_community_sets
                .push(ext_community_set_block_to_config(block));
        }
        for block in &bgp.large_community_sets {
            config
                .defined_sets
                .large_community_sets
                .push(large_community_set_block_to_config(block));
        }

        for policy_block in &bgp.policies {
            config
                .policy_definitions
                .push(policy_block_to_definition(policy_block)?);
        }

        for bmp_block in &bgp.bmp_servers {
            config.bmp_servers.push(bmp_config_from_block(bmp_block));
        }

        for rpki_block in &bgp.rpki_caches {
            config.rpki_caches.push(rpki_config_from_block(rpki_block));
        }

        Ok(config)
    }
}

impl Default for BgpConfig {
    fn default() -> Self {
        BgpConfig {
            asn: 65000,
            listen_addr: "0.0.0.0:179".to_string(),
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            grpc_listen_addr: default_grpc_listen_addr(),
            hold_time_secs: default_hold_time(),
            connect_retry_secs: default_connect_retry_time(),
            peers: Vec::new(),
            bmp_servers: Vec::new(),
            rpki_caches: Vec::new(),
            sys_name: None,
            sys_descr: None,
            log_level: default_log_level(),
            defined_sets: DefinedSetsConfig::default(),
            policy_definitions: Vec::new(),
            cluster_id: None,
            llgr: None,
            enhanced_rr_stale_ttl: default_enhanced_rr_stale_ttl(),
            bgp_ls: BgpLsConfig::default(),
            originate: Vec::new(),
            telemetry: None,
        }
    }
}

impl BgpConfig {
    /// Render this config back into a brace-format `rogg.conf` string. Used by the
    /// daemon's `GetRunningConfig` RPC so ggsh can fetch the running state.
    ///
    /// Only fields covered by the current config language grammar are emitted;
    /// richer BgpConfig-only fields (bmp_servers, defined_sets, etc.) are omitted
    /// because the language doesn't express them yet.
    pub fn to_conf_str(&self) -> String {
        let body = self.to_bgp_service_body();
        let root = crate::language::Root {
            services: vec![crate::language::Service::Bgp(body)],
        };
        root.to_string()
    }

    /// Convert this BgpConfig back into a language-level `BgpServiceBody` AST.
    /// Settings at their default values are omitted so a parse-then-render
    /// round-trip preserves the source file's explicit-setting set.
    pub fn to_bgp_service_body(&self) -> BgpServiceBody {
        let mut settings = vec![Setting::Asn(self.asn), Setting::RouterId(self.router_id)];
        if self.listen_addr != default_listen_addr() {
            settings.push(Setting::ListenAddr(self.listen_addr.clone()));
        }
        if self.grpc_listen_addr != default_grpc_listen_addr() {
            settings.push(Setting::GrpcListenAddr(self.grpc_listen_addr.clone()));
        }
        if self.log_level != default_log_level() {
            settings.push(Setting::LogLevel(self.log_level.clone()));
        }
        if self.hold_time_secs != default_hold_time() {
            settings.push(Setting::HoldTime(self.hold_time_secs));
        }
        if self.connect_retry_secs != default_connect_retry_time() {
            settings.push(Setting::ConnectRetry(self.connect_retry_secs));
        }
        if let Some(cid) = self.cluster_id {
            settings.push(Setting::ClusterId(cid));
        }
        if let Some(name) = &self.sys_name {
            settings.push(Setting::SysName(name.clone()));
        }
        if let Some(descr) = &self.sys_descr {
            settings.push(Setting::SysDescr(descr.clone()));
        }
        if let Some(ttl) = self.enhanced_rr_stale_ttl {
            if Some(ttl) != default_enhanced_rr_stale_ttl() {
                settings.push(Setting::EnhancedRrStaleTtl(ttl));
            }
        }
        for route in &self.originate {
            settings.push(Setting::Originate(route.clone()));
        }

        let peers = self
            .peers
            .iter()
            .map(|p| PeerBlock {
                address: p.address.clone(),
                settings: peer_settings_from_config(p),
                families: families_from_peer_config(p),
            })
            .collect();

        // Prefix sets: emit only entries the grammar can express. Sets that
        // become empty after filtering masklength-range entries are dropped.
        let prefix_lists = self
            .defined_sets
            .prefix_sets
            .iter()
            .filter_map(prefix_set_to_block)
            .collect();
        let neighbor_sets = self
            .defined_sets
            .neighbor_sets
            .iter()
            .map(neighbor_set_config_to_block)
            .collect();
        let as_path_sets = self
            .defined_sets
            .as_path_sets
            .iter()
            .map(as_path_set_config_to_block)
            .collect();
        let community_sets = self
            .defined_sets
            .community_sets
            .iter()
            .map(community_set_config_to_block)
            .collect();
        let ext_community_sets = self
            .defined_sets
            .ext_community_sets
            .iter()
            .map(ext_community_set_config_to_block)
            .collect();
        let large_community_sets = self
            .defined_sets
            .large_community_sets
            .iter()
            .map(large_community_set_config_to_block)
            .collect();

        // Policies: skip any whose statements fall outside the rogg.conf
        // subset (rich condition kinds, attribute-rewriting actions, etc.).
        let policies = self
            .policy_definitions
            .iter()
            .filter_map(policy_definition_to_block)
            .collect();

        let bmp_servers = self.bmp_servers.iter().map(bmp_block_from_config).collect();

        let rpki_caches = self
            .rpki_caches
            .iter()
            .map(rpki_block_from_config)
            .collect();

        let bgp_ls = if self.bgp_ls.instance_id != 0 {
            Some(BgpLsBlock {
                instance_id: self.bgp_ls.instance_id,
            })
        } else {
            None
        };

        let telemetry = self.telemetry.as_ref().map(telemetry_block_from_config);

        BgpServiceBody {
            settings,
            peers,
            policies,
            prefix_lists,
            neighbor_sets,
            as_path_sets,
            community_sets,
            ext_community_sets,
            large_community_sets,
            bmp_servers,
            rpki_caches,
            bgp_ls,
            telemetry,
        }
    }
}

/// Emit the subset of PeerConfig fields that the language currently represents.
/// `address` is the block header (`peer <ADDR> { ... }`) and is NOT emitted as
/// an inner setting.
fn peer_settings_from_config(peer: &PeerConfig) -> Vec<Setting> {
    let mut out = Vec::new();
    if let Some(asn) = peer.asn {
        out.push(Setting::RemoteAs(asn));
    }
    if peer.port != default_port() {
        out.push(Setting::Port(peer.port));
    }
    if let Some(iface) = &peer.interface {
        out.push(Setting::Interface(iface.clone()));
    }
    if let Some(md5) = &peer.md5_key_file {
        out.push(Setting::Md5KeyFile(md5.clone()));
    }
    if let Some(ttl) = peer.ttl_min {
        out.push(Setting::TtlMin(ttl));
    }
    if peer.next_hop_self {
        out.push(Setting::NextHopSelf(true));
    }
    if peer.passive_mode {
        out.push(Setting::Passive(true));
    }
    if peer.rr_client {
        out.push(Setting::RrClient(true));
    }
    if peer.rs_client {
        out.push(Setting::RsClient(true));
    }
    if peer.graceful_shutdown {
        out.push(Setting::GracefulShutdown(true));
    }
    if let Some(v) = peer.delay_open_time_secs {
        out.push(Setting::DelayOpenTimeSecs(v));
    }
    if let Some(v) = peer.idle_hold_time_secs {
        if Some(v) != default_idle_hold_time() {
            out.push(Setting::IdleHoldTimeSecs(v));
        }
    }
    if peer.damp_peer_oscillations != default_damp_peer_oscillations() {
        out.push(Setting::DampPeerOscillations(peer.damp_peer_oscillations));
    }
    if peer.allow_automatic_stop != default_allow_automatic_stop() {
        out.push(Setting::AllowAutomaticStop(peer.allow_automatic_stop));
    }
    if peer.send_notification_without_open {
        out.push(Setting::SendNotificationWithoutOpen(true));
    }
    if let Some(v) = peer.min_route_advertisement_interval_secs {
        out.push(Setting::MinRouteAdvertisementIntervalSecs(v));
    }
    if peer.enforce_first_as != default_enforce_first_as() {
        out.push(Setting::EnforceFirstAs(peer.enforce_first_as));
    }
    if peer.send_rpki_community {
        out.push(Setting::SendRpkiCommunity(true));
    }
    if peer.admin_down {
        out.push(Setting::AdminDown(true));
    }
    out
}

fn bmp_block_from_config(cfg: &BmpConfig) -> BmpServerBlock {
    BmpServerBlock {
        address: cfg.address.clone(),
        statistics_timeout: cfg.statistics_timeout,
    }
}

fn telemetry_config_from_block(block: &TelemetryBlock) -> TelemetryConfig {
    let sink = if block.json {
        Some(TelemetrySink::Json)
    } else {
        block
            .cloudwatch_emf
            .as_ref()
            .map(|emf| TelemetrySink::CloudwatchEmf {
                namespace: emf.namespace.clone(),
            })
    };
    TelemetryConfig { sink }
}

fn telemetry_block_from_config(cfg: &TelemetryConfig) -> TelemetryBlock {
    match &cfg.sink {
        Some(TelemetrySink::Json) => TelemetryBlock {
            json: true,
            cloudwatch_emf: None,
        },
        Some(TelemetrySink::CloudwatchEmf { namespace }) => TelemetryBlock {
            json: false,
            cloudwatch_emf: Some(CloudwatchEmfBlock {
                namespace: namespace.clone(),
            }),
        },
        None => TelemetryBlock::default(),
    }
}

fn bmp_config_from_block(block: &BmpServerBlock) -> BmpConfig {
    BmpConfig {
        address: block.address.clone(),
        statistics_timeout: block.statistics_timeout,
    }
}

fn rpki_block_from_config(cfg: &RpkiCacheConfig) -> RpkiCacheBlock {
    // Emit non-default scalars only, so rendered config stays compact.
    let transport = if matches!(cfg.transport, TransportType::Tcp) {
        None
    } else {
        Some(cfg.transport.clone())
    };
    let preference = if cfg.preference == 0 {
        None
    } else {
        Some(cfg.preference)
    };
    RpkiCacheBlock {
        address: cfg.address.clone(),
        preference,
        transport,
        ssh_username: cfg.ssh_username.clone(),
        ssh_private_key_file: cfg.ssh_private_key_file.clone(),
        ssh_known_hosts_file: cfg.ssh_known_hosts_file.clone(),
        retry_interval: cfg.retry_interval,
        refresh_interval: cfg.refresh_interval,
        expire_interval: cfg.expire_interval,
    }
}

fn rpki_config_from_block(block: &RpkiCacheBlock) -> RpkiCacheConfig {
    RpkiCacheConfig {
        address: block.address.clone(),
        preference: block.preference.unwrap_or(0),
        transport: block.transport.clone().unwrap_or_default(),
        ssh_username: block.ssh_username.clone(),
        ssh_private_key_file: block.ssh_private_key_file.clone(),
        ssh_known_hosts_file: block.ssh_known_hosts_file.clone(),
        retry_interval: block.retry_interval,
        refresh_interval: block.refresh_interval,
        expire_interval: block.expire_interval,
    }
}

/// Build a PeerConfig from a typed PeerBlock. Family blocks become per-(afi,
/// safi) entries in `afi_safis`, with `import policy NAME` / `export policy
/// NAME` directives flattened into the matching entry's `import_policy` /
/// `export_policy` lists.
fn peer_config_from_block(peer: &PeerBlock) -> PeerConfig {
    let mut config = PeerConfig {
        address: peer.address.clone(),
        ..PeerConfig::default()
    };
    for setting in &peer.settings {
        match setting {
            Setting::RemoteAs(val) => config.asn = Some(*val),
            Setting::Port(val) => config.port = *val,
            Setting::Interface(val) => config.interface = Some(val.clone()),
            Setting::Md5KeyFile(val) => config.md5_key_file = Some(val.clone()),
            Setting::TtlMin(val) => config.ttl_min = Some(*val),
            Setting::NextHopSelf(val) => config.next_hop_self = *val,
            Setting::Passive(val) => config.passive_mode = *val,
            Setting::RrClient(val) => config.rr_client = *val,
            Setting::RsClient(val) => config.rs_client = *val,
            Setting::GracefulShutdown(val) => config.graceful_shutdown = *val,
            Setting::DelayOpenTimeSecs(val) => config.delay_open_time_secs = Some(*val),
            Setting::IdleHoldTimeSecs(val) => config.idle_hold_time_secs = Some(*val),
            Setting::DampPeerOscillations(val) => config.damp_peer_oscillations = *val,
            Setting::AllowAutomaticStop(val) => config.allow_automatic_stop = *val,
            Setting::SendNotificationWithoutOpen(val) => {
                config.send_notification_without_open = *val
            }
            Setting::MinRouteAdvertisementIntervalSecs(val) => {
                config.min_route_advertisement_interval_secs = Some(*val)
            }
            Setting::EnforceFirstAs(val) => config.enforce_first_as = *val,
            Setting::SendRpkiCommunity(val) => config.send_rpki_community = *val,
            Setting::AdminDown(val) => config.admin_down = *val,
            _ => {}
        }
    }

    for family in &peer.families {
        let entry = afi_safi_entry_mut(&mut config.afi_safis, family.afi, family.safi);
        for directive in &family.directives {
            match directive {
                FamilyDirective::ImportPolicy(name) => entry.import_policy.push(name.clone()),
                FamilyDirective::ExportPolicy(name) => entry.export_policy.push(name.clone()),
                FamilyDirective::MaxPrefix { limit, action } => {
                    entry.max_prefix = Some(MaxPrefixSetting {
                        limit: *limit,
                        action: match action {
                            MaxPrefixActionKind::Terminate => MaxPrefixAction::Terminate,
                            MaxPrefixActionKind::Discard => MaxPrefixAction::Discard,
                        },
                    });
                }
                FamilyDirective::AddPathSend(mode) => {
                    entry.add_path_send = Some(match mode {
                        LangAddPathSendMode::All => AddPathSend::All,
                        LangAddPathSendMode::Disabled => AddPathSend::Disabled,
                    });
                }
            }
        }
    }

    config
}

/// Mutable reference to the `AfiSafiConfig` matching `(afi, safi)`. Inserts
/// a new entry if none exists.
pub fn afi_safi_entry_mut(
    afi_safis: &mut Vec<AfiSafiConfig>,
    afi: Afi,
    safi: Safi,
) -> &mut AfiSafiConfig {
    if let Some(idx) = afi_safis
        .iter()
        .position(|c| c.afi == afi && c.safi == safi)
    {
        return &mut afi_safis[idx];
    }
    afi_safis.push(AfiSafiConfig::new(afi, safi));
    afi_safis.last_mut().unwrap()
}

/// Convert a `PolicyBlock` into a runtime `PolicyDefinitionConfig`.
/// `match <set> -> ACTION` becomes a statement with a `match_prefix_set`
/// condition; `default -> ACTION` becomes a statement with no conditions.
/// Action strings outside `{accept, reject}` are a parse error.
fn policy_block_to_definition(block: &PolicyBlock) -> Result<PolicyDefinitionConfig, String> {
    let mut statements = Vec::with_capacity(block.rules.len());
    for rule in &block.rules {
        match rule {
            PolicyRule::Match { set_name, action } => {
                statements.push(StatementConfig {
                    name: None,
                    conditions: ConditionsConfig {
                        match_prefix_set: Some(MatchSetRefConfig {
                            set_name: set_name.clone(),
                            match_option: MatchOptionConfig::Any,
                        }),
                        ..Default::default()
                    },
                    actions: action_to_config(action)?,
                });
            }
            PolicyRule::Default { action } => {
                statements.push(StatementConfig {
                    name: None,
                    conditions: ConditionsConfig::default(),
                    actions: action_to_config(action)?,
                });
            }
            PolicyRule::Statement(stmt) => {
                statements.push(statement_block_to_config(stmt)?);
            }
        }
    }
    Ok(PolicyDefinitionConfig {
        name: block.name.clone(),
        statements,
    })
}

fn statement_block_to_config(block: &StatementBlock) -> Result<StatementConfig, String> {
    let mut conditions = ConditionsConfig::default();
    for clause in &block.matches {
        apply_match_clause(&mut conditions, clause)?;
    }
    let mut actions = ActionsConfig::default();
    for clause in &block.sets {
        apply_set_clause(&mut actions, clause);
    }
    match block.disposition {
        Some(Disposition::Accept) => actions.accept = Some(true),
        Some(Disposition::Reject) => actions.reject = Some(true),
        None => {}
    }
    Ok(StatementConfig {
        name: block.name.clone(),
        conditions,
        actions,
    })
}

fn apply_match_clause(
    conditions: &mut ConditionsConfig,
    clause: &MatchClause,
) -> Result<(), String> {
    match clause {
        MatchClause::PrefixSet(r) => conditions.match_prefix_set = Some(match_set_ref_to_config(r)),
        MatchClause::NeighborSet(r) => {
            conditions.match_neighbor_set = Some(match_set_ref_to_config(r))
        }
        MatchClause::AsPathSet(r) => {
            conditions.match_as_path_set = Some(match_set_ref_to_config(r))
        }
        MatchClause::CommunitySet(r) => {
            conditions.match_community_set = Some(match_set_ref_to_config(r))
        }
        MatchClause::ExtCommunitySet(r) => {
            conditions.match_ext_community_set = Some(match_set_ref_to_config(r))
        }
        MatchClause::LargeCommunitySet(r) => {
            conditions.match_large_community_set = Some(match_set_ref_to_config(r))
        }
        MatchClause::Prefix(s) => conditions.prefix = Some(s.clone()),
        MatchClause::Neighbor(s) => conditions.neighbor = Some(s.clone()),
        MatchClause::HasAsn(v) => conditions.has_asn = Some(*v),
        MatchClause::RouteType(s) => conditions.route_type = Some(s.clone()),
        MatchClause::Community(s) => conditions.community = Some(s.clone()),
        MatchClause::Rpki(v) => conditions.rpki_validation = Some(rpki_kind_to_config(*v)),
        MatchClause::AfiSafi(s) => conditions.afi_safi = Some(s.clone()),
        MatchClause::LsNlriType(s) => conditions.ls_nlri_type = Some(s.clone()),
        MatchClause::LsProtocolId(s) => conditions.ls_protocol_id = Some(s.clone()),
        MatchClause::LsInstanceId(v) => conditions.ls_instance_id = Some(*v),
        MatchClause::LsNodeAs(v) => conditions.ls_node_as = Some(*v),
        MatchClause::LsNodeRouterId(s) => conditions.ls_node_router_id = Some(s.clone()),
    }
    Ok(())
}

fn apply_set_clause(actions: &mut ActionsConfig, clause: &SetClause) {
    match clause {
        SetClause::LocalPref { value, force } => {
            actions.local_pref = Some(if *force {
                LocalPrefActionConfig::Force {
                    value: *value,
                    force: true,
                }
            } else {
                LocalPrefActionConfig::Set(*value)
            });
        }
        SetClause::Med(MedSet::Set(v)) => actions.med = Some(MedActionConfig::Set(*v)),
        SetClause::Med(MedSet::Remove) => {
            actions.med = Some(MedActionConfig::Remove { remove: true })
        }
        SetClause::Community(op) => {
            actions.community = Some(CommunityActionConfig {
                operation: community_op_to_str(op.op).to_string(),
                communities: op.values.clone(),
            });
        }
        SetClause::ExtCommunity(op) => {
            actions.ext_community = Some(ExtCommunityActionConfig {
                operation: community_op_to_str(op.op).to_string(),
                ext_communities: op.values.clone(),
            });
        }
        SetClause::LargeCommunity(op) => {
            actions.large_community = Some(LargeCommunityActionConfig {
                operation: community_op_to_str(op.op).to_string(),
                large_communities: op.values.clone(),
            });
        }
        SetClause::SetRpkiState(v) => actions.set_rpki_state = Some(rpki_kind_to_config(*v)),
    }
}

fn match_set_ref_to_config(r: &MatchSetRef) -> MatchSetRefConfig {
    MatchSetRefConfig {
        set_name: r.set_name.clone(),
        match_option: match r.option {
            MatchOptionKind::Any => MatchOptionConfig::Any,
            MatchOptionKind::All => MatchOptionConfig::All,
            MatchOptionKind::Invert => MatchOptionConfig::Invert,
        },
    }
}

fn match_set_ref_from_config(c: &MatchSetRefConfig) -> MatchSetRef {
    MatchSetRef {
        set_name: c.set_name.clone(),
        option: match c.match_option {
            MatchOptionConfig::Any => MatchOptionKind::Any,
            MatchOptionConfig::All => MatchOptionKind::All,
            MatchOptionConfig::Invert => MatchOptionKind::Invert,
        },
    }
}

fn rpki_kind_to_config(v: RpkiValidationKind) -> RpkiValidationConfig {
    match v {
        RpkiValidationKind::Valid => RpkiValidationConfig::Valid,
        RpkiValidationKind::Invalid => RpkiValidationConfig::Invalid,
        RpkiValidationKind::NotFound => RpkiValidationConfig::NotFound,
    }
}

fn rpki_config_to_kind(v: RpkiValidationConfig) -> RpkiValidationKind {
    match v {
        RpkiValidationConfig::Valid => RpkiValidationKind::Valid,
        RpkiValidationConfig::Invalid => RpkiValidationKind::Invalid,
        RpkiValidationConfig::NotFound => RpkiValidationKind::NotFound,
    }
}

fn community_op_to_str(op: CommunityOpKind) -> &'static str {
    match op {
        CommunityOpKind::Add => "add",
        CommunityOpKind::Remove => "remove",
        CommunityOpKind::Replace => "replace",
    }
}

fn community_op_from_str(s: &str) -> Option<CommunityOpKind> {
    match s {
        "add" => Some(CommunityOpKind::Add),
        "remove" => Some(CommunityOpKind::Remove),
        "replace" => Some(CommunityOpKind::Replace),
        _ => None,
    }
}

/// Convert a runtime `PolicyDefinitionConfig` back into a `PolicyBlock`.
/// Statements that fit the simple shorthand (single `match_prefix_set`
/// with `Any` or no conditions, action exactly `accept` xor `reject`,
/// no transformations, no statement name) emit as `match` / `default`.
/// Anything else emits as a full `statement { ... }` block.
fn policy_definition_to_block(def: &PolicyDefinitionConfig) -> Option<PolicyBlock> {
    let mut rules = Vec::with_capacity(def.statements.len());
    for stmt in &def.statements {
        if let Some(rule) = shorthand_for(stmt) {
            rules.push(rule);
        } else {
            let block = statement_config_to_block(stmt)?;
            rules.push(PolicyRule::Statement(block));
        }
    }
    Some(PolicyBlock {
        name: def.name.clone(),
        rules,
    })
}

/// Try to express `stmt` as a `match SET ACTION` or `default ACTION`
/// shorthand. Returns `None` if any statement field falls outside the
/// shorthand subset.
fn shorthand_for(stmt: &StatementConfig) -> Option<PolicyRule> {
    if stmt.name.is_some() {
        return None;
    }
    let conds = &stmt.conditions;
    let has_other_conditions = conds.match_neighbor_set.is_some()
        || conds.match_as_path_set.is_some()
        || conds.match_community_set.is_some()
        || conds.match_ext_community_set.is_some()
        || conds.match_large_community_set.is_some()
        || conds.prefix.is_some()
        || conds.neighbor.is_some()
        || conds.has_asn.is_some()
        || conds.route_type.is_some()
        || conds.community.is_some()
        || conds.rpki_validation.is_some()
        || conds.afi_safi.is_some()
        || conds.ls_nlri_type.is_some()
        || conds.ls_protocol_id.is_some()
        || conds.ls_instance_id.is_some()
        || conds.ls_node_as.is_some()
        || conds.ls_node_router_id.is_some();
    if has_other_conditions {
        return None;
    }
    let action = config_to_action(&stmt.actions)?;
    match &conds.match_prefix_set {
        Some(set_ref) if set_ref.match_option == MatchOptionConfig::Any => {
            Some(PolicyRule::Match {
                set_name: set_ref.set_name.clone(),
                action,
            })
        }
        Some(_) => None,
        None => Some(PolicyRule::Default { action }),
    }
}

/// Convert a `StatementConfig` to a `StatementBlock`. Action fields that
/// have no grammar (e.g. empty community op string) are dropped via `?`.
fn statement_config_to_block(stmt: &StatementConfig) -> Option<StatementBlock> {
    let mut matches = Vec::new();
    let conds = &stmt.conditions;
    if let Some(r) = &conds.match_prefix_set {
        matches.push(MatchClause::PrefixSet(match_set_ref_from_config(r)));
    }
    if let Some(r) = &conds.match_neighbor_set {
        matches.push(MatchClause::NeighborSet(match_set_ref_from_config(r)));
    }
    if let Some(r) = &conds.match_as_path_set {
        matches.push(MatchClause::AsPathSet(match_set_ref_from_config(r)));
    }
    if let Some(r) = &conds.match_community_set {
        matches.push(MatchClause::CommunitySet(match_set_ref_from_config(r)));
    }
    if let Some(r) = &conds.match_ext_community_set {
        matches.push(MatchClause::ExtCommunitySet(match_set_ref_from_config(r)));
    }
    if let Some(r) = &conds.match_large_community_set {
        matches.push(MatchClause::LargeCommunitySet(match_set_ref_from_config(r)));
    }
    if let Some(s) = &conds.prefix {
        matches.push(MatchClause::Prefix(s.clone()));
    }
    if let Some(s) = &conds.neighbor {
        matches.push(MatchClause::Neighbor(s.clone()));
    }
    if let Some(v) = conds.has_asn {
        matches.push(MatchClause::HasAsn(v));
    }
    if let Some(s) = &conds.route_type {
        matches.push(MatchClause::RouteType(s.clone()));
    }
    if let Some(s) = &conds.community {
        matches.push(MatchClause::Community(s.clone()));
    }
    if let Some(v) = conds.rpki_validation {
        matches.push(MatchClause::Rpki(rpki_config_to_kind(v)));
    }
    if let Some(s) = &conds.afi_safi {
        matches.push(MatchClause::AfiSafi(s.clone()));
    }
    if let Some(s) = &conds.ls_nlri_type {
        matches.push(MatchClause::LsNlriType(s.clone()));
    }
    if let Some(s) = &conds.ls_protocol_id {
        matches.push(MatchClause::LsProtocolId(s.clone()));
    }
    if let Some(v) = conds.ls_instance_id {
        matches.push(MatchClause::LsInstanceId(v));
    }
    if let Some(v) = conds.ls_node_as {
        matches.push(MatchClause::LsNodeAs(v));
    }
    if let Some(s) = &conds.ls_node_router_id {
        matches.push(MatchClause::LsNodeRouterId(s.clone()));
    }

    let mut sets = Vec::new();
    let acts = &stmt.actions;
    if let Some(lp) = &acts.local_pref {
        sets.push(match lp {
            LocalPrefActionConfig::Set(v) => SetClause::LocalPref {
                value: *v,
                force: false,
            },
            LocalPrefActionConfig::Force { value, force } => SetClause::LocalPref {
                value: *value,
                force: *force,
            },
        });
    }
    if let Some(med) = &acts.med {
        sets.push(SetClause::Med(match med {
            MedActionConfig::Set(v) => MedSet::Set(*v),
            MedActionConfig::Remove { .. } => MedSet::Remove,
        }));
    }
    if let Some(c) = &acts.community {
        sets.push(SetClause::Community(CommunityOp {
            op: community_op_from_str(&c.operation)?,
            values: c.communities.clone(),
        }));
    }
    if let Some(c) = &acts.ext_community {
        sets.push(SetClause::ExtCommunity(CommunityOp {
            op: community_op_from_str(&c.operation)?,
            values: c.ext_communities.clone(),
        }));
    }
    if let Some(c) = &acts.large_community {
        sets.push(SetClause::LargeCommunity(CommunityOp {
            op: community_op_from_str(&c.operation)?,
            values: c.large_communities.clone(),
        }));
    }
    if let Some(v) = acts.set_rpki_state {
        sets.push(SetClause::SetRpkiState(rpki_config_to_kind(v)));
    }

    let disposition = match (acts.accept.unwrap_or(false), acts.reject.unwrap_or(false)) {
        (true, false) => Some(Disposition::Accept),
        (false, true) => Some(Disposition::Reject),
        (false, false) => None,
        (true, true) => return None,
    };

    Some(StatementBlock {
        name: stmt.name.clone(),
        matches,
        sets,
        disposition,
    })
}

fn action_to_config(action: &str) -> Result<ActionsConfig, String> {
    match action {
        "accept" => Ok(ActionsConfig {
            accept: Some(true),
            ..Default::default()
        }),
        "reject" => Ok(ActionsConfig {
            reject: Some(true),
            ..Default::default()
        }),
        other => Err(format!(
            "policy rule action must be 'accept' or 'reject', got '{}'",
            other
        )),
    }
}

fn config_to_action(actions: &ActionsConfig) -> Option<String> {
    let accept = actions.accept.unwrap_or(false);
    let reject = actions.reject.unwrap_or(false);
    let has_transform = actions.local_pref.is_some()
        || actions.med.is_some()
        || actions.community.is_some()
        || actions.ext_community.is_some()
        || actions.large_community.is_some()
        || actions.set_rpki_state.is_some();
    if has_transform {
        return None;
    }
    match (accept, reject) {
        (true, false) => Some("accept".to_string()),
        (false, true) => Some("reject".to_string()),
        _ => None,
    }
}

/// Convert a `PrefixListBlock` into a runtime `PrefixSetConfig`. The
/// optional `range` on each entry maps to the runtime
/// `masklength_range` string format (`"exact"`, `"X..Y"`, `"..Y"`, `"X.."`).
fn prefix_list_block_to_set(block: &PrefixListBlock) -> PrefixSetConfig {
    PrefixSetConfig {
        name: block.name.clone(),
        prefixes: block
            .prefixes
            .iter()
            .map(|e| PrefixMatchConfig {
                prefix: e.prefix.clone(),
                masklength_range: e.range.as_ref().map(masklength_range_to_runtime),
            })
            .collect(),
    }
}

fn masklength_range_to_runtime(range: &MasklengthRange) -> String {
    match range {
        MasklengthRange::Exact => "exact".to_string(),
        MasklengthRange::Range { ge, le } => {
            let lhs = ge.map(|v| v.to_string()).unwrap_or_default();
            let rhs = le.map(|v| v.to_string()).unwrap_or_default();
            format!("{}..{}", lhs, rhs)
        }
    }
}

fn runtime_to_masklength_range(s: &str) -> Option<MasklengthRange> {
    if s == "exact" {
        return Some(MasklengthRange::Exact);
    }
    let (min_str, max_str) = s.split_once("..")?;
    let ge = if min_str.is_empty() {
        None
    } else {
        Some(min_str.parse::<u8>().ok()?)
    };
    let le = if max_str.is_empty() {
        None
    } else {
        Some(max_str.parse::<u8>().ok()?)
    };
    if ge.is_none() && le.is_none() {
        None
    } else {
        Some(MasklengthRange::Range { ge, le })
    }
}

fn neighbor_set_block_to_config(block: &NeighborSetBlock) -> NeighborSetConfig {
    NeighborSetConfig {
        name: block.name.clone(),
        neighbors: block.neighbors.clone(),
    }
}

fn neighbor_set_config_to_block(cfg: &NeighborSetConfig) -> NeighborSetBlock {
    NeighborSetBlock {
        name: cfg.name.clone(),
        neighbors: cfg.neighbors.clone(),
    }
}

fn as_path_set_block_to_config(block: &AsPathSetBlock) -> AsPathSetConfig {
    AsPathSetConfig {
        name: block.name.clone(),
        patterns: block.patterns.clone(),
    }
}

fn as_path_set_config_to_block(cfg: &AsPathSetConfig) -> AsPathSetBlock {
    AsPathSetBlock {
        name: cfg.name.clone(),
        patterns: cfg.patterns.clone(),
    }
}

fn community_set_block_to_config(block: &CommunitySetBlock) -> CommunitySetConfig {
    CommunitySetConfig {
        name: block.name.clone(),
        communities: block.communities.clone(),
    }
}

fn community_set_config_to_block(cfg: &CommunitySetConfig) -> CommunitySetBlock {
    CommunitySetBlock {
        name: cfg.name.clone(),
        communities: cfg.communities.clone(),
    }
}

fn ext_community_set_block_to_config(block: &ExtCommunitySetBlock) -> ExtCommunitySetConfig {
    ExtCommunitySetConfig {
        name: block.name.clone(),
        ext_communities: block.ext_communities.clone(),
    }
}

fn ext_community_set_config_to_block(cfg: &ExtCommunitySetConfig) -> ExtCommunitySetBlock {
    ExtCommunitySetBlock {
        name: cfg.name.clone(),
        ext_communities: cfg.ext_communities.clone(),
    }
}

fn large_community_set_block_to_config(block: &LargeCommunitySetBlock) -> LargeCommunitySetConfig {
    LargeCommunitySetConfig {
        name: block.name.clone(),
        large_communities: block.large_communities.clone(),
    }
}

fn large_community_set_config_to_block(cfg: &LargeCommunitySetConfig) -> LargeCommunitySetBlock {
    LargeCommunitySetBlock {
        name: cfg.name.clone(),
        large_communities: cfg.large_communities.clone(),
    }
}

/// Convert a runtime `PrefixSetConfig` into a `PrefixListBlock`. Entries
/// whose `masklength_range` string fails to parse fall back to no range
/// (rare; grammar accepts the same shapes the runtime emits).
fn prefix_set_to_block(set: &PrefixSetConfig) -> Option<PrefixListBlock> {
    let prefixes: Vec<PrefixListEntry> = set
        .prefixes
        .iter()
        .map(|e| PrefixListEntry {
            prefix: e.prefix.clone(),
            range: e
                .masklength_range
                .as_deref()
                .and_then(runtime_to_masklength_range),
        })
        .collect();
    if prefixes.is_empty() {
        None
    } else {
        Some(PrefixListBlock {
            name: set.name.clone(),
            prefixes,
        })
    }
}

/// Build the `family` blocks for a peer's `afi_safis` entries that carry
/// any per-family setting (policies, max-prefix, or add-path-send).
fn families_from_peer_config(peer: &PeerConfig) -> Vec<FamilyBlock> {
    let mut blocks = Vec::new();
    for entry in &peer.afi_safis {
        let has_anything = !entry.import_policy.is_empty()
            || !entry.export_policy.is_empty()
            || entry.max_prefix.is_some()
            || entry.add_path_send.is_some();
        if !has_anything {
            continue;
        }
        let mut directives = Vec::new();
        if let Some(mp) = &entry.max_prefix {
            directives.push(FamilyDirective::MaxPrefix {
                limit: mp.limit,
                action: match mp.action {
                    MaxPrefixAction::Terminate => MaxPrefixActionKind::Terminate,
                    MaxPrefixAction::Discard => MaxPrefixActionKind::Discard,
                },
            });
        }
        if let Some(aps) = entry.add_path_send {
            let mode = match aps {
                AddPathSend::All => LangAddPathSendMode::All,
                AddPathSend::Disabled => LangAddPathSendMode::Disabled,
            };
            directives.push(FamilyDirective::AddPathSend(mode));
        }
        for name in &entry.import_policy {
            directives.push(FamilyDirective::ImportPolicy(name.clone()));
        }
        for name in &entry.export_policy {
            directives.push(FamilyDirective::ExportPolicy(name.clone()));
        }
        blocks.push(FamilyBlock {
            afi: entry.afi,
            safi: entry.safi,
            directives,
        });
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs::{self, File};
    use std::io::Write;

    #[test]
    fn test_to_conf_str_round_trip() {
        // Render a BgpConfig back to text and reparse; the parse result should
        // carry the same language-level fields (what the grammar can express).
        let input = "\
service bgp {
  asn 4242423930
  router-id 172.23.211.1
  listen-addr [::]:179
  grpc-listen-addr [::]:50051
  log-level debug
  hold-time 90

  peer 10.0.0.1 {
    remote-as 65000
    passive true
    rr-client true
  }
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        assert_eq!(reparsed.asn, config.asn);
        assert_eq!(reparsed.router_id, config.router_id);
        assert_eq!(reparsed.listen_addr, config.listen_addr);
        assert_eq!(reparsed.grpc_listen_addr, config.grpc_listen_addr);
        assert_eq!(reparsed.log_level, config.log_level);
        assert_eq!(reparsed.hold_time_secs, config.hold_time_secs);
        assert_eq!(reparsed.peers.len(), config.peers.len());
        let original = config.peers.first().unwrap();
        let parsed = reparsed.peers.first().unwrap();
        assert_eq!(parsed.address, original.address);
        assert_eq!(parsed.asn, original.asn);
        assert_eq!(parsed.passive_mode, original.passive_mode);
        assert_eq!(parsed.rr_client, original.rr_client);
    }

    #[test]
    fn test_to_conf_str_omits_default_settings() {
        // A file that doesn't mention connect-retry/hold-time/log-level/
        // grpc-listen-addr/listen-addr should round-trip identically -- the
        // renderer must not re-add the defaults that fill them in.
        let input = "\
service bgp {
  asn 65000
  router-id 1.1.1.1
}";
        let rendered = BgpConfig::from_conf_str(input).unwrap().to_conf_str();
        for hidden in [
            "connect-retry",
            "hold-time",
            "log-level",
            "grpc-listen-addr",
            "listen-addr",
            "telemetry",
        ] {
            assert!(
                !rendered.contains(hidden),
                "rendered config should omit `{hidden}` at default value:\n{rendered}"
            );
        }
    }

    #[test]
    fn test_telemetry_from_conf_and_round_trip() {
        let cases = [
            (
                "  telemetry {\n    json {}\n  }\n",
                Some(TelemetrySink::Json),
            ),
            (
                "  telemetry {\n    cloudwatch-emf {\n      namespace Rogg/Bgpgg\n    }\n  }\n",
                Some(TelemetrySink::CloudwatchEmf {
                    namespace: "Rogg/Bgpgg".to_string(),
                }),
            ),
            ("  telemetry {\n  }\n", None),
        ];
        for (block_text, expected_sink) in cases {
            let input = format!(
                "service bgp {{\n  asn 65000\n  router-id 1.1.1.1\n{}}}",
                block_text
            );
            let config = BgpConfig::from_conf_str(&input).unwrap();
            let telemetry = config.telemetry.as_ref().unwrap();
            assert_eq!(telemetry.sink, expected_sink, "input: {}", input);

            let rendered = config.to_conf_str();
            let reparsed = BgpConfig::from_conf_str(&rendered)
                .unwrap_or_else(|err| panic!("reparse failed:\n{}\nerror: {}", rendered, err));
            assert_eq!(
                reparsed.telemetry, config.telemetry,
                "rendered: {}",
                rendered
            );
        }
    }

    #[test]
    fn test_optional_settings_round_trip() {
        // Populate every optional scalar setting on BgpConfig and PeerConfig
        // (the ones the basic round-trip test doesn't exercise) and verify
        // they survive to_conf_str -> from_conf_str unchanged.
        let mut config = BgpConfig::new(65001, "127.0.0.1:179", Ipv4Addr::new(1, 1, 1, 1), 90);
        config.sys_name = Some("test-router".to_string());
        config.sys_descr = Some("test-build".to_string());
        config.enhanced_rr_stale_ttl = Some(120);
        config.bgp_ls.instance_id = 99;
        config
            .insert_peer(PeerConfig {
                address: "10.0.0.1".to_string(),
                asn: Some(65002),
                delay_open_time_secs: Some(2),
                idle_hold_time_secs: Some(60),
                damp_peer_oscillations: false,
                allow_automatic_stop: false,
                send_notification_without_open: true,
                min_route_advertisement_interval_secs: Some(15),
                enforce_first_as: false,
                send_rpki_community: true,
                ..Default::default()
            })
            .unwrap();

        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered)
            .unwrap_or_else(|err| panic!("reparse failed:\n{}\nerror: {}", rendered, err));

        assert_eq!(reparsed.sys_name, config.sys_name);
        assert_eq!(reparsed.sys_descr, config.sys_descr);
        assert_eq!(reparsed.enhanced_rr_stale_ttl, config.enhanced_rr_stale_ttl);
        assert_eq!(reparsed.bgp_ls.instance_id, config.bgp_ls.instance_id);

        assert_eq!(reparsed.peers.len(), 1);
        let original = config.peers.first().unwrap();
        let parsed = reparsed.peers.first().unwrap();
        assert_eq!(parsed.delay_open_time_secs, original.delay_open_time_secs);
        assert_eq!(parsed.idle_hold_time_secs, original.idle_hold_time_secs);
        assert_eq!(
            parsed.damp_peer_oscillations,
            original.damp_peer_oscillations
        );
        assert_eq!(parsed.allow_automatic_stop, original.allow_automatic_stop);
        assert_eq!(
            parsed.send_notification_without_open,
            original.send_notification_without_open
        );
        assert_eq!(
            parsed.min_route_advertisement_interval_secs,
            original.min_route_advertisement_interval_secs
        );
        assert_eq!(parsed.enforce_first_as, original.enforce_first_as);
        assert_eq!(parsed.send_rpki_community, original.send_rpki_community);
    }

    #[test]
    fn test_originate_round_trip() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  originate 10.0.0.0/24 nexthop 192.168.1.1
  originate 2001:db8::/32 nexthop fe80::1
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(
            config.originate,
            vec![
                OriginateRoute {
                    prefix: "10.0.0.0/24".to_string(),
                    nexthop: "192.168.1.1".to_string(),
                },
                OriginateRoute {
                    prefix: "2001:db8::/32".to_string(),
                    nexthop: "fe80::1".to_string(),
                },
            ]
        );
        let rendered = config.to_conf_str();
        assert!(rendered.contains("originate 10.0.0.0/24 nexthop 192.168.1.1"));
        assert!(rendered.contains("originate 2001:db8::/32 nexthop fe80::1"));
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        assert_eq!(reparsed.originate, config.originate);
    }

    #[test]
    fn test_policy_round_trip() {
        // Policies with `match <set> -> ACTION` and `default -> ACTION` rules
        // round-trip through the full conf-text path.
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  policy mine-only {
    match my-prefixes accept
    default reject
  }

  prefix-list my-prefixes {
    172.23.211.0/27
    fd0d:fbde:bca5::/48
  }
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(config.policy_definitions.len(), 1);
        let policy = &config.policy_definitions[0];
        assert_eq!(policy.name, "mine-only");
        assert_eq!(policy.statements.len(), 2);
        assert_eq!(
            policy.statements[0]
                .conditions
                .match_prefix_set
                .as_ref()
                .map(|m| m.set_name.as_str()),
            Some("my-prefixes")
        );
        assert_eq!(policy.statements[0].actions.accept, Some(true));
        assert!(policy.statements[1].conditions.match_prefix_set.is_none());
        assert_eq!(policy.statements[1].actions.reject, Some(true));

        assert_eq!(config.defined_sets.prefix_sets.len(), 1);
        let set = &config.defined_sets.prefix_sets[0];
        assert_eq!(set.name, "my-prefixes");
        assert_eq!(set.prefixes.len(), 2);
        assert_eq!(set.prefixes[0].prefix, "172.23.211.0/27");
        assert!(set.prefixes[0].masklength_range.is_none());

        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        assert_eq!(reparsed.policy_definitions.len(), 1);
        assert_eq!(reparsed.policy_definitions[0].name, policy.name);
        assert_eq!(
            reparsed.policy_definitions[0].statements.len(),
            policy.statements.len()
        );
        assert_eq!(reparsed.defined_sets.prefix_sets.len(), 1);
        assert_eq!(reparsed.defined_sets.prefix_sets[0].name, set.name);
        assert_eq!(
            reparsed.defined_sets.prefix_sets[0].prefixes.len(),
            set.prefixes.len()
        );
    }

    #[test]
    fn test_peer_family_policy_round_trip() {
        // `peer X { family afi safi { import policy A; export policy B } }`
        // populates `peer.afi_safis[(afi,safi)].{import,export}_policy` and
        // round-trips through to_conf_str.
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer 10.0.0.1 {
    remote-as 65002

    family ipv4 unicast {
      import policy in-v4
      export policy out-v4
    }

    family ipv6 unicast {
      export policy out-v6
    }
  }
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(config.peers.len(), 1);
        let peer = config.peers.first().unwrap();
        assert_eq!(
            peer.import_policy_for(Afi::Ipv4, Safi::Unicast),
            ["in-v4".to_string()]
        );
        assert_eq!(
            peer.export_policy_for(Afi::Ipv4, Safi::Unicast),
            ["out-v4".to_string()]
        );
        assert!(peer.import_policy_for(Afi::Ipv6, Safi::Unicast).is_empty());
        assert_eq!(
            peer.export_policy_for(Afi::Ipv6, Safi::Unicast),
            ["out-v6".to_string()]
        );

        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        let parsed_peer = reparsed.peers.first().unwrap();
        assert_eq!(
            parsed_peer.import_policy_for(Afi::Ipv4, Safi::Unicast),
            peer.import_policy_for(Afi::Ipv4, Safi::Unicast)
        );
        assert_eq!(
            parsed_peer.export_policy_for(Afi::Ipv4, Safi::Unicast),
            peer.export_policy_for(Afi::Ipv4, Safi::Unicast)
        );
        assert_eq!(
            parsed_peer.export_policy_for(Afi::Ipv6, Safi::Unicast),
            peer.export_policy_for(Afi::Ipv6, Safi::Unicast)
        );
    }

    #[test]
    fn test_defined_set_round_trip() {
        // All five non-prefix defined-set types round-trip end-to-end.
        let mut config = BgpConfig::new(65001, "127.0.0.1:179", Ipv4Addr::new(1, 1, 1, 1), 90);
        config.defined_sets.neighbor_sets.push(NeighborSetConfig {
            name: "peers".to_string(),
            neighbors: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
        });
        config.defined_sets.as_path_sets.push(AsPathSetConfig {
            name: "ribbons".to_string(),
            patterns: vec!["^65001 65002$".to_string(), "^65003".to_string()],
        });
        config.defined_sets.community_sets.push(CommunitySetConfig {
            name: "comm".to_string(),
            communities: vec!["65000:100".to_string(), "65000:200".to_string()],
        });
        config
            .defined_sets
            .ext_community_sets
            .push(ExtCommunitySetConfig {
                name: "ext".to_string(),
                ext_communities: vec!["rt:65000:100".to_string()],
            });
        config
            .defined_sets
            .large_community_sets
            .push(LargeCommunitySetConfig {
                name: "lc".to_string(),
                large_communities: vec!["65000:1:1".to_string()],
            });
        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        assert_eq!(reparsed.defined_sets.neighbor_sets.len(), 1);
        assert_eq!(
            reparsed.defined_sets.neighbor_sets[0].neighbors,
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()]
        );
        assert_eq!(
            reparsed.defined_sets.as_path_sets[0].patterns,
            vec!["^65001 65002$".to_string(), "^65003".to_string()]
        );
        assert_eq!(
            reparsed.defined_sets.community_sets[0].communities,
            vec!["65000:100".to_string(), "65000:200".to_string()]
        );
        assert_eq!(
            reparsed.defined_sets.ext_community_sets[0].ext_communities,
            vec!["rt:65000:100".to_string()]
        );
        assert_eq!(
            reparsed.defined_sets.large_community_sets[0].large_communities,
            vec!["65000:1:1".to_string()]
        );
    }

    #[test]
    fn test_per_family_max_prefix_round_trip() {
        let mut config = BgpConfig::new(65001, "127.0.0.1:179", Ipv4Addr::new(1, 1, 1, 1), 90);
        let mut peer = PeerConfig {
            address: "10.0.0.1".to_string(),
            asn: Some(65002),
            ..Default::default()
        };
        peer.afi_safis.push(AfiSafiConfig {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            max_prefix: Some(MaxPrefixSetting {
                limit: 1000,
                action: MaxPrefixAction::Terminate,
            }),
            add_path_send: Some(AddPathSend::All),
            import_policy: Vec::new(),
            export_policy: Vec::new(),
        });
        peer.afi_safis.push(AfiSafiConfig {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            max_prefix: Some(MaxPrefixSetting {
                limit: 5000,
                action: MaxPrefixAction::Discard,
            }),
            add_path_send: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
        });
        config.insert_peer(peer).unwrap();
        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        let p = reparsed.peers.first().unwrap();
        let v4 = p
            .afi_safis
            .iter()
            .find(|c| c.afi == Afi::Ipv4)
            .expect("v4 family");
        assert_eq!(v4.max_prefix.as_ref().map(|m| m.limit), Some(1000));
        assert!(matches!(
            v4.max_prefix.as_ref().map(|m| m.action),
            Some(MaxPrefixAction::Terminate)
        ));
        assert_eq!(v4.add_path_send, Some(AddPathSend::All));
        let v6 = p
            .afi_safis
            .iter()
            .find(|c| c.afi == Afi::Ipv6)
            .expect("v6 family");
        assert_eq!(v6.max_prefix.as_ref().map(|m| m.limit), Some(5000));
        assert!(matches!(
            v6.max_prefix.as_ref().map(|m| m.action),
            Some(MaxPrefixAction::Discard)
        ));
        assert!(v6.add_path_send.is_none());
    }

    #[test]
    fn test_full_statement_round_trip() {
        // Every ConditionsConfig + ActionsConfig field in one statement.
        let mut config = BgpConfig::new(65001, "127.0.0.1:179", Ipv4Addr::new(1, 1, 1, 1), 90);
        config.policy_definitions.push(PolicyDefinitionConfig {
            name: "kitchen-sink".to_string(),
            statements: vec![StatementConfig {
                name: Some("st1".to_string()),
                conditions: ConditionsConfig {
                    match_prefix_set: Some(MatchSetRefConfig {
                        set_name: "ps".to_string(),
                        match_option: MatchOptionConfig::Any,
                    }),
                    match_neighbor_set: Some(MatchSetRefConfig {
                        set_name: "ns".to_string(),
                        match_option: MatchOptionConfig::All,
                    }),
                    match_as_path_set: Some(MatchSetRefConfig {
                        set_name: "as".to_string(),
                        match_option: MatchOptionConfig::Invert,
                    }),
                    match_community_set: Some(MatchSetRefConfig {
                        set_name: "cs".to_string(),
                        match_option: MatchOptionConfig::Any,
                    }),
                    match_ext_community_set: Some(MatchSetRefConfig {
                        set_name: "es".to_string(),
                        match_option: MatchOptionConfig::Any,
                    }),
                    match_large_community_set: Some(MatchSetRefConfig {
                        set_name: "ls".to_string(),
                        match_option: MatchOptionConfig::Any,
                    }),
                    prefix: Some("10.0.0.0/8".to_string()),
                    neighbor: Some("10.0.0.1".to_string()),
                    has_asn: Some(65000),
                    route_type: Some("internal".to_string()),
                    community: Some("65000:100".to_string()),
                    rpki_validation: Some(RpkiValidationConfig::Valid),
                    afi_safi: Some("ipv4-unicast".to_string()),
                    ls_nlri_type: Some("node".to_string()),
                    ls_protocol_id: Some("ospf-v2".to_string()),
                    ls_instance_id: Some(7),
                    ls_node_as: Some(65001),
                    ls_node_router_id: Some("1.1.1.1".to_string()),
                },
                actions: ActionsConfig {
                    accept: Some(true),
                    reject: None,
                    local_pref: Some(LocalPrefActionConfig::Force {
                        value: 200,
                        force: true,
                    }),
                    med: Some(MedActionConfig::Set(100)),
                    community: Some(CommunityActionConfig {
                        operation: "add".to_string(),
                        communities: vec!["65000:100".to_string(), "65000:200".to_string()],
                    }),
                    ext_community: Some(ExtCommunityActionConfig {
                        operation: "remove".to_string(),
                        ext_communities: vec!["rt:65000:100".to_string()],
                    }),
                    large_community: Some(LargeCommunityActionConfig {
                        operation: "replace".to_string(),
                        large_communities: vec!["65000:1:1".to_string()],
                    }),
                    set_rpki_state: Some(RpkiValidationConfig::Invalid),
                },
            }],
        });

        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        assert_eq!(reparsed.policy_definitions.len(), 1);
        let stmt = &reparsed.policy_definitions[0].statements[0];
        // Conditions
        let conds = &stmt.conditions;
        assert_eq!(stmt.name.as_deref(), Some("st1"));
        assert_eq!(
            conds.match_prefix_set.as_ref().map(|c| c.match_option),
            Some(MatchOptionConfig::Any)
        );
        assert_eq!(
            conds.match_neighbor_set.as_ref().map(|c| c.match_option),
            Some(MatchOptionConfig::All)
        );
        assert_eq!(
            conds.match_as_path_set.as_ref().map(|c| c.match_option),
            Some(MatchOptionConfig::Invert)
        );
        assert_eq!(conds.prefix.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(conds.neighbor.as_deref(), Some("10.0.0.1"));
        assert_eq!(conds.has_asn, Some(65000));
        assert_eq!(conds.route_type.as_deref(), Some("internal"));
        assert_eq!(conds.community.as_deref(), Some("65000:100"));
        assert_eq!(conds.rpki_validation, Some(RpkiValidationConfig::Valid));
        assert_eq!(conds.afi_safi.as_deref(), Some("ipv4-unicast"));
        assert_eq!(conds.ls_nlri_type.as_deref(), Some("node"));
        assert_eq!(conds.ls_protocol_id.as_deref(), Some("ospf-v2"));
        assert_eq!(conds.ls_instance_id, Some(7));
        assert_eq!(conds.ls_node_as, Some(65001));
        assert_eq!(conds.ls_node_router_id.as_deref(), Some("1.1.1.1"));
        // Actions
        let acts = &stmt.actions;
        assert_eq!(acts.accept, Some(true));
        assert!(matches!(
            acts.local_pref,
            Some(LocalPrefActionConfig::Force { value: 200, .. })
        ));
        assert!(matches!(acts.med, Some(MedActionConfig::Set(100))));
        let comm = acts.community.as_ref().expect("community");
        assert_eq!(comm.operation, "add");
        assert_eq!(comm.communities.len(), 2);
        let ext = acts.ext_community.as_ref().expect("ext");
        assert_eq!(ext.operation, "remove");
        let lg = acts.large_community.as_ref().expect("large");
        assert_eq!(lg.operation, "replace");
        assert_eq!(acts.set_rpki_state, Some(RpkiValidationConfig::Invalid));
    }

    #[test]
    fn test_med_remove_round_trip() {
        let mut config = BgpConfig::new(65001, "127.0.0.1:179", Ipv4Addr::new(1, 1, 1, 1), 90);
        config.policy_definitions.push(PolicyDefinitionConfig {
            name: "p".to_string(),
            statements: vec![StatementConfig {
                name: None,
                conditions: ConditionsConfig::default(),
                actions: ActionsConfig {
                    med: Some(MedActionConfig::Remove { remove: true }),
                    accept: Some(true),
                    ..Default::default()
                },
            }],
        });
        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        let stmt = &reparsed.policy_definitions[0].statements[0];
        assert!(matches!(
            stmt.actions.med,
            Some(MedActionConfig::Remove { remove: true })
        ));
    }

    #[test]
    fn test_rich_policy_emits_statement_block() {
        // A policy whose statement uses a community-set match -- now
        // expressible -- emits as a `statement { ... }` block and
        // round-trips with the full match preserved.
        let mut config = BgpConfig::new(65001, "127.0.0.1:179", Ipv4Addr::new(1, 1, 1, 1), 90);
        config.policy_definitions.push(PolicyDefinitionConfig {
            name: "rich".to_string(),
            statements: vec![StatementConfig {
                name: None,
                conditions: ConditionsConfig {
                    match_community_set: Some(MatchSetRefConfig {
                        set_name: "my-comms".to_string(),
                        match_option: MatchOptionConfig::Any,
                    }),
                    ..Default::default()
                },
                actions: ActionsConfig {
                    accept: Some(true),
                    ..Default::default()
                },
            }],
        });
        let rendered = config.to_conf_str();
        assert!(
            rendered.contains("policy rich"),
            "rich policy not emitted: {}",
            rendered
        );
        assert!(
            rendered.contains("match community-set my-comms"),
            "community-set match not emitted: {}",
            rendered
        );
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        assert_eq!(reparsed.policy_definitions.len(), 1);
        let stmt = &reparsed.policy_definitions[0].statements[0];
        assert_eq!(
            stmt.conditions
                .match_community_set
                .as_ref()
                .map(|c| c.set_name.as_str()),
            Some("my-comms")
        );
        assert_eq!(stmt.actions.accept, Some(true));
    }

    #[test]
    fn test_prefix_masklength_range_round_trip() {
        // Each masklength_range shape (exact / "X..Y" / "X.." / "..Y")
        // round-trips through to_conf_str -> from_conf_str.
        let mut config = BgpConfig::new(65001, "127.0.0.1:179", Ipv4Addr::new(1, 1, 1, 1), 90);
        config.defined_sets.prefix_sets.push(PrefixSetConfig {
            name: "v4".to_string(),
            prefixes: vec![
                PrefixMatchConfig {
                    prefix: "10.0.0.0/8".to_string(),
                    masklength_range: Some("16..24".to_string()),
                },
                PrefixMatchConfig {
                    prefix: "172.16.0.0/12".to_string(),
                    masklength_range: Some("exact".to_string()),
                },
                PrefixMatchConfig {
                    prefix: "192.168.0.0/16".to_string(),
                    masklength_range: Some("..32".to_string()),
                },
                PrefixMatchConfig {
                    prefix: "203.0.113.0/24".to_string(),
                    masklength_range: Some("28..".to_string()),
                },
                PrefixMatchConfig {
                    prefix: "198.51.100.0/24".to_string(),
                    masklength_range: None,
                },
            ],
        });
        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        let set = &reparsed.defined_sets.prefix_sets[0];
        let original = &config.defined_sets.prefix_sets[0];
        assert_eq!(set.prefixes.len(), original.prefixes.len());
        for (got, want) in set.prefixes.iter().zip(original.prefixes.iter()) {
            assert_eq!(got.prefix, want.prefix);
            assert_eq!(got.masklength_range, want.masklength_range);
        }
    }

    #[test]
    fn test_bmp_and_rpki_round_trip() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  bmp-server 127.0.0.1:1790 {
    statistics-timeout 60
  }

  rpki-cache 10.0.0.1:323 {
    preference 2
    transport ssh
    ssh-username rtr-user
    ssh-private-key-file /etc/bgp/rtr.key
    ssh-known-hosts-file /etc/bgp/known_hosts
    retry-interval 60
    refresh-interval 3600
    expire-interval 7200
  }
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(config.bmp_servers.len(), 1);
        assert_eq!(config.bmp_servers[0].address, "127.0.0.1:1790");
        assert_eq!(config.bmp_servers[0].statistics_timeout, Some(60));

        assert_eq!(config.rpki_caches.len(), 1);
        let cache = &config.rpki_caches[0];
        assert_eq!(cache.address, "10.0.0.1:323");
        assert_eq!(cache.preference, 2);
        assert!(matches!(cache.transport, TransportType::Ssh));
        assert_eq!(cache.ssh_username.as_deref(), Some("rtr-user"));
        assert_eq!(cache.retry_interval, Some(60));
        assert_eq!(cache.refresh_interval, Some(3600));
        assert_eq!(cache.expire_interval, Some(7200));

        let rendered = config.to_conf_str();
        let reparsed = BgpConfig::from_conf_str(&rendered).unwrap();
        assert_eq!(reparsed.bmp_servers.len(), 1);
        assert_eq!(
            reparsed.bmp_servers[0].statistics_timeout,
            config.bmp_servers[0].statistics_timeout
        );
        assert_eq!(reparsed.rpki_caches.len(), 1);
        assert_eq!(reparsed.rpki_caches[0].address, cache.address);
        assert_eq!(reparsed.rpki_caches[0].preference, cache.preference);
        assert_eq!(reparsed.rpki_caches[0].ssh_username, cache.ssh_username);
    }

    #[test]
    fn test_config_new() {
        let config = BgpConfig::new(65100, "192.168.1.1:179", Ipv4Addr::new(192, 168, 1, 1), 180);
        assert_eq!(config.asn, 65100);
        assert_eq!(config.listen_addr, "192.168.1.1:179");
        assert_eq!(config.router_id, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.hold_time_secs, 180);
    }

    #[test]
    fn test_config_default() {
        let config = BgpConfig::default();
        assert_eq!(config.asn, 65000);
        assert_eq!(config.listen_addr, "0.0.0.0:179");
        assert_eq!(config.router_id, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(config.grpc_listen_addr, "127.0.0.1:50051");
    }

    #[test]
    fn test_cluster_id() {
        let mut config = BgpConfig::new(65000, "0.0.0.0:179", Ipv4Addr::new(10, 0, 0, 1), 180);
        assert_eq!(config.cluster_id(), Ipv4Addr::new(10, 0, 0, 1));
        config.cluster_id = Some(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(config.cluster_id(), Ipv4Addr::new(1, 2, 3, 4));
    }

    #[test]
    fn test_read_md5_key() {
        let temp_path = env::temp_dir().join("test_bgp_md5.key");
        let mut file = File::create(&temp_path).unwrap();
        writeln!(file, "my-secret-key").unwrap();

        let peer = PeerConfig {
            md5_key_file: Some(temp_path.to_str().unwrap().to_string()),
            ..Default::default()
        };

        let key = peer.read_md5_key().unwrap();
        assert_eq!(key, b"my-secret-key");

        let peer = PeerConfig::default();
        assert!(peer.read_md5_key().is_none());

        fs::remove_file(temp_path).unwrap();
    }

    #[test]
    fn test_read_md5_key_missing_file() {
        let peer = PeerConfig {
            md5_key_file: Some("/nonexistent/path/bgp_md5.key".to_string()),
            ..Default::default()
        };
        assert!(peer.read_md5_key().is_none());
    }

    #[test]
    fn test_rr_and_rs_conflict() {
        let peer = PeerConfig {
            rr_client: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        let peer = PeerConfig {
            rs_client: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        let peer = PeerConfig {
            rr_client: true,
            rs_client: true,
            ..Default::default()
        };
        let result = peer.validate();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Peer cannot be both rr-client and rs-client"
        );

        let peer = PeerConfig::default();
        assert!(peer.validate().is_ok());
    }

    #[test]
    fn test_rs_client_rejects_add_path_receive() {
        let peer = PeerConfig {
            rs_client: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        let peer = PeerConfig {
            add_path_receive: true,
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        let peer = PeerConfig {
            rs_client: true,
            add_path_receive: true,
            ..Default::default()
        };
        let result = peer.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_llgr_stale_time_validation() {
        let cases = [
            (0, true),
            (3600, true),
            (0xFFFFFF, true),
            (0xFFFFFF + 1, false),
            (u32::MAX, false),
        ];
        for (stale_time, should_ok) in cases {
            let peer = PeerConfig {
                llgr: Some(LlgrConfig {
                    enabled: true,
                    stale_time: Some(stale_time),
                    afi_safis: None,
                }),
                ..Default::default()
            };
            assert_eq!(
                peer.validate().is_ok(),
                should_ok,
                "stale_time={stale_time} expected ok={should_ok}"
            );
        }
    }

    #[test]
    fn test_llgr_requires_graceful_restart() {
        let peer = PeerConfig {
            llgr: Some(LlgrConfig {
                enabled: true,
                stale_time: Some(3600),
                afi_safis: None,
            }),
            ..Default::default()
        };
        assert!(peer.validate().is_ok());

        let peer = PeerConfig {
            graceful_restart: GracefulRestartConfig {
                enabled: false,
                ..Default::default()
            },
            llgr: Some(LlgrConfig {
                enabled: true,
                stale_time: Some(3600),
                afi_safis: None,
            }),
            ..Default::default()
        };
        let result = peer.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("LLGR requires graceful-restart"));
    }

    #[test]
    fn test_llgr_disabled_skips_gr_check() {
        let peer = PeerConfig {
            graceful_restart: GracefulRestartConfig {
                enabled: false,
                ..Default::default()
            },
            llgr: Some(LlgrConfig {
                enabled: false,
                stale_time: Some(3600),
                afi_safis: None,
            }),
            ..Default::default()
        };
        assert!(peer.validate().is_ok());
    }

    #[test]
    fn test_get_peer_llgr() {
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);

        assert!(get_peer_llgr(&None, &None).is_none());

        let server = Some(LlgrConfig {
            enabled: true,
            stale_time: Some(3600),
            afi_safis: Some(vec![ipv4_unicast]),
        });
        let merged = get_peer_llgr(&server, &None).expect("should be enabled");
        assert_eq!(merged.stale_time, Some(3600));
        assert_eq!(merged.afi_safis, Some(vec![ipv4_unicast]));

        let peer = Some(LlgrConfig {
            enabled: true,
            stale_time: Some(7200),
            afi_safis: Some(vec![ipv4_unicast]),
        });
        let merged = get_peer_llgr(&server, &peer).expect("should be enabled");
        assert_eq!(merged.stale_time, Some(7200));
        assert_eq!(merged.afi_safis, Some(vec![ipv4_unicast]));

        let peer_disabled = Some(LlgrConfig {
            enabled: false,
            stale_time: None,
            afi_safis: None,
        });
        assert!(get_peer_llgr(&server, &peer_disabled).is_none());
    }

    #[test]
    fn test_effective_max_prefix() {
        let cases = vec![
            (Some(500), Some(1000), Some(500)),
            (None, Some(1000), Some(1000)),
            (Some(500), None, Some(500)),
            (None, None, None),
        ];
        for (family_limit, peer_limit, expected_limit) in cases {
            let config = PeerConfig {
                max_prefix: peer_limit.map(|limit| MaxPrefixSetting {
                    limit,
                    action: MaxPrefixAction::Terminate,
                }),
                afi_safis: vec![AfiSafiConfig {
                    afi: Afi::LinkState,
                    safi: Safi::LinkState,
                    max_prefix: family_limit.map(|limit| MaxPrefixSetting {
                        limit,
                        action: MaxPrefixAction::Terminate,
                    }),
                    add_path_send: None,
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                }],
                ..Default::default()
            };
            let ls_family = AfiSafi::new(Afi::LinkState, Safi::LinkState);
            let effective = config.effective_max_prefix(&ls_family);
            assert_eq!(
                effective.map(|s| s.limit),
                expected_limit,
                "family_limit={family_limit:?}, peer_limit={peer_limit:?}"
            );
        }
    }

    #[test]
    fn test_effective_max_prefix_different_families() {
        let config = PeerConfig {
            max_prefix: Some(MaxPrefixSetting {
                limit: 1000,
                action: MaxPrefixAction::Terminate,
            }),
            afi_safis: vec![AfiSafiConfig {
                afi: Afi::LinkState,
                safi: Safi::LinkState,
                max_prefix: Some(MaxPrefixSetting {
                    limit: 5000,
                    action: MaxPrefixAction::Discard,
                }),
                add_path_send: None,
                import_policy: Vec::new(),
                export_policy: Vec::new(),
            }],
            ..Default::default()
        };
        let ls = AfiSafi::new(Afi::LinkState, Safi::LinkState);
        let ls_setting = config.effective_max_prefix(&ls).unwrap();
        assert_eq!(ls_setting.limit, 5000);
        assert!(matches!(ls_setting.action, MaxPrefixAction::Discard));

        let ipv4 = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv4_setting = config.effective_max_prefix(&ipv4).unwrap();
        assert_eq!(ipv4_setting.limit, 1000);
        assert!(matches!(ipv4_setting.action, MaxPrefixAction::Terminate));
    }

    #[test]
    fn test_afi_safi_list() {
        let config = PeerConfig {
            afi_safis: vec![
                AfiSafiConfig::new(Afi::LinkState, Safi::LinkState),
                AfiSafiConfig::new(Afi::Ipv4, Safi::Unicast),
            ],
            ..Default::default()
        };
        let list = config.afi_safi_list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], AfiSafi::new(Afi::LinkState, Safi::LinkState));
        assert_eq!(list[1], AfiSafi::new(Afi::Ipv4, Safi::Unicast));
    }

    #[test]
    fn test_validate_duplicate_afi_safis() {
        let config = PeerConfig {
            afi_safis: vec![
                AfiSafiConfig::new(Afi::LinkState, Safi::LinkState),
                AfiSafiConfig::new(Afi::LinkState, Safi::LinkState),
            ],
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn test_bgp_ls_config_default() {
        let config = BgpConfig::default();
        assert_eq!(config.bgp_ls.max_ls_entries, 0);
    }

    #[test]
    fn test_from_conf_basic() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  listen-addr 127.0.0.1:179
  grpc-listen-addr 127.0.0.1:50051
  log-level debug
  hold-time 90
  connect-retry 10
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(config.asn, 65001);
        assert_eq!(config.router_id, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(config.listen_addr, "127.0.0.1:179");
        assert_eq!(config.grpc_listen_addr, "127.0.0.1:50051");
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.hold_time_secs, 90);
        assert_eq!(config.connect_retry_secs, 10);
    }

    #[test]
    fn test_from_conf_defaults() {
        let input = "\
service bgp {
  asn 65001
  router-id 2.2.2.2
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(config.asn, 65001);
        assert_eq!(config.router_id, Ipv4Addr::new(2, 2, 2, 2));
        assert_eq!(config.listen_addr, "0.0.0.0:179");
        assert_eq!(config.grpc_listen_addr, "127.0.0.1:50051");
        assert_eq!(config.hold_time_secs, 180);
    }

    #[test]
    fn test_from_conf_with_peers() {
        let input = "\
service bgp {
  asn 4242423930
  router-id 172.23.211.1

  peer fe80::ade0 {
    remote-as 4242423914
    interface peer1-us3
    md5-key-file /etc/bgp/peer1.key
    next-hop-self true
    port 1179
    ttl-min 254
  }

  peer 10.0.0.1 {
    remote-as 65000
    passive true
    rr-client true
  }
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        assert_eq!(config.asn, 4242423930);
        assert_eq!(config.peers.len(), 2);

        let peer1 = config.find_peer("fe80::ade0".parse().unwrap()).unwrap();
        assert_eq!(peer1.address, "fe80::ade0");
        assert_eq!(peer1.asn, Some(4242423914));
        assert_eq!(peer1.interface.as_deref(), Some("peer1-us3"));
        assert_eq!(peer1.md5_key_file.as_deref(), Some("/etc/bgp/peer1.key"));
        assert!(peer1.next_hop_self);
        assert_eq!(peer1.port, 1179);
        assert_eq!(peer1.ttl_min, Some(254));

        let upstream = config.find_peer("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(upstream.address, "10.0.0.1");
        assert_eq!(upstream.asn, Some(65000));
        assert!(upstream.passive_mode);
        assert!(upstream.rr_client);
    }

    #[test]
    fn test_peer_order_preserved_round_trip() {
        // Operator-written order in rogg.conf must survive parse -> serialize.
        // Listed deliberately out of IP-sort order so we'd notice if the
        // container resorted them.
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer 10.0.0.5 { remote-as 65005 }
  peer 10.0.0.1 { remote-as 65001 }
  peer 10.0.0.3 { remote-as 65003 }
}";
        let config = BgpConfig::from_conf_str(input).unwrap();
        let order: Vec<&str> = config.peers.iter().map(|p| p.address.as_str()).collect();
        assert_eq!(order, ["10.0.0.5", "10.0.0.1", "10.0.0.3"]);

        let reparsed = BgpConfig::from_conf_str(&config.to_conf_str()).unwrap();
        let reparsed_order: Vec<&str> = reparsed.peers.iter().map(|p| p.address.as_str()).collect();
        assert_eq!(reparsed_order, order);
    }

    #[test]
    fn test_from_conf_missing_service_bgp() {
        let result = BgpConfig::from_conf_str("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("service bgp"));
    }

    #[test]
    fn test_from_conf_unknown_service() {
        let input = "service ospf { router-id 1.1.1.1 }";
        let result = BgpConfig::from_conf_str(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown service"));
    }

    #[test]
    fn test_from_conf_missing_required() {
        let input = "service bgp { router-id 1.1.1.1 }";
        let result = BgpConfig::from_conf_str(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("asn"));

        let input = "service bgp { asn 65001 }";
        let result = BgpConfig::from_conf_str(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("router-id"));
    }

    #[test]
    fn test_from_conf_rejects_other_services() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1
}

service ospf {
  router-id 1.1.1.1
}";
        let result = BgpConfig::from_conf_str(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_afi_try_from() {
        assert_eq!(Afi::try_from(1).unwrap(), Afi::Ipv4);
        assert_eq!(Afi::try_from(2).unwrap(), Afi::Ipv6);
        assert_eq!(Afi::try_from(16388).unwrap(), Afi::LinkState);
        assert!(Afi::try_from(99).is_err());
    }

    #[test]
    fn test_safi_try_from() {
        assert_eq!(Safi::try_from(1).unwrap(), Safi::Unicast);
        assert_eq!(Safi::try_from(2).unwrap(), Safi::Multicast);
        assert_eq!(Safi::try_from(4).unwrap(), Safi::MplsLabel);
        assert_eq!(Safi::try_from(71).unwrap(), Safi::LinkState);
        assert_eq!(Safi::try_from(72).unwrap(), Safi::LinkStateVpn);
        assert!(Safi::try_from(99).is_err());
    }

    #[test]
    fn test_afi_safi_from_raw() {
        let result = AfiSafi::from_raw(Some(1), Some(1));
        assert_eq!(result, Some(AfiSafi::new(Afi::Ipv4, Safi::Unicast)));

        let result = AfiSafi::from_raw(Some(2), None);
        assert_eq!(result, Some(AfiSafi::new(Afi::Ipv6, Safi::Unicast)));

        assert!(AfiSafi::from_raw(None, Some(1)).is_none());
        assert!(AfiSafi::from_raw(Some(99), Some(1)).is_none());
    }

    #[test]
    fn test_afi_safi_display() {
        let afi_safi = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        assert_eq!(format!("{}", afi_safi), "IPv4/Unicast");
    }

    #[test]
    fn test_default_afi_safis() {
        let defaults = default_afi_safis();
        assert_eq!(defaults.len(), 2);
        assert_eq!(defaults[0], AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        assert_eq!(defaults[1], AfiSafi::new(Afi::Ipv6, Safi::Unicast));
    }

    #[test]
    fn test_afi_safi_serde_roundtrip() {
        let cases = vec![
            AfiSafi::new(Afi::Ipv4, Safi::Unicast),
            AfiSafi::new(Afi::Ipv6, Safi::Unicast),
            AfiSafi::new(Afi::LinkState, Safi::LinkState),
        ];
        for afi_safi in cases {
            let json = serde_json::to_string(&afi_safi).unwrap();
            let parsed: AfiSafi = serde_json::from_str(&json).unwrap();
            assert_eq!(afi_safi, parsed);
        }
    }
}
