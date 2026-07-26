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

//! BGP-specific AST types and parsing for the rogg config language.
//!
//! ## Grammar (BGP scope)
//!
//! ```text
//! bgp_body     = (setting | peer | policy | prefix_list | bmp_server | rpki_cache)*
//! peer         = "peer" NAME '{' (setting | family)* '}'
//! family       = "family" AFI SAFI '{' family_dir* '}'
//! family_dir   = ("export" | "import") "policy" NAME
//! policy       = "policy" NAME '{' policy_rule* '}'
//! policy_rule  = "match" NAME ACTION | "default" ACTION
//! prefix_list  = "prefix-list" NAME '{' PREFIX* '}'
//! bmp_server   = "bmp-server" ADDR '{' bmp_directive* '}'
//! bmp_directive = "statistics-timeout" N
//! rpki_cache   = "rpki-cache" ADDR '{' rpki_directive* '}'
//! rpki_directive = "preference" N | "transport" ("tcp" | "ssh")
//!                | "ssh-username" NAME | "ssh-private-key-file" PATH
//!                | "ssh-known-hosts-file" PATH
//!                | "retry-interval" N | "refresh-interval" N | "expire-interval" N
//! setting      = KEY VALUE NEWLINE
//! ```

use std::fmt;
use std::net::Ipv4Addr;

use crate::bgp::{Afi, Safi, TransportType};
use crate::language::{
    expect_close_brace, expect_open_brace, expect_word, finish_statement, parse_err, peek_kind,
    skip_newlines, take_word, ParseError, Token, TokenKind,
};

/// Body of `service bgp { ... }`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BgpServiceBody {
    pub settings: Vec<Setting>,
    pub peers: Vec<PeerBlock>,
    pub policies: Vec<PolicyBlock>,
    pub prefix_lists: Vec<PrefixListBlock>,
    pub neighbor_sets: Vec<NeighborSetBlock>,
    pub as_path_sets: Vec<AsPathSetBlock>,
    pub community_sets: Vec<CommunitySetBlock>,
    pub ext_community_sets: Vec<ExtCommunitySetBlock>,
    pub large_community_sets: Vec<LargeCommunitySetBlock>,
    pub bmp_servers: Vec<BmpServerBlock>,
    pub rpki_caches: Vec<RpkiCacheBlock>,
    pub bgp_ls: Option<BgpLsBlock>,
    pub telemetry: Option<TelemetryBlock>,
}

/// Typed config setting. Values are parsed at parse time.
/// Boolean settings (next-hop-self, passive, etc.) take "true" or "false".
#[derive(Debug, Clone, PartialEq)]
pub enum Setting {
    Asn(u32),
    RouterId(Ipv4Addr),
    ListenAddr(String),
    GrpcListenAddr(String),
    LogLevel(String),
    HoldTime(u64),
    ConnectRetry(u64),
    ClusterId(Ipv4Addr),
    SysName(String),
    SysDescr(String),
    EnhancedRrStaleTtl(u64),
    RemoteAs(u32),
    Port(u16),
    Interface(String),
    Md5KeyFile(String),
    TtlMin(u8),
    NextHopSelf(bool),
    Passive(bool),
    RrClient(bool),
    RsClient(bool),
    GracefulShutdown(bool),
    Originate(OriginateRoute),
    DelayOpenTimeSecs(u64),
    IdleHoldTimeSecs(u64),
    DampPeerOscillations(bool),
    AllowAutomaticStop(bool),
    SendNotificationWithoutOpen(bool),
    MinRouteAdvertisementIntervalSecs(u64),
    EnforceFirstAs(bool),
    SendRpkiCommunity(bool),
    AdminDown(bool),
}

/// Static route origination entry: `originate <prefix> nexthop <addr>`.
/// Both fields stay as strings here -- the language layer keeps tokens raw and
/// `BgpConfig` validates them when injecting into the loc-rib at startup.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OriginateRoute {
    pub prefix: String,
    pub nexthop: String,
}

/// `peer <ADDRESS> { ... }` block. The block header is the peer's IP address;
/// there is no separate symbolic name. Matches Cisco/FRR/Junos/GoBGP convention.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerBlock {
    pub address: String,
    pub settings: Vec<Setting>,
    pub families: Vec<FamilyBlock>,
}

/// `family <afi> <safi> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct FamilyBlock {
    pub afi: Afi,
    pub safi: Safi,
    pub directives: Vec<FamilyDirective>,
}

/// Directive inside a family block.
#[derive(Debug, Clone, PartialEq)]
pub enum FamilyDirective {
    ExportPolicy(String),
    ImportPolicy(String),
    /// `max-prefix N [action terminate|discard]`. Action defaults to
    /// terminate (matches `MaxPrefixSetting`'s default).
    MaxPrefix {
        limit: u32,
        action: MaxPrefixActionKind,
    },
    /// `add-path-send all|disabled` — RFC 7911 send mode override.
    AddPathSend(AddPathSendMode),
}

/// `action` qualifier on `max-prefix`. Maps to `conf::bgp::MaxPrefixAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxPrefixActionKind {
    Terminate,
    Discard,
}

/// `add-path-send` value. Maps to `conf::bgp::AddPathSend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddPathSendMode {
    All,
    Disabled,
}

/// `policy <name> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyBlock {
    pub name: String,
    pub rules: Vec<PolicyRule>,
}

/// Rule inside a policy block. Two surfaces coexist: shorthand `match SET
/// ACTION` / `default ACTION` for the common case, and full `statement
/// { ... }` blocks for the rest of `StatementConfig`.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyRule {
    /// `match <prefix-set> <accept|reject>` shorthand.
    Match { set_name: String, action: String },
    /// `default <accept|reject>` shorthand.
    Default { action: String },
    /// Full statement block.
    Statement(StatementBlock),
}

/// Full statement block with arbitrary match clauses, set clauses, and a
/// final disposition. Mirrors `conf::bgp::StatementConfig`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StatementBlock {
    pub name: Option<String>,
    pub matches: Vec<MatchClause>,
    pub sets: Vec<SetClause>,
    pub disposition: Option<Disposition>,
}

/// Match clause inside a statement block. Each variant maps to a single
/// `ConditionsConfig` field.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchClause {
    PrefixSet(MatchSetRef),
    NeighborSet(MatchSetRef),
    AsPathSet(MatchSetRef),
    CommunitySet(MatchSetRef),
    ExtCommunitySet(MatchSetRef),
    LargeCommunitySet(MatchSetRef),
    Prefix(String),
    Neighbor(String),
    HasAsn(u32),
    RouteType(String),
    Community(String),
    Rpki(RpkiValidationKind),
    AfiSafi(String),
    LsNlriType(String),
    LsProtocolId(String),
    LsInstanceId(u64),
    LsNodeAs(u32),
    LsNodeRouterId(String),
}

/// Reference to a defined-set in a match clause.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchSetRef {
    pub set_name: String,
    pub option: MatchOptionKind,
}

/// `any` (default), `all`, or `invert` modifier on a defined-set match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOptionKind {
    Any,
    All,
    Invert,
}

/// RFC 6811 RPKI validation states recognized in match / set clauses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpkiValidationKind {
    Valid,
    Invalid,
    NotFound,
}

/// Set clause inside a statement block. Each variant maps to a single
/// `ActionsConfig` field.
#[derive(Debug, Clone, PartialEq)]
pub enum SetClause {
    LocalPref { value: u32, force: bool },
    Med(MedSet),
    Community(CommunityOp),
    ExtCommunity(CommunityOp),
    LargeCommunity(CommunityOp),
    SetRpkiState(RpkiValidationKind),
}

#[derive(Debug, Clone, PartialEq)]
pub enum MedSet {
    Set(u32),
    Remove,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommunityOp {
    pub op: CommunityOpKind,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityOpKind {
    Add,
    Remove,
    Replace,
}

/// Final disposition of a statement: `accept` or `reject`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Accept,
    Reject,
}

/// `prefix-list <name> { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefixListBlock {
    pub name: String,
    pub prefixes: Vec<PrefixListEntry>,
}

/// One entry in a `prefix-list` block. The optional `range` lets an
/// operator widen or narrow the match: `prefix exact` matches only the
/// configured masklen; `prefix ge N le M` matches masklens in `[N, M]`.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefixListEntry {
    pub prefix: String,
    pub range: Option<MasklengthRange>,
}

/// Optional masklength qualifier on a prefix-list entry.
#[derive(Debug, Clone, PartialEq)]
pub enum MasklengthRange {
    /// `prefix exact` -- matches only the prefix's own masklen.
    Exact,
    /// `prefix [ge N] [le M]` -- at least one of `ge`/`le` is `Some`.
    /// `ge` defaults to the prefix's masklen; `le` defaults to the AFI max.
    Range { ge: Option<u8>, le: Option<u8> },
}

/// `neighbor-set <name> { ADDR; ADDR }` block. Entries are IP literals
/// (parsing accepts any token; the runtime validates the address shape).
#[derive(Debug, Clone, PartialEq)]
pub struct NeighborSetBlock {
    pub name: String,
    pub neighbors: Vec<String>,
}

/// `as-path-set <name> { "REGEX"; "REGEX" }` block. Entries are
/// quote-wrapped regex strings; parser strips the quotes.
#[derive(Debug, Clone, PartialEq)]
pub struct AsPathSetBlock {
    pub name: String,
    pub patterns: Vec<String>,
}

/// `community-set <name> { AA:NN; AA:NN }` block. Entry shape is a
/// 32-bit community in `AA:NN` notation; parser stores it as a token.
#[derive(Debug, Clone, PartialEq)]
pub struct CommunitySetBlock {
    pub name: String,
    pub communities: Vec<String>,
}

/// `ext-community-set <name> { rt:AA:NN; soo:AA:NN }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtCommunitySetBlock {
    pub name: String,
    pub ext_communities: Vec<String>,
}

/// `large-community-set <name> { GA:LD1:LD2 }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct LargeCommunitySetBlock {
    pub name: String,
    pub large_communities: Vec<String>,
}

/// `bmp-server <ADDR> { ... }` block. Mirrors `conf::bgp::BmpConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct BmpServerBlock {
    pub address: String,
    pub statistics_timeout: Option<u64>,
}

/// `bgp-ls { ... }` block. Mirrors operational fields of `conf::bgp::BgpLsConfig`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BgpLsBlock {
    pub instance_id: u64,
}

/// `telemetry { ... }` block. Mirrors `conf::bgp::TelemetryConfig`.
/// `json` and `cloudwatch-emf` are mutually exclusive (both render metrics to
/// the same stdout stream); enforced at parse time.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TelemetryBlock {
    pub json: bool,
    pub cloudwatch_emf: Option<CloudwatchEmfBlock>,
    pub prometheus: Option<PrometheusBlock>,
}

/// `cloudwatch-emf { ... }` sub-block of telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct CloudwatchEmfBlock {
    pub namespace: String,
}

/// `prometheus { ... }` sub-block of telemetry. `listen` defaults to
/// 127.0.0.1:9273 when omitted.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PrometheusBlock {
    pub listen: Option<String>,
}

/// `rpki-cache <ADDR> { ... }` block. Mirrors `conf::bgp::RpkiCacheConfig`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RpkiCacheBlock {
    pub address: String,
    pub preference: Option<u8>,
    pub transport: Option<TransportType>,
    pub ssh_username: Option<String>,
    pub ssh_private_key_file: Option<String>,
    pub ssh_known_hosts_file: Option<String>,
    pub retry_interval: Option<u64>,
    pub refresh_interval: Option<u64>,
    pub expire_interval: Option<u64>,
}

impl fmt::Display for Setting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Setting::Asn(v) => write!(f, "asn {}", v),
            Setting::RouterId(v) => write!(f, "router-id {}", v),
            Setting::ListenAddr(v) => write!(f, "listen-addr {}", v),
            Setting::GrpcListenAddr(v) => write!(f, "grpc-listen-addr {}", v),
            Setting::LogLevel(v) => write!(f, "log-level {}", v),
            Setting::HoldTime(v) => write!(f, "hold-time {}", v),
            Setting::ConnectRetry(v) => write!(f, "connect-retry {}", v),
            Setting::ClusterId(v) => write!(f, "cluster-id {}", v),
            Setting::SysName(v) => write!(f, "sys-name {}", quote_if_needed(v)),
            Setting::SysDescr(v) => write!(f, "sys-descr {}", quote_if_needed(v)),
            Setting::EnhancedRrStaleTtl(v) => write!(f, "enhanced-rr-stale-ttl {}", v),
            Setting::RemoteAs(v) => write!(f, "remote-as {}", v),
            Setting::Port(v) => write!(f, "port {}", v),
            Setting::Interface(v) => write!(f, "interface {}", v),
            Setting::Md5KeyFile(v) => write!(f, "md5-key-file {}", v),
            Setting::TtlMin(v) => write!(f, "ttl-min {}", v),
            Setting::NextHopSelf(v) => write!(f, "next-hop-self {}", v),
            Setting::Passive(v) => write!(f, "passive {}", v),
            Setting::RrClient(v) => write!(f, "rr-client {}", v),
            Setting::RsClient(v) => write!(f, "rs-client {}", v),
            Setting::GracefulShutdown(v) => write!(f, "graceful-shutdown {}", v),
            Setting::Originate(r) => write!(f, "originate {} nexthop {}", r.prefix, r.nexthop),
            Setting::DelayOpenTimeSecs(v) => write!(f, "delay-open-time-secs {}", v),
            Setting::IdleHoldTimeSecs(v) => write!(f, "idle-hold-time-secs {}", v),
            Setting::DampPeerOscillations(v) => write!(f, "damp-peer-oscillations {}", v),
            Setting::AllowAutomaticStop(v) => write!(f, "allow-automatic-stop {}", v),
            Setting::SendNotificationWithoutOpen(v) => {
                write!(f, "send-notification-without-open {}", v)
            }
            Setting::MinRouteAdvertisementIntervalSecs(v) => {
                write!(f, "min-route-advertisement-interval-secs {}", v)
            }
            Setting::EnforceFirstAs(v) => write!(f, "enforce-first-as {}", v),
            Setting::SendRpkiCommunity(v) => write!(f, "send-rpki-community {}", v),
            Setting::AdminDown(v) => write!(f, "admin-down {}", v),
        }
    }
}

impl fmt::Display for FamilyDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FamilyDirective::ExportPolicy(name) => write!(f, "export policy {}", name),
            FamilyDirective::ImportPolicy(name) => write!(f, "import policy {}", name),
            FamilyDirective::MaxPrefix { limit, action } => match action {
                MaxPrefixActionKind::Terminate => write!(f, "max-prefix {}", limit),
                MaxPrefixActionKind::Discard => {
                    write!(f, "max-prefix {} action discard", limit)
                }
            },
            FamilyDirective::AddPathSend(mode) => match mode {
                AddPathSendMode::All => write!(f, "add-path-send all"),
                AddPathSendMode::Disabled => write!(f, "add-path-send disabled"),
            },
        }
    }
}

impl fmt::Display for PolicyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyRule::Match { set_name, action } => write!(f, "match {} {}", set_name, action),
            PolicyRule::Default { action } => write!(f, "default {}", action),
            PolicyRule::Statement(block) => write!(f, "{}", block),
        }
    }
}

impl fmt::Display for FamilyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "family {} {} {{",
            self.afi.as_config_str(),
            self.safi.as_config_str()
        )?;
        for d in &self.directives {
            writeln!(f, "  {}", d)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for PolicyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "policy {} {{", self.name)?;
        for rule in &self.rules {
            match rule {
                PolicyRule::Statement(block) => {
                    for line in block.to_string().lines() {
                        writeln!(f, "  {}", line)?;
                    }
                }
                PolicyRule::Match { .. } | PolicyRule::Default { .. } => writeln!(f, "  {}", rule)?,
            }
        }
        write!(f, "}}")
    }
}

impl fmt::Display for StatementBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => writeln!(f, "statement {} {{", name)?,
            None => writeln!(f, "statement {{")?,
        }
        for m in &self.matches {
            writeln!(f, "  {}", m)?;
        }
        for s in &self.sets {
            writeln!(f, "  {}", s)?;
        }
        if let Some(d) = self.disposition {
            writeln!(
                f,
                "  {}",
                match d {
                    Disposition::Accept => "accept",
                    Disposition::Reject => "reject",
                }
            )?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for MatchSetRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.option {
            MatchOptionKind::Any => write!(f, "{}", self.set_name),
            MatchOptionKind::All => write!(f, "{} all", self.set_name),
            MatchOptionKind::Invert => write!(f, "{} invert", self.set_name),
        }
    }
}

impl fmt::Display for MatchClause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchClause::PrefixSet(r) => write!(f, "match prefix-set {}", r),
            MatchClause::NeighborSet(r) => write!(f, "match neighbor-set {}", r),
            MatchClause::AsPathSet(r) => write!(f, "match as-path-set {}", r),
            MatchClause::CommunitySet(r) => write!(f, "match community-set {}", r),
            MatchClause::ExtCommunitySet(r) => write!(f, "match ext-community-set {}", r),
            MatchClause::LargeCommunitySet(r) => write!(f, "match large-community-set {}", r),
            MatchClause::Prefix(s) => write!(f, "match prefix {}", s),
            MatchClause::Neighbor(s) => write!(f, "match neighbor {}", s),
            MatchClause::HasAsn(v) => write!(f, "match has-asn {}", v),
            MatchClause::RouteType(s) => write!(f, "match route-type {}", s),
            MatchClause::Community(s) => write!(f, "match community {}", s),
            MatchClause::Rpki(v) => write!(f, "match rpki {}", rpki_validation_to_str(*v)),
            MatchClause::AfiSafi(s) => write!(f, "match afi-safi {}", s),
            MatchClause::LsNlriType(s) => write!(f, "match ls-nlri-type {}", s),
            MatchClause::LsProtocolId(s) => write!(f, "match ls-protocol-id {}", s),
            MatchClause::LsInstanceId(v) => write!(f, "match ls-instance-id {}", v),
            MatchClause::LsNodeAs(v) => write!(f, "match ls-node-as {}", v),
            MatchClause::LsNodeRouterId(s) => write!(f, "match ls-node-router-id {}", s),
        }
    }
}

impl fmt::Display for SetClause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetClause::LocalPref { value, force } => {
                if *force {
                    write!(f, "set local-pref force {}", value)
                } else {
                    write!(f, "set local-pref {}", value)
                }
            }
            SetClause::Med(MedSet::Set(v)) => write!(f, "set med {}", v),
            SetClause::Med(MedSet::Remove) => write!(f, "set med remove"),
            SetClause::Community(op) => write_community_set(f, "community", op),
            SetClause::ExtCommunity(op) => write_community_set(f, "ext-community", op),
            SetClause::LargeCommunity(op) => write_community_set(f, "large-community", op),
            SetClause::SetRpkiState(v) => {
                write!(f, "set rpki-state {}", rpki_validation_to_str(*v))
            }
        }
    }
}

fn write_community_set(f: &mut fmt::Formatter<'_>, keyword: &str, op: &CommunityOp) -> fmt::Result {
    let op_str = match op.op {
        CommunityOpKind::Add => "add",
        CommunityOpKind::Remove => "remove",
        CommunityOpKind::Replace => "replace",
    };
    write!(f, "set {} {}", keyword, op_str)?;
    for v in &op.values {
        write!(f, " {}", v)?;
    }
    Ok(())
}

fn rpki_validation_to_str(v: RpkiValidationKind) -> &'static str {
    match v {
        RpkiValidationKind::Valid => "valid",
        RpkiValidationKind::Invalid => "invalid",
        RpkiValidationKind::NotFound => "not-found",
    }
}

impl fmt::Display for PrefixListBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "prefix-list {} {{", self.name)?;
        for entry in &self.prefixes {
            writeln!(f, "  {}", entry)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for PrefixListEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.range {
            None => write!(f, "{}", self.prefix),
            Some(MasklengthRange::Exact) => write!(f, "{} exact", self.prefix),
            Some(MasklengthRange::Range { ge, le }) => {
                write!(f, "{}", self.prefix)?;
                if let Some(g) = ge {
                    write!(f, " ge {}", g)?;
                }
                if let Some(l) = le {
                    write!(f, " le {}", l)?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for NeighborSetBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "neighbor-set {} {{", self.name)?;
        for entry in &self.neighbors {
            writeln!(f, "  {}", entry)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for AsPathSetBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "as-path-set {} {{", self.name)?;
        for pattern in &self.patterns {
            // AS-path patterns can contain whitespace; emit them quoted so the
            // tokenizer treats each one as a single token on parse.
            writeln!(f, "  \"{}\"", pattern)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for CommunitySetBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "community-set {} {{", self.name)?;
        for entry in &self.communities {
            writeln!(f, "  {}", entry)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for ExtCommunitySetBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ext-community-set {} {{", self.name)?;
        for entry in &self.ext_communities {
            writeln!(f, "  {}", entry)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for LargeCommunitySetBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "large-community-set {} {{", self.name)?;
        for entry in &self.large_communities {
            writeln!(f, "  {}", entry)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for BgpLsBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "bgp-ls {{")?;
        writeln!(f, "  instance-id {}", self.instance_id)?;
        write!(f, "}}")
    }
}

impl fmt::Display for TelemetryBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "telemetry {{")?;
        if self.json {
            writeln!(f, "  json {{}}")?;
        }
        if let Some(emf) = &self.cloudwatch_emf {
            writeln!(f, "  cloudwatch-emf {{")?;
            writeln!(f, "    namespace {}", emf.namespace)?;
            writeln!(f, "  }}")?;
        }
        if let Some(prometheus) = &self.prometheus {
            match &prometheus.listen {
                Some(listen) => {
                    writeln!(f, "  prometheus {{")?;
                    writeln!(f, "    listen {}", listen)?;
                    writeln!(f, "  }}")?;
                }
                None => writeln!(f, "  prometheus {{}}")?,
            }
        }
        write!(f, "}}")
    }
}

impl fmt::Display for BmpServerBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "bmp-server {} {{", self.address)?;
        if let Some(v) = self.statistics_timeout {
            writeln!(f, "  statistics-timeout {}", v)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for RpkiCacheBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "rpki-cache {} {{", self.address)?;
        if let Some(v) = self.preference {
            writeln!(f, "  preference {}", v)?;
        }
        if let Some(v) = &self.transport {
            writeln!(f, "  transport {}", v.as_config_str())?;
        }
        if let Some(v) = &self.ssh_username {
            writeln!(f, "  ssh-username {}", v)?;
        }
        if let Some(v) = &self.ssh_private_key_file {
            writeln!(f, "  ssh-private-key-file {}", v)?;
        }
        if let Some(v) = &self.ssh_known_hosts_file {
            writeln!(f, "  ssh-known-hosts-file {}", v)?;
        }
        if let Some(v) = self.retry_interval {
            writeln!(f, "  retry-interval {}", v)?;
        }
        if let Some(v) = self.refresh_interval {
            writeln!(f, "  refresh-interval {}", v)?;
        }
        if let Some(v) = self.expire_interval {
            writeln!(f, "  expire-interval {}", v)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for PeerBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "peer {} {{", self.address)?;
        for setting in &self.settings {
            writeln!(f, "  {}", setting)?;
        }
        for family in &self.families {
            writeln!(f)?;
            for line in family.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
        }
        write!(f, "}}")
    }
}

impl fmt::Display for BgpServiceBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "service bgp {{")?;
        let mut first = true;
        for setting in &self.settings {
            writeln!(f, "  {}", setting)?;
            first = false;
        }
        for peer in &self.peers {
            if !first {
                writeln!(f)?;
            }
            for line in peer.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for bmp in &self.bmp_servers {
            if !first {
                writeln!(f)?;
            }
            for line in bmp.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for rpki in &self.rpki_caches {
            if !first {
                writeln!(f)?;
            }
            for line in rpki.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for policy in &self.policies {
            if !first {
                writeln!(f)?;
            }
            for line in policy.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for prefix_list in &self.prefix_lists {
            if !first {
                writeln!(f)?;
            }
            for line in prefix_list.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for neighbor_set in &self.neighbor_sets {
            if !first {
                writeln!(f)?;
            }
            for line in neighbor_set.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for as_path_set in &self.as_path_sets {
            if !first {
                writeln!(f)?;
            }
            for line in as_path_set.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for community_set in &self.community_sets {
            if !first {
                writeln!(f)?;
            }
            for line in community_set.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for ext_community_set in &self.ext_community_sets {
            if !first {
                writeln!(f)?;
            }
            for line in ext_community_set.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        for large_community_set in &self.large_community_sets {
            if !first {
                writeln!(f)?;
            }
            for line in large_community_set.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        if let Some(bgp_ls) = &self.bgp_ls {
            if !first {
                writeln!(f)?;
            }
            for line in bgp_ls.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
            first = false;
        }
        if let Some(telemetry) = &self.telemetry {
            if !first {
                writeln!(f)?;
            }
            for line in telemetry.to_string().lines() {
                writeln!(f, "  {}", line)?;
            }
        }
        write!(f, "}}")
    }
}

impl Setting {
    /// Parse a typed Setting from a keyword and optional value word. Line-free;
    /// config-file callers attach line context, ggsh uses the message directly.
    pub fn parse(key: &str, value: Option<&str>) -> Result<Setting, String> {
        Ok(match key {
            "asn" => Setting::Asn(parse_value(key, value)?),
            "router-id" => Setting::RouterId(parse_value(key, value)?),
            "listen-addr" => Setting::ListenAddr(parse_value(key, value)?),
            "grpc-listen-addr" => Setting::GrpcListenAddr(parse_value(key, value)?),
            "log-level" => Setting::LogLevel(parse_value(key, value)?),
            "hold-time" => Setting::HoldTime(parse_value(key, value)?),
            "connect-retry" => Setting::ConnectRetry(parse_value(key, value)?),
            "cluster-id" => Setting::ClusterId(parse_value(key, value)?),
            "sys-name" => Setting::SysName(parse_value(key, value)?),
            "sys-descr" => Setting::SysDescr(parse_value(key, value)?),
            "enhanced-rr-stale-ttl" => Setting::EnhancedRrStaleTtl(parse_value(key, value)?),
            "remote-as" => Setting::RemoteAs(parse_value(key, value)?),
            "port" => Setting::Port(parse_value(key, value)?),
            "interface" => Setting::Interface(parse_value(key, value)?),
            "md5-key-file" => Setting::Md5KeyFile(parse_value(key, value)?),
            "ttl-min" => Setting::TtlMin(parse_value(key, value)?),
            "next-hop-self" => Setting::NextHopSelf(parse_value(key, value)?),
            "passive" => Setting::Passive(parse_value(key, value)?),
            "rr-client" => Setting::RrClient(parse_value(key, value)?),
            "rs-client" => Setting::RsClient(parse_value(key, value)?),
            "graceful-shutdown" => Setting::GracefulShutdown(parse_value(key, value)?),
            "originate" => {
                return Err(
                    "originate must be written as 'originate <prefix> nexthop <addr>'".to_string(),
                )
            }
            "delay-open-time-secs" => Setting::DelayOpenTimeSecs(parse_value(key, value)?),
            "idle-hold-time-secs" => Setting::IdleHoldTimeSecs(parse_value(key, value)?),
            "damp-peer-oscillations" => Setting::DampPeerOscillations(parse_value(key, value)?),
            "allow-automatic-stop" => Setting::AllowAutomaticStop(parse_value(key, value)?),
            "send-notification-without-open" => {
                Setting::SendNotificationWithoutOpen(parse_value(key, value)?)
            }
            "min-route-advertisement-interval-secs" => {
                Setting::MinRouteAdvertisementIntervalSecs(parse_value(key, value)?)
            }
            "enforce-first-as" => Setting::EnforceFirstAs(parse_value(key, value)?),
            "send-rpki-community" => Setting::SendRpkiCommunity(parse_value(key, value)?),
            "admin-down" => Setting::AdminDown(parse_value(key, value)?),
            other => return Err(format!("unknown setting '{}'", other)),
        })
    }
}

fn quote_if_needed(s: &str) -> String {
    if s.contains(|c: char| c.is_whitespace() || c == '"' || c == '#' || c == '{' || c == '}') {
        let cleaned: String = s.chars().filter(|c| *c != '"').collect();
        format!("\"{}\"", cleaned)
    } else {
        s.to_string()
    }
}

/// Parse a value of type `T` for the given keyword. `T`'s `FromStr` impl validates;
/// the Setting variant's inner type decides `T` via inference.
fn parse_value<T>(key: &str, value: Option<&str>) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let val = value.ok_or_else(|| format!("{} requires a value", key))?;
    val.parse::<T>()
        .map_err(|err| format!("invalid {} '{}': {}", key, val, err))
}

pub(crate) fn parse_bgp_body(
    tokens: &[Token],
    pos: &mut usize,
) -> Result<BgpServiceBody, ParseError> {
    let mut body = BgpServiceBody::default();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{'"));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "peer" => {
                let address = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "peer requires an address"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.peers.push(parse_peer_block(address, tokens, pos)?);
            }
            "policy" => {
                let name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "policy requires a name"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.policies.push(parse_policy_block(name, tokens, pos)?);
            }
            "prefix-list" => {
                let name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "prefix-list requires a name"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.prefix_lists
                    .push(parse_prefix_list_block(name, tokens, pos)?);
            }
            "neighbor-set" => {
                let name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "neighbor-set requires a name"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.neighbor_sets
                    .push(parse_neighbor_set_block(name, tokens, pos)?);
            }
            "as-path-set" => {
                let name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "as-path-set requires a name"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.as_path_sets
                    .push(parse_as_path_set_block(name, tokens, pos)?);
            }
            "community-set" => {
                let name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "community-set requires a name"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.community_sets
                    .push(parse_community_set_block(name, tokens, pos)?);
            }
            "ext-community-set" => {
                let name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "ext-community-set requires a name"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.ext_community_sets
                    .push(parse_ext_community_set_block(name, tokens, pos)?);
            }
            "large-community-set" => {
                let name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "large-community-set requires a name"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.large_community_sets
                    .push(parse_large_community_set_block(name, tokens, pos)?);
            }
            "bmp-server" => {
                let address = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "bmp-server requires an address"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.bmp_servers
                    .push(parse_bmp_server_block(address, tokens, pos)?);
            }
            "rpki-cache" => {
                let address = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "rpki-cache requires an address"))?
                    .0;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.rpki_caches
                    .push(parse_rpki_cache_block(address, tokens, pos)?);
            }
            "bgp-ls" => {
                if body.bgp_ls.is_some() {
                    return Err(parse_err(line, "duplicate 'bgp-ls' block"));
                }
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.bgp_ls = Some(parse_bgp_ls_block(tokens, pos)?);
            }
            "telemetry" => {
                if body.telemetry.is_some() {
                    return Err(parse_err(line, "duplicate 'telemetry' block"));
                }
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                body.telemetry = Some(parse_telemetry_block(line, tokens, pos)?);
            }
            "originate" => {
                let route = parse_originate_setting(tokens, pos, line)?;
                finish_statement(tokens, pos)?;
                body.settings.push(Setting::Originate(route));
            }
            _ => {
                let value = take_word(tokens, pos);
                finish_statement(tokens, pos)?;
                body.settings.push(
                    Setting::parse(&key, value.as_deref()).map_err(|msg| parse_err(line, msg))?,
                );
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(body)
}

/// Consume the body of an `originate <prefix> nexthop <addr>` line.
/// The leading `originate` keyword is already consumed by the caller.
fn parse_originate_setting(
    tokens: &[Token],
    pos: &mut usize,
    line: usize,
) -> Result<OriginateRoute, ParseError> {
    let prefix = expect_word(tokens, pos)
        .map_err(|_| parse_err(line, "originate requires a prefix"))?
        .0;
    let kw = expect_word(tokens, pos)
        .map_err(|_| parse_err(line, "originate requires 'nexthop <addr>'"))?
        .0;
    if kw != "nexthop" {
        return Err(parse_err(line, format!("expected 'nexthop', got '{}'", kw)));
    }
    let nexthop = expect_word(tokens, pos)
        .map_err(|_| parse_err(line, "nexthop requires an address"))?
        .0;
    Ok(OriginateRoute { prefix, nexthop })
}

fn unexpected_eof(tokens: &[Token], pos: usize) -> ParseError {
    parse_err(
        crate::language::current_line(tokens, pos),
        "unexpected end of input, expected '}'",
    )
}

fn parse_peer_block(
    address: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PeerBlock, ParseError> {
    let mut settings = Vec::new();
    let mut families = Vec::new();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{'"));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "family" => {
                let afi_str = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "family requires afi"))?
                    .0;
                let afi: Afi = afi_str.parse().map_err(|err| {
                    parse_err(line, format!("invalid afi '{}': {}", afi_str, err))
                })?;
                let safi_str = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "family requires safi"))?
                    .0;
                let safi: Safi = safi_str.parse().map_err(|err| {
                    parse_err(line, format!("invalid safi '{}': {}", safi_str, err))
                })?;
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                families.push(parse_family_block(afi, safi, tokens, pos)?);
            }
            _ => {
                let value = take_word(tokens, pos);
                finish_statement(tokens, pos)?;
                settings.push(
                    Setting::parse(&key, value.as_deref()).map_err(|msg| parse_err(line, msg))?,
                );
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(PeerBlock {
        address,
        settings,
        families,
    })
}

fn parse_family_block(
    afi: Afi,
    safi: Safi,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<FamilyBlock, ParseError> {
    let mut directives = Vec::new();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{' inside family"));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        let directive = match key.as_str() {
            "export" | "import" => {
                let sub = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, format!("{} requires 'policy'", key)))?
                    .0;
                if sub != "policy" {
                    return Err(parse_err(
                        line,
                        format!("{} requires 'policy', got '{}'", key, sub),
                    ));
                }
                let policy_name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, format!("{} policy requires a name", key)))?
                    .0;
                if key == "export" {
                    FamilyDirective::ExportPolicy(policy_name)
                } else {
                    FamilyDirective::ImportPolicy(policy_name)
                }
            }
            "max-prefix" => {
                // `max-prefix N [action terminate|discard]`
                let (limit_str, _) = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "max-prefix requires a value"))?;
                let limit: u32 = limit_str.parse().map_err(|_| {
                    parse_err(line, format!("invalid max-prefix value '{}'", limit_str))
                })?;
                let mut action = MaxPrefixActionKind::Terminate;
                if let Some(TokenKind::Word(w)) = peek_kind(tokens, *pos) {
                    if w == "action" {
                        take_word(tokens, pos);
                        let action_word = expect_word(tokens, pos)
                            .map_err(|_| parse_err(line, "action requires terminate|discard"))?
                            .0;
                        action = match action_word.as_str() {
                            "terminate" => MaxPrefixActionKind::Terminate,
                            "discard" => MaxPrefixActionKind::Discard,
                            other => {
                                return Err(parse_err(
                                    line,
                                    format!(
                                        "max-prefix action must be 'terminate' or 'discard', got '{}'",
                                        other
                                    ),
                                ));
                            }
                        };
                    }
                }
                finish_statement(tokens, pos)?;
                FamilyDirective::MaxPrefix { limit, action }
            }
            "add-path-send" => {
                let val = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "add-path-send requires a value"))?
                    .0;
                let mode = match val.as_str() {
                    "all" => AddPathSendMode::All,
                    "disabled" => AddPathSendMode::Disabled,
                    other => {
                        return Err(parse_err(
                            line,
                            format!("add-path-send must be 'all' or 'disabled', got '{}'", other),
                        ));
                    }
                };
                finish_statement(tokens, pos)?;
                FamilyDirective::AddPathSend(mode)
            }
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown family directive '{}'", other),
                ));
            }
        };
        if !matches!(
            &directive,
            FamilyDirective::MaxPrefix { .. } | FamilyDirective::AddPathSend(_)
        ) {
            finish_statement(tokens, pos)?;
        }
        directives.push(directive);
    }
    expect_close_brace(tokens, pos)?;
    Ok(FamilyBlock {
        afi,
        safi,
        directives,
    })
}

fn parse_policy_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PolicyBlock, ParseError> {
    let mut rules = Vec::new();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{' inside policy"));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        let rule = match key.as_str() {
            "match" => {
                let set_name = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "match requires a set name"))?
                    .0;
                let action = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "match requires an action"))?
                    .0;
                finish_statement(tokens, pos)?;
                PolicyRule::Match { set_name, action }
            }
            "default" => {
                let action = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "default requires an action"))?
                    .0;
                finish_statement(tokens, pos)?;
                PolicyRule::Default { action }
            }
            "statement" => {
                // `statement [NAME] { ... }` — the optional name precedes the open brace.
                let stmt_name = match peek_kind(tokens, *pos) {
                    Some(TokenKind::OpenBrace) => None,
                    Some(TokenKind::Word(_)) => {
                        let (n, _) = expect_word(tokens, pos)?;
                        Some(n)
                    }
                    _ => None,
                };
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                let block = parse_statement_block(stmt_name, tokens, pos)?;
                PolicyRule::Statement(block)
            }
            other => {
                return Err(parse_err(line, format!("unknown policy rule '{}'", other)));
            }
        };
        rules.push(rule);
    }
    expect_close_brace(tokens, pos)?;
    Ok(PolicyBlock { name, rules })
}

fn parse_statement_block(
    name: Option<String>,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<StatementBlock, ParseError> {
    let mut block = StatementBlock {
        name,
        ..Default::default()
    };
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside statement",
                ));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "match" => block.matches.push(parse_match_clause(line, tokens, pos)?),
            "set" => block.sets.push(parse_set_clause(line, tokens, pos)?),
            "accept" => {
                if block.disposition.is_some() {
                    return Err(parse_err(line, "duplicate disposition"));
                }
                block.disposition = Some(Disposition::Accept);
                finish_statement(tokens, pos)?;
            }
            "reject" => {
                if block.disposition.is_some() {
                    return Err(parse_err(line, "duplicate disposition"));
                }
                block.disposition = Some(Disposition::Reject);
                finish_statement(tokens, pos)?;
            }
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown statement directive '{}'", other),
                ));
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(block)
}

fn parse_match_clause(
    line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<MatchClause, ParseError> {
    let (kind, _) =
        expect_word(tokens, pos).map_err(|_| parse_err(line, "match requires a directive"))?;
    let clause = match kind.as_str() {
        "prefix-set" => MatchClause::PrefixSet(parse_match_set_ref(line, tokens, pos)?),
        "neighbor-set" => MatchClause::NeighborSet(parse_match_set_ref(line, tokens, pos)?),
        "as-path-set" => MatchClause::AsPathSet(parse_match_set_ref(line, tokens, pos)?),
        "community-set" => MatchClause::CommunitySet(parse_match_set_ref(line, tokens, pos)?),
        "ext-community-set" => {
            MatchClause::ExtCommunitySet(parse_match_set_ref(line, tokens, pos)?)
        }
        "large-community-set" => {
            MatchClause::LargeCommunitySet(parse_match_set_ref(line, tokens, pos)?)
        }
        "prefix" => MatchClause::Prefix(expect_word(tokens, pos)?.0),
        "neighbor" => MatchClause::Neighbor(expect_word(tokens, pos)?.0),
        "has-asn" => {
            let (s, _) = expect_word(tokens, pos)?;
            MatchClause::HasAsn(
                s.parse()
                    .map_err(|_| parse_err(line, format!("invalid has-asn '{}'", s)))?,
            )
        }
        "route-type" => MatchClause::RouteType(expect_word(tokens, pos)?.0),
        "community" => MatchClause::Community(expect_word(tokens, pos)?.0),
        "rpki" => MatchClause::Rpki(parse_rpki_validation(line, tokens, pos)?),
        "afi-safi" => MatchClause::AfiSafi(expect_word(tokens, pos)?.0),
        "ls-nlri-type" => MatchClause::LsNlriType(expect_word(tokens, pos)?.0),
        "ls-protocol-id" => MatchClause::LsProtocolId(expect_word(tokens, pos)?.0),
        "ls-instance-id" => {
            let (s, _) = expect_word(tokens, pos)?;
            MatchClause::LsInstanceId(
                s.parse()
                    .map_err(|_| parse_err(line, format!("invalid ls-instance-id '{}'", s)))?,
            )
        }
        "ls-node-as" => {
            let (s, _) = expect_word(tokens, pos)?;
            MatchClause::LsNodeAs(
                s.parse()
                    .map_err(|_| parse_err(line, format!("invalid ls-node-as '{}'", s)))?,
            )
        }
        "ls-node-router-id" => MatchClause::LsNodeRouterId(expect_word(tokens, pos)?.0),
        other => {
            return Err(parse_err(
                line,
                format!("unknown match directive '{}'", other),
            ));
        }
    };
    finish_statement(tokens, pos)?;
    Ok(clause)
}

fn parse_match_set_ref(
    line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<MatchSetRef, ParseError> {
    let (set_name, _) =
        expect_word(tokens, pos).map_err(|_| parse_err(line, "match-set requires a set name"))?;
    let mut option = MatchOptionKind::Any;
    if let Some(TokenKind::Word(w)) = peek_kind(tokens, *pos) {
        match w.as_str() {
            "all" => {
                take_word(tokens, pos);
                option = MatchOptionKind::All;
            }
            "invert" => {
                take_word(tokens, pos);
                option = MatchOptionKind::Invert;
            }
            "any" => {
                take_word(tokens, pos);
                option = MatchOptionKind::Any;
            }
            _ => {}
        }
    }
    Ok(MatchSetRef { set_name, option })
}

fn parse_rpki_validation(
    line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<RpkiValidationKind, ParseError> {
    let (s, _) = expect_word(tokens, pos)
        .map_err(|_| parse_err(line, "rpki requires valid|invalid|not-found"))?;
    match s.as_str() {
        "valid" => Ok(RpkiValidationKind::Valid),
        "invalid" => Ok(RpkiValidationKind::Invalid),
        "not-found" => Ok(RpkiValidationKind::NotFound),
        other => Err(parse_err(
            line,
            format!("rpki must be valid|invalid|not-found, got '{}'", other),
        )),
    }
}

fn parse_set_clause(
    line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<SetClause, ParseError> {
    let (kind, _) =
        expect_word(tokens, pos).map_err(|_| parse_err(line, "set requires a directive"))?;
    let clause = match kind.as_str() {
        "local-pref" => {
            // `local-pref N` or `local-pref force N`
            let (next, _) = expect_word(tokens, pos)?;
            if next == "force" {
                let (val, _) = expect_word(tokens, pos)?;
                SetClause::LocalPref {
                    value: val
                        .parse()
                        .map_err(|_| parse_err(line, format!("invalid local-pref '{}'", val)))?,
                    force: true,
                }
            } else {
                SetClause::LocalPref {
                    value: next
                        .parse()
                        .map_err(|_| parse_err(line, format!("invalid local-pref '{}'", next)))?,
                    force: false,
                }
            }
        }
        "med" => {
            let (val, _) = expect_word(tokens, pos)?;
            if val == "remove" {
                SetClause::Med(MedSet::Remove)
            } else {
                SetClause::Med(MedSet::Set(
                    val.parse()
                        .map_err(|_| parse_err(line, format!("invalid med '{}'", val)))?,
                ))
            }
        }
        "community" => SetClause::Community(parse_community_op(line, tokens, pos)?),
        "ext-community" => SetClause::ExtCommunity(parse_community_op(line, tokens, pos)?),
        "large-community" => SetClause::LargeCommunity(parse_community_op(line, tokens, pos)?),
        "rpki-state" => SetClause::SetRpkiState(parse_rpki_validation(line, tokens, pos)?),
        other => {
            return Err(parse_err(
                line,
                format!("unknown set directive '{}'", other),
            ));
        }
    };
    finish_statement(tokens, pos)?;
    Ok(clause)
}

fn parse_community_op(
    line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<CommunityOp, ParseError> {
    let (op_str, _) = expect_word(tokens, pos)
        .map_err(|_| parse_err(line, "community requires add|remove|replace"))?;
    let op = match op_str.as_str() {
        "add" => CommunityOpKind::Add,
        "remove" => CommunityOpKind::Remove,
        "replace" => CommunityOpKind::Replace,
        other => {
            return Err(parse_err(
                line,
                format!("community op must be add|remove|replace, got '{}'", other),
            ));
        }
    };
    let mut values = Vec::new();
    while let Some(TokenKind::Word(_)) = peek_kind(tokens, *pos) {
        let (v, _) = expect_word(tokens, pos)?;
        values.push(v);
    }
    Ok(CommunityOp { op, values })
}

fn parse_prefix_list_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PrefixListBlock, ParseError> {
    let mut prefixes = Vec::new();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside prefix-list",
                ));
            }
            _ => {}
        }
        let (prefix, line) = expect_word(tokens, pos)?;
        let range = parse_optional_masklength_range(line, tokens, pos)?;
        finish_statement(tokens, pos)?;
        prefixes.push(PrefixListEntry { prefix, range });
    }
    expect_close_brace(tokens, pos)?;
    Ok(PrefixListBlock { name, prefixes })
}

/// Parse the optional `exact | ge N [le M] | le M [ge N]` tail after a
/// prefix-list entry's prefix. Caller has consumed the prefix word.
/// Returns `None` if the next token is a newline or close brace.
fn parse_optional_masklength_range(
    line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<Option<MasklengthRange>, ParseError> {
    let mut ge = None;
    let mut le = None;
    let mut exact = false;
    while let Some(TokenKind::Word(w)) = peek_kind(tokens, *pos) {
        match w.as_str() {
            "exact" => {
                if exact {
                    return Err(parse_err(line, "duplicate 'exact'"));
                }
                if ge.is_some() || le.is_some() {
                    return Err(parse_err(line, "'exact' cannot combine with ge/le"));
                }
                take_word(tokens, pos);
                exact = true;
            }
            "ge" => {
                if exact {
                    return Err(parse_err(line, "'ge' cannot combine with 'exact'"));
                }
                take_word(tokens, pos);
                let (val, _) = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "'ge' requires a masklen value"))?;
                let n: u8 = val
                    .parse()
                    .map_err(|_| parse_err(line, format!("invalid masklen for 'ge': '{}'", val)))?;
                if ge.is_some() {
                    return Err(parse_err(line, "duplicate 'ge'"));
                }
                ge = Some(n);
            }
            "le" => {
                if exact {
                    return Err(parse_err(line, "'le' cannot combine with 'exact'"));
                }
                take_word(tokens, pos);
                let (val, _) = expect_word(tokens, pos)
                    .map_err(|_| parse_err(line, "'le' requires a masklen value"))?;
                let n: u8 = val
                    .parse()
                    .map_err(|_| parse_err(line, format!("invalid masklen for 'le': '{}'", val)))?;
                if le.is_some() {
                    return Err(parse_err(line, "duplicate 'le'"));
                }
                le = Some(n);
            }
            _ => break,
        }
    }
    if exact {
        Ok(Some(MasklengthRange::Exact))
    } else if ge.is_some() || le.is_some() {
        Ok(Some(MasklengthRange::Range { ge, le }))
    } else {
        Ok(None)
    }
}

fn parse_word_list_block<F>(
    block_kind: &str,
    tokens: &[Token],
    pos: &mut usize,
    mut on_entry: F,
) -> Result<(), ParseError>
where
    F: FnMut(String),
{
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    format!("unexpected '{{' inside {}", block_kind),
                ));
            }
            _ => {}
        }
        let (entry, _) = expect_word(tokens, pos)?;
        finish_statement(tokens, pos)?;
        on_entry(entry);
    }
    expect_close_brace(tokens, pos)?;
    Ok(())
}

fn parse_neighbor_set_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<NeighborSetBlock, ParseError> {
    let mut neighbors = Vec::new();
    parse_word_list_block("neighbor-set", tokens, pos, |w| neighbors.push(w))?;
    Ok(NeighborSetBlock { name, neighbors })
}

fn parse_as_path_set_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<AsPathSetBlock, ParseError> {
    let mut patterns = Vec::new();
    parse_word_list_block("as-path-set", tokens, pos, |w| patterns.push(w))?;
    Ok(AsPathSetBlock { name, patterns })
}

fn parse_community_set_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<CommunitySetBlock, ParseError> {
    let mut communities = Vec::new();
    parse_word_list_block("community-set", tokens, pos, |w| communities.push(w))?;
    Ok(CommunitySetBlock { name, communities })
}

fn parse_ext_community_set_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<ExtCommunitySetBlock, ParseError> {
    let mut ext_communities = Vec::new();
    parse_word_list_block("ext-community-set", tokens, pos, |w| {
        ext_communities.push(w)
    })?;
    Ok(ExtCommunitySetBlock {
        name,
        ext_communities,
    })
}

fn parse_large_community_set_block(
    name: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<LargeCommunitySetBlock, ParseError> {
    let mut large_communities = Vec::new();
    parse_word_list_block("large-community-set", tokens, pos, |w| {
        large_communities.push(w)
    })?;
    Ok(LargeCommunitySetBlock {
        name,
        large_communities,
    })
}

/// Parse a scalar `key VALUE\n` line. `T` decides how the value is interpreted.
fn parse_scalar<T>(
    key: &str,
    line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<T, ParseError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let value = expect_word(tokens, pos)
        .map_err(|_| parse_err(line, format!("{} requires a value", key)))?
        .0;
    let parsed = value
        .parse::<T>()
        .map_err(|err| parse_err(line, format!("invalid {} '{}': {}", key, value, err)))?;
    finish_statement(tokens, pos)?;
    Ok(parsed)
}

fn parse_bmp_server_block(
    address: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<BmpServerBlock, ParseError> {
    let mut block = BmpServerBlock {
        address,
        statistics_timeout: None,
    };
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside bmp-server",
                ));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "statistics-timeout" => {
                block.statistics_timeout = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown bmp-server directive '{}'", other),
                ));
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(block)
}

fn parse_bgp_ls_block(tokens: &[Token], pos: &mut usize) -> Result<BgpLsBlock, ParseError> {
    let mut block = BgpLsBlock::default();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(tokens[*pos].line, "unexpected '{' inside bgp-ls"));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "instance-id" => {
                block.instance_id = parse_scalar(&key, line, tokens, pos)?;
            }
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown bgp-ls directive '{}'", other),
                ));
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(block)
}

fn parse_telemetry_block(
    block_line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<TelemetryBlock, ParseError> {
    let mut block = TelemetryBlock::default();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside telemetry",
                ));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "json" => {
                if block.json {
                    return Err(parse_err(line, "duplicate 'json' block"));
                }
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                parse_telemetry_json_block(tokens, pos)?;
                block.json = true;
            }
            "cloudwatch-emf" => {
                if block.cloudwatch_emf.is_some() {
                    return Err(parse_err(line, "duplicate 'cloudwatch-emf' block"));
                }
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                block.cloudwatch_emf = Some(parse_cloudwatch_emf_block(line, tokens, pos)?);
            }
            "prometheus" => {
                if block.prometheus.is_some() {
                    return Err(parse_err(line, "duplicate 'prometheus' block"));
                }
                skip_newlines(tokens, pos);
                expect_open_brace(tokens, pos)?;
                block.prometheus = Some(parse_prometheus_block(tokens, pos)?);
            }
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown telemetry directive '{}'", other),
                ));
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    if block.json && block.cloudwatch_emf.is_some() {
        return Err(parse_err(
            block_line,
            "'json' and 'cloudwatch-emf' are mutually exclusive",
        ));
    }
    Ok(block)
}

fn parse_telemetry_json_block(tokens: &[Token], pos: &mut usize) -> Result<(), ParseError> {
    skip_newlines(tokens, pos);
    match peek_kind(tokens, *pos) {
        Some(TokenKind::CloseBrace) => {}
        None => return Err(unexpected_eof(tokens, *pos)),
        Some(TokenKind::OpenBrace) => {
            return Err(parse_err(tokens[*pos].line, "unexpected '{' inside json"));
        }
        _ => {
            let (key, line) = expect_word(tokens, pos)?;
            return Err(parse_err(line, format!("unknown json directive '{}'", key)));
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(())
}

fn parse_cloudwatch_emf_block(
    block_line: usize,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<CloudwatchEmfBlock, ParseError> {
    let mut namespace: Option<String> = None;
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside cloudwatch-emf",
                ));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "namespace" => namespace = Some(parse_scalar(&key, line, tokens, pos)?),
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown cloudwatch-emf directive '{}'", other),
                ));
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    match namespace {
        Some(namespace) => Ok(CloudwatchEmfBlock { namespace }),
        None => Err(parse_err(block_line, "cloudwatch-emf requires 'namespace'")),
    }
}

fn parse_prometheus_block(
    tokens: &[Token],
    pos: &mut usize,
) -> Result<PrometheusBlock, ParseError> {
    let mut block = PrometheusBlock::default();
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside prometheus",
                ));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "listen" => block.listen = Some(parse_scalar(&key, line, tokens, pos)?),
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown prometheus directive '{}'", other),
                ));
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(block)
}

fn parse_rpki_cache_block(
    address: String,
    tokens: &[Token],
    pos: &mut usize,
) -> Result<RpkiCacheBlock, ParseError> {
    let mut block = RpkiCacheBlock {
        address,
        ..RpkiCacheBlock::default()
    };
    loop {
        skip_newlines(tokens, pos);
        match peek_kind(tokens, *pos) {
            Some(TokenKind::CloseBrace) => break,
            None => return Err(unexpected_eof(tokens, *pos)),
            Some(TokenKind::OpenBrace) => {
                return Err(parse_err(
                    tokens[*pos].line,
                    "unexpected '{' inside rpki-cache",
                ));
            }
            _ => {}
        }
        let (key, line) = expect_word(tokens, pos)?;
        match key.as_str() {
            "preference" => block.preference = Some(parse_scalar(&key, line, tokens, pos)?),
            "transport" => block.transport = Some(parse_scalar(&key, line, tokens, pos)?),
            "ssh-username" => block.ssh_username = Some(parse_scalar(&key, line, tokens, pos)?),
            "ssh-private-key-file" => {
                block.ssh_private_key_file = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            "ssh-known-hosts-file" => {
                block.ssh_known_hosts_file = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            "retry-interval" => block.retry_interval = Some(parse_scalar(&key, line, tokens, pos)?),
            "refresh-interval" => {
                block.refresh_interval = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            "expire-interval" => {
                block.expire_interval = Some(parse_scalar(&key, line, tokens, pos)?);
            }
            other => {
                return Err(parse_err(
                    line,
                    format!("unknown rpki-cache directive '{}'", other),
                ));
            }
        }
    }
    expect_close_brace(tokens, pos)?;
    Ok(block)
}

/// Token shape vocabulary. Each variant is a predicate over a single token,
/// shared by config-setting values and grammar-tree args (peer addresses,
/// AFI/SAFI keywords, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Asn,
    Ipv4,
    IpAddr,
    AddrPort,
    Prefix,
    Afi,
    Safi,
    LogLevel,
    String,
    Bool,
    U8,
    U16,
    U64,
    Transport,
    PolicyName,
    SetName,
    Action,
}

impl ValueKind {
    pub fn validate(self, token: &str) -> bool {
        match self {
            ValueKind::Asn => token.parse::<u32>().is_ok(),
            ValueKind::Ipv4 => token.parse::<std::net::Ipv4Addr>().is_ok(),
            ValueKind::IpAddr => token.parse::<std::net::IpAddr>().is_ok(),
            ValueKind::AddrPort => token.parse::<std::net::SocketAddr>().is_ok(),
            ValueKind::Prefix => token.contains('/'),
            ValueKind::Afi => matches!(token, "ipv4" | "ipv6" | "ls"),
            ValueKind::Safi => matches!(token, "unicast" | "multicast"),
            ValueKind::LogLevel
            | ValueKind::String
            | ValueKind::PolicyName
            | ValueKind::SetName
            | ValueKind::Action => !token.is_empty(),
            ValueKind::Bool => matches!(token, "true" | "false"),
            ValueKind::U8 => token.parse::<u8>().is_ok(),
            ValueKind::U16 => token.parse::<u16>().is_ok(),
            ValueKind::U64 => token.parse::<u64>().is_ok(),
            ValueKind::Transport => matches!(token, "tcp" | "ssh"),
        }
    }
}

/// Top-level settings inside `service bgp { ... }` (excluding `originate`,
/// which is multi-valued and handled separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TopKey {
    Asn,
    RouterId,
    ListenAddr,
    GrpcListenAddr,
    LogLevel,
    HoldTime,
    ConnectRetry,
    ClusterId,
    SysName,
    SysDescr,
    EnhancedRrStaleTtl,
}

impl TopKey {
    pub fn all() -> &'static [TopKey] {
        &[
            TopKey::Asn,
            TopKey::RouterId,
            TopKey::ListenAddr,
            TopKey::GrpcListenAddr,
            TopKey::LogLevel,
            TopKey::HoldTime,
            TopKey::ConnectRetry,
            TopKey::ClusterId,
            TopKey::SysName,
            TopKey::SysDescr,
            TopKey::EnhancedRrStaleTtl,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TopKey::Asn => "asn",
            TopKey::RouterId => "router-id",
            TopKey::ListenAddr => "listen-addr",
            TopKey::GrpcListenAddr => "grpc-listen-addr",
            TopKey::LogLevel => "log-level",
            TopKey::HoldTime => "hold-time",
            TopKey::ConnectRetry => "connect-retry",
            TopKey::ClusterId => "cluster-id",
            TopKey::SysName => "sys-name",
            TopKey::SysDescr => "sys-descr",
            TopKey::EnhancedRrStaleTtl => "enhanced-rr-stale-ttl",
        }
    }

    pub fn value_kind(&self) -> ValueKind {
        match self {
            TopKey::Asn => ValueKind::Asn,
            TopKey::RouterId => ValueKind::Ipv4,
            TopKey::ListenAddr => ValueKind::AddrPort,
            TopKey::GrpcListenAddr => ValueKind::AddrPort,
            TopKey::LogLevel => ValueKind::LogLevel,
            TopKey::HoldTime => ValueKind::U64,
            TopKey::ConnectRetry => ValueKind::U64,
            TopKey::ClusterId => ValueKind::Ipv4,
            TopKey::SysName => ValueKind::String,
            TopKey::SysDescr => ValueKind::String,
            TopKey::EnhancedRrStaleTtl => ValueKind::U64,
        }
    }

    pub fn help(&self) -> &'static str {
        match self {
            TopKey::Asn => "Local autonomous system number",
            TopKey::RouterId => "BGP router ID (IPv4)",
            TopKey::ListenAddr => "BGP listen address (host:port)",
            TopKey::GrpcListenAddr => "gRPC management listen address (host:port)",
            TopKey::LogLevel => "Daemon log level (e.g. debug, info)",
            TopKey::HoldTime => "Hold time in seconds",
            TopKey::ConnectRetry => "Connect retry interval in seconds",
            TopKey::ClusterId => "Route reflector cluster ID (IPv4)",
            TopKey::SysName => "System name advertised in BMP / ops tooling",
            TopKey::SysDescr => "System description string",
            TopKey::EnhancedRrStaleTtl => "Enhanced route refresh stale TTL (seconds)",
        }
    }
}

/// Per-peer settings inside `peer <addr> { ... }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerKey {
    RemoteAs,
    Port,
    Interface,
    Md5KeyFile,
    TtlMin,
    NextHopSelf,
    Passive,
    RrClient,
    RsClient,
    GracefulShutdown,
    DelayOpenTimeSecs,
    IdleHoldTimeSecs,
    DampPeerOscillations,
    AllowAutomaticStop,
    SendNotificationWithoutOpen,
    MinRouteAdvertisementIntervalSecs,
    EnforceFirstAs,
    SendRpkiCommunity,
    AdminDown,
}

impl PeerKey {
    pub fn all() -> &'static [PeerKey] {
        &[
            PeerKey::RemoteAs,
            PeerKey::Port,
            PeerKey::Interface,
            PeerKey::Md5KeyFile,
            PeerKey::TtlMin,
            PeerKey::NextHopSelf,
            PeerKey::Passive,
            PeerKey::RrClient,
            PeerKey::RsClient,
            PeerKey::GracefulShutdown,
            PeerKey::DelayOpenTimeSecs,
            PeerKey::IdleHoldTimeSecs,
            PeerKey::DampPeerOscillations,
            PeerKey::AllowAutomaticStop,
            PeerKey::SendNotificationWithoutOpen,
            PeerKey::MinRouteAdvertisementIntervalSecs,
            PeerKey::EnforceFirstAs,
            PeerKey::SendRpkiCommunity,
            PeerKey::AdminDown,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PeerKey::RemoteAs => "remote-as",
            PeerKey::Port => "port",
            PeerKey::Interface => "interface",
            PeerKey::Md5KeyFile => "md5-key-file",
            PeerKey::TtlMin => "ttl-min",
            PeerKey::NextHopSelf => "next-hop-self",
            PeerKey::Passive => "passive",
            PeerKey::RrClient => "rr-client",
            PeerKey::RsClient => "rs-client",
            PeerKey::GracefulShutdown => "graceful-shutdown",
            PeerKey::DelayOpenTimeSecs => "delay-open-time-secs",
            PeerKey::IdleHoldTimeSecs => "idle-hold-time-secs",
            PeerKey::DampPeerOscillations => "damp-peer-oscillations",
            PeerKey::AllowAutomaticStop => "allow-automatic-stop",
            PeerKey::SendNotificationWithoutOpen => "send-notification-without-open",
            PeerKey::MinRouteAdvertisementIntervalSecs => "min-route-advertisement-interval-secs",
            PeerKey::EnforceFirstAs => "enforce-first-as",
            PeerKey::SendRpkiCommunity => "send-rpki-community",
            PeerKey::AdminDown => "admin-down",
        }
    }

    pub fn value_kind(&self) -> ValueKind {
        match self {
            PeerKey::RemoteAs => ValueKind::Asn,
            PeerKey::Port => ValueKind::U16,
            PeerKey::Interface => ValueKind::String,
            PeerKey::Md5KeyFile => ValueKind::String,
            PeerKey::TtlMin => ValueKind::U8,
            PeerKey::NextHopSelf => ValueKind::Bool,
            PeerKey::Passive => ValueKind::Bool,
            PeerKey::RrClient => ValueKind::Bool,
            PeerKey::RsClient => ValueKind::Bool,
            PeerKey::GracefulShutdown => ValueKind::Bool,
            PeerKey::DelayOpenTimeSecs => ValueKind::U64,
            PeerKey::IdleHoldTimeSecs => ValueKind::U64,
            PeerKey::DampPeerOscillations => ValueKind::Bool,
            PeerKey::AllowAutomaticStop => ValueKind::Bool,
            PeerKey::SendNotificationWithoutOpen => ValueKind::Bool,
            PeerKey::MinRouteAdvertisementIntervalSecs => ValueKind::U64,
            PeerKey::EnforceFirstAs => ValueKind::Bool,
            PeerKey::SendRpkiCommunity => ValueKind::Bool,
            PeerKey::AdminDown => ValueKind::Bool,
        }
    }

    pub fn help(&self) -> &'static str {
        match self {
            PeerKey::RemoteAs => "Peer ASN",
            PeerKey::Port => "Peer TCP port",
            PeerKey::Interface => "Outgoing interface (link-local peers)",
            PeerKey::Md5KeyFile => "Path to TCP MD5 key file",
            PeerKey::TtlMin => "Minimum incoming TTL (RFC 5082)",
            PeerKey::NextHopSelf => "Set self as next-hop on advertisements",
            PeerKey::Passive => "Passive mode (do not initiate connections)",
            PeerKey::RrClient => "Treat peer as a route-reflector client",
            PeerKey::RsClient => "Treat peer as a route-server client",
            PeerKey::GracefulShutdown => "Send graceful shutdown community on outbound",
            PeerKey::DelayOpenTimeSecs => "Delay before sending OPEN (seconds)",
            PeerKey::IdleHoldTimeSecs => "Idle hold time before retry (seconds)",
            PeerKey::DampPeerOscillations => "Damp peer oscillations",
            PeerKey::AllowAutomaticStop => "Allow automatic state transition to Idle",
            PeerKey::SendNotificationWithoutOpen => "Send NOTIFICATION before OPEN exchange",
            PeerKey::MinRouteAdvertisementIntervalSecs => "MinRouteAdvertisementInterval (seconds)",
            PeerKey::EnforceFirstAs => "Reject UPDATE if peer ASN is not first in AS_PATH",
            PeerKey::SendRpkiCommunity => "Append RPKI validation community to outbound",
            PeerKey::AdminDown => "Administratively disable the peer",
        }
    }
}

/// Per-family directive inside `peer <addr> { family <afi> <safi> { ... } }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FamilyDirectiveKey {
    ExportPolicy,
    ImportPolicy,
}

impl FamilyDirectiveKey {
    pub fn all() -> &'static [FamilyDirectiveKey] {
        &[
            FamilyDirectiveKey::ExportPolicy,
            FamilyDirectiveKey::ImportPolicy,
        ]
    }

    /// First word of the directive (`export` / `import`). The grammar requires
    /// the literal `policy` keyword next, then a name.
    pub fn as_str(&self) -> &'static str {
        match self {
            FamilyDirectiveKey::ExportPolicy => "export",
            FamilyDirectiveKey::ImportPolicy => "import",
        }
    }

    pub fn value_kind(&self) -> ValueKind {
        ValueKind::PolicyName
    }

    pub fn help(&self) -> &'static str {
        match self {
            FamilyDirectiveKey::ExportPolicy => "Apply policy to outbound updates",
            FamilyDirectiveKey::ImportPolicy => "Apply policy to inbound updates",
        }
    }
}

/// Rule keyword inside `policy <name> { ... }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyRuleKey {
    Match,
    Default,
}

impl PolicyRuleKey {
    pub fn all() -> &'static [PolicyRuleKey] {
        &[PolicyRuleKey::Match, PolicyRuleKey::Default]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyRuleKey::Match => "match",
            PolicyRuleKey::Default => "default",
        }
    }

    pub fn help(&self) -> &'static str {
        match self {
            PolicyRuleKey::Match => "Match a prefix-list and apply an action",
            PolicyRuleKey::Default => "Default action when no rules match",
        }
    }
}

/// Directive keyword inside `bmp-server <addr> { ... }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BmpServerKey {
    StatisticsTimeout,
}

impl BmpServerKey {
    pub fn all() -> &'static [BmpServerKey] {
        &[BmpServerKey::StatisticsTimeout]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BmpServerKey::StatisticsTimeout => "statistics-timeout",
        }
    }

    pub fn value_kind(&self) -> ValueKind {
        match self {
            BmpServerKey::StatisticsTimeout => ValueKind::U64,
        }
    }

    pub fn help(&self) -> &'static str {
        match self {
            BmpServerKey::StatisticsTimeout => "BMP statistics report interval (seconds)",
        }
    }
}

/// Directive keyword inside `rpki-cache <addr> { ... }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpkiCacheKey {
    Preference,
    Transport,
    SshUsername,
    SshPrivateKeyFile,
    SshKnownHostsFile,
    RetryInterval,
    RefreshInterval,
    ExpireInterval,
}

impl RpkiCacheKey {
    pub fn all() -> &'static [RpkiCacheKey] {
        &[
            RpkiCacheKey::Preference,
            RpkiCacheKey::Transport,
            RpkiCacheKey::SshUsername,
            RpkiCacheKey::SshPrivateKeyFile,
            RpkiCacheKey::SshKnownHostsFile,
            RpkiCacheKey::RetryInterval,
            RpkiCacheKey::RefreshInterval,
            RpkiCacheKey::ExpireInterval,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RpkiCacheKey::Preference => "preference",
            RpkiCacheKey::Transport => "transport",
            RpkiCacheKey::SshUsername => "ssh-username",
            RpkiCacheKey::SshPrivateKeyFile => "ssh-private-key-file",
            RpkiCacheKey::SshKnownHostsFile => "ssh-known-hosts-file",
            RpkiCacheKey::RetryInterval => "retry-interval",
            RpkiCacheKey::RefreshInterval => "refresh-interval",
            RpkiCacheKey::ExpireInterval => "expire-interval",
        }
    }

    pub fn value_kind(&self) -> ValueKind {
        match self {
            RpkiCacheKey::Preference => ValueKind::U8,
            RpkiCacheKey::Transport => ValueKind::Transport,
            RpkiCacheKey::SshUsername => ValueKind::String,
            RpkiCacheKey::SshPrivateKeyFile => ValueKind::String,
            RpkiCacheKey::SshKnownHostsFile => ValueKind::String,
            RpkiCacheKey::RetryInterval => ValueKind::U64,
            RpkiCacheKey::RefreshInterval => ValueKind::U64,
            RpkiCacheKey::ExpireInterval => ValueKind::U64,
        }
    }

    pub fn help(&self) -> &'static str {
        match self {
            RpkiCacheKey::Preference => "Cache preference tier (lower wins)",
            RpkiCacheKey::Transport => "Transport: tcp or ssh",
            RpkiCacheKey::SshUsername => "SSH username (transport ssh)",
            RpkiCacheKey::SshPrivateKeyFile => "Path to SSH private key (transport ssh)",
            RpkiCacheKey::SshKnownHostsFile => "Path to SSH known_hosts (transport ssh)",
            RpkiCacheKey::RetryInterval => "Retry interval (seconds)",
            RpkiCacheKey::RefreshInterval => "Refresh interval (seconds)",
            RpkiCacheKey::ExpireInterval => "Expire interval (seconds)",
        }
    }
}

/// Directive keyword inside `bgp-ls { ... }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BgpLsKey {
    InstanceId,
}

impl BgpLsKey {
    pub fn all() -> &'static [BgpLsKey] {
        &[BgpLsKey::InstanceId]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BgpLsKey::InstanceId => "instance-id",
        }
    }

    pub fn value_kind(&self) -> ValueKind {
        match self {
            BgpLsKey::InstanceId => ValueKind::U64,
        }
    }

    pub fn help(&self) -> &'static str {
        match self {
            BgpLsKey::InstanceId => "BGP-LS instance ID (RFC 9552)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::{parse, Service};

    #[test]
    fn test_parse_bgp_basic() {
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
        let root = parse(input).unwrap();
        assert_eq!(root.services.len(), 1);

        let Service::Bgp(body) = &root.services[0];
        assert!(body.settings.contains(&Setting::Asn(65001)));
        assert!(body
            .settings
            .contains(&Setting::RouterId("1.1.1.1".parse().unwrap())));
        assert!(body
            .settings
            .contains(&Setting::ListenAddr("127.0.0.1:179".to_string())));
        assert!(body
            .settings
            .contains(&Setting::LogLevel("debug".to_string())));
        assert!(body.settings.contains(&Setting::HoldTime(90)));
        assert!(body.settings.contains(&Setting::ConnectRetry(10)));
    }

    #[test]
    fn test_parse_bgp_peers() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

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
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(body.peers.len(), 2);

        let peer1 = &body.peers[0];
        assert_eq!(peer1.address, "fe80::ade0");
        assert!(peer1.settings.contains(&Setting::RemoteAs(4242423914)));
        assert!(peer1.settings.contains(&Setting::NextHopSelf(true)));
        assert!(peer1.settings.contains(&Setting::Port(1179)));

        let upstream = &body.peers[1];
        assert_eq!(upstream.address, "10.0.0.1");
        assert!(upstream.settings.contains(&Setting::Passive(true)));
        assert!(upstream.settings.contains(&Setting::RrClient(true)));
    }

    #[test]
    fn test_parse_family() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer 10.0.0.1 {
    family ipv4 unicast {
      export policy mine-only
    }
    family ipv6 unicast {
      import policy allow-all
    }
  }
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        let peer = &body.peers[0];
        assert_eq!(peer.families.len(), 2);

        assert!(matches!(
            &peer.families[0].directives[0],
            FamilyDirective::ExportPolicy(name) if name == "mine-only"
        ));
        assert!(matches!(
            &peer.families[1].directives[0],
            FamilyDirective::ImportPolicy(name) if name == "allow-all"
        ));
    }

    #[test]
    fn test_parse_policy_and_prefix_list() {
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
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];

        let policy = &body.policies[0];
        assert_eq!(policy.name, "mine-only");
        assert!(matches!(
            &policy.rules[0],
            PolicyRule::Match { set_name, action } if set_name == "my-prefixes" && action == "accept"
        ));
        assert!(matches!(
            &policy.rules[1],
            PolicyRule::Default { action } if action == "reject"
        ));

        let prefix_list = &body.prefix_lists[0];
        assert_eq!(prefix_list.name, "my-prefixes");
        let prefix_strings: Vec<&str> = prefix_list
            .prefixes
            .iter()
            .map(|e| e.prefix.as_str())
            .collect();
        assert_eq!(
            prefix_strings,
            vec!["172.23.211.0/27", "fd0d:fbde:bca5::/48"]
        );
        assert!(prefix_list.prefixes.iter().all(|e| e.range.is_none()));
    }

    #[test]
    fn test_parse_originate() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  originate 172.23.211.0/27 nexthop 192.168.217.19
  originate fd0d:fbde:bca5::/48 nexthop fe80::ade1
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert!(body.settings.contains(&Setting::Originate(OriginateRoute {
            prefix: "172.23.211.0/27".to_string(),
            nexthop: "192.168.217.19".to_string(),
        })));
        assert!(body.settings.contains(&Setting::Originate(OriginateRoute {
            prefix: "fd0d:fbde:bca5::/48".to_string(),
            nexthop: "fe80::ade1".to_string(),
        })));
    }

    #[test]
    fn test_parse_originate_missing_nexthop() {
        let err =
            parse("service bgp { asn 1\n router-id 1.1.1.1\n originate 10.0.0.0/24 }").unwrap_err();
        assert!(
            err.message.contains("nexthop"),
            "expected nexthop in error: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_originate_wrong_keyword() {
        let err =
            parse("service bgp { asn 1\n router-id 1.1.1.1\n originate 10.0.0.0/24 via 1.2.3.4 }")
                .unwrap_err();
        assert!(
            err.message.contains("expected 'nexthop'"),
            "expected wrong-keyword error: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_full_config() {
        let input = "\
service bgp {
  asn 4242423930
  router-id 172.23.211.1
  listen-addr [::]:179
  grpc-listen-addr [::]:50051
  log-level debug
  hold-time 90

  peer fe80::ade0 {
    interface peer1-us3
    remote-as 4242423914
    next-hop-self true
    md5-key-file /etc/bgp/peer1.key

    family ipv4 unicast {
      export policy mine-only
    }

    family ipv6 unicast {
      export policy mine-only
    }
  }

  originate 172.23.211.0/27 nexthop 192.168.217.19
  originate fd0d:fbde:bca5::/48 nexthop fe80::ade1

  policy mine-only {
    match my-prefixes accept
    default reject
  }

  prefix-list my-prefixes {
    172.23.211.0/27
    fd0d:fbde:bca5::/48
  }
}";
        let root = parse(input).unwrap();
        assert_eq!(root.services.len(), 1);

        let Service::Bgp(body) = &root.services[0];

        assert!(body.settings.contains(&Setting::Asn(4242423930)));
        assert_eq!(body.peers.len(), 1);
        assert!(body.settings.contains(&Setting::Originate(OriginateRoute {
            prefix: "172.23.211.0/27".to_string(),
            nexthop: "192.168.217.19".to_string(),
        })));
        assert_eq!(body.policies.len(), 1);
        assert_eq!(body.prefix_lists.len(), 1);
        assert!(body.peers[0].settings.contains(&Setting::NextHopSelf(true)));
    }

    #[test]
    fn test_setting_parse_ok() {
        let cases = vec![
            ("asn", Some("65001"), Setting::Asn(65001)),
            (
                "router-id",
                Some("1.2.3.4"),
                Setting::RouterId("1.2.3.4".parse().unwrap()),
            ),
            (
                "cluster-id",
                Some("10.0.0.1"),
                Setting::ClusterId("10.0.0.1".parse().unwrap()),
            ),
            ("port", Some("179"), Setting::Port(179)),
            ("ttl-min", Some("254"), Setting::TtlMin(254)),
            ("hold-time", Some("90"), Setting::HoldTime(90)),
            ("next-hop-self", Some("true"), Setting::NextHopSelf(true)),
            ("passive", Some("false"), Setting::Passive(false)),
            ("rr-client", Some("true"), Setting::RrClient(true)),
            ("rs-client", Some("true"), Setting::RsClient(true)),
            (
                "graceful-shutdown",
                Some("true"),
                Setting::GracefulShutdown(true),
            ),
            (
                "interface",
                Some("eth0"),
                Setting::Interface("eth0".to_string()),
            ),
            (
                "md5-key-file",
                Some("/etc/bgp/x.key"),
                Setting::Md5KeyFile("/etc/bgp/x.key".to_string()),
            ),
            (
                "listen-addr",
                Some("[::]:179"),
                Setting::ListenAddr("[::]:179".to_string()),
            ),
        ];
        for (key, value, expected) in cases {
            let got = Setting::parse(key, value).unwrap();
            assert_eq!(got, expected, "for ({:?}, {:?})", key, value);
        }
    }

    #[test]
    fn test_setting_parse_originate_rejected() {
        // originate is multi-token (`originate <prefix> nexthop <addr>`) and
        // is parsed by parse_bgp_body, not Setting::parse. Single-value form
        // surfaces a clear hint.
        let err = Setting::parse("originate", Some("10.0.0.0/24")).unwrap_err();
        assert!(
            err.contains("originate <prefix> nexthop <addr>"),
            "expected hint message, got: {}",
            err
        );
    }

    #[test]
    fn test_setting_parse_errors() {
        let cases = vec![
            ("asn", None, "asn requires a value"),
            ("asn", Some("true"), "invalid asn 'true'"),
            ("asn", Some("foo"), "invalid asn 'foo'"),
            ("router-id", Some("300.0.0.0"), "invalid router-id"),
            ("port", Some("99999"), "invalid port"),
            ("next-hop-self", Some("yes"), "invalid next-hop-self 'yes'"),
            ("next-hop-self", None, "next-hop-self requires a value"),
            ("weird-key", Some("x"), "unknown setting 'weird-key'"),
            ("weird-key", None, "unknown setting 'weird-key'"),
        ];
        for (key, value, expected) in cases {
            let err = Setting::parse(key, value).unwrap_err();
            assert!(
                err.contains(expected),
                "for ({:?}, {:?}): expected {:?} in {:?}",
                key,
                value,
                expected,
                err
            );
        }
    }

    #[test]
    fn test_display_round_trip() {
        let cases = vec![
            // minimal config
            "service bgp {\n  asn 65001\n  router-id 1.1.1.1\n}",
            // top-level service settings
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  listen-addr 127.0.0.1:179
  grpc-listen-addr 127.0.0.1:50051
  log-level debug
  hold-time 90
  connect-retry 10
}",
            // peer settings
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

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
}",
            // peer family directives (export/import policy, max-prefix, add-path-send)
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer 10.0.0.1 {
    family ipv4 unicast {
      export policy mine-only
      max-prefix 1000 action discard
      add-path-send all
    }

    family ipv6 unicast {
      import policy allow-all
    }
  }
}",
            // originate + shorthand-form policy + bare prefix-list
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1
  originate 172.23.211.0/27 nexthop 192.168.217.19
  originate fd0d:fbde:bca5::/48 nexthop fe80::ade1

  policy mine-only {
    match my-prefixes accept
    default reject
  }

  prefix-list my-prefixes {
    172.23.211.0/27
    fd0d:fbde:bca5::/48
  }
}",
            // bmp-server and rpki-cache blocks
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  bmp-server 127.0.0.1:1790 {
    statistics-timeout 60
  }

  rpki-cache 10.0.0.1:323 {
    preference 1
    transport ssh
    ssh-username rtr-user
    ssh-private-key-file /etc/bgp/rtr.key
    retry-interval 60
  }
}",
            // statement-form policy with typed match/set clauses
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  policy mine-only {
    statement allow-customers {
      match prefix-set my-prefixes
      match neighbor-set my-neighbors all
      match as-path-set transit-as invert
      match community-set well-known
      match has-asn 65000
      match rpki valid
      match afi-safi ipv4-unicast
      set local-pref force 200
      set med remove
      set community add 65001:100 65001:200
      set ext-community remove rt:65001:1
      set large-community replace 65001:1:1
      set rpki-state valid
      accept
    }
    default reject
  }
}",
            // prefix-list masklength range variants
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  prefix-list ranged {
    10.0.0.0/8 exact
    172.16.0.0/12 ge 16
    192.168.0.0/16 ge 24 le 28
    fd00::/8
  }
}",
            // named set blocks + bgp-ls
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  neighbor-set my-neighbors {
    10.0.0.1
    10.0.0.2
  }

  as-path-set transit-as {
    \"_65000_\"
    \"^65001$\"
  }

  community-set well-known {
    65001:100
  }

  ext-community-set rt-set {
    rt:65001:1
  }

  large-community-set lc-set {
    65001:1:1
  }

  bgp-ls {
    instance-id 0
  }
}",
            // telemetry variants
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  telemetry {
    json {}
  }
}",
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  telemetry {
    cloudwatch-emf {
      namespace Rogg/Bgpgg
    }
  }
}",
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  telemetry {
    json {}
    prometheus {}
  }
}",
            "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  telemetry {
    prometheus {
      listen 0.0.0.0:9273
    }
  }
}",
        ];
        for input in cases {
            let root =
                parse(input).unwrap_or_else(|err| panic!("parse failed for {:?}: {}", input, err));
            let serialized = root.to_string();
            let reparsed = parse(&serialized).unwrap_or_else(|err| {
                panic!(
                    "reparse failed for {:?}:\nserialized:\n{}\nerror: {}",
                    input, serialized, err
                )
            });
            assert_eq!(
                root, reparsed,
                "round-trip mismatch for input {:?}\nserialized:\n{}",
                input, serialized
            );
        }
    }

    #[test]
    fn test_display_format() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  peer 10.0.0.1 {
    remote-as 65002
  }
}";
        let root = parse(input).unwrap();
        let out = root.to_string();
        // Check key structural elements without pinning exact whitespace counts.
        assert!(out.contains("service bgp {"));
        assert!(out.contains("  asn 65001"));
        assert!(out.contains("  router-id 1.1.1.1"));
        assert!(out.contains("  peer 10.0.0.1 {"));
        assert!(out.contains("    remote-as 65002"));
        assert!(out.ends_with("}\n"));
    }

    #[test]
    fn test_parse_invalid_afi_safi_rejected_at_parse_time() {
        let cases = vec![
            (
                "service bgp { peer x { family ipvv4 unicast { } } }",
                "invalid afi 'ipvv4'",
            ),
            (
                "service bgp { peer x { family ipv4 unicorn { } } }",
                "invalid safi 'unicorn'",
            ),
        ];
        for (input, expected) in cases {
            let err = parse(input).unwrap_err();
            assert!(
                err.message.contains(expected),
                "for {:?}: expected {:?} in {:?}",
                input,
                expected,
                err.message
            );
        }
    }

    #[test]
    fn test_parse_invalid_settings_carry_line() {
        // Errors from Setting::parse are wrapped with the keyword's line by the
        // recursive-descent parser.
        let cases = vec![
            ("service bgp { asn }", "asn requires a value"),
            ("service bgp { asn true }", "invalid asn 'true'"),
            ("service bgp { weird-key x }", "unknown setting 'weird-key'"),
            (
                "service bgp { peer x { weird-key x } }",
                "unknown setting 'weird-key'",
            ),
        ];
        for (input, expected) in cases {
            let err = parse(input).unwrap_err();
            assert!(
                err.message.contains(expected),
                "for {:?}: expected {:?} in {:?}",
                input,
                expected,
                err.message
            );
        }
    }

    #[test]
    fn test_parse_bmp_server() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  bmp-server 127.0.0.1:1790 {
    statistics-timeout 60
  }

  bmp-server [::1]:1790 {
  }
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(body.bmp_servers.len(), 2);
        assert_eq!(body.bmp_servers[0].address, "127.0.0.1:1790");
        assert_eq!(body.bmp_servers[0].statistics_timeout, Some(60));
        assert_eq!(body.bmp_servers[1].address, "[::1]:1790");
        assert_eq!(body.bmp_servers[1].statistics_timeout, None);
    }

    #[test]
    fn test_parse_rpki_cache() {
        let input = "\
service bgp {
  asn 65001
  router-id 1.1.1.1

  rpki-cache 127.0.0.1:323 {
    preference 1
    transport tcp
    refresh-interval 3600
  }

  rpki-cache 10.0.0.1:323 {
    preference 2
    transport ssh
    ssh-username rtr-user
    ssh-private-key-file /etc/bgp/rtr.key
    ssh-known-hosts-file /etc/bgp/known_hosts
    retry-interval 60
    expire-interval 7200
  }
}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(body.rpki_caches.len(), 2);

        let first = &body.rpki_caches[0];
        assert_eq!(first.address, "127.0.0.1:323");
        assert_eq!(first.preference, Some(1));
        assert_eq!(first.transport, Some(TransportType::Tcp));
        assert_eq!(first.refresh_interval, Some(3600));

        let second = &body.rpki_caches[1];
        assert_eq!(second.preference, Some(2));
        assert_eq!(second.transport, Some(TransportType::Ssh));
        assert_eq!(second.ssh_username.as_deref(), Some("rtr-user"));
        assert_eq!(
            second.ssh_private_key_file.as_deref(),
            Some("/etc/bgp/rtr.key")
        );
        assert_eq!(second.retry_interval, Some(60));
        assert_eq!(second.expire_interval, Some(7200));
    }

    #[test]
    fn test_parse_telemetry() {
        let cases = [
            (
                "telemetry {\n  json {}\n}",
                TelemetryBlock {
                    json: true,
                    cloudwatch_emf: None,
                    prometheus: None,
                },
            ),
            (
                "telemetry {\n  cloudwatch-emf {\n    namespace Rogg/Bgpgg\n  }\n}",
                TelemetryBlock {
                    json: false,
                    cloudwatch_emf: Some(CloudwatchEmfBlock {
                        namespace: "Rogg/Bgpgg".to_string(),
                    }),
                    prometheus: None,
                },
            ),
            (
                "telemetry {\n}",
                TelemetryBlock {
                    json: false,
                    cloudwatch_emf: None,
                    prometheus: None,
                },
            ),
            (
                "telemetry {\n  prometheus {}\n}",
                TelemetryBlock {
                    json: false,
                    cloudwatch_emf: None,
                    prometheus: Some(PrometheusBlock { listen: None }),
                },
            ),
            (
                "telemetry {\n  json {}\n  prometheus {\n    listen 0.0.0.0:9273\n  }\n}",
                TelemetryBlock {
                    json: true,
                    cloudwatch_emf: None,
                    prometheus: Some(PrometheusBlock {
                        listen: Some("0.0.0.0:9273".to_string()),
                    }),
                },
            ),
            (
                "telemetry {\n  cloudwatch-emf {\n    namespace X\n  }\n  prometheus {}\n}",
                TelemetryBlock {
                    json: false,
                    cloudwatch_emf: Some(CloudwatchEmfBlock {
                        namespace: "X".to_string(),
                    }),
                    prometheus: Some(PrometheusBlock { listen: None }),
                },
            ),
        ];
        for (block_text, expected) in cases {
            let input = format!(
                "service bgp {{\n  asn 65001\n  router-id 1.1.1.1\n\n  {}\n}}",
                block_text
            );
            let root = parse(&input).unwrap();
            let Service::Bgp(body) = &root.services[0];
            assert_eq!(body.telemetry.as_ref(), Some(&expected), "input: {}", input);
        }
    }

    #[test]
    fn test_parse_telemetry_errors() {
        let cases = [
            (
                "telemetry {\n  json {}\n  cloudwatch-emf {\n    namespace X\n  }\n}",
                "'json' and 'cloudwatch-emf' are mutually exclusive",
            ),
            (
                "telemetry {\n  json {}\n  prometheus {}\n  cloudwatch-emf {\n    namespace X\n  }\n}",
                "'json' and 'cloudwatch-emf' are mutually exclusive",
            ),
            (
                "telemetry {\n  prometheus {}\n  prometheus {}\n}",
                "duplicate 'prometheus' block",
            ),
            (
                "telemetry {\n  prometheus {\n    weird 1\n  }\n}",
                "unknown prometheus directive 'weird'",
            ),
            (
                "telemetry {\n  cloudwatch-emf {\n  }\n}",
                "cloudwatch-emf requires 'namespace'",
            ),
            (
                "telemetry {\n}\n  telemetry {\n}",
                "duplicate 'telemetry' block",
            ),
            (
                "telemetry {\n  weird 1\n}",
                "unknown telemetry directive 'weird'",
            ),
            (
                "telemetry {\n  json {\n    weird 1\n  }\n}",
                "unknown json directive 'weird'",
            ),
            (
                "telemetry {\n  cloudwatch-emf {\n    weird 1\n  }\n}",
                "unknown cloudwatch-emf directive 'weird'",
            ),
            (
                "telemetry {\n  json {}\n  json {}\n}",
                "duplicate 'json' block",
            ),
        ];
        for (block_text, expected_message) in cases {
            let input = format!(
                "service bgp {{\n  asn 65001\n  router-id 1.1.1.1\n  {}\n}}",
                block_text
            );
            let err = parse(&input).unwrap_err();
            assert!(
                err.message.contains(expected_message),
                "input: {} got: {}",
                input,
                err.message
            );
        }
    }

    #[test]
    fn test_parse_bmp_server_unknown_directive() {
        let err =
            parse("service bgp { asn 1\n router-id 1.1.1.1\n bmp-server 127.0.0.1:1 { weird 1 } }")
                .unwrap_err();
        assert!(
            err.message.contains("unknown bmp-server directive 'weird'"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_rpki_cache_unknown_directive() {
        let err =
            parse("service bgp { asn 1\n router-id 1.1.1.1\n rpki-cache 127.0.0.1:1 { weird 1 } }")
                .unwrap_err();
        assert!(
            err.message.contains("unknown rpki-cache directive 'weird'"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_rpki_cache_invalid_transport() {
        let err = parse(
            "service bgp { asn 1\n router-id 1.1.1.1\n rpki-cache 127.0.0.1:1 { transport foo } }",
        )
        .unwrap_err();
        assert!(
            err.message.contains("invalid transport 'foo'"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn test_parse_trailing_tokens_rejected() {
        let cases = vec![
            (
                "service bgp { asn 65001 junk }",
                "unexpected trailing token",
            ),
            (
                "service bgp { peer 10.0.0.1 { remote-as 65001 junk } }",
                "unexpected trailing token",
            ),
            (
                "service bgp { peer x { family ipv4 unicast { export policy p extra } } }",
                "unexpected trailing token",
            ),
            (
                "service bgp { policy p { default reject extra } }",
                "unexpected trailing token",
            ),
            (
                "service bgp { prefix-list p { 10.0.0.0/24 extra } }",
                "unexpected trailing token",
            ),
        ];
        for (input, expected) in cases {
            let err = parse(input).unwrap_err();
            assert!(
                err.message.contains(expected),
                "for {:?}: expected {:?} in {:?}",
                input,
                expected,
                err.message
            );
        }
    }

    fn sample_for(kind: ValueKind) -> &'static str {
        match kind {
            ValueKind::Asn => "65001",
            ValueKind::Ipv4 => "1.2.3.4",
            ValueKind::IpAddr => "1.2.3.4",
            ValueKind::AddrPort => "127.0.0.1:179",
            ValueKind::LogLevel => "debug",
            ValueKind::String => "value",
            ValueKind::Prefix => "10.0.0.0/24",
            ValueKind::Afi => "ipv4",
            ValueKind::Safi => "unicast",
            ValueKind::U8 => "100",
            ValueKind::U16 => "1179",
            ValueKind::U64 => "90",
            ValueKind::Bool => "true",
            ValueKind::Transport => "tcp",
            ValueKind::PolicyName => "mine-only",
            ValueKind::SetName => "my-prefixes",
            ValueKind::Action => "accept",
        }
    }

    #[test]
    fn test_top_key_parity() {
        for &key in TopKey::all() {
            let value = sample_for(key.value_kind());
            let parsed = Setting::parse(key.as_str(), Some(value));
            assert!(
                parsed.is_ok(),
                "TopKey::{:?} ({}) failed to parse value {:?}: {:?}",
                key,
                key.as_str(),
                value,
                parsed.err()
            );
        }
    }

    #[test]
    fn test_peer_key_parity() {
        for &key in PeerKey::all() {
            let value = sample_for(key.value_kind());
            let parsed = Setting::parse(key.as_str(), Some(value));
            assert!(
                parsed.is_ok(),
                "PeerKey::{:?} ({}) failed to parse value {:?}: {:?}",
                key,
                key.as_str(),
                value,
                parsed.err()
            );
        }
    }

    #[test]
    fn test_top_key_round_trip_through_grammar() {
        for &key in TopKey::all() {
            let value = sample_for(key.value_kind());
            let input = format!(
                "service bgp {{\n  asn 1\n  router-id 0.0.0.0\n  {} {}\n}}",
                key.as_str(),
                value
            );
            let root = parse(&input)
                .unwrap_or_else(|err| panic!("TopKey::{:?} grammar parse failed: {:?}", key, err));
            let Service::Bgp(body) = &root.services[0];
            assert!(
                body.settings
                    .iter()
                    .any(|s| s.to_string().starts_with(key.as_str())),
                "TopKey::{:?} ({}) not present after round-trip",
                key,
                key.as_str()
            );
        }
    }

    #[test]
    fn test_peer_key_round_trip_through_grammar() {
        for &key in PeerKey::all() {
            let value = sample_for(key.value_kind());
            let input = format!(
                "service bgp {{\n  asn 1\n  router-id 0.0.0.0\n  peer 10.0.0.1 {{\n    {} {}\n  }}\n}}",
                key.as_str(),
                value
            );
            let root = parse(&input)
                .unwrap_or_else(|err| panic!("PeerKey::{:?} grammar parse failed: {:?}", key, err));
            let Service::Bgp(body) = &root.services[0];
            let peer = &body.peers[0];
            assert!(
                peer.settings
                    .iter()
                    .any(|s| s.to_string().starts_with(key.as_str())),
                "PeerKey::{:?} ({}) not present after round-trip",
                key,
                key.as_str()
            );
        }
    }

    #[test]
    fn test_family_directive_key_round_trip() {
        for &key in FamilyDirectiveKey::all() {
            let input = format!(
                "service bgp {{\n  asn 1\n  router-id 0.0.0.0\n  peer 10.0.0.1 {{\n    family ipv4 unicast {{\n      {} policy mine-only\n    }}\n  }}\n}}",
                key.as_str()
            );
            let root = parse(&input).unwrap_or_else(|err| {
                panic!("FamilyDirectiveKey::{:?} parse failed: {:?}", key, err)
            });
            let Service::Bgp(body) = &root.services[0];
            assert_eq!(body.peers[0].families[0].directives.len(), 1);
        }
    }

    #[test]
    fn test_policy_rule_key_round_trip() {
        let input = "service bgp {\n  asn 1\n  router-id 0.0.0.0\n  policy mine-only {\n    match my-prefixes accept\n    default reject\n  }\n}";
        let root = parse(input).unwrap();
        let Service::Bgp(body) = &root.services[0];
        assert_eq!(body.policies[0].rules.len(), 2);
        assert!(matches!(
            &body.policies[0].rules[0],
            PolicyRule::Match { .. }
        ));
        assert!(matches!(
            &body.policies[0].rules[1],
            PolicyRule::Default { .. }
        ));
    }

    #[test]
    fn test_bmp_server_key_round_trip() {
        for &key in BmpServerKey::all() {
            let value = sample_for(key.value_kind());
            let input = format!(
                "service bgp {{\n  asn 1\n  router-id 0.0.0.0\n  bmp-server 127.0.0.1:1790 {{\n    {} {}\n  }}\n}}",
                key.as_str(),
                value
            );
            let root = parse(&input)
                .unwrap_or_else(|err| panic!("BmpServerKey::{:?} parse failed: {:?}", key, err));
            let Service::Bgp(body) = &root.services[0];
            assert_eq!(body.bmp_servers[0].address, "127.0.0.1:1790");
        }
    }

    #[test]
    fn test_rpki_cache_key_round_trip() {
        for &key in RpkiCacheKey::all() {
            let value = sample_for(key.value_kind());
            let input = format!(
                "service bgp {{\n  asn 1\n  router-id 0.0.0.0\n  rpki-cache 127.0.0.1:323 {{\n    {} {}\n  }}\n}}",
                key.as_str(),
                value
            );
            let root = parse(&input)
                .unwrap_or_else(|err| panic!("RpkiCacheKey::{:?} parse failed: {:?}", key, err));
            let Service::Bgp(body) = &root.services[0];
            assert_eq!(body.rpki_caches[0].address, "127.0.0.1:323");
        }
    }

    #[test]
    fn test_bgp_ls_key_round_trip() {
        for &key in BgpLsKey::all() {
            let value = sample_for(key.value_kind());
            let input = format!(
                "service bgp {{\n  asn 1\n  router-id 0.0.0.0\n  bgp-ls {{\n    {} {}\n  }}\n}}",
                key.as_str(),
                value
            );
            let root = parse(&input)
                .unwrap_or_else(|err| panic!("BgpLsKey::{:?} parse failed: {:?}", key, err));
            let Service::Bgp(body) = &root.services[0];
            assert!(body.bgp_ls.is_some());
        }
    }
}
