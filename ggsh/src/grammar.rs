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

use conf::language_bgp::{
    BgpLsKey, BmpServerKey, FamilyDirectiveKey, PeerKey, PolicyRuleKey, RpkiCacheKey, TopKey,
    ValueKind,
};

use crate::parser::{BgpggCommand, Command, ServiceKind};

#[derive(Clone)]
pub(crate) struct Node {
    pub(crate) name: &'static str,
    pub(crate) help: &'static str,
    pub(crate) children: Vec<Node>,
    pub(crate) command: Option<Command>,
    /// `Some` -> arg node validated by the kind; `None` -> keyword matched on `name`.
    pub(crate) kind: Option<ValueKind>,
}

impl Node {
    pub(crate) fn keyword(name: &'static str, help: &'static str) -> Self {
        Node {
            name,
            help,
            children: vec![],
            command: None,
            kind: None,
        }
    }

    pub(crate) fn arg(name: &'static str, help: &'static str, kind: ValueKind) -> Self {
        Node {
            name,
            help,
            children: vec![],
            command: None,
            kind: Some(kind),
        }
    }

    pub(crate) fn children(mut self, children: Vec<Node>) -> Self {
        self.children = children;
        self
    }

    pub(crate) fn cmd(mut self, command: Command) -> Self {
        self.command = Some(command);
        self
    }

    pub(crate) fn is_arg(&self) -> bool {
        self.kind.is_some()
    }
}

/// Common shape of "schema enum that drives a `<key> <value>` editing surface."
trait SchemaKey: Copy + 'static {
    fn all() -> &'static [Self];
    fn as_str(&self) -> &'static str;
    fn help(&self) -> &'static str;
    fn value_kind(&self) -> ValueKind;
}

impl SchemaKey for TopKey {
    fn all() -> &'static [Self] {
        TopKey::all()
    }
    fn as_str(&self) -> &'static str {
        TopKey::as_str(self)
    }
    fn help(&self) -> &'static str {
        TopKey::help(self)
    }
    fn value_kind(&self) -> ValueKind {
        TopKey::value_kind(self)
    }
}

impl SchemaKey for PeerKey {
    fn all() -> &'static [Self] {
        PeerKey::all()
    }
    fn as_str(&self) -> &'static str {
        PeerKey::as_str(self)
    }
    fn help(&self) -> &'static str {
        PeerKey::help(self)
    }
    fn value_kind(&self) -> ValueKind {
        PeerKey::value_kind(self)
    }
}

impl SchemaKey for BmpServerKey {
    fn all() -> &'static [Self] {
        BmpServerKey::all()
    }
    fn as_str(&self) -> &'static str {
        BmpServerKey::as_str(self)
    }
    fn help(&self) -> &'static str {
        BmpServerKey::help(self)
    }
    fn value_kind(&self) -> ValueKind {
        BmpServerKey::value_kind(self)
    }
}

impl SchemaKey for RpkiCacheKey {
    fn all() -> &'static [Self] {
        RpkiCacheKey::all()
    }
    fn as_str(&self) -> &'static str {
        RpkiCacheKey::as_str(self)
    }
    fn help(&self) -> &'static str {
        RpkiCacheKey::help(self)
    }
    fn value_kind(&self) -> ValueKind {
        RpkiCacheKey::value_kind(self)
    }
}

impl SchemaKey for BgpLsKey {
    fn all() -> &'static [Self] {
        BgpLsKey::all()
    }
    fn as_str(&self) -> &'static str {
        BgpLsKey::as_str(self)
    }
    fn help(&self) -> &'static str {
        BgpLsKey::help(self)
    }
    fn value_kind(&self) -> ValueKind {
        BgpLsKey::value_kind(self)
    }
}

/// Generates `<key> <value>` leaves for every variant of `K`, with `make_cmd`
/// turning the key into the command attached at the value node.
fn setting_leaves<K: SchemaKey>(make_cmd: impl Fn(K) -> Command) -> Vec<Node> {
    K::all()
        .iter()
        .map(|&key| {
            Node::keyword(key.as_str(), key.help()).children(vec![Node::arg(
                "<value>",
                "Value",
                key.value_kind(),
            )
            .cmd(make_cmd(key))])
        })
        .collect()
}

pub fn tree() -> Vec<Node> {
    vec![
        Node::keyword("show", "Show operational information").children(tree_show()),
        Node::keyword("configure", "Enter configuration mode").cmd(Command::Configure),
        Node::keyword("exit", "Exit ggsh").cmd(Command::Exit),
        Node::keyword("quit", "Exit ggsh").cmd(Command::Exit),
    ]
}

/// `(config)>` grammar — session verbs only.
pub fn tree_config() -> Vec<Node> {
    vec![
        Node::keyword("service", "Enter a service block").children(vec![Node::keyword(
            "bgp",
            "Enter the BGP service",
        )
        .cmd(Command::EnterService(ServiceKind::Bgp))]),
        Node::keyword("commit", "Apply candidate, persist, return to operational")
            .cmd(Command::Commit),
        Node::keyword("exit", "Discard candidate and return to operational").cmd(Command::Exit),
        Node::keyword("show", "Show information").children(tree_show_cfg()),
    ]
}

/// `(config-bgp)>` grammar — full BGP service editing.
pub fn tree_config_bgp() -> Vec<Node> {
    let mut nodes = vec![
        Node::keyword("commit", "Apply candidate, persist, return to operational")
            .cmd(Command::Commit),
        Node::keyword("exit", "Return to (config)").cmd(Command::Exit),
        Node::keyword("show", "Show information").children(tree_show_cfg_bgp()),
        Node::keyword("unset", "Remove a setting, peer, or block").children(unset_subtree()),
    ];
    nodes.extend(setting_leaves::<TopKey>(Command::SetTop));
    nodes.push(
        Node::keyword("originate", "Originate a prefix").children(vec![Node::arg(
            "<prefix>",
            "Prefix in CIDR notation",
            ValueKind::Prefix,
        )
        .children(vec![Node::keyword("nexthop", "Forwarding next-hop")
            .children(vec![Node::arg(
                "<addr>",
                "Next-hop IP address",
                ValueKind::IpAddr,
            )
            .cmd(Command::SetTopOriginate)])])]),
    );
    nodes.push(peer_subtree());
    nodes.push(policy_subtree());
    nodes.push(prefix_list_subtree());
    nodes.push(bmp_server_subtree());
    nodes.push(rpki_cache_subtree());
    nodes.push(bgp_ls_subtree());
    nodes.push(telemetry_subtree());
    nodes
}

fn tree_show() -> Vec<Node> {
    vec![
        Node::keyword("bgp", "BGP information").children(tree_show_bgp()),
        Node::keyword("rpki", "RPKI information").children(tree_show_rpki()),
        Node::keyword("config", "Config information").children(tree_show_config()),
        Node::keyword("version", "Version information").cmd(Command::Version),
    ]
}

/// `show` subtree available in `(config)`. Subset of operational `show` plus
/// candidate-vs-running views.
fn tree_show_cfg() -> Vec<Node> {
    vec![
        Node::keyword("diff", "Candidate vs running config").cmd(Command::ShowDiff),
        Node::keyword("running-config", "Currently running config").cmd(Command::ShowRunningConfig),
    ]
}

/// `show` subtree available in `(config-bgp)`. Adds bare `show` for the
/// candidate.
fn tree_show_cfg_bgp() -> Vec<Node> {
    vec![
        Node::keyword("diff", "Candidate vs running config").cmd(Command::ShowDiff),
        Node::keyword("running-config", "Currently running config").cmd(Command::ShowRunningConfig),
        Node::keyword("candidate", "In-progress candidate config").cmd(Command::ShowCandidate),
    ]
}

fn bgpgg(c: BgpggCommand) -> Command {
    Command::Bgpgg(c)
}

/// AFI/SAFI arg nodes. AFI accepts ipv4/ipv6/ls, SAFI accepts unicast/multicast.
fn afi_safi_nodes(cmd: Command) -> Vec<Node> {
    vec![
        Node::arg("<afi>", "Address family (ipv4, ipv6, ls)", ValueKind::Afi)
            .cmd(cmd)
            .children(vec![Node::arg(
                "<safi>",
                "Sub-address family (unicast, multicast)",
                ValueKind::Safi,
            )
            .cmd(cmd)]),
    ]
}

fn tree_show_bgp() -> Vec<Node> {
    vec![
        Node::keyword("summary", "Peer table overview").cmd(bgpgg(BgpggCommand::BgpSummary)),
        Node::keyword("info", "Server information").cmd(bgpgg(BgpggCommand::BgpInfo)),
        Node::keyword("peers", "Peer information")
            .cmd(bgpgg(BgpggCommand::BgpPeers))
            .children(vec![Node::arg(
                "<address>",
                "Peer address",
                ValueKind::IpAddr,
            )
            .cmd(bgpgg(BgpggCommand::BgpPeer))
            .children(vec![
                Node::keyword("in", "Adj-RIB-In")
                    .cmd(bgpgg(BgpggCommand::BgpPeerIn))
                    .children(afi_safi_nodes(bgpgg(BgpggCommand::BgpPeerIn))),
                Node::keyword("out", "Adj-RIB-Out")
                    .cmd(bgpgg(BgpggCommand::BgpPeerOut))
                    .children(afi_safi_nodes(bgpgg(BgpggCommand::BgpPeerOut))),
            ])]),
        Node::keyword("routes", "Routing table")
            .cmd(bgpgg(BgpggCommand::BgpRoute))
            .children({
                let mut nodes = afi_safi_nodes(bgpgg(BgpggCommand::BgpRoute));
                nodes.push(
                    Node::arg("<prefix>", "Prefix in CIDR format", ValueKind::Prefix)
                        .cmd(bgpgg(BgpggCommand::BgpRoute)),
                );
                nodes
            }),
    ]
}

fn tree_show_config() -> Vec<Node> {
    vec![Node::keyword("history", "Stored config snapshots").cmd(bgpgg(BgpggCommand::ConfigHistory))]
}

fn tree_show_rpki() -> Vec<Node> {
    vec![
        Node::keyword("caches", "RPKI cache status").cmd(bgpgg(BgpggCommand::RpkiCaches)),
        Node::keyword("roa", "ROA table").cmd(bgpgg(BgpggCommand::RpkiRoa)),
        Node::keyword("validate", "Validate a prefix").children(vec![Node::arg(
            "<prefix>",
            "Prefix in CIDR format",
            ValueKind::Prefix,
        )
        .children(vec![Node::keyword("origin", "Origin AS keyword")
            .children(vec![Node::arg("<asn>", "AS number", ValueKind::Asn)
                .cmd(bgpgg(BgpggCommand::RpkiValidate))])])]),
    ]
}

/// `peer <addr> ...` subtree: per-peer settings + family directives.
fn peer_subtree() -> Node {
    let mut peer_children = setting_leaves::<PeerKey>(Command::SetPeer);
    peer_children.push(
        Node::keyword("family", "Per-AFI/SAFI directives").children(vec![Node::arg(
            "<afi>",
            "Address family (ipv4, ipv6, ls)",
            ValueKind::Afi,
        )
        .children(vec![Node::arg(
            "<safi>",
            "Sub-address family (unicast, multicast)",
            ValueKind::Safi,
        )
        .children(family_directive_subtree(false))])]),
    );
    Node::keyword("peer", "Per-peer block").children(vec![Node::arg(
        "<addr>",
        "Peer address",
        ValueKind::IpAddr,
    )
    .children(peer_children)])
}

/// Children under `family <afi> <safi>`. `for_unset` strips the `<name>` arg
/// since `unset` doesn't take a value.
fn family_directive_subtree(for_unset: bool) -> Vec<Node> {
    FamilyDirectiveKey::all()
        .iter()
        .map(|&dir| {
            let policy = if for_unset {
                Node::keyword("policy", "Policy keyword")
                    .cmd(Command::UnsetPeerFamilyDirective(dir))
            } else {
                Node::keyword("policy", "Policy keyword").children(vec![Node::arg(
                    "<name>",
                    "Policy name",
                    dir.value_kind(),
                )
                .cmd(Command::SetPeerFamily(dir))])
            };
            Node::keyword(dir.as_str(), dir.help()).children(vec![policy])
        })
        .collect()
}

/// `policy <name> ...` subtree.
fn policy_subtree() -> Node {
    let name_children = vec![
        Node::keyword(PolicyRuleKey::Match.as_str(), PolicyRuleKey::Match.help()).children(vec![
            Node::arg("<set>", "Prefix-list set name", ValueKind::String).children(vec![
                Node::arg(
                    "<action>",
                    "Action (accept, reject, ...)",
                    ValueKind::String,
                )
                .cmd(Command::SetPolicyMatch),
            ]),
        ]),
        Node::keyword(
            PolicyRuleKey::Default.as_str(),
            PolicyRuleKey::Default.help(),
        )
        .children(vec![Node::arg(
            "<action>",
            "Action (accept, reject, ...)",
            ValueKind::String,
        )
        .cmd(Command::SetPolicyDefault)]),
    ];
    Node::keyword("policy", "Named policy").children(vec![Node::arg(
        "<name>",
        "Policy name",
        ValueKind::String,
    )
    .children(name_children)])
}

/// `prefix-list <name> <prefix>` subtree.
fn prefix_list_subtree() -> Node {
    Node::keyword("prefix-list", "Named prefix list").children(vec![Node::arg(
        "<name>",
        "Prefix-list name",
        ValueKind::String,
    )
    .children(vec![Node::arg(
        "<prefix>",
        "Prefix in CIDR notation",
        ValueKind::Prefix,
    )
    .cmd(Command::SetPrefixListEntry)])])
}

/// `bmp-server <addr> <key> <value>` subtree.
fn bmp_server_subtree() -> Node {
    Node::keyword("bmp-server", "BMP collector").children(vec![Node::arg(
        "<addr>",
        "BMP collector host:port",
        ValueKind::AddrPort,
    )
    .children(setting_leaves::<BmpServerKey>(Command::SetBmpServer))])
}

/// `rpki-cache <addr> <key> <value>` subtree.
fn rpki_cache_subtree() -> Node {
    Node::keyword("rpki-cache", "RPKI cache").children(vec![Node::arg(
        "<addr>",
        "RPKI cache host:port",
        ValueKind::AddrPort,
    )
    .children(setting_leaves::<RpkiCacheKey>(Command::SetRpkiCache))])
}

/// `bgp-ls <key> <value>` subtree (singleton block, no identifier).
fn bgp_ls_subtree() -> Node {
    Node::keyword("bgp-ls", "BGP-LS settings")
        .children(setting_leaves::<BgpLsKey>(Command::SetBgpLs))
}

/// `telemetry ...` subtree. json and cloudwatch-emf are mutually exclusive;
/// enforced in the apply handlers.
fn telemetry_subtree() -> Node {
    Node::keyword("telemetry", "Telemetry settings").children(vec![
        Node::keyword("json", "Emit metrics as JSON log lines").cmd(Command::SetTelemetryJson),
        Node::keyword("cloudwatch-emf", "Emit metrics as CloudWatch EMF log lines").children(vec![
            Node::keyword("namespace", "CloudWatch namespace").children(vec![Node::arg(
                "<namespace>",
                "Namespace (e.g. Rogg/Bgpgg)",
                ValueKind::String,
            )
            .cmd(Command::SetTelemetryCloudwatchEmf)]),
        ]),
        Node::keyword("prometheus", "Prometheus pull endpoint")
            .cmd(Command::SetTelemetryPrometheus)
            .children(vec![Node::keyword("listen", "Listen address").children(
                vec![Node::arg("<addr>", "host:port", ValueKind::AddrPort)
                    .cmd(Command::SetTelemetryPrometheusListen)],
            )]),
    ])
}

/// `unset ...` subtree mirroring the set surface, sans value tokens.
fn unset_subtree() -> Vec<Node> {
    let mut nodes = Vec::new();

    for &key in TopKey::all() {
        nodes.push(Node::keyword(key.as_str(), key.help()).cmd(Command::UnsetTop(key)));
    }
    nodes.push(
        Node::keyword("originate", "Stop originating a prefix").children(vec![Node::arg(
            "<prefix>",
            "Prefix in CIDR notation",
            ValueKind::Prefix,
        )
        .cmd(Command::UnsetTopOriginate)]),
    );

    let mut peer_children = vec![];
    peer_children.extend(
        PeerKey::all()
            .iter()
            .map(|&k| Node::keyword(k.as_str(), k.help()).cmd(Command::UnsetPeerSetting(k))),
    );
    peer_children.push(
        Node::keyword("family", "Remove a family or directive").children(vec![Node::arg(
            "<afi>",
            "Address family",
            ValueKind::Afi,
        )
        .children(vec![Node::arg(
            "<safi>",
            "Sub-address family",
            ValueKind::Safi,
        )
        .cmd(Command::UnsetPeerFamily)
        .children(family_directive_subtree(true))])]),
    );
    nodes.push(
        Node::keyword("peer", "Remove a peer or peer setting").children(vec![Node::arg(
            "<addr>",
            "Peer address",
            ValueKind::IpAddr,
        )
        .cmd(Command::UnsetPeer)
        .children(peer_children)]),
    );

    nodes.push(Node::keyword("policy", "Remove a policy").children(vec![
        Node::arg("<name>", "Policy name", ValueKind::String).cmd(Command::UnsetPolicy),
    ]));

    nodes.push(
        Node::keyword("prefix-list", "Remove a prefix-list or entry").children(vec![Node::arg(
            "<name>",
            "Prefix-list name",
            ValueKind::String,
        )
        .cmd(Command::UnsetPrefixList)
        .children(vec![Node::arg(
            "<prefix>",
            "Prefix in CIDR notation",
            ValueKind::Prefix,
        )
        .cmd(Command::UnsetPrefixListEntry)])]),
    );

    let mut bmp_children = vec![];
    for &key in BmpServerKey::all() {
        bmp_children
            .push(Node::keyword(key.as_str(), key.help()).cmd(Command::UnsetBmpServerSetting(key)));
    }
    nodes.push(
        Node::keyword("bmp-server", "Remove a BMP server or setting").children(vec![Node::arg(
            "<addr>",
            "BMP host:port",
            ValueKind::AddrPort,
        )
        .cmd(Command::UnsetBmpServer)
        .children(bmp_children)]),
    );

    let mut rpki_children = vec![];
    for &key in RpkiCacheKey::all() {
        rpki_children
            .push(Node::keyword(key.as_str(), key.help()).cmd(Command::UnsetRpkiCacheSetting(key)));
    }
    nodes.push(
        Node::keyword("rpki-cache", "Remove an RPKI cache or setting").children(vec![Node::arg(
            "<addr>",
            "RPKI host:port",
            ValueKind::AddrPort,
        )
        .cmd(Command::UnsetRpkiCache)
        .children(rpki_children)]),
    );

    let mut bgp_ls_children = vec![];
    for &key in BgpLsKey::all() {
        bgp_ls_children
            .push(Node::keyword(key.as_str(), key.help()).cmd(Command::UnsetBgpLsSetting(key)));
    }
    nodes.push(
        Node::keyword("bgp-ls", "Remove the bgp-ls block or a setting")
            .cmd(Command::UnsetBgpLs)
            .children(bgp_ls_children),
    );

    nodes.push(
        Node::keyword("telemetry", "Remove the telemetry block or a sub-block")
            .cmd(Command::UnsetTelemetry)
            .children(vec![
                Node::keyword("json", "Remove the json sink").cmd(Command::UnsetTelemetryJson),
                Node::keyword("cloudwatch-emf", "Remove the cloudwatch-emf sink")
                    .cmd(Command::UnsetTelemetryCloudwatchEmf),
                Node::keyword("prometheus", "Remove the prometheus endpoint")
                    .cmd(Command::UnsetTelemetryPrometheus)
                    .children(vec![Node::keyword(
                        "listen",
                        "Reset listen to the default (127.0.0.1:9273)",
                    )
                    .cmd(Command::UnsetTelemetryPrometheusListen)]),
            ]),
    );

    nodes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_structure() {
        let root = tree();
        let top: Vec<&str> = root.iter().map(|n| n.name).collect();
        assert_eq!(top, vec!["show", "configure", "exit", "quit"]);
        let cfg: Vec<&str> = tree_config().iter().map(|n| n.name).collect();
        assert_eq!(cfg, vec!["service", "commit", "exit", "show"]);
    }

    #[test]
    fn test_tree_config_bgp_has_all_top_keys() {
        let tree = tree_config_bgp();
        let names: Vec<&str> = tree.iter().map(|n| n.name).collect();
        for &key in TopKey::all() {
            assert!(
                names.contains(&key.as_str()),
                "tree_config_bgp missing top key {}",
                key.as_str()
            );
        }
        for &fixed in &[
            "commit",
            "exit",
            "show",
            "unset",
            "originate",
            "peer",
            "policy",
            "prefix-list",
            "bmp-server",
            "rpki-cache",
            "bgp-ls",
            "telemetry",
        ] {
            assert!(names.contains(&fixed), "tree_config_bgp missing {}", fixed);
        }
    }

    #[test]
    fn test_peer_subtree_has_all_peer_keys() {
        let peer = peer_subtree();
        let addr_node = &peer.children[0];
        let names: Vec<&str> = addr_node.children.iter().map(|n| n.name).collect();
        for &key in PeerKey::all() {
            assert!(
                names.contains(&key.as_str()),
                "peer subtree missing peer key {}",
                key.as_str()
            );
        }
        assert!(names.contains(&"family"), "peer subtree missing family");
    }

    #[test]
    fn test_rpki_cache_subtree_has_all_rpki_keys() {
        let cache = rpki_cache_subtree();
        let addr_node = &cache.children[0];
        let names: Vec<&str> = addr_node.children.iter().map(|n| n.name).collect();
        for &key in RpkiCacheKey::all() {
            assert!(
                names.contains(&key.as_str()),
                "rpki-cache subtree missing key {}",
                key.as_str()
            );
        }
    }
}
