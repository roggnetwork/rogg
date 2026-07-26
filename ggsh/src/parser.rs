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

//! Token-tree parser. Walks the grammar tree from `grammar::tree()`,
//! produces a `Command` to execute or a help/error result.

use rustyline::completion::Completer;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::Helper;

use conf::language_bgp::{
    BgpLsKey, BmpServerKey, FamilyDirectiveKey, PeerKey, RpkiCacheKey, TopKey,
};

use crate::grammar::Node;

/// Commands dispatched to the bgpggd daemon.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BgpggCommand {
    BgpSummary,
    BgpInfo,
    BgpPeers,
    BgpPeer,
    BgpPeerIn,
    BgpPeerOut,
    BgpRoute,
    RpkiCaches,
    RpkiRoa,
    RpkiValidate,
    ConfigHistory,
}

/// Top-level service kind (for `(config)> service <kind>`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServiceKind {
    Bgp,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    Bgpgg(BgpggCommand),
    Version,
    Configure,
    Exit,

    EnterService(ServiceKind),
    Commit,
    ShowDiff,
    ShowRunningConfig,
    ShowCandidate,

    SetTop(TopKey),                    // args: [value]
    SetTopOriginate,                   // args: [prefix, nexthop]
    SetPeer(PeerKey),                  // args: [addr, value]
    SetPeerFamily(FamilyDirectiveKey), // args: [addr, afi, safi, name]
    SetPolicyMatch,                    // args: [name, set, action]
    SetPolicyDefault,                  // args: [name, action]
    SetPrefixListEntry,                // args: [name, prefix]
    SetBmpServer(BmpServerKey),        // args: [addr, value]
    SetRpkiCache(RpkiCacheKey),        // args: [addr, value]
    SetBgpLs(BgpLsKey),                // args: [value]
    SetTelemetryJson,                  // args: []
    SetTelemetryCloudwatchEmf,         // args: [namespace]
    SetTelemetryPrometheus,            // args: []
    SetTelemetryPrometheusListen,      // args: [addr]

    UnsetTop(TopKey),                             // args: []
    UnsetTopOriginate,                            // args: [prefix]
    UnsetPeer,                                    // args: [addr]
    UnsetPeerSetting(PeerKey),                    // args: [addr]
    UnsetPeerFamily,                              // args: [addr, afi, safi]
    UnsetPeerFamilyDirective(FamilyDirectiveKey), // args: [addr, afi, safi]
    UnsetPolicy,                                  // args: [name]
    UnsetPrefixList,                              // args: [name]
    UnsetPrefixListEntry,                         // args: [name, prefix]
    UnsetBmpServer,                               // args: [addr]
    UnsetBmpServerSetting(BmpServerKey),          // args: [addr]
    UnsetRpkiCache,                               // args: [addr]
    UnsetRpkiCacheSetting(RpkiCacheKey),          // args: [addr]
    UnsetBgpLs,                                   // args: []
    UnsetBgpLsSetting(BgpLsKey),                  // args: []
    UnsetTelemetry,                               // args: []
    UnsetTelemetryJson,                           // args: []
    UnsetTelemetryCloudwatchEmf,                  // args: []
    UnsetTelemetryPrometheus,                     // args: []
    UnsetTelemetryPrometheusListen,               // args: []
}

pub struct HelpEntry {
    pub keyword: String,
    pub description: String,
}

pub enum ParseResult {
    Execution { cmd: Command, args: Vec<String> },
    Help { entries: Vec<HelpEntry> },
    Error(String),
}

pub struct TabCompleter {
    pub tree: Vec<Node>,
}

impl Completer for TabCompleter {
    type Candidate = String;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<String>)> {
        let input = &line[..pos];
        let candidates = completions(&self.tree, input);
        let start = input.rfind(' ').map(|i| i + 1).unwrap_or(0);
        Ok((start, candidates))
    }
}

impl Hinter for TabCompleter {
    type Hint = String;
}
impl Highlighter for TabCompleter {}
impl Validator for TabCompleter {}
impl Helper for TabCompleter {}

pub fn parse(tree: &[Node], tokens: &[&str]) -> ParseResult {
    if tokens.is_empty() {
        return ParseResult::Error("no command entered".to_string());
    }

    let last = tokens[tokens.len() - 1];
    if matches!(last, "?" | "help" | "--help") {
        let preceding = &tokens[..tokens.len() - 1];
        let mut nodes = tree;
        for &token in preceding {
            match find_match(token, nodes) {
                Some(node) => nodes = &node.children,
                None => break,
            }
        }
        let items = nodes
            .iter()
            .map(|n| HelpEntry {
                keyword: n.name.to_string(),
                description: n.help.to_string(),
            })
            .collect();
        return ParseResult::Help { entries: items };
    }

    let mut nodes = tree;
    let mut args = Vec::new();
    let mut last_node: Option<&Node> = None;

    for (idx, &token) in tokens.iter().enumerate() {
        match find_match(token, nodes) {
            Some(node) => {
                if node.is_arg() {
                    args.push(token.to_string());
                }
                last_node = Some(node);
                if idx < tokens.len() - 1 {
                    if node.children.is_empty() {
                        return ParseResult::Error(format!(
                            "unexpected token: {}",
                            tokens[idx + 1]
                        ));
                    }
                    nodes = &node.children;
                }
            }
            None => {
                let valid: Vec<&str> = nodes.iter().map(|n| n.name).collect();
                return ParseResult::Error(format!(
                    "unknown command '{}', expected: {}",
                    token,
                    valid.join(", ")
                ));
            }
        }
    }

    match last_node.and_then(|node| node.command) {
        Some(cmd) => ParseResult::Execution { cmd, args },
        _ => {
            let help_nodes = last_node
                .filter(|n| !n.children.is_empty())
                .map(|n| n.children.as_slice())
                .unwrap_or(nodes);
            let items = help_nodes
                .iter()
                .map(|n| HelpEntry {
                    keyword: n.name.to_string(),
                    description: n.help.to_string(),
                })
                .collect();
            ParseResult::Help { entries: items }
        }
    }
}

pub fn completions(tree: &[Node], input: &str) -> Vec<String> {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    let completing_next = input.ends_with(' ');
    let mut nodes = tree;

    let walk_count = if completing_next {
        tokens.len()
    } else {
        tokens.len().saturating_sub(1)
    };
    for &token in &tokens[..walk_count] {
        match find_match(token, nodes) {
            Some(node) => nodes = &node.children,
            None => return vec![],
        }
    }

    let prefix = if completing_next {
        ""
    } else {
        tokens.last().copied().unwrap_or("")
    };

    nodes
        .iter()
        .filter(|n| !n.is_arg() && n.name.starts_with(prefix))
        .map(|n| n.name.to_string())
        .collect()
}

fn find_match<'a>(token: &str, nodes: &'a [Node]) -> Option<&'a Node> {
    if let Some(node) = nodes.iter().find(|n| !n.is_arg() && n.name == token) {
        return Some(node);
    }
    nodes
        .iter()
        .find(|n| n.kind.is_some_and(|kind| kind.validate(token)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grammar;

    fn parse_cmd(input: &str) -> (Command, Vec<String>) {
        let root = grammar::tree();
        let tokens: Vec<&str> = input.split_whitespace().collect();
        match parse(&root, &tokens) {
            ParseResult::Execution { cmd, args } => (cmd, args),
            _ => panic!("expected Command for '{}'", input),
        }
    }

    #[test]
    fn test_parse_commands() {
        use BgpggCommand as B;
        let bgpgg = Command::Bgpgg;
        let cases = vec![
            ("show bgp summary", bgpgg(B::BgpSummary), vec![]),
            ("show bgp info", bgpgg(B::BgpInfo), vec![]),
            ("show bgp peers", bgpgg(B::BgpPeers), vec![]),
            (
                "show bgp peers 10.0.0.1",
                bgpgg(B::BgpPeer),
                vec!["10.0.0.1"],
            ),
            (
                "show bgp peers 10.0.0.1 in",
                bgpgg(B::BgpPeerIn),
                vec!["10.0.0.1"],
            ),
            (
                "show bgp peers 10.0.0.1 out ipv4",
                bgpgg(B::BgpPeerOut),
                vec!["10.0.0.1", "ipv4"],
            ),
            (
                "show bgp peers 10.0.0.1 in ipv6 unicast",
                bgpgg(B::BgpPeerIn),
                vec!["10.0.0.1", "ipv6", "unicast"],
            ),
            ("show bgp routes", bgpgg(B::BgpRoute), vec![]),
            (
                "show bgp routes 10.0.0.0/24",
                bgpgg(B::BgpRoute),
                vec!["10.0.0.0/24"],
            ),
            ("show bgp routes ipv4", bgpgg(B::BgpRoute), vec!["ipv4"]),
            (
                "show bgp routes ipv6 unicast",
                bgpgg(B::BgpRoute),
                vec!["ipv6", "unicast"],
            ),
            ("show rpki caches", bgpgg(B::RpkiCaches), vec![]),
            ("show rpki roa", bgpgg(B::RpkiRoa), vec![]),
            (
                "show rpki validate 10.0.0.0/24 origin 65001",
                bgpgg(B::RpkiValidate),
                vec!["10.0.0.0/24", "65001"],
            ),
            ("show version", Command::Version, vec![]),
            ("exit", Command::Exit, vec![]),
            ("quit", Command::Exit, vec![]),
        ];

        for (input, expected_cmd, expected_args) in cases {
            let (cmd, args) = parse_cmd(input);
            assert_eq!(cmd, expected_cmd, "wrong command for: {}", input);
            let expected_args: Vec<String> = expected_args.iter().map(|s| s.to_string()).collect();
            assert_eq!(args, expected_args, "wrong args for: {}", input);
        }
    }

    fn parse_cfg_root(input: &str) -> ParseResult {
        let tree = grammar::tree_config();
        let tokens: Vec<&str> = input.split_whitespace().collect();
        parse(&tree, &tokens)
    }

    fn parse_cfg_bgp(input: &str) -> (Command, Vec<String>) {
        let tree = grammar::tree_config_bgp();
        let tokens: Vec<&str> = input.split_whitespace().collect();
        match parse(&tree, &tokens) {
            ParseResult::Execution { cmd, args } => (cmd, args),
            other => panic!(
                "expected Execution for {:?}, got {:?}",
                input,
                match other {
                    ParseResult::Error(e) => e,
                    ParseResult::Help { entries } => format!("Help with {} entries", entries.len()),
                    ParseResult::Execution { .. } => unreachable!(),
                }
            ),
        }
    }

    #[test]
    fn test_parse_config_root_commands() {
        for (input, expected) in [
            ("service bgp", Command::EnterService(ServiceKind::Bgp)),
            ("commit", Command::Commit),
            ("exit", Command::Exit),
            ("show diff", Command::ShowDiff),
            ("show running-config", Command::ShowRunningConfig),
        ] {
            match parse_cfg_root(input) {
                ParseResult::Execution { cmd, args } => {
                    assert_eq!(cmd, expected, "wrong cmd for {:?}", input);
                    assert!(args.is_empty(), "expected no args for {:?}", input);
                }
                other => panic!(
                    "expected Execution for {:?}: {:?}",
                    input,
                    match other {
                        ParseResult::Error(e) => e,
                        _ => "non-error".into(),
                    }
                ),
            }
        }
    }

    #[test]
    fn test_parse_config_bgp_top_settings() {
        let (cmd, args) = parse_cfg_bgp("asn 65001");
        assert_eq!(cmd, Command::SetTop(TopKey::Asn));
        assert_eq!(args, vec!["65001".to_string()]);

        let (cmd, args) = parse_cfg_bgp("router-id 1.2.3.4");
        assert_eq!(cmd, Command::SetTop(TopKey::RouterId));
        assert_eq!(args, vec!["1.2.3.4".to_string()]);

        let (cmd, args) = parse_cfg_bgp("originate 10.0.0.0/24 nexthop 192.168.1.1");
        assert_eq!(cmd, Command::SetTopOriginate);
        assert_eq!(
            args,
            vec!["10.0.0.0/24".to_string(), "192.168.1.1".to_string()]
        );
    }

    #[test]
    fn test_parse_config_bgp_peer_settings() {
        let (cmd, args) = parse_cfg_bgp("peer fe80::ade0 remote-as 65001");
        assert_eq!(cmd, Command::SetPeer(PeerKey::RemoteAs));
        assert_eq!(args, vec!["fe80::ade0".to_string(), "65001".to_string()]);

        let (cmd, args) = parse_cfg_bgp("peer 10.0.0.1 next-hop-self true");
        assert_eq!(cmd, Command::SetPeer(PeerKey::NextHopSelf));
        assert_eq!(args, vec!["10.0.0.1".to_string(), "true".to_string()]);

        let (cmd, args) =
            parse_cfg_bgp("peer 10.0.0.1 family ipv4 unicast export policy mine-only");
        assert_eq!(
            cmd,
            Command::SetPeerFamily(FamilyDirectiveKey::ExportPolicy)
        );
        assert_eq!(
            args,
            vec![
                "10.0.0.1".to_string(),
                "ipv4".to_string(),
                "unicast".to_string(),
                "mine-only".to_string(),
            ]
        );
    }

    #[test]
    fn test_parse_config_bgp_policy() {
        let (cmd, args) = parse_cfg_bgp("policy mine-only match my-prefixes accept");
        assert_eq!(cmd, Command::SetPolicyMatch);
        assert_eq!(
            args,
            vec![
                "mine-only".to_string(),
                "my-prefixes".to_string(),
                "accept".to_string(),
            ]
        );

        let (cmd, args) = parse_cfg_bgp("policy mine-only default reject");
        assert_eq!(cmd, Command::SetPolicyDefault);
        assert_eq!(args, vec!["mine-only".to_string(), "reject".to_string()]);
    }

    #[test]
    fn test_parse_config_bgp_prefix_list() {
        let (cmd, args) = parse_cfg_bgp("prefix-list my-prefixes 10.0.0.0/24");
        assert_eq!(cmd, Command::SetPrefixListEntry);
        assert_eq!(
            args,
            vec!["my-prefixes".to_string(), "10.0.0.0/24".to_string()]
        );
    }

    #[test]
    fn test_parse_config_bgp_bmp_rpki_bgp_ls() {
        let (cmd, args) = parse_cfg_bgp("bmp-server 127.0.0.1:1790 statistics-timeout 60");
        assert_eq!(cmd, Command::SetBmpServer(BmpServerKey::StatisticsTimeout));
        assert_eq!(args, vec!["127.0.0.1:1790".to_string(), "60".to_string()]);

        let (cmd, args) = parse_cfg_bgp("rpki-cache 127.0.0.1:323 transport tcp");
        assert_eq!(cmd, Command::SetRpkiCache(RpkiCacheKey::Transport));
        assert_eq!(args, vec!["127.0.0.1:323".to_string(), "tcp".to_string()]);

        let (cmd, args) = parse_cfg_bgp("bgp-ls instance-id 99");
        assert_eq!(cmd, Command::SetBgpLs(BgpLsKey::InstanceId));
        assert_eq!(args, vec!["99".to_string()]);
    }

    #[test]
    fn test_parse_config_bgp_telemetry() {
        let (cmd, args) = parse_cfg_bgp("telemetry json");
        assert_eq!(cmd, Command::SetTelemetryJson);
        assert!(args.is_empty());

        let (cmd, args) = parse_cfg_bgp("telemetry cloudwatch-emf namespace Rogg/Bgpgg");
        assert_eq!(cmd, Command::SetTelemetryCloudwatchEmf);
        assert_eq!(args, vec!["Rogg/Bgpgg".to_string()]);

        let (cmd, args) = parse_cfg_bgp("telemetry prometheus");
        assert_eq!(cmd, Command::SetTelemetryPrometheus);
        assert!(args.is_empty());

        let (cmd, args) = parse_cfg_bgp("telemetry prometheus listen 0.0.0.0:9273");
        assert_eq!(cmd, Command::SetTelemetryPrometheusListen);
        assert_eq!(args, vec!["0.0.0.0:9273".to_string()]);

        let (cmd, args) = parse_cfg_bgp("unset telemetry");
        assert_eq!(cmd, Command::UnsetTelemetry);
        assert!(args.is_empty());

        let (cmd, _) = parse_cfg_bgp("unset telemetry json");
        assert_eq!(cmd, Command::UnsetTelemetryJson);

        let (cmd, _) = parse_cfg_bgp("unset telemetry cloudwatch-emf");
        assert_eq!(cmd, Command::UnsetTelemetryCloudwatchEmf);

        let (cmd, _) = parse_cfg_bgp("unset telemetry prometheus");
        assert_eq!(cmd, Command::UnsetTelemetryPrometheus);

        let (cmd, _) = parse_cfg_bgp("unset telemetry prometheus listen");
        assert_eq!(cmd, Command::UnsetTelemetryPrometheusListen);
    }

    #[test]
    fn test_parse_config_bgp_unset() {
        let (cmd, args) = parse_cfg_bgp("unset asn");
        assert_eq!(cmd, Command::UnsetTop(TopKey::Asn));
        assert!(args.is_empty());

        let (cmd, args) = parse_cfg_bgp("unset peer 10.0.0.1");
        assert_eq!(cmd, Command::UnsetPeer);
        assert_eq!(args, vec!["10.0.0.1".to_string()]);

        let (cmd, args) = parse_cfg_bgp("unset peer 10.0.0.1 remote-as");
        assert_eq!(cmd, Command::UnsetPeerSetting(PeerKey::RemoteAs));
        assert_eq!(args, vec!["10.0.0.1".to_string()]);

        let (cmd, args) = parse_cfg_bgp("unset peer 10.0.0.1 family ipv4 unicast");
        assert_eq!(cmd, Command::UnsetPeerFamily);
        assert_eq!(
            args,
            vec![
                "10.0.0.1".to_string(),
                "ipv4".to_string(),
                "unicast".to_string()
            ]
        );

        let (cmd, args) = parse_cfg_bgp("unset peer 10.0.0.1 family ipv4 unicast export policy");
        assert_eq!(
            cmd,
            Command::UnsetPeerFamilyDirective(FamilyDirectiveKey::ExportPolicy)
        );
        assert_eq!(
            args,
            vec![
                "10.0.0.1".to_string(),
                "ipv4".to_string(),
                "unicast".to_string()
            ]
        );

        let (cmd, args) = parse_cfg_bgp("unset prefix-list p 10.0.0.0/24");
        assert_eq!(cmd, Command::UnsetPrefixListEntry);
        assert_eq!(args, vec!["p".to_string(), "10.0.0.0/24".to_string()]);

        let (cmd, args) = parse_cfg_bgp("unset bgp-ls");
        assert_eq!(cmd, Command::UnsetBgpLs);
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_config_bgp_invalid_value_rejected() {
        let tree = grammar::tree_config_bgp();
        for bad in &[
            "asn notanumber",
            "router-id 999.999.999.999",
            "peer notanip remote-as 65001",
            "peer 10.0.0.1 port notnum",
            "rpki-cache 127.0.0.1:323 transport ftp",
            "rpki-cache 127.0.0.1:323 preference 999", // u8 overflow
            "telemetry prometheus listen notanaddr",
        ] {
            let tokens: Vec<&str> = bad.split_whitespace().collect();
            assert!(
                matches!(parse(&tree, &tokens), ParseResult::Error(_)),
                "expected Error for {:?}",
                bad
            );
        }
    }

    #[test]
    fn test_parse_errors() {
        let root = grammar::tree();

        for input in &[
            "",
            "invalid",
            "show bgp routes 10.0.0.0/24 unicast extra",
            "show version extra",
        ] {
            let tokens: Vec<&str> = input.split_whitespace().collect();
            assert!(
                matches!(parse(&root, &tokens), ParseResult::Error(_)),
                "expected Error for: {}",
                input
            );
        }

        for input in &["show", "show bgp", "show rpki validate"] {
            let tokens: Vec<&str> = input.split_whitespace().collect();
            assert!(
                matches!(parse(&root, &tokens), ParseResult::Help { .. }),
                "expected Help for: {}",
                input
            );
        }

        match parse(&root, &["show", "bgp"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(keywords.contains(&"summary"));
                assert!(keywords.contains(&"peers"));
                assert!(!keywords.contains(&"rpki"));
            }
            _ => panic!("expected Help for 'show bgp'"),
        }

        match parse(&root, &["show"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(keywords.contains(&"bgp"));
                assert!(keywords.contains(&"rpki"));
                assert!(keywords.contains(&"version"));
            }
            _ => panic!("expected Help for 'show'"),
        }
    }

    #[test]
    fn test_completions() {
        let root = grammar::tree();

        let cases = vec![
            ("", vec!["show", "configure", "exit", "quit"]),
            ("sh", vec!["show"]),
            ("co", vec!["configure"]),
            ("show ", vec!["bgp", "config", "rpki", "version"]),
            ("show bgp ", vec!["summary", "info", "peers", "routes"]),
            ("show bgp s", vec!["summary"]),
            ("show rpki ", vec!["caches", "roa", "validate"]),
            ("show config ", vec!["history"]),
        ];

        for (input, expected) in cases {
            let mut result = completions(&root, input);
            let mut expected: Vec<String> = expected.into_iter().map(String::from).collect();
            result.sort();
            expected.sort();
            assert_eq!(
                result, expected,
                "completions failed for input: {:?}",
                input
            );
        }
    }

    #[test]
    fn test_help() {
        let root = grammar::tree();

        match parse(&root, &["show", "?"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(keywords.contains(&"bgp"));
                assert!(keywords.contains(&"rpki"));
                assert!(keywords.contains(&"version"));
            }
            _ => panic!("expected Help"),
        }

        match parse(&root, &["show", "bgp", "?"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(keywords.contains(&"summary"));
                assert!(keywords.contains(&"info"));
                assert!(keywords.contains(&"peers"));
                assert!(keywords.contains(&"routes"));
            }
            _ => panic!("expected Help"),
        }

        match parse(&root, &["?"]) {
            ParseResult::Help { entries } => {
                let keywords: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
                assert!(keywords.contains(&"show"));
                assert!(keywords.contains(&"exit"));
            }
            _ => panic!("expected Help"),
        }
    }
}
