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

//! Policy API integration tests

mod utils;
pub use utils::*;

use bgpgg::grpc::proto::{
    defined_set_config, defined_set_info, ActionsConfig, AsPathSetData, CommunitySetData,
    ConditionsConfig, DefinedSetConfig, DefinedSetInfo, MatchSetRef, NeighborSetData, PolicyInfo,
    PrefixMatch, PrefixSetData, StatementConfig, StatementInfo,
};
use conf::bgp::{Afi, BgpConfig, Safi};
use std::net::Ipv4Addr;

// Test fixtures

fn prefix_set_config(name: &str, prefixes: Vec<(&str, Option<&str>)>) -> DefinedSetConfig {
    DefinedSetConfig {
        set_type: "prefix-set".to_string(),
        name: name.to_string(),
        config: Some(defined_set_config::Config::PrefixSet(PrefixSetData {
            prefixes: prefixes
                .into_iter()
                .map(|(prefix, range)| PrefixMatch {
                    prefix: prefix.to_string(),
                    masklength_range: range.map(|r| r.to_string()),
                })
                .collect(),
        })),
    }
}

fn neighbor_set_config(name: &str, addresses: Vec<&str>) -> DefinedSetConfig {
    DefinedSetConfig {
        set_type: "neighbor-set".to_string(),
        name: name.to_string(),
        config: Some(defined_set_config::Config::NeighborSet(NeighborSetData {
            addresses: addresses.into_iter().map(|a| a.to_string()).collect(),
        })),
    }
}

fn as_path_set_config(name: &str, patterns: Vec<&str>) -> DefinedSetConfig {
    DefinedSetConfig {
        set_type: "as-path-set".to_string(),
        name: name.to_string(),
        config: Some(defined_set_config::Config::AsPathSet(AsPathSetData {
            patterns: patterns.into_iter().map(|p| p.to_string()).collect(),
        })),
    }
}

fn community_set_config(name: &str, communities: Vec<&str>) -> DefinedSetConfig {
    DefinedSetConfig {
        set_type: "community-set".to_string(),
        name: name.to_string(),
        config: Some(defined_set_config::Config::CommunitySet(CommunitySetData {
            communities: communities.into_iter().map(|c| c.to_string()).collect(),
        })),
    }
}

fn expected_prefix_set_info(name: &str, prefixes: Vec<(&str, Option<&str>)>) -> DefinedSetInfo {
    DefinedSetInfo {
        set_type: "prefix-set".to_string(),
        name: name.to_string(),
        set_data: Some(defined_set_info::SetData::PrefixSet(PrefixSetData {
            prefixes: prefixes
                .into_iter()
                .map(|(prefix, range)| PrefixMatch {
                    prefix: prefix.to_string(),
                    masklength_range: range.map(|r| r.to_string()),
                })
                .collect(),
        })),
    }
}

fn expected_neighbor_set_info(name: &str, addresses: Vec<&str>) -> DefinedSetInfo {
    DefinedSetInfo {
        set_type: "neighbor-set".to_string(),
        name: name.to_string(),
        set_data: Some(defined_set_info::SetData::NeighborSet(NeighborSetData {
            addresses: addresses.into_iter().map(|a| a.to_string()).collect(),
        })),
    }
}

fn expected_as_path_set_info(name: &str, patterns: Vec<&str>) -> DefinedSetInfo {
    DefinedSetInfo {
        set_type: "as-path-set".to_string(),
        name: name.to_string(),
        set_data: Some(defined_set_info::SetData::AsPathSet(AsPathSetData {
            patterns: patterns.into_iter().map(|p| p.to_string()).collect(),
        })),
    }
}

fn expected_community_set_info(name: &str, communities: Vec<&str>) -> DefinedSetInfo {
    DefinedSetInfo {
        set_type: "community-set".to_string(),
        name: name.to_string(),
        set_data: Some(defined_set_info::SetData::CommunitySet(CommunitySetData {
            communities: communities.into_iter().map(|c| c.to_string()).collect(),
        })),
    }
}

fn simple_statement_config(
    prefix: Option<&str>,
    accept: bool,
    local_pref: Option<u32>,
) -> StatementConfig {
    StatementConfig {
        conditions: Some(ConditionsConfig {
            prefix: prefix.map(|p| p.to_string()),
            ..Default::default()
        }),
        actions: Some(ActionsConfig {
            accept: if accept { Some(true) } else { None },
            reject: if !accept { Some(true) } else { None },
            local_pref,
            ..Default::default()
        }),
    }
}

fn statement_with_prefix_set(
    set_name: &str,
    match_option: &str,
    accept: bool,
    local_pref: Option<u32>,
) -> StatementConfig {
    StatementConfig {
        conditions: Some(ConditionsConfig {
            match_prefix_set: Some(MatchSetRef {
                set_name: set_name.to_string(),
                match_option: match_option.to_string(),
            }),
            ..Default::default()
        }),
        actions: Some(ActionsConfig {
            accept: if accept { Some(true) } else { None },
            reject: if !accept { Some(true) } else { None },
            local_pref,
            ..Default::default()
        }),
    }
}

fn expected_simple_statement_info(
    prefix: Option<&str>,
    accept: bool,
    local_pref: Option<u32>,
) -> StatementInfo {
    StatementInfo {
        conditions: Some(ConditionsConfig {
            prefix: prefix.map(|p| p.to_string()),
            ..Default::default()
        }),
        actions: Some(ActionsConfig {
            accept: if accept { Some(true) } else { None },
            reject: if !accept { Some(true) } else { None },
            local_pref,
            ..Default::default()
        }),
    }
}

fn expected_statement_with_prefix_set(
    set_name: &str,
    match_option: &str,
    accept: bool,
    local_pref: Option<u32>,
) -> StatementInfo {
    StatementInfo {
        conditions: Some(ConditionsConfig {
            match_prefix_set: Some(MatchSetRef {
                set_name: set_name.to_string(),
                match_option: match_option.to_string(),
            }),
            ..Default::default()
        }),
        actions: Some(ActionsConfig {
            accept: if accept { Some(true) } else { None },
            reject: if !accept { Some(true) } else { None },
            local_pref,
            ..Default::default()
        }),
    }
}

#[tokio::test]
async fn test_add_defined_sets() {
    let test_cases = vec![
        (
            "prefix-set",
            prefix_set_config(
                "test-prefixes",
                vec![("10.0.0.0/8", Some("16..24")), ("192.168.0.0/16", None)],
            ),
            expected_prefix_set_info(
                "test-prefixes",
                vec![("10.0.0.0/8", Some("16..24")), ("192.168.0.0/16", None)],
            ),
        ),
        (
            "neighbor-set",
            neighbor_set_config("my-peers", vec!["10.0.0.1", "10.0.0.2"]),
            expected_neighbor_set_info("my-peers", vec!["10.0.0.1", "10.0.0.2"]),
        ),
        (
            "as-path-set",
            as_path_set_config("customer-asns", vec!["_65001$", "_65002$"]),
            expected_as_path_set_info("customer-asns", vec!["_65001$", "_65002$"]),
        ),
        (
            "community-set",
            community_set_config("no-export", vec!["65000:100", "65000:200"]),
            expected_community_set_info("no-export", vec!["65000:100", "65000:200"]),
        ),
    ];

    for (desc, input, expected) in test_cases {
        let server = start_test_server(BgpConfig::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
        ))
        .await;

        // Initially no defined sets
        let sets = server.client.list_defined_sets().await.unwrap();
        assert_eq!(sets.len(), 0, "{}: should start with no sets", desc);

        // Add the defined set
        let result = server.client.add_defined_set(input, false).await;
        assert!(result.is_ok(), "{}: add should succeed", desc);

        // Verify exact response
        let sets = server.client.list_defined_sets().await.unwrap();
        assert_eq!(sets, vec![expected], "{}: set data should match", desc);
    }
}

#[tokio::test]
async fn test_add_duplicate_set_fails() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    let prefix_set = prefix_set_config("test-prefixes", vec![("10.0.0.0/8", None)]);

    // First add should succeed
    let result = server
        .client
        .add_defined_set(prefix_set.clone(), false)
        .await;
    assert!(result.is_ok());

    // Second add should fail (duplicate)
    let err = server
        .client
        .add_defined_set(prefix_set, false)
        .await
        .unwrap_err();
    assert!(err.message().contains("already exists"));
}

#[tokio::test]
async fn test_list_defined_sets() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Add two defined sets
    server
        .client
        .add_defined_set(
            prefix_set_config("my-prefixes", vec![("10.0.0.0/8", None)]),
            false,
        )
        .await
        .unwrap();

    server
        .client
        .add_defined_set(neighbor_set_config("my-neighbors", vec!["10.0.0.1"]), false)
        .await
        .unwrap();

    // List and verify
    let sets = server.client.list_defined_sets().await.unwrap();
    assert_eq!(sets.len(), 2);

    let expected = vec![
        expected_prefix_set_info("my-prefixes", vec![("10.0.0.0/8", None)]),
        expected_neighbor_set_info("my-neighbors", vec!["10.0.0.1"]),
    ];

    // Sort for consistent comparison
    let mut sets_sorted = sets.clone();
    sets_sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut expected_sorted = expected.clone();
    expected_sorted.sort_by(|a, b| a.name.cmp(&b.name));

    assert_eq!(sets_sorted, expected_sorted);
}

#[tokio::test]
async fn test_remove_defined_set() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Add two defined sets
    server
        .client
        .add_defined_set(prefix_set_config("set1", vec![("10.0.0.0/8", None)]), false)
        .await
        .unwrap();

    server
        .client
        .add_defined_set(neighbor_set_config("set2", vec!["10.0.0.1"]), false)
        .await
        .unwrap();

    let expected_after_removal = vec![expected_neighbor_set_info("set2", vec!["10.0.0.1"])];

    // Remove twice to test idempotency
    for i in 1..=2 {
        let result = server
            .client
            .remove_defined_set("prefix-set".to_string(), "set1".to_string())
            .await;
        assert!(result.is_ok(), "remove {} should succeed", i);

        // Verify state after each removal
        let sets = server.client.list_defined_sets().await.unwrap();
        assert_eq!(sets, expected_after_removal, "after remove {}", i);
    }
}

#[tokio::test]
async fn test_add_policy() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // First add a defined set that the policy will reference
    server
        .client
        .add_defined_set(
            prefix_set_config("customer-prefixes", vec![("10.0.0.0/8", Some("16..24"))]),
            false,
        )
        .await
        .unwrap();

    // Add a policy that references the defined set
    let result = server
        .client
        .add_policy(
            "customer-import".to_string(),
            vec![statement_with_prefix_set(
                "customer-prefixes",
                "any",
                true,
                Some(200),
            )],
        )
        .await;

    assert!(result.is_ok());

    // Verify the policy was added
    let mut policies = server.client.list_policies().await.unwrap();
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        policies,
        vec![
            PolicyInfo {
                name: "customer-import".to_string(),
                statements: vec![expected_statement_with_prefix_set(
                    "customer-prefixes",
                    "any",
                    true,
                    Some(200),
                )],
            },
            PolicyInfo {
                name: "default-deny-all".to_string(),
                statements: vec![expected_simple_statement_info(None, false, None)],
            },
            PolicyInfo {
                name: "default-permit-all".to_string(),
                statements: vec![expected_simple_statement_info(None, true, None)],
            },
        ]
    );
}

#[tokio::test]
async fn test_add_policy_missing_defined_set() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Try to add a policy that references a non-existent defined set
    let err = server
        .client
        .add_policy(
            "test-policy".to_string(),
            vec![statement_with_prefix_set(
                "nonexistent-set",
                "any",
                true,
                None,
            )],
        )
        .await
        .unwrap_err();

    assert!(err.message().contains("not found"));
}

#[tokio::test]
async fn test_list_policies() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Add a defined set first
    server
        .client
        .add_defined_set(
            prefix_set_config("test-prefixes", vec![("10.0.0.0/8", None)]),
            false,
        )
        .await
        .unwrap();

    // Add two policies
    server
        .client
        .add_policy(
            "policy1".to_string(),
            vec![statement_with_prefix_set(
                "test-prefixes",
                "any",
                true,
                None,
            )],
        )
        .await
        .unwrap();

    server
        .client
        .add_policy(
            "policy2".to_string(),
            vec![simple_statement_config(Some("192.168.0.0/16"), false, None)],
        )
        .await
        .unwrap();

    // List and verify all policies present (user + built-in)
    let mut policies = server.client.list_policies().await.unwrap();
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        policies,
        vec![
            PolicyInfo {
                name: "default-deny-all".to_string(),
                statements: vec![expected_simple_statement_info(None, false, None)],
            },
            PolicyInfo {
                name: "default-permit-all".to_string(),
                statements: vec![expected_simple_statement_info(None, true, None)],
            },
            PolicyInfo {
                name: "policy1".to_string(),
                statements: vec![expected_statement_with_prefix_set(
                    "test-prefixes",
                    "any",
                    true,
                    None,
                )],
            },
            PolicyInfo {
                name: "policy2".to_string(),
                statements: vec![expected_simple_statement_info(
                    Some("192.168.0.0/16"),
                    false,
                    None,
                )],
            },
        ]
    );
}

#[tokio::test]
async fn test_remove_policy() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Add two policies
    server
        .client
        .add_policy(
            "policy1".to_string(),
            vec![simple_statement_config(Some("10.0.0.0/8"), true, None)],
        )
        .await
        .unwrap();

    server
        .client
        .add_policy(
            "policy2".to_string(),
            vec![simple_statement_config(Some("192.168.0.0/16"), false, None)],
        )
        .await
        .unwrap();

    let expected_after_removal = vec![
        PolicyInfo {
            name: "default-deny-all".to_string(),
            statements: vec![expected_simple_statement_info(None, false, None)],
        },
        PolicyInfo {
            name: "default-permit-all".to_string(),
            statements: vec![expected_simple_statement_info(None, true, None)],
        },
        PolicyInfo {
            name: "policy2".to_string(),
            statements: vec![expected_simple_statement_info(
                Some("192.168.0.0/16"),
                false,
                None,
            )],
        },
    ];

    // Remove twice to test idempotency
    for i in 1..=2 {
        let result = server.client.remove_policy("policy1".to_string()).await;
        assert!(result.is_ok(), "remove {} should succeed", i);

        let mut policies = server.client.list_policies().await.unwrap();
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(policies, expected_after_removal, "after remove {}", i);
    }
}

#[tokio::test]
async fn test_set_policy_assignment() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    // Create policies on server1
    server1
        .client
        .add_policy(
            "import-policy".to_string(),
            vec![simple_statement_config(Some("10.0.0.0/8"), true, Some(200))],
        )
        .await
        .unwrap();

    server1
        .client
        .add_policy(
            "export-policy".to_string(),
            vec![simple_statement_config(
                Some("192.168.0.0/16"),
                true,
                Some(150),
            )],
        )
        .await
        .unwrap();

    // Replace import on every common family so the assertion stays clean.
    // (Helper applied permit-all to ipv4/ipv6/LinkState.)
    for (afi, safi) in [
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv6, Safi::Unicast),
        (Afi::LinkState, Safi::LinkState),
    ] {
        server1
            .client
            .set_policy_assignment(
                server2.address.to_string(),
                afi as u32,
                safi as u32,
                "import".to_string(),
                vec!["import-policy".to_string()],
                None,
            )
            .await
            .unwrap();
    }

    // Assert: import policy replaced on all families, export unchanged.
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].import_policies, vec!["import-policy"]);
    assert_eq!(peers[0].export_policies, vec!["permit-all"]);

    // Replace export on every common family.
    for (afi, safi) in [
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv6, Safi::Unicast),
        (Afi::LinkState, Safi::LinkState),
    ] {
        server1
            .client
            .set_policy_assignment(
                server2.address.to_string(),
                afi as u32,
                safi as u32,
                "export".to_string(),
                vec!["export-policy".to_string()],
                None,
            )
            .await
            .unwrap();
    }

    // Assert: both user policies set.
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].import_policies, vec!["import-policy"]);
    assert_eq!(peers[0].export_policies, vec!["export-policy"]);

    // Create another policy and override import on every common family.
    server1
        .client
        .add_policy(
            "new-import-policy".to_string(),
            vec![simple_statement_config(
                Some("172.16.0.0/12"),
                true,
                Some(250),
            )],
        )
        .await
        .unwrap();

    for (afi, safi) in [
        (Afi::Ipv4, Safi::Unicast),
        (Afi::Ipv6, Safi::Unicast),
        (Afi::LinkState, Safi::LinkState),
    ] {
        server1
            .client
            .set_policy_assignment(
                server2.address.to_string(),
                afi as u32,
                safi as u32,
                "import".to_string(),
                vec!["new-import-policy".to_string()],
                None,
            )
            .await
            .unwrap();
    }

    // Assert: import policy overridden on all families; export remains.
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].import_policies, vec!["new-import-policy"]);
    assert_eq!(peers[0].export_policies, vec!["export-policy"]);

    // Persist to rogg.conf and verify the per-family assignment shows up on disk.
    server1.save_config().await.unwrap();
    let conf = server1.read_conf();
    let saved = conf
        .peers
        .iter()
        .find(|peer| peer.address == server2.address.to_string())
        .expect("peer in saved config");
    let family = saved
        .afi_safis
        .iter()
        .find(|afi_safi| afi_safi.afi == Afi::Ipv4 && afi_safi.safi == Safi::Unicast)
        .expect("ipv4 unicast family in saved config");
    assert_eq!(family.import_policy, vec!["new-import-policy".to_string()]);
    assert_eq!(family.export_policy, vec!["export-policy".to_string()]);
}

#[tokio::test]
async fn test_reject_policy_name_starting_with_underscore() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Try to create a policy starting with underscore
    let result = server
        .client
        .add_policy(
            "_my_policy".to_string(),
            vec![simple_statement_config(Some("10.0.0.0/8"), true, None)],
        )
        .await;

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("cannot start with underscore"));
}
