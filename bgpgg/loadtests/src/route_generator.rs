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

use bgpgg::bgp::msg_update::{AsPathSegment, AsPathSegmentType, NextHopAddr, Origin};
use bgpgg::net::{IpNetwork, Ipv4Net};
use bgpgg::rib::{Path, PathAttrs, RouteSource};
use bgpgg::rpki::vrp::RpkiValidation;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Configuration for route generation
#[derive(Debug, Clone)]
pub struct RouteGenConfig {
    pub total_routes: usize,
    pub num_peers: usize,
    pub seed: u64,
    pub prefix_len_dist: PrefixLengthDistribution,
    pub overlap_config: OverlapConfig,
    pub attr_config: AttributeConfig,
}

/// Prefix length distribution percentages (must sum to 100)
#[derive(Debug, Clone)]
pub struct PrefixLengthDistribution {
    pub len_24: u8,
    pub len_22_23: u8,
    pub len_20_21: u8,
    pub len_16_19: u8,
}

impl Default for PrefixLengthDistribution {
    fn default() -> Self {
        Self {
            len_24: 60,
            len_22_23: 25,
            len_20_21: 10,
            len_16_19: 5,
        }
    }
}

/// Controls how prefixes overlap between peers
#[derive(Debug, Clone)]
pub struct OverlapConfig {
    pub single_peer_pct: u8,
    pub two_three_peer_pct: u8,
    pub heavy_peer_pct: u8,
}

impl Default for OverlapConfig {
    fn default() -> Self {
        Self {
            single_peer_pct: 25,
            two_three_peer_pct: 65,
            heavy_peer_pct: 10,
        }
    }
}

/// Attribute diversity configuration
#[derive(Debug, Clone)]
pub struct AttributeConfig {
    pub as_path_min_len: u8,
    pub as_path_max_len: u8,
    pub as_path_avg_len: u8,
    pub origin_igp_pct: u8,
    pub origin_incomplete_pct: u8,
    pub origin_egp_pct: u8,
    pub med_presence_pct: u8,
    pub communities_pct: u8,
}

impl Default for AttributeConfig {
    fn default() -> Self {
        Self {
            as_path_min_len: 1,
            as_path_max_len: 8,
            as_path_avg_len: 4,
            origin_igp_pct: 80,
            origin_incomplete_pct: 15,
            origin_egp_pct: 5,
            med_presence_pct: 20,
            communities_pct: 30,
        }
    }
}

/// Template for a route with its characteristics (before peer assignment)
#[derive(Debug, Clone)]
struct RouteTemplate {
    prefix: IpNetwork,
    as_path_length: u8,
    origin_type: Origin,
    has_med: bool,
    has_communities: bool,
}

/// A route announcement from a specific peer
#[derive(Debug, Clone)]
pub struct PeerRoute {
    pub prefix: IpNetwork,
    pub as_path: Vec<u16>,
    pub origin: Origin,
    pub med: Option<u32>,
    pub communities: Vec<u32>,
}

impl PeerRoute {
    /// Convert PeerRoute to Path for best path selection
    pub fn to_path(&self, peer_ip: IpAddr, next_hop: Ipv4Addr) -> Path {
        // Convert Vec<u16> to Vec<AsPathSegment>
        let as_path_segments = if self.as_path.is_empty() {
            vec![]
        } else {
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: self.as_path.len() as u8,
                asn_list: self.as_path.iter().map(|&asn| asn as u32).collect(),
            }]
        };

        // For load tests, derive bgp_id from peer_ip
        let bgp_id = match peer_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
        };
        Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin: self.origin,
                as_path: as_path_segments,
                next_hop: NextHopAddr::Ipv4(next_hop),
                source: RouteSource::Ebgp { peer_ip, bgp_id },
                local_pref: Some(100), // eBGP routes get LOCAL_PREF 100 in loc-rib
                med: self.med,
                atomic_aggregate: false,
                aggregator: None,
                communities: self.communities.clone(),
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
                ls_attr: None,
            }),
        }
    }
}

/// All routes for a specific peer
#[derive(Debug, Clone)]
pub struct PeerRouteSet {
    pub peer_index: usize,
    pub routes: Vec<PeerRoute>,
}

/// Generate all route sets for all peers with controlled overlap
pub fn generate_peer_routes(config: RouteGenConfig) -> Vec<PeerRouteSet> {
    let mut rng = StdRng::seed_from_u64(config.seed);

    // Step 1: Generate master prefix pool
    let prefix_pool = generate_prefix_pool(&config, &mut rng);

    // Step 2: Create templates with characteristics
    let templates = create_route_templates(prefix_pool, &config, &mut rng);

    // Step 3: Distribute prefixes to peers with overlap strategy
    let peer_assignments = distribute_with_overlap(templates, &config, &mut rng);

    // Step 4: Generate diverse attributes for each peer's version
    generate_peer_attributes(peer_assignments, &config, &mut rng)
}

/// Calculate expected best paths from all peer route sets
/// Returns a HashMap of prefix -> best Path
pub fn calculate_expected_best_paths(peer_route_sets: &[PeerRouteSet]) -> HashMap<IpNetwork, Path> {
    // Group all routes by prefix
    let mut routes_by_prefix: HashMap<IpNetwork, Vec<(usize, &PeerRoute)>> = HashMap::new();

    for peer_set in peer_route_sets {
        for route in &peer_set.routes {
            routes_by_prefix
                .entry(route.prefix)
                .or_default()
                .push((peer_set.peer_index, route));
        }
    }

    // For each prefix, find the best path using BGP decision process
    let mut best_paths = HashMap::new();
    for (prefix, peer_routes) in routes_by_prefix {
        // Convert all routes to Path objects
        let paths: Vec<Path> = peer_routes
            .iter()
            .map(|(peer_idx, route)| {
                let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1 + *peer_idx as u8));
                // Use peer's router ID as next hop (same as sender in load test)
                let next_hop = Ipv4Addr::new(2, 0, 0, 1 + *peer_idx as u8);
                route.to_path(peer_ip, next_hop)
            })
            .collect();

        // Select best path using BGP best path selection
        if let Some(best) = paths.into_iter().max_by(|a, b| a.best_path_cmp(b)) {
            best_paths.insert(prefix, best);
        }
    }

    best_paths
}

/// Generate unique prefixes with realistic length distribution
fn generate_prefix_pool(config: &RouteGenConfig, rng: &mut StdRng) -> Vec<IpNetwork> {
    let dist = &config.prefix_len_dist;
    let total = config.total_routes;

    // Calculate counts per prefix length
    let count_24 = (total * dist.len_24 as usize) / 100;
    let count_22_23 = (total * dist.len_22_23 as usize) / 100;
    let count_20_21 = (total * dist.len_20_21 as usize) / 100;
    let count_16_19 = (total * dist.len_16_19 as usize) / 100;

    let mut prefixes = Vec::with_capacity(total);

    // Generate /24 prefixes
    generate_prefixes_for_length(&mut prefixes, count_24, 24);

    // Generate /22-/23 prefixes
    let count_22 = count_22_23 / 2;
    let count_23 = count_22_23 - count_22;
    generate_prefixes_for_length(&mut prefixes, count_22, 22);
    generate_prefixes_for_length(&mut prefixes, count_23, 23);

    // Generate /20-/21 prefixes
    let count_20 = count_20_21 / 2;
    let count_21 = count_20_21 - count_20;
    generate_prefixes_for_length(&mut prefixes, count_20, 20);
    generate_prefixes_for_length(&mut prefixes, count_21, 21);

    // Generate /16-/19 prefixes
    let count_per_len = count_16_19 / 4;
    generate_prefixes_for_length(&mut prefixes, count_per_len, 16);
    generate_prefixes_for_length(&mut prefixes, count_per_len, 17);
    generate_prefixes_for_length(&mut prefixes, count_per_len, 18);
    generate_prefixes_for_length(&mut prefixes, count_16_19 - count_per_len * 3, 19);

    // Shuffle to mix prefix lengths
    prefixes.shuffle(rng);

    prefixes
}

/// Generate prefixes for a specific prefix length
fn generate_prefixes_for_length(prefixes: &mut Vec<IpNetwork>, count: usize, prefix_len: u8) {
    // Start from 10.0.0.0 base address
    let base = u32::from(Ipv4Addr::new(10, 0, 0, 0));
    let increment = 1u32 << (32 - prefix_len);

    for i in 0..count {
        // Generate sequential, properly aligned prefixes
        let addr = base.wrapping_add((i as u32).wrapping_mul(increment));

        // Ensure address is properly aligned to prefix boundary
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        let aligned_addr = addr & mask;

        prefixes.push(IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::from(aligned_addr),
            prefix_length: prefix_len,
        }));
    }
}

/// Assign characteristics to each prefix (before peer distribution)
fn create_route_templates(
    prefixes: Vec<IpNetwork>,
    config: &RouteGenConfig,
    rng: &mut StdRng,
) -> Vec<RouteTemplate> {
    let attr = &config.attr_config;

    prefixes
        .into_iter()
        .map(|prefix| {
            // Generate AS_PATH length with normal distribution around avg
            let as_path_length = generate_as_path_length(
                attr.as_path_min_len,
                attr.as_path_max_len,
                attr.as_path_avg_len,
                rng,
            );

            // Pick origin type from distribution
            let origin_type = pick_origin(
                attr.origin_igp_pct,
                attr.origin_incomplete_pct,
                attr.origin_egp_pct,
                rng,
            );

            // Decide if should have MED
            let has_med = rng.gen_range(0..100) < attr.med_presence_pct;

            // Decide if should have communities
            let has_communities = rng.gen_range(0..100) < attr.communities_pct;

            RouteTemplate {
                prefix,
                as_path_length,
                origin_type,
                has_med,
                has_communities,
            }
        })
        .collect()
}

/// Generate AS_PATH length with normal distribution
fn generate_as_path_length(min: u8, max: u8, avg: u8, rng: &mut StdRng) -> u8 {
    // Simple normal distribution approximation using sum of uniform random variables
    let mut sum = 0.0;
    for _ in 0..6 {
        sum += rng.gen::<f64>();
    }
    let normal = (sum - 3.0) / 1.5; // Mean 0, std dev ~1

    let target = avg as f64 + normal * 1.5;
    target.clamp(min as f64, max as f64) as u8
}

/// Pick origin type from distribution
fn pick_origin(igp_pct: u8, incomplete_pct: u8, _egp_pct: u8, rng: &mut StdRng) -> Origin {
    let roll = rng.gen_range(0..100);
    if roll < igp_pct {
        Origin::IGP
    } else if roll < igp_pct + incomplete_pct {
        Origin::INCOMPLETE
    } else {
        Origin::EGP
    }
}

/// Distribute prefixes to peers according to overlap strategy
fn distribute_with_overlap(
    mut templates: Vec<RouteTemplate>,
    config: &RouteGenConfig,
    rng: &mut StdRng,
) -> HashMap<usize, Vec<RouteTemplate>> {
    let overlap = &config.overlap_config;
    let num_peers = config.num_peers;

    // Shuffle templates randomly
    templates.shuffle(rng);

    // Calculate bucket sizes
    let total = templates.len();
    let single_bucket_size = (total * overlap.single_peer_pct as usize) / 100;
    let two_three_bucket_size = (total * overlap.two_three_peer_pct as usize) / 100;
    let heavy_bucket_size = total - single_bucket_size - two_three_bucket_size;

    let mut peer_templates: HashMap<usize, Vec<RouteTemplate>> = HashMap::new();
    for i in 0..num_peers {
        peer_templates.insert(i, Vec::new());
    }

    let mut idx = 0;

    // Single peer routes
    for _ in 0..single_bucket_size {
        if idx >= templates.len() {
            break;
        }
        let template = templates[idx].clone();
        let peer_idx = rng.gen_range(0..num_peers);
        peer_templates.get_mut(&peer_idx).unwrap().push(template);
        idx += 1;
    }

    // Two-three peer routes
    for _ in 0..two_three_bucket_size {
        if idx >= templates.len() {
            break;
        }
        let template = templates[idx].clone();
        let num_copies = if rng.gen_bool(0.5) { 2 } else { 3 };

        let peer_indices = pick_random_peers(num_peers, num_copies, rng);
        for peer_idx in peer_indices {
            peer_templates
                .get_mut(&peer_idx)
                .unwrap()
                .push(template.clone());
        }
        idx += 1;
    }

    // Heavy peer routes (4-7 peers)
    for _ in 0..heavy_bucket_size {
        if idx >= templates.len() {
            break;
        }
        let template = templates[idx].clone();
        let num_copies = rng.gen_range(4..=std::cmp::min(7, num_peers));

        let peer_indices = pick_random_peers(num_peers, num_copies, rng);
        for peer_idx in peer_indices {
            peer_templates
                .get_mut(&peer_idx)
                .unwrap()
                .push(template.clone());
        }
        idx += 1;
    }

    peer_templates
}

/// Pick N random unique peer indices
fn pick_random_peers(num_peers: usize, count: usize, rng: &mut StdRng) -> Vec<usize> {
    let mut peers: Vec<usize> = (0..num_peers).collect();
    peers.shuffle(rng);
    peers.into_iter().take(count).collect()
}

/// Generate actual attributes for each peer's routes
fn generate_peer_attributes(
    peer_assignments: HashMap<usize, Vec<RouteTemplate>>,
    config: &RouteGenConfig,
    rng: &mut StdRng,
) -> Vec<PeerRouteSet> {
    let mut result = Vec::new();

    for peer_idx in 0..config.num_peers {
        let templates = peer_assignments.get(&peer_idx).cloned().unwrap_or_default();

        let routes: Vec<PeerRoute> = templates
            .into_iter()
            .map(|template| {
                // Generate AS_PATH: peer's ASN + random path
                let peer_asn = 65001 + peer_idx as u16;
                let as_path = generate_as_path(peer_asn, template.as_path_length, rng);

                // Vary origin around template (80% same as template, 20% different)
                let origin = if rng.gen_bool(0.8) {
                    template.origin_type
                } else {
                    pick_origin(
                        config.attr_config.origin_igp_pct,
                        config.attr_config.origin_incomplete_pct,
                        config.attr_config.origin_egp_pct,
                        rng,
                    )
                };

                // Generate MED if template says so
                let med = if template.has_med {
                    Some(rng.gen_range(0..1000))
                } else {
                    None
                };

                // Generate communities if template says so
                let communities = if template.has_communities {
                    generate_communities(rng)
                } else {
                    vec![]
                };

                PeerRoute {
                    prefix: template.prefix,
                    as_path,
                    origin,
                    med,
                    communities,
                }
            })
            .collect();

        result.push(PeerRouteSet {
            peer_index: peer_idx,
            routes,
        });
    }

    result
}

/// Generate AS_PATH with peer ASN prepended
fn generate_as_path(peer_asn: u16, target_length: u8, rng: &mut StdRng) -> Vec<u16> {
    let mut as_path = vec![peer_asn];

    // Add additional ASNs to reach target length
    for _ in 1..target_length {
        let asn = rng.gen_range(100..65000);
        as_path.push(asn);
    }

    as_path
}

/// Generate random communities from common pool
fn generate_communities(rng: &mut StdRng) -> Vec<u32> {
    // Common community values in real networks
    let common_communities = [
        0x00640064, // 100:100
        0x006400C8, // 100:200
        0x00C80064, // 200:100
        0x01F40064, // 500:100
        0x03E80064, // 1000:100
    ];

    let count = rng.gen_range(1..=3);
    (0..count)
        .map(|_| *common_communities.choose(rng).unwrap())
        .collect()
}
