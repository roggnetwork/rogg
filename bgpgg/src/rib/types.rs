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

use crate::bgp::bgpls_nlri::LsNlri;
use crate::bgp::msg_update_types::Nlri;
use crate::bgp::multiprotocol::{Afi, AfiSafi};
use crate::net::IpNetwork;
use crate::peer::SessionType;
use crate::rib::path::Path;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Identifies a route across all address families.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RouteKey {
    Prefix(IpNetwork),
    LinkState(Box<LsNlri>),
}

impl RouteKey {
    pub fn afi_safi(&self) -> AfiSafi {
        match self {
            RouteKey::Prefix(prefix) => prefix.afi_safi(),
            RouteKey::LinkState(nlri) => AfiSafi::new(Afi::LinkState, nlri.safi()),
        }
    }
}

/// (route_key, remote_path_id) -- None means remove all paths from peer (non-ADD-PATH)
pub type Withdrawal = (RouteKey, Option<u32>);

/// Split withdrawals into IP (as Nlri), LS (SAFI 71), and LS-VPN (SAFI 72)
/// for separate UPDATE encoding.
pub fn split_withdrawals(withdrawn: &[Withdrawal]) -> (Vec<Nlri>, Vec<LsNlri>, Vec<LsNlri>) {
    let mut ip_withdrawn = Vec::new();
    let mut ls_withdrawn = Vec::new();
    let mut ls_vpn_withdrawn = Vec::new();
    for (key, path_id) in withdrawn {
        match key {
            RouteKey::Prefix(prefix) => {
                ip_withdrawn.push(Nlri {
                    prefix: *prefix,
                    path_id: *path_id,
                });
            }
            RouteKey::LinkState(nlri) => {
                if nlri.is_vpn() {
                    ls_vpn_withdrawn.push((**nlri).clone());
                } else {
                    ls_withdrawn.push((**nlri).clone());
                }
            }
        }
    }
    (ip_withdrawn, ls_withdrawn, ls_vpn_withdrawn)
}

/// A single route with a single path, used for propagation and wire encoding.
/// Carries any address family via RouteKey (IP prefix, BGP-LS NLRI, etc.).
#[derive(Debug, Clone)]
pub struct RoutePath {
    pub key: RouteKey,
    pub path: Arc<Path>,
}

impl RoutePath {
    /// Create a new RoutePath, wrapping the path in an Arc
    pub fn new(key: RouteKey, path: Path) -> Self {
        Self {
            key,
            path: Arc::new(path),
        }
    }
}

/// Source of a route
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum RouteSource {
    /// Route learned from an EBGP peer (external AS)
    /// Contains peer IP and peer's BGP Router ID
    Ebgp { peer_ip: IpAddr, bgp_id: Ipv4Addr },
    /// Route learned from an IBGP peer (same AS)
    /// Contains peer IP, peer's BGP Router ID, and whether peer is an RR client
    Ibgp {
        peer_ip: IpAddr,
        bgp_id: Ipv4Addr,
        rr_client: bool,
    },
    /// Route originated locally by this router
    Local,
}

impl RouteSource {
    /// Create a RouteSource based on BGP session type
    /// rr_client: For iBGP sessions, whether the peer is configured as an RR client
    pub fn from_session(
        session_type: SessionType,
        peer_ip: IpAddr,
        bgp_id: Ipv4Addr,
        rr_client: bool,
    ) -> Self {
        match session_type {
            SessionType::Ebgp => RouteSource::Ebgp { peer_ip, bgp_id },
            SessionType::Ibgp => RouteSource::Ibgp {
                peer_ip,
                bgp_id,
                rr_client,
            },
        }
    }

    /// Check if route was learned from an RR client (only meaningful for iBGP routes)
    pub fn is_rr_client(&self) -> bool {
        matches!(
            self,
            RouteSource::Ibgp {
                rr_client: true,
                ..
            }
        )
    }

    /// Check if this route was learned via iBGP
    pub fn is_ibgp(&self) -> bool {
        matches!(self, RouteSource::Ibgp { .. })
    }

    /// Check if this route was learned via eBGP
    pub fn is_ebgp(&self) -> bool {
        matches!(self, RouteSource::Ebgp { .. })
    }

    /// Check if this route was originated locally
    pub fn is_local(&self) -> bool {
        matches!(self, RouteSource::Local)
    }

    /// Get the peer's BGP Router ID (for ORIGINATOR_ID)
    pub fn bgp_id(&self) -> Option<Ipv4Addr> {
        match self {
            RouteSource::Ebgp { bgp_id, .. } | RouteSource::Ibgp { bgp_id, .. } => Some(*bgp_id),
            RouteSource::Local => None,
        }
    }

    /// Get the peer IP address
    pub fn peer_ip(&self) -> Option<IpAddr> {
        match self {
            RouteSource::Ebgp { peer_ip, .. } | RouteSource::Ibgp { peer_ip, .. } => Some(*peer_ip),
            RouteSource::Local => None,
        }
    }
}

/// Represents a route with one or more paths
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Route {
    pub key: RouteKey,
    pub paths: Vec<Arc<Path>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_source_from_session() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let bgp_id1 = Ipv4Addr::new(1, 1, 1, 1);
        let bgp_id2 = Ipv4Addr::new(2, 2, 2, 2);
        assert_eq!(
            RouteSource::from_session(SessionType::Ebgp, ip1, bgp_id1, false),
            RouteSource::Ebgp {
                peer_ip: ip1,
                bgp_id: bgp_id1
            }
        );
        assert_eq!(
            RouteSource::from_session(SessionType::Ibgp, ip2, bgp_id2, true),
            RouteSource::Ibgp {
                peer_ip: ip2,
                bgp_id: bgp_id2,
                rr_client: true
            }
        );
        assert_eq!(
            RouteSource::from_session(SessionType::Ibgp, ip2, bgp_id2, false),
            RouteSource::Ibgp {
                peer_ip: ip2,
                bgp_id: bgp_id2,
                rr_client: false
            }
        );
    }

    #[test]
    fn test_is_ibgp() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        assert!(RouteSource::Ibgp {
            peer_ip: ip1,
            bgp_id,
            rr_client: false
        }
        .is_ibgp());
        assert!(!RouteSource::Ebgp {
            peer_ip: ip2,
            bgp_id
        }
        .is_ibgp());
        assert!(!RouteSource::Local.is_ibgp());
    }

    #[test]
    fn test_is_ebgp() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        assert!(RouteSource::Ebgp {
            peer_ip: ip1,
            bgp_id
        }
        .is_ebgp());
        assert!(!RouteSource::Ibgp {
            peer_ip: ip2,
            bgp_id,
            rr_client: false
        }
        .is_ebgp());
        assert!(!RouteSource::Local.is_ebgp());
    }

    #[test]
    fn test_is_local() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        assert!(RouteSource::Local.is_local());
        assert!(!RouteSource::Ebgp {
            peer_ip: ip1,
            bgp_id
        }
        .is_local());
        assert!(!RouteSource::Ibgp {
            peer_ip: ip2,
            bgp_id,
            rr_client: false
        }
        .is_local());
    }

    #[test]
    fn test_bgp_id() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        assert_eq!(RouteSource::Ebgp { peer_ip, bgp_id }.bgp_id(), Some(bgp_id));
        assert_eq!(
            RouteSource::Ibgp {
                peer_ip,
                bgp_id,
                rr_client: false
            }
            .bgp_id(),
            Some(bgp_id)
        );
        assert_eq!(RouteSource::Local.bgp_id(), None);
    }

    #[test]
    fn test_peer_ip() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        assert_eq!(
            RouteSource::Ebgp { peer_ip, bgp_id }.peer_ip(),
            Some(peer_ip)
        );
        assert_eq!(
            RouteSource::Ibgp {
                peer_ip,
                bgp_id,
                rr_client: false
            }
            .peer_ip(),
            Some(peer_ip)
        );
        assert_eq!(RouteSource::Local.peer_ip(), None);
    }

    #[test]
    fn test_is_rr_client() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        assert!(RouteSource::Ibgp {
            peer_ip,
            bgp_id,
            rr_client: true
        }
        .is_rr_client());
        assert!(!RouteSource::Ibgp {
            peer_ip,
            bgp_id,
            rr_client: false
        }
        .is_rr_client());
        assert!(!RouteSource::Ebgp { peer_ip, bgp_id }.is_rr_client());
        assert!(!RouteSource::Local.is_rr_client());
    }
}
