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

use crate::bgp::msg_update::UpdateMessage;
use crate::log::{info, warn};
use crate::rib::{Path, RouteKey, RoutePath, RouteSource};
use std::sync::Arc;

use super::{Peer, RouteChanges, SessionType, Withdrawal};

impl Peer {
    /// Parse a BGP UPDATE message into structured route changes.
    /// Pure wire-protocol deserialization — no routing validation.
    /// Validation (AS loop, nexthop, etc.) happens on the server.
    pub(super) fn handle_update(&mut self, mut update_msg: UpdateMessage) -> RouteChanges {
        // RFC 6793 Section 4.1: NEW speakers MUST NOT send AS4_PATH/AS4_AGGREGATOR.
        // Strip these from NEW speakers before building Path (wire cleanup).
        let peer_supports_4byte_asn = self.capabilities.four_octet_asn.is_some();
        if peer_supports_4byte_asn {
            let has_as4_path = update_msg.as4_path().is_some();
            let has_as4_aggregator = update_msg.as4_aggregator().is_some();
            if has_as4_path || has_as4_aggregator {
                warn!(peer_ip = %self.addr, has_as4_path, has_as4_aggregator,
                      "received AS4_PATH/AS4_AGGREGATOR from NEW speaker, discarding per RFC 6793");
                update_msg.strip_as4_attributes();
            }
        }

        let withdrawn = self.process_withdrawals(&update_msg);
        let announced = self.process_announcements(&update_msg);
        (announced, withdrawn)
    }

    /// Extract withdrawn routes from an UPDATE message (IP + BGP-LS).
    fn process_withdrawals(&self, update_msg: &UpdateMessage) -> Vec<Withdrawal> {
        let mut withdrawn = Vec::new();
        for entry in update_msg.withdrawn_routes() {
            info!(prefix = ?entry.prefix, peer_ip = %self.addr, "withdrawing route");
            withdrawn.push((RouteKey::Prefix(entry.prefix), entry.path_id));
        }
        for ls_nlri in update_msg.ls_withdrawn_list() {
            info!(nlri_type = ls_nlri.nlri_type, peer_ip = %self.addr, "withdrawing LS route");
            withdrawn.push((RouteKey::LinkState(Box::new(ls_nlri)), None));
        }
        withdrawn
    }

    /// Build Path objects from UPDATE attributes and extract NLRI.
    /// Pure deserialization — no validation or filtering.
    fn process_announcements(&self, update_msg: &UpdateMessage) -> Vec<RoutePath> {
        let Some(peer_bgp_id) = self.bgp_id else {
            return vec![];
        };

        let session_type = self.session_type.unwrap_or(SessionType::Ebgp);
        let source =
            RouteSource::from_session(session_type, self.addr, peer_bgp_id, self.config.rr_client);

        let peer_supports_4byte_asn = self.capabilities.four_octet_asn.is_some();
        let nlri_list = update_msg.nlri_list();

        let Some(path) = Path::from_update_msg(update_msg, source, peer_supports_4byte_asn) else {
            if !nlri_list.is_empty() {
                warn!(peer_ip = %self.addr, "UPDATE has NLRI but missing required attributes, skipping announcements");
            }
            return vec![];
        };

        let mut announced = Vec::new();
        for entry in &nlri_list {
            let mut path_clone = path.clone();
            path_clone.remote_path_id = entry.path_id;
            let path_arc = Arc::new(path_clone);
            info!(prefix = ?entry.prefix, peer_ip = %self.addr, med = ?path_arc.med(), "announcing route");
            announced.push(RoutePath {
                key: RouteKey::Prefix(entry.prefix),
                path: path_arc,
            });
        }

        // BGP-LS NLRIs share the same Path (same attributes in the UPDATE).
        // All NLRIs in a single UPDATE share the same path attributes (RFC 4271 Section 4.3).
        for ls_nlri in update_msg.ls_nlri_list() {
            let path_arc = Arc::new(path.clone());
            info!(nlri_type = ls_nlri.nlri_type, peer_ip = %self.addr, "announcing LS route");
            announced.push(RoutePath {
                key: RouteKey::LinkState(Box::new(ls_nlri)),
                path: path_arc,
            });
        }

        announced
    }
}
