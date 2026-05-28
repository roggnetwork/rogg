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

pub mod bgpls;
pub mod bgpls_attr;
pub mod bgpls_nlri;
pub mod community;
pub mod ext_community;
pub mod large_community;
pub mod msg;
pub mod msg_keepalive;
pub mod msg_notification;
pub mod msg_open;
pub mod msg_open_types;
pub mod msg_route_refresh;
pub mod msg_update;
mod msg_update_codec;
pub mod msg_update_types;
pub mod multiprotocol;
pub mod utils;

// Re-export AS4_PATH merge function for use by rib module
pub use msg_update_codec::merge_as_paths;

#[cfg(test)]
use crate::net::{IpNetwork, Ipv4Net};
#[cfg(test)]
use msg_update_types::{AttrType, Nlri, PathAttrFlag};
#[cfg(test)]
use std::net::Ipv4Addr;

#[cfg(test)]
pub(crate) fn nlri_v4(a: u8, b: u8, c: u8, d: u8, len: u8, path_id: Option<u32>) -> Nlri {
    Nlri {
        prefix: IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(a, b, c, d),
            prefix_length: len,
        }),
        path_id,
    }
}

#[cfg(test)]
pub(crate) const DEFAULT_FORMAT: msg::MessageFormat = msg::MessageFormat {
    use_4byte_asn: true,
    add_path: msg::AddPathMask::NONE,
    is_ebgp: false,
    enhanced_rr: false,
};

#[cfg(test)]
pub(crate) const ADDPATH_FORMAT: msg::MessageFormat = msg::MessageFormat {
    use_4byte_asn: true,
    add_path: msg::AddPathMask::ALL,
    is_ebgp: false,
    enhanced_rr: false,
};

#[cfg(test)]
pub(crate) const PATH_ATTR_COMMUNITIES_TWO: &[u8] = &[
    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
    AttrType::Communities as u8,
    0x08, // Length: 8 bytes (2 communities)
    0x00,
    0x01,
    0x00,
    0x64, // Community 1: 1:100
    0xFF,
    0xFF,
    0xFF,
    0x01, // Community 2: NO_EXPORT
];

#[cfg(test)]
pub(crate) const PATH_ATTR_EXTENDED_COMMUNITIES_TWO: &[u8] = &[
    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
    AttrType::ExtendedCommunities as u8,
    0x10, // Length: 16 bytes (2 extended communities)
    0x00,
    0x02,
    0xFD,
    0xE8,
    0x00,
    0x00,
    0x00,
    0x64, // rt:65000:100
    0x01,
    0x02,
    0xC0,
    0xA8,
    0x01,
    0x01,
    0x00,
    0x64, // rt:192.168.1.1:100
];
