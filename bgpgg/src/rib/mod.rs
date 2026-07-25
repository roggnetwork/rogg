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

//! Routing Information Base (RIB) module
//!
//! This module implements BGP's RIB components:
//! - Adj-RIB-In: Per-peer input tables storing routes received from peers (owned by Peer)
//! - Loc-RIB: Local routing table containing best paths (owned by BgpServer)
//! - Adj-RIB-Out: Per-peer output tables tracking routes exported to peers

mod path;
pub mod path_id;
pub mod rib_in;
pub mod rib_loc;
pub mod rib_out;
mod stale;
mod types;

// Re-exports
pub use path::{Path, PathAttrs};
pub use rib_loc::RouteDelta;
pub use rib_out::AdjRibOut;
pub use types::{split_withdrawals, Route, RouteKey, RoutePath, RouteSource, Withdrawal};
