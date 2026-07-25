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

//! BGP-side commit orchestration. `commit_config` validates, runs each
//! per-subsystem reconfigure, and persists via `conf::fs::persist_config`.
//! Disk primitives (lock, snapshot rotation, atomic write, multi-service
//! merge) live in `conf::fs`.

use super::{parse_prefix_and_nexthop, BgpServer};
use crate::log::error;
use conf::bgp::BgpConfig;
use conf::fs::persist_service_config;
use conf::language::Service;
use std::net::SocketAddr;

/// Validate, apply, persist. On apply failure, returns `Err` without
/// reverting — operator uses `RollbackConfig` to recover.
pub(crate) async fn commit_config(
    server: &mut BgpServer,
    new_config: BgpConfig,
    bind_addr: SocketAddr,
) -> Result<(), String> {
    for peer in &new_config.peers {
        peer.validate()?;
    }
    for entry in &new_config.originate {
        parse_prefix_and_nexthop(&entry.prefix, &entry.nexthop)?;
    }
    reject_unsupported_changes(&server.config, &new_config)?;

    let old_config = server.config.clone();
    reconfigure_all(server, &old_config, &new_config, bind_addr).await?;

    let service = Service::Bgp(new_config.to_bgp_service_body());
    if let Err(e) = persist_service_config(&server.config_path, service) {
        error!(error = %e, "failed to persist rogg.conf after in-memory commit");
        return Err(format!("applied but failed to persist: {}", e));
    }

    server.config = new_config;
    Ok(())
}

/// Persist `server.config` to `server.config_path`. Used by the
/// gRPC-imperative path which mutates `self.config` in place and asks the
/// operator (or `auto-save`) to flush on demand.
pub(crate) fn save_config(server: &BgpServer) -> Result<(), String> {
    let service = Service::Bgp(server.config.to_bgp_service_body());
    persist_service_config(&server.config_path, service)
        .map_err(|e| format!("failed to persist rogg.conf: {}", e))
}

/// Apply the new config to runtime, one subsystem at a time. First failure
/// aborts the rest and bubbles up; runtime is left in whatever partial state
/// the failure produced.
async fn reconfigure_all(
    server: &mut BgpServer,
    old: &BgpConfig,
    new: &BgpConfig,
    bind_addr: SocketAddr,
) -> Result<(), String> {
    server.reconfigure_peers(new, bind_addr).await;
    server.reconfigure_originate_routes(old, new).await;
    server.reconfigure_bmp_servers(old, new).await?;
    server.reconfigure_rpki_caches(old, new).await?;
    Ok(())
}

/// Reject changes to fields that require a daemon restart: identity (asn,
/// router-id) and the bound listener addresses.
fn reject_unsupported_changes(old: &BgpConfig, new: &BgpConfig) -> Result<(), String> {
    if old.asn != new.asn {
        return Err("changing 'asn' requires daemon restart".into());
    }
    if old.router_id != new.router_id {
        return Err("changing 'router-id' requires daemon restart".into());
    }
    if old.listen_addr != new.listen_addr {
        return Err("changing 'listen-addr' requires daemon restart".into());
    }
    if old.grpc_listen_addr != new.grpc_listen_addr {
        return Err("changing 'grpc-listen-addr' requires daemon restart".into());
    }
    Ok(())
}
