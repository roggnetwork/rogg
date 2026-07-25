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

use super::proto::{
    self,
    bgp_service_client::BgpServiceClient,
    AddBmpServerRequest,
    AddDefinedSetRequest,
    AddPeerRequest,
    AddPolicyRequest,
    AddRouteRequest,
    // RPKI
    AddRpkiCacheRequest,
    CommitConfigRequest,
    DefinedSetConfig,
    DefinedSetInfo,
    DisablePeerRequest,
    EnablePeerRequest,
    GetPeerRequest,
    GetRpkiValidationRequest,
    GetRpkiValidationResponse,
    GetRunningConfigRequest,
    GetServerInfoRequest,
    ListBmpServersRequest,
    ListConfigSnapshotsRequest,
    ListDefinedSetsRequest,
    ListPeersRequest,
    ListPoliciesRequest,
    ListRoutesRequest,
    ListRpkiCachesRequest,
    ListRpkiCachesResponse,
    Peer,
    PeerStatistics,
    PolicyInfo,
    RemoveBmpServerRequest,
    RemoveDefinedSetRequest,
    RemovePeerRequest,
    RemovePolicyRequest,
    RemoveRouteRequest,
    RemoveRpkiCacheRequest,
    ResetPeerRequest,
    RollbackConfigRequest,
    Route,
    SaveConfigRequest,
    SessionConfig,
    SetPeerGracefulShutdownRequest,
    SetPolicyAssignmentRequest,
    StatementConfig,
};
use std::net::Ipv4Addr;
use tokio_stream::StreamExt;
use tonic::transport::Channel;

/// Simplified wrapper around the gRPC client that hides boilerplate
#[derive(Clone)]
pub struct BgpClient {
    inner: BgpServiceClient<Channel>,
    /// Router ID of the BGP server this client is connected to.
    pub router_id: Ipv4Addr,
}

impl BgpClient {
    /// Connect to a BGP gRPC server
    pub async fn connect(addr: impl Into<String>) -> Result<Self, tonic::transport::Error> {
        let inner = BgpServiceClient::connect(addr.into()).await?;
        Ok(Self {
            inner,
            router_id: Ipv4Addr::UNSPECIFIED,
        })
    }

    /// Connect to a BGP gRPC server with a known router ID
    pub async fn connect_with_router_id(
        addr: impl Into<String>,
        router_id: Ipv4Addr,
    ) -> Result<Self, tonic::transport::Error> {
        let inner = BgpServiceClient::connect(addr.into()).await?;
        Ok(Self { inner, router_id })
    }

    /// List routes. Caller builds ListRoutesRequest with rib_type, peer_address, afi, safi.
    pub async fn list_routes(&self, req: ListRoutesRequest) -> Result<Vec<Route>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_routes(req)
            .await?
            .into_inner()
            .routes)
    }

    /// List routes using streaming.
    pub async fn list_routes_stream(
        &self,
        req: ListRoutesRequest,
    ) -> Result<Vec<Route>, tonic::Status> {
        let mut stream = self
            .inner
            .clone()
            .list_routes_stream(req)
            .await?
            .into_inner();

        let mut routes = Vec::new();
        while let Some(route) = stream.next().await {
            routes.push(route?);
        }
        Ok(routes)
    }

    /// Get all configured peers
    pub async fn get_peers(&self) -> Result<Vec<Peer>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_peers(ListPeersRequest {})
            .await?
            .into_inner()
            .peers)
    }

    /// Get all configured peers using streaming
    pub async fn get_peers_stream(&self) -> Result<Vec<Peer>, tonic::Status> {
        let mut stream = self
            .inner
            .clone()
            .list_peers_stream(ListPeersRequest {})
            .await?
            .into_inner();

        let mut peers = Vec::new();
        while let Some(peer) = stream.next().await {
            peers.push(peer?);
        }
        Ok(peers)
    }

    /// Get a specific peer with statistics
    pub async fn get_peer(
        &self,
        address: String,
    ) -> Result<(Option<Peer>, Option<PeerStatistics>), tonic::Status> {
        let resp = self
            .inner
            .clone()
            .get_peer(GetPeerRequest { address })
            .await?
            .into_inner();

        Ok((resp.peer, resp.statistics))
    }

    /// Add a new BGP peer. Pass None for config to use all defaults.
    pub async fn add_peer(
        &self,
        address: String,
        config: Option<SessionConfig>,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .add_peer(AddPeerRequest { address, config })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Remove a BGP peer
    pub async fn remove_peer(&self, address: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .remove_peer(RemovePeerRequest { address })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Disable a BGP peer (RFC 4486 Administrative Shutdown)
    pub async fn disable_peer(&self, address: String) -> Result<(), tonic::Status> {
        self.inner
            .clone()
            .disable_peer(DisablePeerRequest { address })
            .await?;
        Ok(())
    }

    /// Enable a BGP peer (undo Administrative Shutdown)
    pub async fn enable_peer(&self, address: String) -> Result<(), tonic::Status> {
        self.inner
            .clone()
            .enable_peer(EnablePeerRequest { address })
            .await?;
        Ok(())
    }

    /// Reset a BGP peer with flexible reset types and AFI/SAFI support
    pub async fn reset_peer(
        &self,
        address: String,
        reset_type: proto::ResetType,
        afi: Option<proto::Afi>,
        safi: Option<proto::Safi>,
    ) -> Result<(), tonic::Status> {
        self.inner
            .clone()
            .reset_peer(ResetPeerRequest {
                address,
                reset_type: reset_type as i32,
                afi: afi.map(|a| a as i32),
                safi: safi.map(|s| s as i32),
            })
            .await?;
        Ok(())
    }

    /// Add a route to the global RIB.
    pub async fn add_route(&self, req: AddRouteRequest) -> Result<String, tonic::Status> {
        let resp = self.inner.clone().add_route(req).await?.into_inner();
        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Add multiple routes using streaming API.
    pub async fn add_route_stream(
        &self,
        routes: Vec<AddRouteRequest>,
    ) -> Result<u64, tonic::Status> {
        let stream = tokio_stream::iter(routes);
        let resp = self
            .inner
            .clone()
            .add_route_stream(stream)
            .await?
            .into_inner();
        Ok(resp.count)
    }

    /// Remove a route from the global RIB.
    pub async fn remove_route(&self, req: RemoveRouteRequest) -> Result<String, tonic::Status> {
        let resp = self.inner.clone().remove_route(req).await?.into_inner();
        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Get server info including the listen address, port, and route count
    pub async fn get_server_info(&self) -> Result<(std::net::IpAddr, u16, u64), tonic::Status> {
        let resp = self
            .inner
            .clone()
            .get_server_info(GetServerInfoRequest {})
            .await?
            .into_inner();

        let addr: std::net::IpAddr = resp
            .listen_addr
            .parse()
            .map_err(|_| tonic::Status::internal("invalid listen_addr"))?;
        Ok((addr, resp.listen_port as u16, resp.num_routes))
    }

    /// Commit `text` as the new running config.
    pub async fn commit_config(
        &self,
        text: String,
        session_uuid: uuid::Uuid,
    ) -> Result<(), tonic::Status> {
        let resp = self
            .inner
            .clone()
            .commit_config(CommitConfigRequest {
                text,
                session_uuid: session_uuid.to_string(),
            })
            .await?
            .into_inner();
        if resp.ok {
            Ok(())
        } else {
            Err(tonic::Status::unknown(resp.error))
        }
    }

    /// Fetch the daemon's current running config as rogg.conf brace-format text.
    /// Used by ggsh for `show running-config` and `show diff`.
    pub async fn get_running_config(&self) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .get_running_config(GetRunningConfigRequest {})
            .await?
            .into_inner();
        Ok(resp.text)
    }

    /// List stored config snapshots. Returns one entry per existing
    /// `rogg.<n>.conf` file, sorted by index ascending.
    pub async fn list_config_snapshots(&self) -> Result<Vec<proto::ConfigSnapshot>, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .list_config_snapshots(ListConfigSnapshotsRequest {})
            .await?
            .into_inner();
        Ok(resp.snapshots)
    }

    /// Persist the daemon's current `self.config` to `rogg.conf`.
    pub async fn save_config(&self, session_uuid: uuid::Uuid) -> Result<(), tonic::Status> {
        let resp = self
            .inner
            .clone()
            .save_config(SaveConfigRequest {
                session_uuid: session_uuid.to_string(),
            })
            .await?
            .into_inner();
        if resp.ok {
            Ok(())
        } else {
            Err(tonic::Status::unknown(resp.error))
        }
    }

    /// Roll back to the config at `index` (1-based). Loads the snapshot file,
    /// parses it, and commits it — the rollback itself becomes a new commit.
    pub async fn rollback_config(
        &self,
        index: u32,
        session_uuid: uuid::Uuid,
    ) -> Result<(), tonic::Status> {
        let resp = self
            .inner
            .clone()
            .rollback_config(RollbackConfigRequest {
                index,
                session_uuid: session_uuid.to_string(),
            })
            .await?
            .into_inner();
        if resp.ok {
            Ok(())
        } else {
            Err(tonic::Status::unknown(resp.error))
        }
    }

    /// Add a BMP server destination
    pub async fn add_bmp_server(
        &self,
        address: String,
        statistics_timeout: Option<u64>,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .add_bmp_server(AddBmpServerRequest {
                address,
                statistics_timeout,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Remove a BMP server destination
    pub async fn remove_bmp_server(&self, address: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .remove_bmp_server(RemoveBmpServerRequest { address })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Get all BMP server destinations
    pub async fn get_bmp_servers(&self) -> Result<Vec<String>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_bmp_servers(ListBmpServersRequest {})
            .await?
            .into_inner()
            .addresses)
    }

    /// Add a policy definition
    pub async fn add_policy(
        &self,
        name: String,
        statements: Vec<StatementConfig>,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .add_policy(AddPolicyRequest { name, statements })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// List all policy definitions
    pub async fn list_policies(&self) -> Result<Vec<PolicyInfo>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_policies(ListPoliciesRequest { name: None })
            .await?
            .into_inner()
            .policies)
    }

    /// Add a defined set
    pub async fn add_defined_set(
        &self,
        set: DefinedSetConfig,
        replace: bool,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .add_defined_set(AddDefinedSetRequest {
                set: Some(set),
                replace,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// List all defined sets
    pub async fn list_defined_sets(&self) -> Result<Vec<DefinedSetInfo>, tonic::Status> {
        Ok(self
            .inner
            .clone()
            .list_defined_sets(ListDefinedSetsRequest {
                set_type: None,
                name: None,
            })
            .await?
            .into_inner()
            .sets)
    }

    /// Remove a defined set
    pub async fn remove_defined_set(
        &self,
        set_type: String,
        name: String,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .remove_defined_set(RemoveDefinedSetRequest {
                set_type,
                name,
                all: false,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Remove a policy
    pub async fn remove_policy(&self, name: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .remove_policy(RemovePolicyRequest { name })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Set policy assignment for a peer's (afi, safi). Replaces all
    /// currently-attached policies for that direction with `policy_names`.
    pub async fn set_policy_assignment(
        &self,
        peer_address: String,
        afi: u32,
        safi: u32,
        direction: String,
        policy_names: Vec<String>,
        default_action: Option<String>,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .set_policy_assignment(SetPolicyAssignmentRequest {
                peer_address,
                afi,
                safi,
                direction,
                policy_names,
                default_action,
            })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Add an RPKI cache server
    pub async fn add_rpki_cache(
        &self,
        request: AddRpkiCacheRequest,
    ) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .add_rpki_cache(request)
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// Remove an RPKI cache server
    pub async fn remove_rpki_cache(&self, address: String) -> Result<String, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .remove_rpki_cache(RemoveRpkiCacheRequest { address })
            .await?
            .into_inner();

        if resp.success {
            Ok(resp.message)
        } else {
            Err(tonic::Status::unknown(resp.message))
        }
    }

    /// List all configured RPKI caches
    pub async fn list_rpki_caches(&self) -> Result<ListRpkiCachesResponse, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .list_rpki_caches(ListRpkiCachesRequest {})
            .await?
            .into_inner();
        Ok(resp)
    }

    /// Query RPKI validation state for a prefix + origin AS
    pub async fn get_rpki_validation(
        &self,
        prefix: String,
        origin_as: u32,
    ) -> Result<GetRpkiValidationResponse, tonic::Status> {
        let resp = self
            .inner
            .clone()
            .get_rpki_validation(GetRpkiValidationRequest { prefix, origin_as })
            .await?
            .into_inner();
        Ok(resp)
    }

    /// RFC 8326: enable or disable graceful shutdown tagging for a peer
    pub async fn set_peer_graceful_shutdown(
        &self,
        address: String,
        enabled: bool,
    ) -> Result<(), tonic::Status> {
        self.inner
            .clone()
            .set_peer_graceful_shutdown(SetPeerGracefulShutdownRequest { address, enabled })
            .await?;
        Ok(())
    }
}
