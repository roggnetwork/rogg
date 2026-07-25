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

use crate::bgp::msg_update::{
    AsPathSegment, AsPathSegmentType, NextHopAddr, Origin, PathAttrValue,
};
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use crate::peer::BgpState;
use crate::rib::{PathAttrs, Route, RouteKey, RouteSource};
use crate::rpki::vrp::RpkiValidation;
use crate::server::ops_mgmt::MgmtOp;
use crate::server::{parse_prefix_and_nexthop, AdminState};
use conf::bgp::{
    AddPathSend, AfiSafiConfig, LlgrConfig, MaxPrefixAction, MaxPrefixSetting, PeerConfig,
    RpkiCacheConfig, TransportType,
};
use std::net::IpAddr;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use super::proto::{
    self,
    bgp_service_server::BgpService,
    AddBmpServerRequest,
    AddBmpServerResponse,
    AddDefinedSetRequest,
    AddDefinedSetResponse,
    AddPeerRequest,
    AddPeerResponse,
    AddPolicyRequest,
    AddPolicyResponse,
    AddRouteRequest,
    AddRouteResponse,
    AddRouteStreamResponse,
    // RPKI
    AddRpkiCacheRequest,
    AddRpkiCacheResponse,
    AdminState as ProtoAdminState,
    BgpState as ProtoBgpState,
    CommitConfigRequest,
    CommitConfigResponse,
    ConfigSnapshot as ProtoConfigSnapshot,
    DisablePeerRequest,
    DisablePeerResponse,
    EnablePeerRequest,
    EnablePeerResponse,
    GetPeerRequest,
    GetPeerResponse,
    GetRpkiValidationRequest,
    GetRpkiValidationResponse,
    GetRunningConfigRequest,
    GetRunningConfigResponse,
    GetServerInfoRequest,
    GetServerInfoResponse,
    ListBmpServersRequest,
    ListBmpServersResponse,
    ListConfigSnapshotsRequest,
    ListConfigSnapshotsResponse,
    ListDefinedSetsRequest,
    ListDefinedSetsResponse,
    ListPeersRequest,
    ListPeersResponse,
    ListPoliciesRequest,
    ListPoliciesResponse,
    ListRoutesRequest,
    ListRoutesResponse,
    ListRpkiCachesRequest,
    ListRpkiCachesResponse,
    Path as ProtoPath,
    Peer as ProtoPeer,
    PeerStatistics as ProtoPeerStatistics,
    RemoveBmpServerRequest,
    RemoveBmpServerResponse,
    RemoveDefinedSetRequest,
    RemoveDefinedSetResponse,
    RemovePeerRequest,
    RemovePeerResponse,
    RemovePolicyRequest,
    RemovePolicyResponse,
    RemoveRouteRequest,
    RemoveRouteResponse,
    RemoveRpkiCacheRequest,
    RemoveRpkiCacheResponse,
    ResetPeerRequest,
    ResetPeerResponse,
    RollbackConfigRequest,
    RollbackConfigResponse,
    Route as ProtoRoute,
    RpkiCacheInfo,
    RpkiVrp,
    SaveConfigRequest,
    SaveConfigResponse,
    SessionConfig as ProtoSessionConfig,
    SetPeerGracefulShutdownRequest,
    SetPeerGracefulShutdownResponse,
    SetPolicyAssignmentRequest,
    SetPolicyAssignmentResponse,
};

// Proto conversion functions from sibling modules
use super::proto_community::{
    internal_to_proto_large_community, proto_extcomm_to_u64, proto_large_community_to_internal,
    u64_to_proto_extcomm,
};
use super::proto_ls;
use super::proto_policy::{
    defined_set_config_to_proto, policy_info_to_proto, proto_to_defined_set_config,
    proto_to_statement_config,
};

const LOCAL_ROUTE_SOURCE_STR: &str = "127.0.0.1";

type PeerStream =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<ProtoPeer, Status>> + Send>>;
type RouteStream =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<ProtoRoute, Status>> + Send>>;

/// Convert internal route to proto Route
fn route_to_proto(route: Route) -> ProtoRoute {
    let key = match &route.key {
        RouteKey::Prefix(IpNetwork::V4(v4)) => Some(proto::route::Key::Prefix(format!(
            "{}/{}",
            v4.address, v4.prefix_length
        ))),
        RouteKey::Prefix(IpNetwork::V6(v6)) => Some(proto::route::Key::Prefix(format!(
            "{}/{}",
            v6.address, v6.prefix_length
        ))),
        RouteKey::LinkState(nlri) => Some(proto::route::Key::LsNlri(Box::new(
            proto_ls::ls_nlri_to_proto(nlri),
        ))),
    };

    let proto_paths: Vec<ProtoPath> = route
        .paths
        .into_iter()
        .map(|path| ProtoPath {
            origin: match path.origin() {
                Origin::IGP => 0,
                Origin::EGP => 1,
                Origin::INCOMPLETE => 2,
            },
            as_path: path
                .as_path()
                .iter()
                .filter_map(|segment| {
                    // Filter out confederation segments per RFC 5065 (not exposed externally)
                    match segment.segment_type {
                        AsPathSegmentType::AsSet => Some(proto::AsPathSegment {
                            segment_type: proto::AsPathSegmentType::AsSet as i32,
                            asns: segment.asn_list.clone(),
                        }),
                        AsPathSegmentType::AsSequence => Some(proto::AsPathSegment {
                            segment_type: proto::AsPathSegmentType::AsSequence as i32,
                            asns: segment.asn_list.clone(),
                        }),
                        AsPathSegmentType::AsConfedSequence | AsPathSegmentType::AsConfedSet => {
                            None
                        }
                    }
                })
                .collect(),
            next_hop: path.next_hop().global_addr().to_string(),
            link_local_next_hop: path.next_hop().link_local().map(|addr| addr.to_string()),
            peer_address: path
                .source()
                .peer_ip()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| LOCAL_ROUTE_SOURCE_STR.to_string()),
            local_pref: path.local_pref(),
            med: path.med(),
            atomic_aggregate: path.atomic_aggregate(),
            unknown_attributes: path
                .unknown_attrs()
                .iter()
                .filter_map(|attr| {
                    if let PathAttrValue::Unknown {
                        type_code,
                        flags,
                        data,
                    } = &attr.value
                    {
                        Some(proto::UnknownAttribute {
                            attr_type: *type_code as u32,
                            flags: *flags as u32,
                            value: data.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect(),
            communities: path.communities().clone(),
            extended_communities: path
                .extended_communities()
                .iter()
                .map(|&ec| u64_to_proto_extcomm(ec))
                .collect(),
            large_communities: path
                .large_communities()
                .iter()
                .map(internal_to_proto_large_community)
                .collect(),
            originator_id: path.originator_id().map(|id| id.to_string()),
            cluster_list: path
                .cluster_list()
                .iter()
                .map(|id| id.to_string())
                .collect(),
            local_path_id: path.local_path_id,
            remote_path_id: path.remote_path_id,
            aggregator: path.aggregator().map(|agg| proto::Aggregator {
                asn: agg.asn,
                ip_address: agg.ip_addr.to_string(),
            }),
            rpki_validation: match path.rpki_state {
                RpkiValidation::NotFound => proto::RpkiValidation::RpkiNotFound,
                RpkiValidation::Valid => proto::RpkiValidation::RpkiValid,
                RpkiValidation::Invalid => proto::RpkiValidation::RpkiInvalid,
            }
            .into(),
            ls_attribute: path.attrs.ls_attr.as_ref().map(proto_ls::ls_attr_to_proto),
        })
        .collect();

    ProtoRoute {
        paths: proto_paths,
        key,
    }
}

/// Parse an AddIpRouteRequest into internal types
fn parse_add_ip_route(
    req: &proto::AddIpRouteRequest,
) -> Result<(IpNetwork, NextHopAddr, Origin, Vec<AsPathSegment>), String> {
    let (prefix, next_hop) = parse_prefix_and_nexthop(&req.prefix, &req.next_hop)?;

    let origin = match req.origin {
        0 => Origin::IGP,
        1 => Origin::EGP,
        2 => Origin::INCOMPLETE,
        _ => return Err("Invalid origin value".to_string()),
    };

    let as_path: Vec<AsPathSegment> = req
        .as_path
        .iter()
        .map(|seg| AsPathSegment {
            segment_type: match seg.segment_type {
                0 => AsPathSegmentType::AsSet,
                1 => AsPathSegmentType::AsSequence,
                _ => AsPathSegmentType::AsSequence,
            },
            segment_len: seg.asns.len() as u8,
            asn_list: seg.asns.to_vec(),
        })
        .collect();

    Ok((prefix, next_hop, origin, as_path))
}

/// Convert internal BgpState to proto BgpState
fn to_proto_state(state: BgpState) -> i32 {
    match state {
        BgpState::Idle => ProtoBgpState::Idle as i32,
        BgpState::Connect => ProtoBgpState::Connect as i32,
        BgpState::Active => ProtoBgpState::Active as i32,
        BgpState::OpenSent => ProtoBgpState::OpenSent as i32,
        BgpState::OpenConfirm => ProtoBgpState::OpenConfirm as i32,
        BgpState::Established => ProtoBgpState::Established as i32,
    }
}

/// Convert internal AdminState to proto AdminState
fn to_proto_admin_state(state: AdminState) -> i32 {
    match state {
        AdminState::Up => ProtoAdminState::Up as i32,
        AdminState::Down => ProtoAdminState::Down as i32,
        AdminState::PrefixLimitReached => ProtoAdminState::PrefixLimitExceeded as i32,
    }
}

/// Convert proto SessionConfig to internal PeerConfig
fn proto_to_peer_config(proto: Option<ProtoSessionConfig>) -> Result<PeerConfig, String> {
    let defaults = PeerConfig::default();
    let Some(cfg) = proto else {
        return Ok(defaults);
    };

    let max_prefix = cfg.max_prefix.map(|p| MaxPrefixSetting {
        limit: p.limit,
        action: match p.action {
            1 => MaxPrefixAction::Discard,
            _ => MaxPrefixAction::Terminate,
        },
    });

    let graceful_restart = if let Some(gr) = cfg.graceful_restart {
        conf::bgp::GracefulRestartConfig {
            enabled: gr.enabled.unwrap_or(defaults.graceful_restart.enabled),
            restart_time: gr
                .restart_time_secs
                .unwrap_or(defaults.graceful_restart.restart_time as u32)
                as u16,
        }
    } else {
        defaults.graceful_restart
    };

    Ok(PeerConfig {
        address: String::new(),
        port: cfg.port.map(|p| p as u16).unwrap_or(defaults.port),
        idle_hold_time_secs: cfg.idle_hold_time_secs.or(defaults.idle_hold_time_secs),
        damp_peer_oscillations: cfg
            .damp_peer_oscillations
            .unwrap_or(defaults.damp_peer_oscillations),
        allow_automatic_stop: cfg
            .allow_automatic_stop
            .unwrap_or(defaults.allow_automatic_stop),
        passive_mode: cfg.passive_mode.unwrap_or(defaults.passive_mode),
        delay_open_time_secs: cfg.delay_open_time_secs,
        max_prefix,
        send_notification_without_open: cfg
            .send_notification_without_open
            .unwrap_or(defaults.send_notification_without_open),
        min_route_advertisement_interval_secs: cfg.min_route_advertisement_interval_secs,
        graceful_restart,
        rr_client: cfg.rr_client.unwrap_or(defaults.rr_client),
        rs_client: cfg.rs_client.unwrap_or(defaults.rs_client),
        enforce_first_as: cfg.enforce_first_as.unwrap_or(defaults.enforce_first_as),
        add_path_send: match cfg.add_path_send {
            Some(v) if v == proto::AddPathSendMode::AddPathSendAll as i32 => AddPathSend::All,
            Some(_) => AddPathSend::Disabled,
            None => defaults.add_path_send,
        },
        add_path_receive: cfg.add_path_receive.unwrap_or(defaults.add_path_receive),
        asn: cfg.asn,
        md5_key_file: cfg.md5_key_file.or(defaults.md5_key_file),
        next_hop_self: cfg.next_hop_self.unwrap_or(defaults.next_hop_self),
        graceful_shutdown: cfg.graceful_shutdown.unwrap_or(defaults.graceful_shutdown),
        ttl_min: cfg.ttl_min.map(|v| v as u8).or(defaults.ttl_min),
        llgr: proto_to_llgr_config(cfg.llgr)?,
        send_rpki_community: cfg
            .send_rpki_community
            .unwrap_or(defaults.send_rpki_community),
        afi_safis: proto_to_afi_safis(&cfg.afi_safis)?,
        interface: cfg.interface.or(defaults.interface.clone()),
        admin_down: defaults.admin_down,
    })
}

fn proto_to_llgr_config(proto: Option<proto::LlgrConfig>) -> Result<Option<LlgrConfig>, String> {
    let Some(llgr) = proto else {
        return Ok(None);
    };

    let afi_safis = if llgr.afi_safis.is_empty() {
        None
    } else {
        let mut parsed = Vec::new();
        for entry in &llgr.afi_safis {
            let afi = Afi::try_from(entry.afi as u16)
                .map_err(|_| format!("LLGR: unknown AFI {}", entry.afi))?;
            let safi = Safi::try_from(entry.safi as u8)
                .map_err(|_| format!("LLGR: unknown SAFI {}", entry.safi))?;
            parsed.push(AfiSafi::new(afi, safi));
        }
        Some(parsed)
    };

    Ok(Some(LlgrConfig {
        enabled: llgr.enabled.unwrap_or(true),
        stale_time: llgr.stale_time_secs,
        afi_safis,
    }))
}

fn proto_to_afi_safis(entries: &[proto::AfiSafiConfig]) -> Result<Vec<AfiSafiConfig>, String> {
    let mut result = Vec::new();
    for entry in entries {
        let afi =
            Afi::try_from(entry.afi as u16).map_err(|_| format!("unknown AFI {}", entry.afi))?;
        let safi =
            Safi::try_from(entry.safi as u8).map_err(|_| format!("unknown SAFI {}", entry.safi))?;
        let max_prefix = entry.max_prefix.as_ref().map(|mp| MaxPrefixSetting {
            limit: mp.limit,
            action: match proto::MaxPrefixAction::try_from(mp.action) {
                Ok(proto::MaxPrefixAction::Discard) => MaxPrefixAction::Discard,
                _ => MaxPrefixAction::Terminate,
            },
        });
        let add_path_send = entry.add_path_send.and_then(|v| {
            proto::AddPathSendMode::try_from(v)
                .ok()
                .map(|mode| match mode {
                    proto::AddPathSendMode::AddPathSendDisabled => AddPathSend::Disabled,
                    proto::AddPathSendMode::AddPathSendAll => AddPathSend::All,
                })
        });
        result.push(AfiSafiConfig {
            afi,
            safi,
            max_prefix,
            add_path_send,
            import_policy: entry.import_policy.clone(),
            export_policy: entry.export_policy.clone(),
        });
    }
    Ok(result)
}

/// Convert internal PeerConfig to proto SessionConfig
fn peer_config_to_proto(config: &PeerConfig) -> ProtoSessionConfig {
    let max_prefix = config
        .max_prefix
        .as_ref()
        .map(|mp| proto::MaxPrefixSetting {
            limit: mp.limit,
            action: match mp.action {
                MaxPrefixAction::Terminate => 0,
                MaxPrefixAction::Discard => 1,
            },
        });

    let graceful_restart = Some(proto::GracefulRestartConfig {
        enabled: Some(config.graceful_restart.enabled),
        restart_time_secs: Some(config.graceful_restart.restart_time as u32),
    });

    let llgr = config.llgr.as_ref().map(|llgr| proto::LlgrConfig {
        enabled: Some(llgr.enabled),
        stale_time_secs: llgr.stale_time,
        afi_safis: llgr
            .afi_safis
            .as_ref()
            .map(|afis| {
                afis.iter()
                    .map(|afi_safi| proto::AfiSafi {
                        afi: afi_safi.afi as u16 as u32,
                        safi: afi_safi.safi as u8 as u32,
                    })
                    .collect()
            })
            .unwrap_or_default(),
    });

    let add_path_send = match config.add_path_send {
        AddPathSend::All => Some(proto::AddPathSendMode::AddPathSendAll as i32),
        AddPathSend::Disabled => Some(proto::AddPathSendMode::AddPathSendDisabled as i32),
    };

    ProtoSessionConfig {
        idle_hold_time_secs: config.idle_hold_time_secs,
        damp_peer_oscillations: Some(config.damp_peer_oscillations),
        allow_automatic_stop: Some(config.allow_automatic_stop),
        passive_mode: Some(config.passive_mode),
        delay_open_time_secs: config.delay_open_time_secs,
        max_prefix,
        send_notification_without_open: Some(config.send_notification_without_open),
        min_route_advertisement_interval_secs: config.min_route_advertisement_interval_secs,
        graceful_restart,
        port: Some(config.port as u32),
        rr_client: Some(config.rr_client),
        rs_client: Some(config.rs_client),
        add_path_send,
        add_path_receive: Some(config.add_path_receive),
        asn: config.asn,
        enforce_first_as: Some(config.enforce_first_as),
        md5_key_file: config.md5_key_file.clone(),
        next_hop_self: Some(config.next_hop_self),
        graceful_shutdown: Some(config.graceful_shutdown),
        ttl_min: config.ttl_min.map(|v| v as u32),
        llgr,
        send_rpki_community: Some(config.send_rpki_community),
        interface: config.interface.clone(),
        afi_safis: config
            .afi_safis
            .iter()
            .map(|entry| {
                let max_prefix = entry.max_prefix.as_ref().map(|mp| proto::MaxPrefixSetting {
                    limit: mp.limit,
                    action: match mp.action {
                        MaxPrefixAction::Terminate => 0,
                        MaxPrefixAction::Discard => 1,
                    },
                });
                let add_path_send = entry.add_path_send.map(|aps| match aps {
                    AddPathSend::All => proto::AddPathSendMode::AddPathSendAll as i32,
                    AddPathSend::Disabled => proto::AddPathSendMode::AddPathSendDisabled as i32,
                });
                proto::AfiSafiConfig {
                    afi: entry.afi as u16 as u32,
                    safi: entry.safi as u8 as u32,
                    max_prefix,
                    add_path_send,
                    import_policy: entry.import_policy.clone(),
                    export_policy: entry.export_policy.clone(),
                }
            })
            .collect(),
    }
}

#[derive(Clone)]
pub struct BgpGrpcService {
    mgmt_request_tx: mpsc::Sender<MgmtOp>,
}

impl BgpGrpcService {
    pub fn new(mgmt_request_tx: mpsc::Sender<MgmtOp>) -> Self {
        Self { mgmt_request_tx }
    }
}

#[tonic::async_trait]
impl BgpService for BgpGrpcService {
    type ListPeersStreamStream = PeerStream;
    type ListRoutesStreamStream = RouteStream;

    async fn add_peer(
        &self,
        request: Request<AddPeerRequest>,
    ) -> Result<Response<AddPeerResponse>, Status> {
        let inner = request.into_inner();
        let addr = inner.address;

        if let Some(ref cfg) = inner.config {
            if let Some(ttl) = cfg.ttl_min {
                if ttl == 0 || ttl > 255 {
                    return Err(Status::invalid_argument(
                        "ttl_min must be between 1 and 255",
                    ));
                }
            }
        }

        let config = proto_to_peer_config(inner.config).map_err(Status::invalid_argument)?;

        // Send request to BGP server via channel
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::AddPeer {
            addr: addr.clone(),
            config,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddPeerResponse {
                success: true,
                message: format!("Peer {} added", addr),
            })),
            Ok(Err(e)) => Ok(Response::new(AddPeerResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn remove_peer(
        &self,
        request: Request<RemovePeerRequest>,
    ) -> Result<Response<RemovePeerResponse>, Status> {
        let peer_ip = request.into_inner().address;

        // Validate that it's a valid IP address
        peer_ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| Status::invalid_argument("invalid IP address format"))?;

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RemovePeer {
            addr: peer_ip.clone(),
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemovePeerResponse {
                success: true,
                message: format!("Peer {} removed", peer_ip),
            })),
            Ok(Err(e)) => Ok(Response::new(RemovePeerResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn disable_peer(
        &self,
        request: Request<DisablePeerRequest>,
    ) -> Result<Response<DisablePeerResponse>, Status> {
        let addr = request.into_inner().address;

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.mgmt_request_tx
            .send(MgmtOp::DisablePeer { addr, response: tx })
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(DisablePeerResponse {})),
            Ok(Err(e)) => Err(Status::not_found(e)),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn enable_peer(
        &self,
        request: Request<EnablePeerRequest>,
    ) -> Result<Response<EnablePeerResponse>, Status> {
        let addr = request.into_inner().address;

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.mgmt_request_tx
            .send(MgmtOp::EnablePeer { addr, response: tx })
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(EnablePeerResponse {})),
            Ok(Err(e)) => Err(Status::not_found(e)),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn reset_peer(
        &self,
        request: Request<ResetPeerRequest>,
    ) -> Result<Response<ResetPeerResponse>, Status> {
        use crate::bgp::multiprotocol::{Afi, Safi};
        use crate::server::ResetType;

        let req = request.into_inner();

        let reset_type = match proto::ResetType::try_from(req.reset_type) {
            Ok(proto::ResetType::SoftIn) => ResetType::SoftIn,
            Ok(proto::ResetType::SoftOut) => ResetType::SoftOut,
            Ok(proto::ResetType::Soft) => ResetType::Soft,
            Ok(proto::ResetType::Hard) => ResetType::Hard,
            Err(_) => return Err(Status::invalid_argument("invalid reset type")),
        };

        let afi = req.afi.and_then(|a| match proto::Afi::try_from(a) {
            Ok(proto::Afi::Ipv4) => Some(Afi::Ipv4),
            Ok(proto::Afi::Ipv6) => Some(Afi::Ipv6),
            Err(_) => None,
        });

        let safi = req.safi.and_then(|s| match proto::Safi::try_from(s) {
            Ok(proto::Safi::Unicast) => Some(Safi::Unicast),
            Err(_) => None,
        });

        let (tx, rx) = oneshot::channel();
        self.mgmt_request_tx
            .send(MgmtOp::ResetPeer {
                addr: req.address,
                reset_type,
                afi,
                safi,
                response: tx,
            })
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(ResetPeerResponse {})),
            Ok(Err(e)) => Err(Status::not_found(e)),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_peers(
        &self,
        _request: Request<ListPeersRequest>,
    ) -> Result<Response<ListPeersResponse>, Status> {
        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetPeers { response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        let peers = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        let proto_peers: Vec<ProtoPeer> = peers
            .iter()
            .map(|peer| ProtoPeer {
                address: peer.address.clone(),
                asn: peer.asn.unwrap_or(0), // 0 for peers still in handshake
                state: to_proto_state(peer.state),
                admin_state: to_proto_admin_state(peer.admin_state),
                import_policies: peer.import_policies.clone(),
                export_policies: peer.export_policies.clone(),
                session_config: None,
            })
            .collect();

        Ok(Response::new(ListPeersResponse { peers: proto_peers }))
    }

    async fn list_peers_stream(
        &self,
        _request: Request<ListPeersRequest>,
    ) -> Result<Response<Self::ListPeersStreamStream>, Status> {
        use tokio_stream::wrappers::UnboundedReceiverStream;
        use tokio_stream::StreamExt;

        let (tx, rx) = mpsc::unbounded_channel();

        // Send streaming request to BGP server
        let mgmt_req = MgmtOp::GetPeersStream { tx };
        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Convert channel receiver to gRPC stream
        let stream = UnboundedReceiverStream::new(rx)
            .map(|peer| ProtoPeer {
                address: peer.address,
                asn: peer.asn.unwrap_or(0),
                state: to_proto_state(peer.state),
                admin_state: to_proto_admin_state(peer.admin_state),
                import_policies: peer.import_policies,
                export_policies: peer.export_policies,
                session_config: None,
            })
            .map(Ok);

        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_peer(
        &self,
        request: Request<GetPeerRequest>,
    ) -> Result<Response<GetPeerResponse>, Status> {
        let addr = request.into_inner().address;

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetPeer {
            addr: addr.clone(),
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        let peer_info = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        match peer_info {
            Some(peer) => {
                let proto_peer = ProtoPeer {
                    address: peer.address.clone(),
                    asn: peer.asn.unwrap_or(0), // 0 for peers still in handshake
                    state: to_proto_state(peer.state),
                    admin_state: to_proto_admin_state(peer.admin_state),
                    import_policies: peer.import_policies.clone(),
                    export_policies: peer.export_policies.clone(),
                    session_config: Some(peer_config_to_proto(&peer.config)),
                };

                let proto_statistics = ProtoPeerStatistics {
                    open_sent: peer.statistics.open_sent,
                    keepalive_sent: peer.statistics.keepalive_sent,
                    update_sent: peer.statistics.update_sent,
                    notification_sent: peer.statistics.notification_sent,
                    open_received: peer.statistics.open_received,
                    keepalive_received: peer.statistics.keepalive_received,
                    update_received: peer.statistics.update_received,
                    notification_received: peer.statistics.notification_received,
                };

                Ok(Response::new(GetPeerResponse {
                    peer: Some(proto_peer),
                    statistics: Some(proto_statistics),
                }))
            }
            None => Err(Status::not_found(format!("Peer {} not found", addr))),
        }
    }

    async fn add_route(
        &self,
        request: Request<AddRouteRequest>,
    ) -> Result<Response<AddRouteResponse>, Status> {
        let req = request.into_inner();

        let (key, attrs, description) = match req.route {
            Some(proto::add_route_request::Route::Ls(ls)) => {
                let nlri_msg = ls
                    .nlri
                    .ok_or_else(|| Status::invalid_argument("ls route requires nlri"))?;
                let nlri = proto_ls::proto_to_ls_nlri(&nlri_msg)
                    .map_err(|e| Status::invalid_argument(format!("invalid ls_nlri: {e}")))?;
                let ls_attr = ls.attribute.as_ref().map(proto_ls::proto_to_ls_attr);
                let next_hop = if let Some(ref nh) = ls.next_hop {
                    let addr: std::net::IpAddr = nh
                        .parse()
                        .map_err(|_| Status::invalid_argument("invalid next_hop"))?;
                    match addr {
                        std::net::IpAddr::V4(v4) => NextHopAddr::Ipv4(v4),
                        std::net::IpAddr::V6(v6) => NextHopAddr::Ipv6(v6),
                    }
                } else {
                    NextHopAddr::Ipv4(std::net::Ipv4Addr::UNSPECIFIED)
                };
                let description = format!("LS {:?}", nlri.nlri_type);
                let key = RouteKey::LinkState(Box::new(nlri));
                let attrs = PathAttrs {
                    origin: Origin::IGP,
                    as_path: vec![],
                    next_hop,
                    source: RouteSource::Local,
                    local_pref: None,
                    med: None,
                    atomic_aggregate: false,
                    aggregator: None,
                    communities: vec![],
                    extended_communities: vec![],
                    large_communities: vec![],
                    unknown_attrs: vec![],
                    originator_id: None,
                    cluster_list: vec![],
                    ls_attr,
                };
                (key, attrs, description)
            }
            Some(proto::add_route_request::Route::Ip(ip)) => {
                let (prefix, next_hop, origin, as_path) =
                    parse_add_ip_route(&ip).map_err(Status::invalid_argument)?;
                let extended_communities: Vec<u64> = ip
                    .extended_communities
                    .iter()
                    .map(proto_extcomm_to_u64)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        Status::invalid_argument(format!("Invalid extended community: {e}"))
                    })?;
                let large_communities = ip
                    .large_communities
                    .iter()
                    .map(proto_large_community_to_internal)
                    .collect();
                let originator_id = ip
                    .originator_id
                    .as_ref()
                    .map(|s| s.parse::<std::net::Ipv4Addr>())
                    .transpose()
                    .map_err(|_| Status::invalid_argument("Invalid originator_id"))?;
                let cluster_list: Vec<std::net::Ipv4Addr> = ip
                    .cluster_list
                    .iter()
                    .map(|s| s.parse::<std::net::Ipv4Addr>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| Status::invalid_argument("Invalid cluster_list"))?;
                let description = ip.prefix.clone();
                let key = RouteKey::Prefix(prefix);
                let attrs = PathAttrs {
                    origin,
                    as_path,
                    next_hop,
                    source: RouteSource::Local,
                    local_pref: ip.local_pref,
                    med: ip.med,
                    atomic_aggregate: ip.atomic_aggregate,
                    aggregator: None,
                    communities: ip.communities,
                    extended_communities,
                    large_communities,
                    unknown_attrs: vec![],
                    originator_id,
                    cluster_list,
                    ls_attr: None,
                };
                (key, attrs, description)
            }
            None => {
                return Ok(Response::new(AddRouteResponse {
                    success: false,
                    message: "request must contain either ip or ls route".to_string(),
                }));
            }
        };

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mgmt_req = MgmtOp::AddRoute {
            key: Box::new(key),
            attrs: Box::new(attrs),
            response: tx,
        };

        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddRouteResponse {
                success: true,
                message: format!("Route {} added", description),
            })),
            Ok(Err(e)) => Ok(Response::new(AddRouteResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn add_route_stream(
        &self,
        request: Request<tonic::Streaming<AddRouteRequest>>,
    ) -> Result<Response<AddRouteStreamResponse>, Status> {
        let mut stream = request.into_inner();
        let mut count = 0u64;

        while let Some(req) = stream.next().await {
            let req = req?;

            let ip = match req.route {
                Some(proto::add_route_request::Route::Ip(ip)) => ip,
                _ => continue, // Stream only supports IP routes
            };

            let (prefix, next_hop, origin, as_path) = match parse_add_ip_route(&ip) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };

            let extended_communities: Vec<u64> = match ip
                .extended_communities
                .iter()
                .map(proto_extcomm_to_u64)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(ec) => ec,
                Err(_) => continue,
            };

            let large_communities = ip
                .large_communities
                .iter()
                .map(proto_large_community_to_internal)
                .collect();

            let originator_id = match ip
                .originator_id
                .as_ref()
                .map(|s| s.parse::<std::net::Ipv4Addr>())
                .transpose()
            {
                Ok(id) => id,
                Err(_) => continue,
            };

            let cluster_list: Vec<std::net::Ipv4Addr> = match ip
                .cluster_list
                .iter()
                .map(|s| s.parse::<std::net::Ipv4Addr>())
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(cl) => cl,
                Err(_) => continue,
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            let mgmt_req = MgmtOp::AddRoute {
                key: Box::new(RouteKey::Prefix(prefix)),
                attrs: Box::new(PathAttrs {
                    origin,
                    as_path,
                    next_hop,
                    source: RouteSource::Local,
                    local_pref: ip.local_pref,
                    med: ip.med,
                    atomic_aggregate: ip.atomic_aggregate,
                    aggregator: None,
                    communities: ip.communities,
                    extended_communities,
                    large_communities,
                    unknown_attrs: vec![],
                    originator_id,
                    cluster_list,
                    ls_attr: None,
                }),
                response: tx,
            };

            if self.mgmt_request_tx.send(mgmt_req).await.is_err() {
                break;
            }

            if let Ok(Ok(())) = rx.await {
                count += 1;
            }
        }

        Ok(Response::new(AddRouteStreamResponse {
            count,
            message: format!("{} routes added", count),
        }))
    }

    async fn remove_route(
        &self,
        request: Request<RemoveRouteRequest>,
    ) -> Result<Response<RemoveRouteResponse>, Status> {
        let req = request.into_inner();

        let (key, description) = match req.key {
            Some(proto::remove_route_request::Key::LsNlri(ref proto_nlri)) => {
                let nlri = proto_ls::proto_to_ls_nlri(proto_nlri)
                    .map_err(|e| Status::invalid_argument(format!("invalid ls_nlri: {e}")))?;
                let desc = format!("LS {:?}", nlri.nlri_type);
                (RouteKey::LinkState(Box::new(nlri)), desc)
            }
            Some(proto::remove_route_request::Key::Prefix(ref prefix_str)) => {
                let parts: Vec<&str> = prefix_str.split('/').collect();
                if parts.len() != 2 {
                    return Ok(Response::new(RemoveRouteResponse {
                        success: false,
                        message: "Invalid prefix format, expected CIDR".to_string(),
                    }));
                }
                let address: IpAddr = parts[0]
                    .parse()
                    .map_err(|_| Status::invalid_argument("Invalid IP address"))?;
                let prefix_length: u8 = parts[1]
                    .parse()
                    .map_err(|_| Status::invalid_argument("Invalid prefix length"))?;
                let prefix = match address {
                    IpAddr::V4(ipv4) => IpNetwork::V4(Ipv4Net {
                        address: ipv4,
                        prefix_length,
                    }),
                    IpAddr::V6(ipv6) => IpNetwork::V6(Ipv6Net {
                        address: ipv6,
                        prefix_length,
                    }),
                };
                (RouteKey::Prefix(prefix), prefix_str.clone())
            }
            None => {
                return Ok(Response::new(RemoveRouteResponse {
                    success: false,
                    message: "request must contain either prefix or ls_nlri".to_string(),
                }));
            }
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        let mgmt_req = MgmtOp::RemoveRoute {
            key: Box::new(key),
            response: tx,
        };

        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemoveRouteResponse {
                success: true,
                message: format!("Route {} removed", description),
            })),
            Ok(Err(e)) => Ok(Response::new(RemoveRouteResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_routes(
        &self,
        request: Request<ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        let req = request.into_inner();

        // Send request to BGP server
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mgmt_req = MgmtOp::GetRoutes {
            rib_type: req.rib_type,
            peer_address: req.peer_address,
            afi: req.afi,
            safi: req.safi,
            response: tx,
        };

        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Wait for response
        let routes = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?
            .map_err(Status::invalid_argument)?;

        // Convert Rust routes to proto routes
        let proto_routes: Vec<ProtoRoute> = routes.into_iter().map(route_to_proto).collect();

        Ok(Response::new(ListRoutesResponse {
            routes: proto_routes,
        }))
    }

    async fn list_routes_stream(
        &self,
        request: Request<ListRoutesRequest>,
    ) -> Result<Response<Self::ListRoutesStreamStream>, Status> {
        use tokio_stream::wrappers::UnboundedReceiverStream;
        use tokio_stream::StreamExt;

        let req = request.into_inner();
        let (tx, rx) = mpsc::unbounded_channel();

        // Send streaming request to BGP server
        let mgmt_req = MgmtOp::GetRoutesStream {
            rib_type: req.rib_type,
            peer_address: req.peer_address,
            afi: req.afi,
            safi: req.safi,
            tx,
        };
        self.mgmt_request_tx
            .send(mgmt_req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        // Convert channel receiver to gRPC stream
        let stream = UnboundedReceiverStream::new(rx).map(route_to_proto).map(Ok);

        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_server_info(
        &self,
        _request: Request<GetServerInfoRequest>,
    ) -> Result<Response<GetServerInfoResponse>, Status> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetServerInfo { response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        let (listen_addr, listen_port, num_routes) = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        Ok(Response::new(GetServerInfoResponse {
            listen_addr: listen_addr.to_string(),
            listen_port: listen_port as u32,
            num_routes,
        }))
    }

    async fn get_running_config(
        &self,
        _request: Request<GetRunningConfigRequest>,
    ) -> Result<Response<GetRunningConfigResponse>, Status> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetRunningConfig { response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        let text = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        Ok(Response::new(GetRunningConfigResponse { text }))
    }

    async fn commit_config(
        &self,
        request: Request<CommitConfigRequest>,
    ) -> Result<Response<CommitConfigResponse>, Status> {
        let inner = request.into_inner();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::CommitConfig {
            text: inner.text,
            session_uuid: inner.session_uuid,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?
        {
            Ok(()) => Ok(Response::new(CommitConfigResponse {
                ok: true,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(CommitConfigResponse {
                ok: false,
                error: e,
            })),
        }
    }

    async fn save_config(
        &self,
        request: Request<SaveConfigRequest>,
    ) -> Result<Response<SaveConfigResponse>, Status> {
        let inner = request.into_inner();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::SaveConfig {
            session_uuid: inner.session_uuid,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?
        {
            Ok(()) => Ok(Response::new(SaveConfigResponse {
                ok: true,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(SaveConfigResponse {
                ok: false,
                error: e,
            })),
        }
    }

    async fn rollback_config(
        &self,
        request: Request<RollbackConfigRequest>,
    ) -> Result<Response<RollbackConfigResponse>, Status> {
        let inner = request.into_inner();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RollbackConfig {
            index: inner.index,
            session_uuid: inner.session_uuid,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?
        {
            Ok(()) => Ok(Response::new(RollbackConfigResponse {
                ok: true,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(RollbackConfigResponse {
                ok: false,
                error: e,
            })),
        }
    }

    async fn list_config_snapshots(
        &self,
        _request: Request<ListConfigSnapshotsRequest>,
    ) -> Result<Response<ListConfigSnapshotsResponse>, Status> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::ListConfigSnapshots { response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        let snapshots = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        let proto_snapshots = snapshots
            .into_iter()
            .map(|s| ProtoConfigSnapshot {
                index: s.index,
                mtime_unix: s.mtime_unix,
                size_bytes: s.size_bytes,
            })
            .collect();

        Ok(Response::new(ListConfigSnapshotsResponse {
            snapshots: proto_snapshots,
        }))
    }

    async fn add_bmp_server(
        &self,
        request: Request<AddBmpServerRequest>,
    ) -> Result<Response<AddBmpServerResponse>, Status> {
        let inner = request.into_inner();
        let addr = inner
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid BMP server address: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::AddBmpServer {
            addr,
            statistics_timeout: inner.statistics_timeout,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddBmpServerResponse {
                success: true,
                message: format!("BMP server {} added", addr),
            })),
            Ok(Err(e)) => Ok(Response::new(AddBmpServerResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn remove_bmp_server(
        &self,
        request: Request<RemoveBmpServerRequest>,
    ) -> Result<Response<RemoveBmpServerResponse>, Status> {
        let addr_str = request.into_inner().address;
        let addr = addr_str
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid BMP server address: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RemoveBmpServer { addr, response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemoveBmpServerResponse {
                success: true,
                message: format!("BMP server {} removed", addr),
            })),
            Ok(Err(e)) => Ok(Response::new(RemoveBmpServerResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_bmp_servers(
        &self,
        _request: Request<ListBmpServersRequest>,
    ) -> Result<Response<ListBmpServersResponse>, Status> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetBmpServers { response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        let addresses = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        Ok(Response::new(ListBmpServersResponse { addresses }))
    }

    async fn add_rpki_cache(
        &self,
        request: Request<AddRpkiCacheRequest>,
    ) -> Result<Response<AddRpkiCacheResponse>, Status> {
        let inner = request.into_inner();
        let addr: std::net::SocketAddr = inner
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {}", e)))?;

        let transport = inner
            .transport
            .as_deref()
            .map(str::parse::<TransportType>)
            .transpose()
            .map_err(|e| Status::invalid_argument(format!("invalid transport: {}", e)))?
            .unwrap_or_default();
        if matches!(transport, TransportType::Ssh) {
            if inner.ssh_username.is_none() {
                return Err(Status::invalid_argument(
                    "ssh_username required for SSH transport",
                ));
            }
            if inner.ssh_private_key_file.is_none() {
                return Err(Status::invalid_argument(
                    "ssh_private_key_file required for SSH transport",
                ));
            }
        }

        let config = RpkiCacheConfig {
            address: addr.to_string(),
            preference: inner.preference.map(|p| p as u8).unwrap_or(0),
            transport,
            ssh_username: inner.ssh_username,
            ssh_private_key_file: inner.ssh_private_key_file,
            ssh_known_hosts_file: inner.ssh_known_hosts_file,
            retry_interval: inner.retry_interval,
            refresh_interval: inner.refresh_interval,
            expire_interval: inner.expire_interval,
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::AddRpkiCache {
            config,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddRpkiCacheResponse {
                success: true,
                message: format!("RPKI cache {} added", addr),
            })),
            Ok(Err(e)) => Ok(Response::new(AddRpkiCacheResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn remove_rpki_cache(
        &self,
        request: Request<RemoveRpkiCacheRequest>,
    ) -> Result<Response<RemoveRpkiCacheResponse>, Status> {
        let addr: std::net::SocketAddr = request
            .into_inner()
            .address
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid address: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RemoveRpkiCache { addr, response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemoveRpkiCacheResponse {
                success: true,
                message: format!("RPKI cache {} removed", addr),
            })),
            Ok(Err(e)) => Ok(Response::new(RemoveRpkiCacheResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_rpki_caches(
        &self,
        _request: Request<ListRpkiCachesRequest>,
    ) -> Result<Response<ListRpkiCachesResponse>, Status> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetRpkiCaches { response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        let (caches, total_vrp_count) = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        let proto_caches = caches
            .into_iter()
            .map(|cache| RpkiCacheInfo {
                address: cache.address.to_string(),
                preference: cache.preference as u32,
                transport: cache.transport_name.to_string(),
                session_active: cache.session_active,
                vrp_count: cache.vrp_count as u64,
            })
            .collect();

        Ok(Response::new(ListRpkiCachesResponse {
            caches: proto_caches,
            total_vrp_count: total_vrp_count as u64,
        }))
    }

    async fn get_rpki_validation(
        &self,
        request: Request<GetRpkiValidationRequest>,
    ) -> Result<Response<GetRpkiValidationResponse>, Status> {
        let inner = request.into_inner();
        let prefix: IpNetwork = inner
            .prefix
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid prefix: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::GetRpkiValidation {
            prefix,
            origin_as: inner.origin_as,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        let (validation, covering) = rx
            .await
            .map_err(|_| Status::internal("request processing failed"))?;

        let proto_validation = match validation {
            RpkiValidation::Valid => proto::RpkiValidation::RpkiValid,
            RpkiValidation::Invalid => proto::RpkiValidation::RpkiInvalid,
            RpkiValidation::NotFound => proto::RpkiValidation::RpkiNotFound,
        };

        let covering_vrps = covering
            .into_iter()
            .map(|vrp| RpkiVrp {
                prefix: vrp.prefix.to_string(),
                max_length: vrp.max_length as u32,
                origin_as: vrp.origin_as,
            })
            .collect();

        Ok(Response::new(GetRpkiValidationResponse {
            validation: proto_validation.into(),
            covering_vrps,
        }))
    }

    async fn add_defined_set(
        &self,
        request: Request<AddDefinedSetRequest>,
    ) -> Result<Response<AddDefinedSetResponse>, Status> {
        let inner = request.into_inner();
        let set_config = inner
            .set
            .ok_or_else(|| Status::invalid_argument("set config required"))?;

        // Convert proto to internal types
        let set = proto_to_defined_set_config(&set_config)
            .map_err(|e| Status::invalid_argument(format!("invalid set config: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::AddDefinedSet { set, response: tx };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddDefinedSetResponse {
                success: true,
                message: "defined set added".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(AddDefinedSetResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn remove_defined_set(
        &self,
        request: Request<RemoveDefinedSetRequest>,
    ) -> Result<Response<RemoveDefinedSetResponse>, Status> {
        use crate::policy::DefinedSetType;

        let inner = request.into_inner();

        let set_type = DefinedSetType::parse(&inner.set_type).map_err(Status::invalid_argument)?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RemoveDefinedSet {
            set_type,
            name: inner.name,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemoveDefinedSetResponse {
                success: true,
                message: "defined set removed".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(RemoveDefinedSetResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_defined_sets(
        &self,
        request: Request<ListDefinedSetsRequest>,
    ) -> Result<Response<ListDefinedSetsResponse>, Status> {
        use crate::policy::DefinedSetType;

        let inner = request.into_inner();

        let set_type = if let Some(st) = inner.set_type {
            Some(DefinedSetType::parse(&st).map_err(Status::invalid_argument)?)
        } else {
            None
        };

        let (tx, rx) = tokio::sync::oneshot::channel();

        let req = MgmtOp::ListDefinedSets {
            set_type,
            name: inner.name,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(results) => {
                let sets = results
                    .into_iter()
                    .map(defined_set_config_to_proto)
                    .collect();
                Ok(Response::new(ListDefinedSetsResponse { sets }))
            }
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn add_policy(
        &self,
        request: Request<AddPolicyRequest>,
    ) -> Result<Response<AddPolicyResponse>, Status> {
        let inner = request.into_inner();

        // Convert proto statements to internal format
        let statements = inner
            .statements
            .into_iter()
            .map(proto_to_statement_config)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Status::invalid_argument(format!("invalid statement config: {}", e)))?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::AddPolicy {
            name: inner.name,
            statements,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(AddPolicyResponse {
                success: true,
                message: "policy added".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(AddPolicyResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn remove_policy(
        &self,
        request: Request<RemovePolicyRequest>,
    ) -> Result<Response<RemovePolicyResponse>, Status> {
        let inner = request.into_inner();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::RemovePolicy {
            name: inner.name,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(RemovePolicyResponse {
                success: true,
                message: "policy removed".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(RemovePolicyResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn list_policies(
        &self,
        request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let inner = request.into_inner();
        let (tx, rx) = tokio::sync::oneshot::channel();

        let req = MgmtOp::ListPolicies {
            name: inner.name,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(results) => {
                let policies = results.into_iter().map(policy_info_to_proto).collect();
                Ok(Response::new(ListPoliciesResponse { policies }))
            }
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn set_policy_assignment(
        &self,
        request: Request<SetPolicyAssignmentRequest>,
    ) -> Result<Response<SetPolicyAssignmentResponse>, Status> {
        let inner = request.into_inner();

        // Parse peer address
        let peer_addr = inner
            .peer_address
            .parse::<std::net::IpAddr>()
            .map_err(|_| Status::invalid_argument("invalid peer address"))?;

        // Parse direction
        let direction = match inner.direction.as_str() {
            "import" => crate::server::PolicyDirection::Import,
            "export" => crate::server::PolicyDirection::Export,
            _ => {
                return Err(Status::invalid_argument(
                    "direction must be 'import' or 'export'",
                ))
            }
        };

        let afi = Afi::try_from(inner.afi as u16)
            .map_err(|_| Status::invalid_argument(format!("unknown AFI {}", inner.afi)))?;
        let safi = Safi::try_from(inner.safi as u8)
            .map_err(|_| Status::invalid_argument(format!("unknown SAFI {}", inner.safi)))?;
        let family = AfiSafi::new(afi, safi);

        // Parse default action
        let default_action = inner
            .default_action
            .as_ref()
            .map(|action| match action.as_str() {
                "accept" => crate::policy::PolicyResult::Accept,
                "reject" => crate::policy::PolicyResult::Reject,
                _ => crate::policy::PolicyResult::Reject, // Default to reject
            });

        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = MgmtOp::SetPolicyAssignment {
            peer_addr,
            family,
            direction,
            policy_names: inner.policy_names,
            default_action,
            response: tx,
        };

        self.mgmt_request_tx
            .send(req)
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(SetPolicyAssignmentResponse {
                success: true,
                message: "policy assignment set".to_string(),
            })),
            Ok(Err(e)) => Ok(Response::new(SetPolicyAssignmentResponse {
                success: false,
                message: e,
            })),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }

    async fn set_peer_graceful_shutdown(
        &self,
        request: Request<SetPeerGracefulShutdownRequest>,
    ) -> Result<Response<SetPeerGracefulShutdownResponse>, Status> {
        let inner = request.into_inner();

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.mgmt_request_tx
            .send(MgmtOp::SetPeerGracefulShutdown {
                addr: inner.address,
                enabled: inner.enabled,
                response: tx,
            })
            .await
            .map_err(|_| Status::internal("failed to send request"))?;

        match rx.await {
            Ok(Ok(())) => Ok(Response::new(SetPeerGracefulShutdownResponse {
                success: true,
                message: String::new(),
            })),
            Ok(Err(e)) => Err(Status::not_found(e)),
            Err(_) => Err(Status::internal("request processing failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
    use crate::grpc::proto::{self, SessionConfig};

    #[test]
    fn test_proto_to_peer_config_ttl_min() {
        let cases: &[(Option<u32>, Option<u8>)] = &[
            (Some(1), Some(1)),
            (Some(254), Some(254)),
            (Some(255), Some(255)),
            (None, None),
        ];
        for (input, expected) in cases {
            let config = proto_to_peer_config(Some(SessionConfig {
                ttl_min: *input,
                ..Default::default()
            }))
            .unwrap();
            assert_eq!(config.ttl_min, *expected);
        }
    }

    #[test]
    fn test_proto_to_peer_config_llgr() {
        // Valid config with afi_safis
        let config = proto_to_peer_config(Some(SessionConfig {
            llgr: Some(proto::LlgrConfig {
                enabled: Some(true),
                stale_time_secs: Some(3600),
                afi_safis: vec![proto::AfiSafi { afi: 1, safi: 1 }],
            }),
            ..Default::default()
        }))
        .unwrap();
        let llgr = config.llgr.unwrap();
        assert!(llgr.enabled);
        assert_eq!(llgr.stale_time, Some(3600));
        let afi_safis = llgr.afi_safis.unwrap();
        assert_eq!(afi_safis.len(), 1);
        assert_eq!(afi_safis[0], AfiSafi::new(Afi::Ipv4, Safi::Unicast));

        // Invalid AFI is rejected
        let result = proto_to_peer_config(Some(SessionConfig {
            llgr: Some(proto::LlgrConfig {
                enabled: Some(true),
                stale_time_secs: Some(100),
                afi_safis: vec![proto::AfiSafi { afi: 99, safi: 1 }],
            }),
            ..Default::default()
        }));
        assert!(result.is_err());

        // enabled: false
        let config = proto_to_peer_config(Some(SessionConfig {
            llgr: Some(proto::LlgrConfig {
                enabled: Some(false),
                stale_time_secs: None,
                afi_safis: vec![],
            }),
            ..Default::default()
        }))
        .unwrap();
        let llgr = config.llgr.unwrap();
        assert!(!llgr.enabled);

        // No LLGR config -> None
        let config = proto_to_peer_config(Some(SessionConfig::default())).unwrap();
        assert!(config.llgr.is_none());
    }
}
