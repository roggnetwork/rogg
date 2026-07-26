// Copyright 2026 rogg Authors
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

//! Metric names emitted by bgpggd. Public contract (see ARCHITECTURE.md);
//! renames are breaking changes. Names are PascalCase (CloudWatch
//! convention) and end in their unit as a full word (Count, Seconds,
//! Milliseconds, Bytes), except cumulative counters which end in Total
//! (running total, not a per-event 1 -- aggregate with MAX, not SUM).
//! The Prometheus endpoint converts to snake_case with a `bgpgg_` prefix
//! (see `prometheus_name`).

// Event metrics: one emission per occurrence, at the event site.
pub const SESSION_ESTABLISHED_COUNT: &str = "SessionEstablishedCount";
pub const SESSION_DOWN_COUNT: &str = "SessionDownCount";
pub const CONNECT_RETRY_COUNT: &str = "ConnectRetryCount";
/// A TCP connection became the peer's active connection and the handshake
/// is starting. Dimension Direction: Dialed | Accepted.
pub const TCP_CONNECTION_COUNT: &str = "TcpConnectionCount";
// Connection collision handling (RFC 4271 6.8), one metric per event:
/// Inbound connection held as the collision candidate.
pub const COLLISION_DETECTED_COUNT: &str = "CollisionDetectedCount";
/// Resolution: the connection we dialed won; candidate dropped.
pub const COLLISION_DIALED_WINS_COUNT: &str = "CollisionDialedWinsCount";
/// Resolution: the accepted connection won; dialed connection closed.
pub const COLLISION_ACCEPTED_WINS_COUNT: &str = "CollisionAcceptedWinsCount";
/// A held candidate was dropped without resolving (closed or sent junk before OPEN).
pub const COLLISION_CANDIDATE_DROPPED_COUNT: &str = "CollisionCandidateDroppedCount";
pub const HOLD_TIMER_EXPIRED_COUNT: &str = "HoldTimerExpiredCount";
pub const NOTIFICATION_RECEIVED_COUNT: &str = "NotificationReceivedCount";
pub const NOTIFICATION_SENT_COUNT: &str = "NotificationSentCount";
pub const BMP_CONNECTION_DOWN_COUNT: &str = "BmpConnectionDownCount";
pub const SESSION_CONVERGENCE_MILLISECONDS: &str = "SessionConvergenceMilliseconds";
pub const INITIAL_ADVERTISEMENT_MILLISECONDS: &str = "InitialAdvertisementMilliseconds";
pub const ROUTE_REFRESH_PROCESSING_MILLISECONDS: &str = "RouteRefreshProcessingMilliseconds";
pub const CONFIG_RELOAD_SUCCESS_COUNT: &str = "ConfigReloadSuccessCount";
pub const CONFIG_RELOAD_FAILURE_COUNT: &str = "ConfigReloadFailureCount";

// Periodic gauges: emitted by the server task on a timer.
pub const PEER_COUNT: &str = "PeerCount";
/// FSM state code per peer, RFC 4271 numbering: 1=Idle, 2=Connect,
/// 3=Active, 4=OpenSent, 5=OpenConfirm, 6=Established. No unit suffix;
/// the value is a code, not a quantity.
pub const SESSION_STATE: &str = "SessionState";
pub const SESSION_UPTIME_SECONDS: &str = "SessionUptimeSeconds";
pub const LOC_RIB_ROUTE_COUNT: &str = "LocRibRouteCount";
pub const ADJ_RIB_IN_ROUTE_COUNT: &str = "AdjRibInRouteCount";
pub const ADJ_RIB_IN_AFI_SAFI_ROUTE_COUNT: &str = "AdjRibInAfiSafiRouteCount";
/// Routes received across all peers (sum of per-peer adj-rib-in; the same
/// prefix from N peers counts N times). Router-wide, no Peer dimension.
pub const ADJ_RIB_IN_ROUTE_TOTAL_COUNT: &str = "AdjRibInRouteTotalCount";
pub const ADJ_RIB_OUT_ROUTE_COUNT: &str = "AdjRibOutRouteCount";
pub const ADJ_RIB_OUT_AFI_SAFI_ROUTE_COUNT: &str = "AdjRibOutAfiSafiRouteCount";
/// Routes advertised across all peers (sum of per-peer adj-rib-out; a route
/// sent to N peers counts N times). Router-wide, no Peer dimension.
pub const ADJ_RIB_OUT_ROUTE_TOTAL_COUNT: &str = "AdjRibOutRouteTotalCount";
pub const PROCESS_MEMORY_BYTES: &str = "ProcessMemoryBytes";

// Cumulative per-peer message counters
pub const MESSAGES_RECEIVED_TOTAL: &str = "MessagesReceivedTotal";
pub const MESSAGES_SENT_TOTAL: &str = "MessagesSentTotal";

/// Prometheus exposition name: snake_case with the daemon prefix,
/// e.g. "PeerCount" -> "bgpgg_peer_count".
pub fn prometheus_name(metric: &str) -> String {
    let mut name = String::from("bgpgg");
    for ch in metric.chars() {
        if ch.is_ascii_uppercase() {
            name.push('_');
            name.push(ch.to_ascii_lowercase());
        } else {
            name.push(ch);
        }
    }
    name
}
