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
//! renames are breaking changes. Names end in their unit as a full word
//! (_count, _seconds, _milliseconds, _bytes), except cumulative counters
//! which end in _total (running total, not a per-event 1 -- aggregate with
//! MAX, not SUM; also the Prometheus counter convention). The Prometheus
//! endpoint exposes the same names with a `bgpgg_` prefix (see
//! `prometheus_name`).

// Event metrics: one emission per occurrence, at the event site.
pub const SESSION_ESTABLISHED_COUNT: &str = "session_established_count";
pub const SESSION_DOWN_COUNT: &str = "session_down_count";
pub const CONNECT_RETRY_COUNT: &str = "connect_retry_count";
pub const HOLD_TIMER_EXPIRED_COUNT: &str = "hold_timer_expired_count";
pub const NOTIFICATION_RECEIVED_COUNT: &str = "notification_received_count";
pub const NOTIFICATION_SENT_COUNT: &str = "notification_sent_count";
pub const BMP_CONNECTION_DOWN_COUNT: &str = "bmp_connection_down_count";
pub const SESSION_CONVERGENCE_MILLISECONDS: &str = "session_convergence_milliseconds";
pub const INITIAL_ADVERTISEMENT_MILLISECONDS: &str = "initial_advertisement_milliseconds";
pub const ROUTE_REFRESH_PROCESSING_MILLISECONDS: &str = "route_refresh_processing_milliseconds";
pub const CONFIG_RELOAD_SUCCESS_COUNT: &str = "config_reload_success_count";
pub const CONFIG_RELOAD_FAILURE_COUNT: &str = "config_reload_failure_count";

// Periodic gauges: emitted by the server task on a timer.
pub const PEER_COUNT: &str = "peer_count";
pub const SESSION_UPTIME_SECONDS: &str = "session_uptime_seconds";
pub const LOC_RIB_ROUTE_COUNT: &str = "loc_rib_route_count";
pub const ADJ_RIB_IN_ROUTE_COUNT: &str = "adj_rib_in_route_count";
pub const ADJ_RIB_IN_AFI_SAFI_ROUTE_COUNT: &str = "adj_rib_in_afi_safi_route_count";
pub const ADJ_RIB_OUT_ROUTE_COUNT: &str = "adj_rib_out_route_count";
pub const ADJ_RIB_OUT_AFI_SAFI_ROUTE_COUNT: &str = "adj_rib_out_afi_safi_route_count";
pub const PROCESS_MEMORY_BYTES: &str = "process_memory_bytes";

// Cumulative per-peer message counters
pub const MESSAGES_RECEIVED_TOTAL: &str = "messages_received_total";
pub const MESSAGES_SENT_TOTAL: &str = "messages_sent_total";

/// Prometheus exposition name: the metric name with the daemon prefix.
pub fn prometheus_name(metric: &str) -> String {
    format!("bgpgg_{metric}")
}
