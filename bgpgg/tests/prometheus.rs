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

//! Tests for the Prometheus scrape endpoint.

mod utils;
pub use utils::*;

use conf::bgp::{BgpConfig, PrometheusConfig, TelemetryConfig};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Reserve a free port by binding to :0 and dropping the listener.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to free port");
    listener.local_addr().expect("local addr").port()
}

/// One HTTP GET against the scrape endpoint. None if the connection fails.
async fn scrape(port: u16, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await.ok()?;
    Some(response)
}

fn prometheus_telemetry(port: u16) -> TelemetryConfig {
    TelemetryConfig {
        sink: None,
        prometheus: Some(PrometheusConfig {
            listen: format!("127.0.0.1:{port}"),
        }),
    }
}

/// Replace time-dependent values (uptime, RSS, keepalive/update counts)
/// with "X" so the full body compares deterministically.
fn mask_dynamic_values(body: &str) -> String {
    let mut masked = String::new();
    for line in body.lines() {
        let dynamic = line.starts_with("bgpgg_session_uptime_seconds{")
            || line.starts_with("bgpgg_process_memory_bytes ")
            || line.contains("message_type=\"keepalive\"")
            || line.contains("message_type=\"update\"");
        match line.rsplit_once(' ') {
            Some((prefix, _)) if dynamic => {
                masked.push_str(prefix);
                masked.push_str(" X\n");
            }
            _ => {
                masked.push_str(line);
                masked.push('\n');
            }
        }
    }
    masked
}

#[tokio::test]
async fn test_prometheus_scrape() {
    let scrape_port = free_port();
    let config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 90)
        .with_telemetry(prometheus_telemetry(scrape_port));
    let server1 = start_test_server(config).await;
    let server2 = start_test_server(BgpConfig::new(
        65002,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;
    peer_servers(&server1, &server2).await;

    let response = scrape(scrape_port, "/metrics").await.expect("scrape");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        response.contains("content-type: text/plain; version=0.0.4\r\n"),
        "{response}"
    );
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("body");

    let process_memory = if cfg!(target_os = "linux") {
        "# TYPE bgpgg_process_memory_bytes gauge\nbgpgg_process_memory_bytes X\n"
    } else {
        ""
    };
    let expected = format!(
        "\
# TYPE bgpgg_peer_count gauge
bgpgg_peer_count 1
# TYPE bgpgg_session_state gauge
bgpgg_session_state{{peer=\"127.0.0.2\"}} 6
# TYPE bgpgg_session_uptime_seconds gauge
bgpgg_session_uptime_seconds{{peer=\"127.0.0.2\"}} X
# TYPE bgpgg_loc_rib_route_count gauge
bgpgg_loc_rib_route_count{{afi_safi=\"IPv4/Unicast\"}} 0
bgpgg_loc_rib_route_count{{afi_safi=\"IPv6/Unicast\"}} 0
bgpgg_loc_rib_route_count{{afi_safi=\"LinkState/LinkState\"}} 0
# TYPE bgpgg_adj_rib_in_route_count gauge
bgpgg_adj_rib_in_route_count{{peer=\"127.0.0.2\"}} 0
# TYPE bgpgg_adj_rib_in_afi_safi_route_count gauge
bgpgg_adj_rib_in_afi_safi_route_count{{peer=\"127.0.0.2\",afi_safi=\"IPv4/Unicast\"}} 0
bgpgg_adj_rib_in_afi_safi_route_count{{peer=\"127.0.0.2\",afi_safi=\"IPv6/Unicast\"}} 0
bgpgg_adj_rib_in_afi_safi_route_count{{peer=\"127.0.0.2\",afi_safi=\"LinkState/LinkState\"}} 0
# TYPE bgpgg_adj_rib_in_route_total_count gauge
bgpgg_adj_rib_in_route_total_count 0
# TYPE bgpgg_adj_rib_out_route_count gauge
bgpgg_adj_rib_out_route_count{{peer=\"127.0.0.2\"}} 0
# TYPE bgpgg_adj_rib_out_afi_safi_route_count gauge
bgpgg_adj_rib_out_afi_safi_route_count{{peer=\"127.0.0.2\",afi_safi=\"IPv4/Unicast\"}} 0
bgpgg_adj_rib_out_afi_safi_route_count{{peer=\"127.0.0.2\",afi_safi=\"IPv6/Unicast\"}} 0
bgpgg_adj_rib_out_afi_safi_route_count{{peer=\"127.0.0.2\",afi_safi=\"LinkState/LinkState\"}} 0
# TYPE bgpgg_adj_rib_out_route_total_count gauge
bgpgg_adj_rib_out_route_total_count 0
{process_memory}\
# TYPE bgpgg_messages_received_total counter
bgpgg_messages_received_total{{peer=\"127.0.0.2\",message_type=\"open\"}} 1
bgpgg_messages_received_total{{peer=\"127.0.0.2\",message_type=\"keepalive\"}} X
bgpgg_messages_received_total{{peer=\"127.0.0.2\",message_type=\"update\"}} X
bgpgg_messages_received_total{{peer=\"127.0.0.2\",message_type=\"notification\"}} 0
bgpgg_messages_received_total{{peer=\"127.0.0.2\",message_type=\"route_refresh\"}} 0
# TYPE bgpgg_messages_sent_total counter
bgpgg_messages_sent_total{{peer=\"127.0.0.2\",message_type=\"open\"}} 1
bgpgg_messages_sent_total{{peer=\"127.0.0.2\",message_type=\"keepalive\"}} X
bgpgg_messages_sent_total{{peer=\"127.0.0.2\",message_type=\"update\"}} X
bgpgg_messages_sent_total{{peer=\"127.0.0.2\",message_type=\"notification\"}} 0
bgpgg_messages_sent_total{{peer=\"127.0.0.2\",message_type=\"route_refresh\"}} 0
"
    );
    assert_eq!(mask_dynamic_values(body), expected);

    let not_found = scrape(scrape_port, "/other").await.expect("scrape /other");
    assert!(
        not_found.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "{not_found}"
    );
}

#[tokio::test]
async fn test_prometheus_reconfigure() {
    let port_a = free_port();
    let config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 90)
        .with_telemetry(prometheus_telemetry(port_a));
    let server = start_test_server(config).await;

    poll_until(
        || async { scrape(port_a, "/metrics").await.is_some() },
        "Timeout waiting for initial listener",
    )
    .await;

    // Move the listener to a new port.
    let port_b = free_port();
    let mut new_config = server.read_conf();
    new_config.telemetry = Some(prometheus_telemetry(port_b));
    server
        .commit_config(new_config.to_conf_str())
        .await
        .expect("commit listen change");
    assert_metric(&server, "ConfigReloadSuccessCount", &[], &[]).await;

    poll_until(
        || async {
            scrape(port_b, "/metrics").await.is_some() && scrape(port_a, "/metrics").await.is_none()
        },
        "Timeout waiting for listener to move ports",
    )
    .await;

    // Remove the prometheus block; the listener must stop.
    let mut new_config = server.read_conf();
    new_config.telemetry = None;
    server
        .commit_config(new_config.to_conf_str())
        .await
        .expect("commit telemetry removal");

    poll_until(
        || async { scrape(port_b, "/metrics").await.is_none() },
        "Timeout waiting for listener to stop",
    )
    .await;
}
