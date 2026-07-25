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

//! Prometheus exposition: text format 0.0.4 renderer and a minimal HTTP
//! listener. Daemons supply a handler that returns the metric families for
//! one scrape; identity labels (instance/job) are the scraper's job.

use std::convert::Infallible;
use std::fmt::Write;
use std::future::Future;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

pub const CONTENT_TYPE_TEXT: &str = "text/plain; version=0.0.4";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
}

impl MetricType {
    pub fn as_str(self) -> &'static str {
        match self {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub labels: Vec<(String, String)>,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetricFamily {
    pub name: String,
    pub metric_type: MetricType,
    pub samples: Vec<Sample>,
}

/// Render text exposition format 0.0.4: a `# TYPE` line per family, then one
/// line per sample. Families with no samples are skipped.
pub fn render(families: &[MetricFamily]) -> String {
    let mut out = String::new();
    for family in families {
        if family.samples.is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "# TYPE {} {}",
            family.name,
            family.metric_type.as_str()
        );
        for sample in &family.samples {
            out.push_str(&family.name);
            if !sample.labels.is_empty() {
                out.push('{');
                for (index, (key, value)) in sample.labels.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "{}=\"{}\"", key, escape_label_value(value));
                }
                out.push('}');
            }
            let _ = writeln!(out, " {}", sample.value);
        }
    }
    out
}

fn escape_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Accept loop serving scrapes until the task is aborted. GET /metrics runs
/// the handler: Some -> 200 with the rendered body, None -> 503. Any other
/// request -> 404. Accept and connection errors are ignored; the loop
/// continues.
pub async fn serve<F, Fut>(listener: TcpListener, handler: F)
where
    F: Fn() -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Option<Vec<MetricFamily>>> + Send + 'static,
{
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let handler = handler.clone();
                async move { Ok::<_, Infallible>(handle_request(&request, handler).await) }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn handle_request<F, Fut>(request: &Request<Incoming>, handler: F) -> Response<Full<Bytes>>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Option<Vec<MetricFamily>>>,
{
    if request.method() != Method::GET || request.uri().path() != "/metrics" {
        let mut response = Response::new(Full::new(Bytes::new()));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    }
    match handler().await {
        Some(families) => {
            let mut response = Response::new(Full::new(Bytes::from(render(&families))));
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE_TEXT));
            response
        }
        None => {
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    fn family(
        name: &str,
        metric_type: MetricType,
        samples: Vec<(Vec<(&str, &str)>, f64)>,
    ) -> MetricFamily {
        MetricFamily {
            name: name.to_string(),
            metric_type,
            samples: samples
                .into_iter()
                .map(|(labels, value)| Sample {
                    labels: labels
                        .into_iter()
                        .map(|(key, val)| (key.to_string(), val.to_string()))
                        .collect(),
                    value,
                })
                .collect(),
        }
    }

    #[test]
    fn test_render() {
        let families = [
            family("bgpgg_peers", MetricType::Gauge, vec![(vec![], 2.0)]),
            family(
                "bgpgg_messages_received_total",
                MetricType::Counter,
                vec![
                    (vec![("peer", "10.0.0.1"), ("type", "open")], 1.0),
                    (vec![("peer", "10.0.0.1"), ("type", "update")], 42.0),
                ],
            ),
            family(
                "bgpgg_process_memory_bytes",
                MetricType::Gauge,
                vec![(vec![], 1.5)],
            ),
        ];
        assert_eq!(
            render(&families),
            "# TYPE bgpgg_peers gauge\n\
             bgpgg_peers 2\n\
             # TYPE bgpgg_messages_received_total counter\n\
             bgpgg_messages_received_total{peer=\"10.0.0.1\",type=\"open\"} 1\n\
             bgpgg_messages_received_total{peer=\"10.0.0.1\",type=\"update\"} 42\n\
             # TYPE bgpgg_process_memory_bytes gauge\n\
             bgpgg_process_memory_bytes 1.5\n"
        );
    }

    #[test]
    fn test_render_empty_family_skipped() {
        let families = [
            family("bgpgg_empty", MetricType::Gauge, vec![]),
            family("bgpgg_peers", MetricType::Gauge, vec![(vec![], 0.0)]),
        ];
        assert_eq!(
            render(&families),
            "# TYPE bgpgg_peers gauge\nbgpgg_peers 0\n"
        );
        assert_eq!(render(&[]), "");
    }

    #[test]
    fn test_render_label_escaping() {
        let families = [family(
            "probe",
            MetricType::Gauge,
            vec![(vec![("name", "a\\b\"c\nd")], 1.0)],
        )];
        assert_eq!(
            render(&families),
            "# TYPE probe gauge\nprobe{name=\"a\\\\b\\\"c\\nd\"} 1\n"
        );
    }

    async fn scrape(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn test_serve() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve(listener, || async {
            Some(vec![family(
                "bgpgg_peers",
                MetricType::Gauge,
                vec![(vec![], 1.0)],
            )])
        }));

        let response = scrape(addr, "/metrics").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains("content-type: text/plain; version=0.0.4\r\n"),
            "{response}"
        );
        assert!(
            response.ends_with("# TYPE bgpgg_peers gauge\nbgpgg_peers 1\n"),
            "{response}"
        );

        let response = scrape(addr, "/other").await;
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{response}"
        );

        task.abort();
    }

    #[tokio::test]
    async fn test_serve_handler_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(serve(listener, || async { None }));

        let response = scrape(addr, "/metrics").await;
        assert!(
            response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
            "{response}"
        );

        task.abort();
    }
}
