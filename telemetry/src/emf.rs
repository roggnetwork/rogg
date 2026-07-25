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

//! CloudWatch Embedded Metric Format sink. One self-describing JSON line per
//! metric; CloudWatch Logs extracts the metric server-side, no SDK involved.
//! CloudWatch silently drops malformed EMF, so the byte-exact tests here are
//! load-bearing.

use std::io;
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Map, Value as JsonValue};

use crate::{write_line, Clock, MetricRecord, Sink, SystemClock};

pub struct EmfSink {
    namespace: String,
    clock: Box<dyn Clock>,
    out: Mutex<Box<dyn Write + Send>>,
}

impl EmfSink {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            clock: Box::new(SystemClock),
            out: Mutex::new(Box::new(io::stdout())),
        }
    }
}

/// The record's dimension sets, each with "router_id" added, sorted.
/// CloudWatch only builds series for declared sets. No sets -> router_id only.
fn dimension_sets(record: &MetricRecord) -> Vec<Vec<String>> {
    if record.dimension_sets.is_empty() {
        return vec![vec!["router_id".to_string()]];
    }
    record
        .dimension_sets
        .iter()
        .map(|set| {
            let mut set: Vec<String> = set.clone();
            set.push("router_id".to_string());
            set.sort();
            set.dedup();
            set
        })
        .collect()
}

impl Sink for EmfSink {
    fn emit(&self, record: &MetricRecord) {
        let Some(number) = record.value.to_json_number() else {
            return;
        };

        let millis = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis();
        let timestamp = u64::try_from(millis).unwrap_or(0);

        let mut metric_entry = Map::new();
        metric_entry.insert("Name".to_string(), JsonValue::String(record.name.clone()));
        metric_entry.insert(
            "Unit".to_string(),
            JsonValue::String(record.unit.as_str().to_string()),
        );

        let mut directive = Map::new();
        directive.insert(
            "Dimensions".to_string(),
            JsonValue::Array(
                dimension_sets(record)
                    .into_iter()
                    .map(|set| JsonValue::Array(set.into_iter().map(JsonValue::String).collect()))
                    .collect(),
            ),
        );
        directive.insert(
            "Metrics".to_string(),
            JsonValue::Array(vec![JsonValue::Object(metric_entry)]),
        );
        directive.insert(
            "Namespace".to_string(),
            JsonValue::String(self.namespace.clone()),
        );

        let mut aws = Map::new();
        aws.insert(
            "CloudWatchMetrics".to_string(),
            JsonValue::Array(vec![JsonValue::Object(directive)]),
        );
        aws.insert("Timestamp".to_string(), JsonValue::Number(timestamp.into()));

        let mut root = Map::new();
        for (key, val) in &record.context {
            root.insert(key.clone(), JsonValue::String(val.clone()));
        }
        for (key, val) in &record.dimensions {
            root.insert(key.clone(), JsonValue::String(val.clone()));
        }
        root.insert(
            "router_id".to_string(),
            JsonValue::String(record.router_id.clone()),
        );
        root.insert("_aws".to_string(), JsonValue::Object(aws));
        root.insert(record.name.clone(), JsonValue::Number(number));
        write_line(&self.out, &JsonValue::Object(root));
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use crate::test_util::{with_sink, FixedClock, SharedBuffer};
    use crate::{metric, Clock, Unit};

    use super::EmfSink;

    impl EmfSink {
        fn with_clock(mut self, clock: impl Clock + 'static) -> Self {
            self.clock = Box::new(clock);
            self
        }

        fn with_writer(mut self, writer: impl Write + Send + 'static) -> Self {
            self.out = Mutex::new(Box::new(writer));
            self
        }
    }

    fn sink_with_buffer() -> (Arc<EmfSink>, SharedBuffer) {
        let buffer = SharedBuffer::new();
        let sink = EmfSink::new("Rogg/Bgpgg")
            .with_clock(FixedClock::at_millis(1784971456789))
            .with_writer(buffer.clone());
        (Arc::new(sink), buffer)
    }

    #[test]
    fn test_output_line() {
        let (sink, buffer) = sink_with_buffer();
        with_sink(sink, || {
            metric(
                "notification_received_count",
                1,
                Unit::Count,
                &[("peer", &"10.0.0.1")],
                &[&["peer"]],
                &[("code", &6)],
            );
        });
        assert_eq!(
            buffer.contents(),
            concat!(
                r#"{"_aws":{"CloudWatchMetrics":[{"Dimensions":[["peer","router_id"]],"Metrics":[{"Name":"notification_received_count","Unit":"Count"}],"Namespace":"Rogg/Bgpgg"}],"Timestamp":1784971456789},"code":"6","notification_received_count":1,"peer":"10.0.0.1","router_id":"1.1.1.1"}"#,
                "\n"
            )
        );
    }

    #[test]
    fn test_output_line_multi_dimension_sets() {
        let (sink, buffer) = sink_with_buffer();
        with_sink(sink, || {
            metric(
                "session_convergence_ms",
                420u64,
                Unit::Milliseconds,
                &[("peer", &"10.0.0.1"), ("afi_safi", &"ipv4-unicast")],
                &[&["peer"], &["afi_safi"], &["peer", "afi_safi"]],
                &[],
            );
        });
        // Each declared set becomes a CloudWatch series, router_id in all.
        assert_eq!(
            buffer.contents(),
            concat!(
                r#"{"_aws":{"CloudWatchMetrics":[{"Dimensions":[["peer","router_id"],["afi_safi","router_id"],["afi_safi","peer","router_id"]],"Metrics":[{"Name":"session_convergence_ms","Unit":"Milliseconds"}],"Namespace":"Rogg/Bgpgg"}],"Timestamp":1784971456789},"afi_safi":"ipv4-unicast","peer":"10.0.0.1","router_id":"1.1.1.1","session_convergence_ms":420}"#,
                "\n"
            )
        );
    }

    #[test]
    fn test_output_line_no_dims_router_id_only() {
        let (sink, buffer) = sink_with_buffer();
        with_sink(sink, || {
            metric("process_memory_bytes", 1024u64, Unit::Bytes, &[], &[], &[]);
        });
        assert_eq!(
            buffer.contents(),
            concat!(
                r#"{"_aws":{"CloudWatchMetrics":[{"Dimensions":[["router_id"]],"Metrics":[{"Name":"process_memory_bytes","Unit":"Bytes"}],"Namespace":"Rogg/Bgpgg"}],"Timestamp":1784971456789},"process_memory_bytes":1024,"router_id":"1.1.1.1"}"#,
                "\n"
            )
        );
    }

    #[test]
    fn test_nan_value_dropped() {
        let (sink, buffer) = sink_with_buffer();
        with_sink(sink, || {
            metric("bad_value", f64::NAN, Unit::Count, &[], &[], &[]);
        });
        assert_eq!(buffer.contents(), "");
    }
}
