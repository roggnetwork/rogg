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
    host: String,
    clock: Box<dyn Clock>,
    out: Mutex<Box<dyn Write + Send>>,
}

impl EmfSink {
    pub fn new(namespace: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            host: host.into(),
            clock: Box::new(SystemClock),
            out: Mutex::new(Box::new(io::stdout())),
        }
    }
}

impl Sink for EmfSink {
    fn emit(&self, record: &MetricRecord) {
        let Some(number) = record.value.to_json_number() else {
            return;
        };
        let mut dim_names: Vec<String> = record
            .dimensions
            .iter()
            .map(|(key, _)| key.clone())
            .collect();
        dim_names.push("host".to_string());
        dim_names.sort();
        dim_names.dedup();

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
            JsonValue::Array(vec![JsonValue::Array(
                dim_names.into_iter().map(JsonValue::String).collect(),
            )]),
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
        root.insert("host".to_string(), JsonValue::String(self.host.clone()));
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
        let sink = EmfSink::new("Rogg/Bgpgg", "edge03")
            .with_clock(FixedClock::at_millis(1784971456789))
            .with_writer(buffer.clone());
        (Arc::new(sink), buffer)
    }

    #[test]
    fn test_output_line() {
        let (sink, buffer) = sink_with_buffer();
        with_sink(sink, || {
            metric(
                "notification_received",
                1,
                Unit::Count,
                &[("peer", &"10.0.0.1")],
                &[("code", &6)],
            );
        });
        assert_eq!(
            buffer.contents(),
            "{\"_aws\":{\"CloudWatchMetrics\":[{\"Dimensions\":[[\"host\",\"peer\"]],\"Metrics\":[{\"Name\":\"notification_received\",\"Unit\":\"Count\"}],\"Namespace\":\"Rogg/Bgpgg\"}],\"Timestamp\":1784971456789},\"code\":\"6\",\"host\":\"edge03\",\"notification_received\":1,\"peer\":\"10.0.0.1\"}\n"
        );
    }

    #[test]
    fn test_output_line_multi_dim_sorted() {
        let (sink, buffer) = sink_with_buffer();
        with_sink(sink, || {
            metric(
                "session_convergence",
                420u64,
                Unit::Milliseconds,
                &[("peer", &"10.0.0.1"), ("afi_safi", &"ipv4-unicast")],
                &[],
            );
        });
        assert_eq!(
            buffer.contents(),
            "{\"_aws\":{\"CloudWatchMetrics\":[{\"Dimensions\":[[\"afi_safi\",\"host\",\"peer\"]],\"Metrics\":[{\"Name\":\"session_convergence\",\"Unit\":\"Milliseconds\"}],\"Namespace\":\"Rogg/Bgpgg\"}],\"Timestamp\":1784971456789},\"afi_safi\":\"ipv4-unicast\",\"host\":\"edge03\",\"peer\":\"10.0.0.1\",\"session_convergence\":420}\n"
        );
    }

    #[test]
    fn test_nan_value_dropped() {
        let (sink, buffer) = sink_with_buffer();
        with_sink(sink, || {
            metric("bad_value", f64::NAN, Unit::Count, &[], &[]);
        });
        assert_eq!(buffer.contents(), "");
    }
}
