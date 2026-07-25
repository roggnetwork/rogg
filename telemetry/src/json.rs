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

//! Plain JSON sink: one self-contained line per metric, extracted platform-side
//! (GCP log-based metrics, Datadog, Azure, Alibaba SLS, Loki).

use std::io;
use std::io::Write;
use std::sync::Mutex;

use serde_json::{Map, Value as JsonValue};

use crate::{write_line, Clock, MetricRecord, Sink, SystemClock};

pub struct JsonSink {
    host: String,
    clock: Box<dyn Clock>,
    out: Mutex<Box<dyn Write + Send>>,
}

impl JsonSink {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            clock: Box::new(SystemClock),
            out: Mutex::new(Box::new(io::stdout())),
        }
    }
}

impl Sink for JsonSink {
    fn emit(&self, record: &MetricRecord) {
        let Some(number) = record.value.to_json_number() else {
            return;
        };
        let mut root = Map::new();
        for (key, val) in &record.context {
            root.insert(key.clone(), JsonValue::String(val.clone()));
        }
        if !record.dimensions.is_empty() {
            let mut dimensions = Map::new();
            for (key, val) in &record.dimensions {
                dimensions.insert(key.clone(), JsonValue::String(val.clone()));
            }
            root.insert("dim".to_string(), JsonValue::Object(dimensions));
        }
        root.insert(
            "ts".to_string(),
            JsonValue::String(crate::rfc3339_millis(self.clock.now())),
        );
        root.insert("host".to_string(), JsonValue::String(self.host.clone()));
        root.insert("metric".to_string(), JsonValue::String(record.name.clone()));
        root.insert(
            "unit".to_string(),
            JsonValue::String(record.unit.as_str().to_string()),
        );
        root.insert("value".to_string(), JsonValue::Number(number));
        write_line(&self.out, &JsonValue::Object(root));
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use crate::test_util::{with_sink, FixedClock, SharedBuffer};
    use crate::{metric, Clock, Unit};

    use super::JsonSink;

    impl JsonSink {
        fn with_clock(mut self, clock: impl Clock + 'static) -> Self {
            self.clock = Box::new(clock);
            self
        }

        fn with_writer(mut self, writer: impl Write + Send + 'static) -> Self {
            self.out = Mutex::new(Box::new(writer));
            self
        }
    }

    fn sink_with_buffer() -> (Arc<JsonSink>, SharedBuffer) {
        let buffer = SharedBuffer::new();
        let sink = JsonSink::new("edge03")
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
            "{\"code\":\"6\",\"dim\":{\"peer\":\"10.0.0.1\"},\"host\":\"edge03\",\"metric\":\"notification_received\",\"ts\":\"2026-07-25T09:24:16.789Z\",\"unit\":\"Count\",\"value\":1}\n"
        );
    }

    #[test]
    fn test_output_line_no_dims() {
        let (sink, buffer) = sink_with_buffer();
        with_sink(sink, || {
            metric("process_memory", 4096u64, Unit::Bytes, &[], &[]);
        });
        assert_eq!(
            buffer.contents(),
            "{\"host\":\"edge03\",\"metric\":\"process_memory\",\"ts\":\"2026-07-25T09:24:16.789Z\",\"unit\":\"Bytes\",\"value\":4096}\n"
        );
    }

    #[test]
    fn test_output_line_float_and_negative() {
        let (sink, buffer) = sink_with_buffer();
        with_sink(sink, || {
            metric("cpu_usage", 12.5, Unit::Percent, &[], &[]);
            metric("clock_skew", -250i64, Unit::Milliseconds, &[], &[]);
        });
        assert_eq!(
            buffer.contents(),
            "{\"host\":\"edge03\",\"metric\":\"cpu_usage\",\"ts\":\"2026-07-25T09:24:16.789Z\",\"unit\":\"Percent\",\"value\":12.5}\n{\"host\":\"edge03\",\"metric\":\"clock_skew\",\"ts\":\"2026-07-25T09:24:16.789Z\",\"unit\":\"Milliseconds\",\"value\":-250}\n"
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
