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

//! Metric emission for rogg daemons.
//!
//! `metric()` writes one line to the configured sink per call. With no sink
//! configured (the default), calls cost one atomic load and return. Sinks render
//! the same `MetricRecord` in different formats: `JsonSink` for plain structured
//! lines (extracted platform-side by GCP, Datadog, etc.), `EmfSink` for CloudWatch
//! Embedded Metric Format, `CaptureSink` for test assertions.

use std::fmt::Display;
use std::io::Write;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};

mod emf;
mod json;

pub use emf::EmfSink;
pub use json::JsonSink;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unit {
    Count,
    Milliseconds,
    Microseconds,
    Seconds,
    Bytes,
    Percent,
}

impl Unit {
    pub fn as_str(self) -> &'static str {
        match self {
            Unit::Count => "Count",
            Unit::Milliseconds => "Milliseconds",
            Unit::Microseconds => "Microseconds",
            Unit::Seconds => "Seconds",
            Unit::Bytes => "Bytes",
            Unit::Percent => "Percent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    Int(i64),
    UInt(u64),
    Float(f64),
}

impl Value {
    /// None for NaN/infinite floats; such emissions are dropped.
    pub(crate) fn to_json_number(self) -> Option<serde_json::Number> {
        match self {
            Value::Int(int) => Some(serde_json::Number::from(int)),
            Value::UInt(uint) => Some(serde_json::Number::from(uint)),
            Value::Float(float) => serde_json::Number::from_f64(float),
        }
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Value::Int(value.into())
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Value::Int(value)
    }
}

impl From<u32> for Value {
    fn from(value: u32) -> Self {
        Value::UInt(value.into())
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Value::UInt(value)
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Value::UInt(value as u64)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Value::Float(value)
    }
}

/// One metric emission: name, value, unit, dimensions (slice the metric by
/// these), context (logged alongside, never extracted).
#[derive(Debug, Clone, PartialEq)]
pub struct MetricRecord {
    pub name: String,
    pub value: Value,
    pub unit: Unit,
    pub dimensions: Vec<(String, String)>,
    pub context: Vec<(String, String)>,
}

pub trait Sink: Send + Sync {
    fn emit(&self, record: &MetricRecord);
}

struct Telemetry {
    sink: RwLock<Option<Arc<dyn Sink>>>,
}

impl Telemetry {
    const fn new() -> Self {
        Self {
            sink: RwLock::new(None),
        }
    }

    fn set_sink(&self, sink: Option<Arc<dyn Sink>>) {
        if let Ok(mut slot) = self.sink.write() {
            *slot = sink;
        }
    }

    fn get_sink(&self) -> Option<Arc<dyn Sink>> {
        self.sink.read().ok().and_then(|slot| slot.clone())
    }
}

static TELEMETRY: Telemetry = Telemetry::new();

/// Install (or replace, or remove with None) the process-wide sink. Used at
/// daemon startup and for config hot reload.
pub fn set_sink(sink: Option<Arc<dyn Sink>>) {
    TELEMETRY.set_sink(sink)
}

/// Emit one metric. Dimension and context values are formatted via Display
/// only when a sink is configured.
pub fn metric(
    name: &str,
    value: impl Into<Value>,
    unit: Unit,
    dimensions: &[(&str, &dyn Display)],
    context: &[(&str, &dyn Display)],
) {
    let sink = match TELEMETRY.get_sink() {
        Some(sink) => sink,
        None => return,
    };
    let record = MetricRecord {
        name: name.to_string(),
        value: value.into(),
        unit,
        dimensions: dimensions
            .iter()
            .map(|(key, val)| (key.to_string(), val.to_string()))
            .collect(),
        context: context
            .iter()
            .map(|(key, val)| (key.to_string(), val.to_string()))
            .collect(),
    };
    sink.emit(&record);
}

pub(crate) trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub(crate) fn rfc3339_millis(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Serialize and write as a single write_all so concurrent writers to the same
/// stream cannot interleave partial lines. Errors are ignored: telemetry must
/// never take the daemon down.
pub(crate) fn write_line(out: &Mutex<Box<dyn Write + Send>>, root: &serde_json::Value) {
    let Ok(mut line) = serde_json::to_vec(root) else {
        return;
    };
    line.push(b'\n');
    if let Ok(mut writer) = out.lock() {
        let _ = writer.write_all(&line);
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use std::io;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::{set_sink, Clock, MetricRecord, Sink};

    pub(crate) static SINK_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Default)]
    pub(crate) struct CaptureSink {
        records: Arc<Mutex<Vec<MetricRecord>>>,
    }

    impl CaptureSink {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn records(&self) -> Vec<MetricRecord> {
            self.records
                .lock()
                .map(|records| records.clone())
                .unwrap_or_default()
        }
    }

    impl Sink for CaptureSink {
        fn emit(&self, record: &MetricRecord) {
            if let Ok(mut records) = self.records.lock() {
                records.push(record.clone());
            }
        }
    }

    /// Run `body` with `sink` installed as the process-wide sink, exactly as
    /// production installs it. Tests that emit metrics serialize on SINK_LOCK
    /// so they don't clobber each other's sink.
    pub(crate) fn with_sink<R>(sink: Arc<dyn Sink>, body: impl FnOnce() -> R) -> R {
        let guard = SINK_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        set_sink(Some(sink));
        let result = body();
        set_sink(None);
        drop(guard);
        result
    }

    #[derive(Clone, Default)]
    pub(crate) struct SharedBuffer {
        data: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedBuffer {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn contents(&self) -> String {
            let data = self.data.lock().unwrap();
            String::from_utf8(data.clone()).unwrap()
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub(crate) struct FixedClock(SystemTime);

    impl FixedClock {
        pub(crate) fn at_millis(millis: u64) -> Self {
            Self(UNIX_EPOCH + Duration::from_millis(millis))
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::test_util::{with_sink, CaptureSink};
    use crate::{metric, Unit, Value};

    #[test]
    fn test_unit_strings() {
        let cases = [
            (Unit::Count, "Count"),
            (Unit::Milliseconds, "Milliseconds"),
            (Unit::Microseconds, "Microseconds"),
            (Unit::Seconds, "Seconds"),
            (Unit::Bytes, "Bytes"),
            (Unit::Percent, "Percent"),
        ];
        for (unit, expected) in cases {
            assert_eq!(unit.as_str(), expected);
        }
    }

    #[test]
    fn test_value_from_impls() {
        assert_eq!(Value::from(-3i64), Value::Int(-3));
        assert_eq!(Value::from(7i32), Value::Int(7));
        assert_eq!(Value::from(7u32), Value::UInt(7));
        assert_eq!(Value::from(7u64), Value::UInt(7));
        assert_eq!(Value::from(7usize), Value::UInt(7));
        assert_eq!(Value::from(1.5f64), Value::Float(1.5));
    }

    #[test]
    fn test_metric_with_sink() {
        let capture = Arc::new(CaptureSink::new());
        with_sink(capture.clone(), || {
            metric(
                "probe",
                2u64,
                Unit::Count,
                &[("peer", &"10.0.0.1")],
                &[("reason", &"test")],
            );
        });
        let records = capture.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "probe");
        assert_eq!(records[0].value, Value::UInt(2));
        assert_eq!(records[0].unit, Unit::Count);
        assert_eq!(
            records[0].dimensions,
            vec![("peer".to_string(), "10.0.0.1".to_string())]
        );
        assert_eq!(
            records[0].context,
            vec![("reason".to_string(), "test".to_string())]
        );
    }
}
