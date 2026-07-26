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

use std::sync::{Arc, Mutex};

use crate::{MetricRecord, Sink};

/// Records every emitted metric for test assertions.
#[derive(Clone, Default)]
pub struct CaptureSink {
    records: Arc<Mutex<Vec<MetricRecord>>>,
}

impl CaptureSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> Vec<MetricRecord> {
        self.records
            .lock()
            .map(|records| records.clone())
            .unwrap_or_default()
    }

    /// Records matching name whose dimensions include every given pair.
    pub fn find(&self, name: &str, dimensions: &[(&str, &str)]) -> Vec<MetricRecord> {
        self.records()
            .into_iter()
            .filter(|record| {
                record.name == name
                    && dimensions.iter().all(|(key, value)| {
                        record
                            .dimensions
                            .iter()
                            .any(|(rkey, rvalue)| rkey == key && rvalue == value)
                    })
            })
            .collect()
    }
}

impl Sink for CaptureSink {
    fn emit(&self, record: &MetricRecord) {
        if let Ok(mut records) = self.records.lock() {
            records.push(record.clone());
        }
    }
}
