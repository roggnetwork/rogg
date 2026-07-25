// Copyright 2026 bgpgg Authors
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

pub mod sets;
pub mod statement;

pub use sets::{DefinedSetType, DefinedSets};
use statement::Action;
pub use statement::{CommunityOp, RouteType, Statement};

use crate::bgp::multiprotocol::AfiSafi;
use crate::rib::{Path, RouteKey};
use conf::bgp::{BgpConfig, PolicyDefinitionConfig};
use std::collections::HashMap;
use std::sync::Arc;

/// Resolved policies keyed by AFI/SAFI. Used for both import and export sides.
pub type AfiSafiPolicies = HashMap<AfiSafi, Vec<Arc<Policy>>>;

/// Built-in policy that permits all routes. Fallback for iBGP import and export.
pub const DEFAULT_PERMIT_ALL: &str = "default-permit-all";

/// Built-in policy that denies all routes. Fallback for eBGP import and export (RFC 8212).
pub const DEFAULT_DENY_ALL: &str = "default-deny-all";

/// Result of policy evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyResult {
    /// Accept route, stop processing
    Accept,
    /// Reject route, stop processing
    Reject,
    /// No match, try next policy
    Continue,
}

/// A policy consisting of multiple statements evaluated in order
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub name: String,
    statements: Vec<Statement>,
}

impl Policy {
    pub fn new(name: String) -> Self {
        Self {
            name,
            statements: Vec::new(),
        }
    }

    /// Get the statements (for API responses)
    pub fn statements(&self) -> &[Statement] {
        &self.statements
    }

    /// Permit all routes. Fallback for iBGP import and export when no user policy is configured.
    pub fn permit_all() -> Self {
        Self::new(DEFAULT_PERMIT_ALL.to_string()).with(Statement::new().then(Action::Accept))
    }

    /// Deny all routes. Fallback for eBGP import and export when no user policy is configured (RFC 8212).
    pub fn deny_all() -> Self {
        Self::new(DEFAULT_DENY_ALL.to_string()).with(Statement::new().then(Action::Reject))
    }

    /// Returns true if this is a reserved policy name
    pub fn is_reserved_name(name: &str) -> bool {
        name == DEFAULT_PERMIT_ALL || name == DEFAULT_DENY_ALL
    }

    /// Create a policy from YAML config
    pub fn from_config(
        def: &PolicyDefinitionConfig,
        defined_sets: &DefinedSets,
    ) -> Result<Self, String> {
        if Self::is_reserved_name(&def.name) {
            return Err(format!("policy name '{}' is reserved", def.name));
        }
        let mut policy = Policy::new(def.name.clone());

        for stmt_def in &def.statements {
            let stmt = statement::build_statement(stmt_def, defined_sets)?;
            policy = policy.with(stmt);
        }

        Ok(policy)
    }

    /// Add a statement to the policy
    pub fn with(mut self, statement: Statement) -> Self {
        self.statements.push(statement);
        self
    }

    /// Evaluate the policy against a route
    /// Returns PolicyResult indicating whether to Accept, Reject, or Continue
    pub fn evaluate(&self, route_key: &RouteKey, path: &mut Path) -> PolicyResult {
        // Try each statement in order
        for statement in &self.statements {
            if let Some(accept) = statement.apply(route_key, path) {
                return if accept {
                    PolicyResult::Accept
                } else {
                    PolicyResult::Reject
                };
            }
        }
        // No statement matched - continue to next policy
        PolicyResult::Continue
    }

    /// Evaluate the policy against a route (convenience wrapper)
    /// Returns true if the route is accepted, false if rejected
    /// If no statements match, rejects the route
    pub fn accept(&self, route_key: &RouteKey, path: &mut Path) -> bool {
        matches!(self.evaluate(route_key, path), PolicyResult::Accept)
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new(String::new())
    }
}

/// Reserved policy names that users cannot use in config
pub const RESERVED_POLICY_NAMES: &[&str] = &[DEFAULT_PERMIT_ALL, DEFAULT_DENY_ALL];

/// Policy context containing compiled policies and defined sets
pub struct PolicyContext {
    pub policies: HashMap<String, Arc<Policy>>,
    pub defined_sets: Arc<DefinedSets>,
}

impl PolicyContext {
    /// Build policy context from config
    pub fn from_config(config: &BgpConfig) -> Result<Self, String> {
        // Compile defined sets
        let defined_sets = Arc::new(DefinedSets::new(&config.defined_sets)?);

        // Build named policies
        let mut policies = HashMap::new();
        for policy_def in &config.policy_definitions {
            let policy = Policy::from_config(policy_def, &defined_sets)?;
            policies.insert(policy_def.name.clone(), Arc::new(policy));
        }

        // Register built-in policies
        policies.insert(
            DEFAULT_PERMIT_ALL.to_string(),
            Arc::new(Policy::permit_all()),
        );
        policies.insert(DEFAULT_DENY_ALL.to_string(), Arc::new(Policy::deny_all()));

        Ok(PolicyContext {
            policies,
            defined_sets,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::bgp::msg_update::{NextHopAddr, Origin};
    use crate::net::{IpNetwork, Ipv4Net};
    use crate::rib::{Path, PathAttrs, RouteSource};
    use crate::rpki::vrp::RpkiValidation;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    pub fn create_path(source: RouteSource) -> Path {
        Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin: Origin::IGP,
                as_path: vec![],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                source,
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
                ls_attr: None,
            }),
        }
    }

    pub fn test_prefix() -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })
    }
}
