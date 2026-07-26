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

use std::collections::BTreeSet;
use std::str::FromStr;

use conf::bgp::{Afi, Safi, TransportType};
use conf::language::{Root, Service};
use conf::language_bgp::{
    BgpLsBlock, BgpLsKey, BgpServiceBody, BmpServerBlock, BmpServerKey, CloudwatchEmfBlock,
    FamilyBlock, FamilyDirective, FamilyDirectiveKey, OriginateRoute, PeerBlock, PeerKey,
    PolicyBlock, PolicyRule, PrefixListBlock, PrometheusBlock, RpkiCacheBlock, RpkiCacheKey,
    Setting, TelemetryBlock, TopKey,
};

use crate::shell::{Shell, ShellLevel};

pub fn enter_configure(shell: &mut Shell) -> Result<(), String> {
    if shell.levels.last() != Some(&ShellLevel::Root) {
        return Err("already in configure mode".into());
    }

    let session_lock = conf::fs::acquire_exclusive_lock(&shell.config_path, shell.session_uuid)?;

    let text = match std::fs::read_to_string(&shell.config_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read {}: {}",
                shell.config_path.display(),
                e
            ));
        }
    };

    let root = match conf::language::parse(&text) {
        Ok(r) => r,
        Err(e) => {
            drop(session_lock);
            let _ = std::fs::remove_file(conf::fs::lock_path_for(&shell.config_path));
            return Err(format!(
                "failed to parse {}: {}",
                shell.config_path.display(),
                e
            ));
        }
    };

    shell.candidate = Some(root);
    shell.session_lock = Some(session_lock);
    shell.enter_level(ShellLevel::Configure)?;
    Ok(())
}

pub async fn commit_configure(shell: &mut Shell) -> Result<(), String> {
    if !matches!(
        shell.levels.last(),
        Some(ShellLevel::Configure | ShellLevel::BgpService)
    ) {
        return Err("not in configure mode".into());
    }
    let text = shell
        .candidate
        .as_ref()
        .expect("candidate present whenever Configure level is on the stack")
        .to_string();
    let uuid = shell.session_uuid;

    let result = {
        let client = shell.bgp().await?;
        client.commit_config(text, uuid).await
    };

    match result {
        Ok(()) => {
            // Pop everything above Root and run the configure-mode cleanup.
            while !matches!(shell.levels.last(), Some(ShellLevel::Root) | None) {
                shell.levels.pop();
            }
            let _ = std::fs::remove_file(conf::fs::lock_path_for(&shell.config_path));
            shell.session_lock = None;
            shell.candidate = None;
            Ok(())
        }
        Err(status) => Err(format!("commit failed: {}", status.message())),
    }
}

pub async fn show_running_config(shell: &mut Shell) -> Result<(), String> {
    let client = shell.bgp().await?;
    let text = client
        .get_running_config()
        .await
        .map_err(|status| format!("failed to fetch running config: {}", status.message()))?;
    print!("{}", text);
    Ok(())
}

pub fn show_candidate(shell: &mut Shell) -> Result<(), String> {
    let candidate = shell
        .candidate
        .as_ref()
        .ok_or_else(|| "no candidate config".to_string())?;
    print!("{}", candidate);
    Ok(())
}

pub async fn show_diff(shell: &mut Shell) -> Result<(), String> {
    let candidate = shell
        .candidate
        .clone()
        .ok_or_else(|| "no candidate config".to_string())?;
    let running_text = {
        let client = shell.bgp().await?;
        client
            .get_running_config()
            .await
            .map_err(|status| format!("failed to fetch running config: {}", status.message()))?
    };
    let running = if running_text.trim().is_empty() {
        Root::default()
    } else {
        conf::language::parse(&running_text)
            .map_err(|e| format!("failed to parse running config: {}", e))?
    };

    let candidate_lines: BTreeSet<String> = flatten(&candidate).into_iter().collect();
    let running_lines: BTreeSet<String> = flatten(&running).into_iter().collect();

    for line in running_lines.difference(&candidate_lines) {
        println!("- {}", line);
    }
    for line in candidate_lines.difference(&running_lines) {
        println!("+ {}", line);
    }
    Ok(())
}

pub fn apply_set_top(shell: &mut Shell, key: TopKey, value: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let setting = Setting::parse(key.as_str(), Some(value))?;
    body.settings.retain(|s| !setting_matches_top_key(s, key));
    body.settings.push(setting);
    Ok(())
}

pub fn apply_set_top_originate(
    shell: &mut Shell,
    prefix: &str,
    nexthop: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let route = OriginateRoute {
        prefix: prefix.to_string(),
        nexthop: nexthop.to_string(),
    };
    body.settings
        .retain(|s| !matches!(s, Setting::Originate(r) if r.prefix == prefix));
    body.settings.push(Setting::Originate(route));
    Ok(())
}

pub fn apply_set_peer(
    shell: &mut Shell,
    key: PeerKey,
    addr: &str,
    value: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let peer = peer_mut(body, addr);
    let setting = Setting::parse(key.as_str(), Some(value))?;
    peer.settings.retain(|s| !setting_matches_peer_key(s, key));
    peer.settings.push(setting);
    Ok(())
}

pub fn apply_set_peer_family(
    shell: &mut Shell,
    directive: FamilyDirectiveKey,
    addr: &str,
    afi_str: &str,
    safi_str: &str,
    name: &str,
) -> Result<(), String> {
    let afi = parse_afi(afi_str)?;
    let safi = parse_safi(safi_str)?;
    let body = bgp_body_mut(shell)?;
    let peer = peer_mut(body, addr);
    let family = family_mut(peer, afi, safi);
    let new = match directive {
        FamilyDirectiveKey::ExportPolicy => FamilyDirective::ExportPolicy(name.to_string()),
        FamilyDirectiveKey::ImportPolicy => FamilyDirective::ImportPolicy(name.to_string()),
    };
    family
        .directives
        .retain(|d| !family_directive_matches(d, directive));
    family.directives.push(new);
    Ok(())
}

pub fn apply_set_policy_match(
    shell: &mut Shell,
    name: &str,
    set: &str,
    action: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let policy = policy_mut(body, name);
    policy
        .rules
        .retain(|rule| !matches!(rule, PolicyRule::Match { set_name, .. } if set_name == set));
    policy.rules.push(PolicyRule::Match {
        set_name: set.to_string(),
        action: action.to_string(),
    });
    Ok(())
}

pub fn apply_set_policy_default(shell: &mut Shell, name: &str, action: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let policy = policy_mut(body, name);
    policy
        .rules
        .retain(|rule| !matches!(rule, PolicyRule::Default { .. }));
    policy.rules.push(PolicyRule::Default {
        action: action.to_string(),
    });
    Ok(())
}

pub fn apply_set_prefix_list_entry(
    shell: &mut Shell,
    name: &str,
    prefix: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let plist = prefix_list_mut(body, name);
    if !plist.prefixes.iter().any(|e| e.prefix == prefix) {
        plist.prefixes.push(conf::language_bgp::PrefixListEntry {
            prefix: prefix.to_string(),
            range: None,
        });
    }
    Ok(())
}

pub fn apply_set_bmp_server(
    shell: &mut Shell,
    key: BmpServerKey,
    addr: &str,
    value: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let bmp = bmp_server_mut(body, addr);
    match key {
        BmpServerKey::StatisticsTimeout => {
            bmp.statistics_timeout = Some(parse_value::<u64>(key.as_str(), value)?);
        }
    }
    Ok(())
}

pub fn apply_set_rpki_cache(
    shell: &mut Shell,
    key: RpkiCacheKey,
    addr: &str,
    value: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let rpki = rpki_cache_mut(body, addr);
    match key {
        RpkiCacheKey::Preference => {
            rpki.preference = Some(parse_value::<u8>(key.as_str(), value)?);
        }
        RpkiCacheKey::Transport => {
            rpki.transport = Some(
                TransportType::from_str(value)
                    .map_err(|e| format!("invalid transport '{}': {}", value, e))?,
            );
        }
        RpkiCacheKey::SshUsername => rpki.ssh_username = Some(value.to_string()),
        RpkiCacheKey::SshPrivateKeyFile => rpki.ssh_private_key_file = Some(value.to_string()),
        RpkiCacheKey::SshKnownHostsFile => rpki.ssh_known_hosts_file = Some(value.to_string()),
        RpkiCacheKey::RetryInterval => {
            rpki.retry_interval = Some(parse_value::<u64>(key.as_str(), value)?);
        }
        RpkiCacheKey::RefreshInterval => {
            rpki.refresh_interval = Some(parse_value::<u64>(key.as_str(), value)?);
        }
        RpkiCacheKey::ExpireInterval => {
            rpki.expire_interval = Some(parse_value::<u64>(key.as_str(), value)?);
        }
    }
    Ok(())
}

pub fn apply_set_bgp_ls(shell: &mut Shell, key: BgpLsKey, value: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let block = body.bgp_ls.get_or_insert_with(BgpLsBlock::default);
    match key {
        BgpLsKey::InstanceId => {
            block.instance_id = parse_value::<u64>(key.as_str(), value)?;
        }
    }
    Ok(())
}

pub fn apply_set_telemetry_json(shell: &mut Shell) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let telemetry = body.telemetry.get_or_insert_with(TelemetryBlock::default);
    if telemetry.cloudwatch_emf.is_some() {
        return Err(
            "json and cloudwatch-emf are mutually exclusive; unset telemetry cloudwatch-emf first"
                .into(),
        );
    }
    telemetry.json = true;
    Ok(())
}

pub fn apply_set_telemetry_cloudwatch_emf(
    shell: &mut Shell,
    namespace: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let telemetry = body.telemetry.get_or_insert_with(TelemetryBlock::default);
    if telemetry.json {
        return Err(
            "json and cloudwatch-emf are mutually exclusive; unset telemetry json first".into(),
        );
    }
    telemetry.cloudwatch_emf = Some(CloudwatchEmfBlock {
        namespace: namespace.to_string(),
    });
    Ok(())
}

pub fn apply_set_telemetry_prometheus(shell: &mut Shell) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let telemetry = body.telemetry.get_or_insert_with(TelemetryBlock::default);
    telemetry
        .prometheus
        .get_or_insert_with(PrometheusBlock::default);
    Ok(())
}

pub fn apply_set_telemetry_prometheus_listen(shell: &mut Shell, addr: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let telemetry = body.telemetry.get_or_insert_with(TelemetryBlock::default);
    let prometheus = telemetry
        .prometheus
        .get_or_insert_with(PrometheusBlock::default);
    prometheus.listen = Some(addr.to_string());
    Ok(())
}

pub fn apply_unset_top(shell: &mut Shell, key: TopKey) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let before = body.settings.len();
    body.settings.retain(|s| !setting_matches_top_key(s, key));
    if body.settings.len() == before {
        return Err(format!("{} not set", key.as_str()));
    }
    Ok(())
}

pub fn apply_unset_top_originate(shell: &mut Shell, prefix: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let before = body.settings.len();
    body.settings
        .retain(|s| !matches!(s, Setting::Originate(r) if r.prefix == prefix));
    if body.settings.len() == before {
        return Err(format!("originate {} not set", prefix));
    }
    Ok(())
}

pub fn apply_unset_peer(shell: &mut Shell, addr: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let before = body.peers.len();
    body.peers.retain(|p| p.address != addr);
    if body.peers.len() == before {
        return Err(format!("peer {} not found", addr));
    }
    Ok(())
}

pub fn apply_unset_peer_setting(shell: &mut Shell, key: PeerKey, addr: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let peer = body
        .peers
        .iter_mut()
        .find(|p| p.address == addr)
        .ok_or_else(|| format!("peer {} not found", addr))?;
    let before = peer.settings.len();
    peer.settings.retain(|s| !setting_matches_peer_key(s, key));
    if peer.settings.len() == before {
        return Err(format!("{} not set on peer {}", key.as_str(), addr));
    }
    Ok(())
}

pub fn apply_unset_peer_family(
    shell: &mut Shell,
    addr: &str,
    afi_str: &str,
    safi_str: &str,
) -> Result<(), String> {
    let afi = parse_afi(afi_str)?;
    let safi = parse_safi(safi_str)?;
    let body = bgp_body_mut(shell)?;
    let peer = body
        .peers
        .iter_mut()
        .find(|p| p.address == addr)
        .ok_or_else(|| format!("peer {} not found", addr))?;
    let before = peer.families.len();
    peer.families.retain(|f| !(f.afi == afi && f.safi == safi));
    if peer.families.len() == before {
        return Err(format!(
            "family {} {} not set on peer {}",
            afi_str, safi_str, addr
        ));
    }
    Ok(())
}

pub fn apply_unset_peer_family_directive(
    shell: &mut Shell,
    directive: FamilyDirectiveKey,
    addr: &str,
    afi_str: &str,
    safi_str: &str,
) -> Result<(), String> {
    let afi = parse_afi(afi_str)?;
    let safi = parse_safi(safi_str)?;
    let body = bgp_body_mut(shell)?;
    let peer = body
        .peers
        .iter_mut()
        .find(|p| p.address == addr)
        .ok_or_else(|| format!("peer {} not found", addr))?;
    let family = peer
        .families
        .iter_mut()
        .find(|f| f.afi == afi && f.safi == safi)
        .ok_or_else(|| format!("family {} {} not set on peer {}", afi_str, safi_str, addr))?;
    let before = family.directives.len();
    family
        .directives
        .retain(|d| !family_directive_matches(d, directive));
    if family.directives.len() == before {
        return Err(format!(
            "{} policy not set on peer {} family {} {}",
            directive.as_str(),
            addr,
            afi_str,
            safi_str
        ));
    }
    Ok(())
}

pub fn apply_unset_policy(shell: &mut Shell, name: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let before = body.policies.len();
    body.policies.retain(|p| p.name != name);
    if body.policies.len() == before {
        return Err(format!("policy {} not found", name));
    }
    Ok(())
}

pub fn apply_unset_prefix_list(shell: &mut Shell, name: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let before = body.prefix_lists.len();
    body.prefix_lists.retain(|p| p.name != name);
    if body.prefix_lists.len() == before {
        return Err(format!("prefix-list {} not found", name));
    }
    Ok(())
}

pub fn apply_unset_prefix_list_entry(
    shell: &mut Shell,
    name: &str,
    prefix: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let plist = body
        .prefix_lists
        .iter_mut()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("prefix-list {} not found", name))?;
    let before = plist.prefixes.len();
    plist.prefixes.retain(|e| e.prefix != prefix);
    if plist.prefixes.len() == before {
        return Err(format!("prefix {} not in prefix-list {}", prefix, name));
    }
    Ok(())
}

pub fn apply_unset_bmp_server(shell: &mut Shell, addr: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let before = body.bmp_servers.len();
    body.bmp_servers.retain(|b| b.address != addr);
    if body.bmp_servers.len() == before {
        return Err(format!("bmp-server {} not found", addr));
    }
    Ok(())
}

pub fn apply_unset_bmp_server_setting(
    shell: &mut Shell,
    key: BmpServerKey,
    addr: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let bmp = body
        .bmp_servers
        .iter_mut()
        .find(|b| b.address == addr)
        .ok_or_else(|| format!("bmp-server {} not found", addr))?;
    let was_set = match key {
        BmpServerKey::StatisticsTimeout => bmp.statistics_timeout.take().is_some(),
    };
    if !was_set {
        return Err(format!("{} not set on bmp-server {}", key.as_str(), addr));
    }
    Ok(())
}

pub fn apply_unset_rpki_cache(shell: &mut Shell, addr: &str) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let before = body.rpki_caches.len();
    body.rpki_caches.retain(|r| r.address != addr);
    if body.rpki_caches.len() == before {
        return Err(format!("rpki-cache {} not found", addr));
    }
    Ok(())
}

pub fn apply_unset_rpki_cache_setting(
    shell: &mut Shell,
    key: RpkiCacheKey,
    addr: &str,
) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let rpki = body
        .rpki_caches
        .iter_mut()
        .find(|r| r.address == addr)
        .ok_or_else(|| format!("rpki-cache {} not found", addr))?;
    let was_set = match key {
        RpkiCacheKey::Preference => rpki.preference.take().is_some(),
        RpkiCacheKey::Transport => rpki.transport.take().is_some(),
        RpkiCacheKey::SshUsername => rpki.ssh_username.take().is_some(),
        RpkiCacheKey::SshPrivateKeyFile => rpki.ssh_private_key_file.take().is_some(),
        RpkiCacheKey::SshKnownHostsFile => rpki.ssh_known_hosts_file.take().is_some(),
        RpkiCacheKey::RetryInterval => rpki.retry_interval.take().is_some(),
        RpkiCacheKey::RefreshInterval => rpki.refresh_interval.take().is_some(),
        RpkiCacheKey::ExpireInterval => rpki.expire_interval.take().is_some(),
    };
    if !was_set {
        return Err(format!("{} not set on rpki-cache {}", key.as_str(), addr));
    }
    Ok(())
}

pub fn apply_unset_bgp_ls(shell: &mut Shell) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    if body.bgp_ls.take().is_none() {
        return Err("bgp-ls not set".into());
    }
    Ok(())
}

/// Granular `unset bgp-ls instance-id` is rejected — `instance-id` has no
/// `Option` wrapper, so removing just the field would leave an invalid block.
/// Operators should use `unset bgp-ls` to remove the whole block.
pub fn apply_unset_bgp_ls_setting(shell: &mut Shell, _key: BgpLsKey) -> Result<(), String> {
    let _ = shell;
    Err(
        "instance-id is required when bgp-ls is present; use 'unset bgp-ls' to remove the block"
            .into(),
    )
}

pub fn apply_unset_telemetry(shell: &mut Shell) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    if body.telemetry.take().is_none() {
        return Err("telemetry not set".into());
    }
    Ok(())
}

pub fn apply_unset_telemetry_json(shell: &mut Shell) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let telemetry = body
        .telemetry
        .as_mut()
        .filter(|t| t.json)
        .ok_or_else(|| "telemetry json not set".to_string())?;
    telemetry.json = false;
    Ok(())
}

pub fn apply_unset_telemetry_cloudwatch_emf(shell: &mut Shell) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let was_set = body
        .telemetry
        .as_mut()
        .and_then(|t| t.cloudwatch_emf.take())
        .is_some();
    if !was_set {
        return Err("telemetry cloudwatch-emf not set".into());
    }
    Ok(())
}

pub fn apply_unset_telemetry_prometheus(shell: &mut Shell) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let was_set = body
        .telemetry
        .as_mut()
        .and_then(|t| t.prometheus.take())
        .is_some();
    if !was_set {
        return Err("telemetry prometheus not set".into());
    }
    Ok(())
}

pub fn apply_unset_telemetry_prometheus_listen(shell: &mut Shell) -> Result<(), String> {
    let body = bgp_body_mut(shell)?;
    let was_set = body
        .telemetry
        .as_mut()
        .and_then(|t| t.prometheus.as_mut())
        .and_then(|p| p.listen.take())
        .is_some();
    if !was_set {
        return Err("telemetry prometheus listen not set".into());
    }
    Ok(())
}

fn bgp_body_mut(shell: &mut Shell) -> Result<&mut BgpServiceBody, String> {
    let candidate = shell
        .candidate
        .as_mut()
        .ok_or_else(|| "no candidate config".to_string())?;
    let pos = candidate
        .services
        .iter()
        .position(|s| matches!(s, Service::Bgp(_)));
    let idx = match pos {
        Some(p) => p,
        None => {
            candidate
                .services
                .push(Service::Bgp(BgpServiceBody::default()));
            candidate.services.len() - 1
        }
    };
    let Service::Bgp(body) = &mut candidate.services[idx];
    Ok(body)
}

fn peer_mut<'a>(body: &'a mut BgpServiceBody, addr: &str) -> &'a mut PeerBlock {
    let exists = body.peers.iter().any(|p| p.address == addr);
    if !exists {
        body.peers.push(PeerBlock {
            address: addr.to_string(),
            settings: Vec::new(),
            families: Vec::new(),
        });
    }
    body.peers
        .iter_mut()
        .find(|p| p.address == addr)
        .expect("just inserted")
}

fn family_mut(peer: &mut PeerBlock, afi: Afi, safi: Safi) -> &mut FamilyBlock {
    let exists = peer.families.iter().any(|f| f.afi == afi && f.safi == safi);
    if !exists {
        peer.families.push(FamilyBlock {
            afi,
            safi,
            directives: Vec::new(),
        });
    }
    peer.families
        .iter_mut()
        .find(|f| f.afi == afi && f.safi == safi)
        .expect("just inserted")
}

fn policy_mut<'a>(body: &'a mut BgpServiceBody, name: &str) -> &'a mut PolicyBlock {
    let exists = body.policies.iter().any(|p| p.name == name);
    if !exists {
        body.policies.push(PolicyBlock {
            name: name.to_string(),
            rules: Vec::new(),
        });
    }
    body.policies
        .iter_mut()
        .find(|p| p.name == name)
        .expect("just inserted")
}

fn prefix_list_mut<'a>(body: &'a mut BgpServiceBody, name: &str) -> &'a mut PrefixListBlock {
    let exists = body.prefix_lists.iter().any(|p| p.name == name);
    if !exists {
        body.prefix_lists.push(PrefixListBlock {
            name: name.to_string(),
            prefixes: Vec::new(),
        });
    }
    body.prefix_lists
        .iter_mut()
        .find(|p| p.name == name)
        .expect("just inserted")
}

fn bmp_server_mut<'a>(body: &'a mut BgpServiceBody, addr: &str) -> &'a mut BmpServerBlock {
    let exists = body.bmp_servers.iter().any(|b| b.address == addr);
    if !exists {
        body.bmp_servers.push(BmpServerBlock {
            address: addr.to_string(),
            statistics_timeout: None,
        });
    }
    body.bmp_servers
        .iter_mut()
        .find(|b| b.address == addr)
        .expect("just inserted")
}

fn rpki_cache_mut<'a>(body: &'a mut BgpServiceBody, addr: &str) -> &'a mut RpkiCacheBlock {
    let exists = body.rpki_caches.iter().any(|r| r.address == addr);
    if !exists {
        body.rpki_caches.push(RpkiCacheBlock {
            address: addr.to_string(),
            ..RpkiCacheBlock::default()
        });
    }
    body.rpki_caches
        .iter_mut()
        .find(|r| r.address == addr)
        .expect("just inserted")
}

fn parse_afi(s: &str) -> Result<Afi, String> {
    Afi::from_str(s).map_err(|e| format!("invalid afi '{}': {}", s, e))
}

fn parse_safi(s: &str) -> Result<Safi, String> {
    Safi::from_str(s).map_err(|e| format!("invalid safi '{}': {}", s, e))
}

fn parse_value<T>(key: &str, value: &str) -> Result<T, String>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|e| format!("invalid {} '{}': {}", key, value, e))
}

fn setting_matches_top_key(setting: &Setting, key: TopKey) -> bool {
    matches!(
        (key, setting),
        (TopKey::Asn, Setting::Asn(_))
            | (TopKey::RouterId, Setting::RouterId(_))
            | (TopKey::ListenAddr, Setting::ListenAddr(_))
            | (TopKey::GrpcListenAddr, Setting::GrpcListenAddr(_))
            | (TopKey::LogLevel, Setting::LogLevel(_))
            | (TopKey::HoldTime, Setting::HoldTime(_))
            | (TopKey::ConnectRetry, Setting::ConnectRetry(_))
            | (TopKey::ClusterId, Setting::ClusterId(_))
            | (TopKey::SysName, Setting::SysName(_))
            | (TopKey::SysDescr, Setting::SysDescr(_))
            | (TopKey::EnhancedRrStaleTtl, Setting::EnhancedRrStaleTtl(_))
    )
}

fn setting_matches_peer_key(setting: &Setting, key: PeerKey) -> bool {
    matches!(
        (key, setting),
        (PeerKey::RemoteAs, Setting::RemoteAs(_))
            | (PeerKey::Port, Setting::Port(_))
            | (PeerKey::Interface, Setting::Interface(_))
            | (PeerKey::Md5KeyFile, Setting::Md5KeyFile(_))
            | (PeerKey::TtlMin, Setting::TtlMin(_))
            | (PeerKey::NextHopSelf, Setting::NextHopSelf(_))
            | (PeerKey::Passive, Setting::Passive(_))
            | (PeerKey::RrClient, Setting::RrClient(_))
            | (PeerKey::RsClient, Setting::RsClient(_))
            | (PeerKey::GracefulShutdown, Setting::GracefulShutdown(_))
            | (PeerKey::DelayOpenTimeSecs, Setting::DelayOpenTimeSecs(_))
            | (PeerKey::IdleHoldTimeSecs, Setting::IdleHoldTimeSecs(_))
            | (
                PeerKey::DampPeerOscillations,
                Setting::DampPeerOscillations(_)
            )
            | (PeerKey::AllowAutomaticStop, Setting::AllowAutomaticStop(_))
            | (
                PeerKey::SendNotificationWithoutOpen,
                Setting::SendNotificationWithoutOpen(_)
            )
            | (
                PeerKey::MinRouteAdvertisementIntervalSecs,
                Setting::MinRouteAdvertisementIntervalSecs(_)
            )
            | (PeerKey::EnforceFirstAs, Setting::EnforceFirstAs(_))
            | (PeerKey::SendRpkiCommunity, Setting::SendRpkiCommunity(_))
            | (PeerKey::AdminDown, Setting::AdminDown(_))
    )
}

fn family_directive_matches(d: &FamilyDirective, key: FamilyDirectiveKey) -> bool {
    matches!(
        (key, d),
        (
            FamilyDirectiveKey::ExportPolicy,
            FamilyDirective::ExportPolicy(_)
        ) | (
            FamilyDirectiveKey::ImportPolicy,
            FamilyDirective::ImportPolicy(_)
        )
    )
}

/// Flat one-line-per-leaf serialization in the same shape the operator types
/// at the `(config-bgp)` prompt. Used by `show diff`.
fn flatten(root: &Root) -> Vec<String> {
    let mut lines = Vec::new();
    for service in &root.services {
        let Service::Bgp(body) = service;
        for setting in &body.settings {
            lines.push(setting.to_string());
        }
        for peer in &body.peers {
            for setting in &peer.settings {
                lines.push(format!("peer {} {}", peer.address, setting));
            }
            for family in &peer.families {
                for directive in &family.directives {
                    lines.push(format!(
                        "peer {} family {} {} {}",
                        peer.address,
                        family.afi.as_config_str(),
                        family.safi.as_config_str(),
                        directive
                    ));
                }
            }
        }
        for policy in &body.policies {
            for rule in &policy.rules {
                lines.push(format!("policy {} {}", policy.name, rule));
            }
        }
        for plist in &body.prefix_lists {
            for prefix in &plist.prefixes {
                lines.push(format!("prefix-list {} {}", plist.name, prefix));
            }
        }
        for bmp in &body.bmp_servers {
            if let Some(v) = bmp.statistics_timeout {
                lines.push(format!(
                    "bmp-server {} statistics-timeout {}",
                    bmp.address, v
                ));
            }
        }
        for rpki in &body.rpki_caches {
            if let Some(v) = rpki.preference {
                lines.push(format!("rpki-cache {} preference {}", rpki.address, v));
            }
            if let Some(v) = &rpki.transport {
                lines.push(format!(
                    "rpki-cache {} transport {}",
                    rpki.address,
                    v.as_config_str()
                ));
            }
            if let Some(v) = &rpki.ssh_username {
                lines.push(format!("rpki-cache {} ssh-username {}", rpki.address, v));
            }
            if let Some(v) = &rpki.ssh_private_key_file {
                lines.push(format!(
                    "rpki-cache {} ssh-private-key-file {}",
                    rpki.address, v
                ));
            }
            if let Some(v) = &rpki.ssh_known_hosts_file {
                lines.push(format!(
                    "rpki-cache {} ssh-known-hosts-file {}",
                    rpki.address, v
                ));
            }
            if let Some(v) = rpki.retry_interval {
                lines.push(format!("rpki-cache {} retry-interval {}", rpki.address, v));
            }
            if let Some(v) = rpki.refresh_interval {
                lines.push(format!(
                    "rpki-cache {} refresh-interval {}",
                    rpki.address, v
                ));
            }
            if let Some(v) = rpki.expire_interval {
                lines.push(format!("rpki-cache {} expire-interval {}", rpki.address, v));
            }
        }
        if let Some(bgp_ls) = &body.bgp_ls {
            lines.push(format!("bgp-ls instance-id {}", bgp_ls.instance_id));
        }
        if let Some(telemetry) = &body.telemetry {
            if telemetry.json {
                lines.push("telemetry json".to_string());
            }
            if let Some(emf) = &telemetry.cloudwatch_emf {
                lines.push(format!(
                    "telemetry cloudwatch-emf namespace {}",
                    emf.namespace
                ));
            }
            if let Some(prometheus) = &telemetry.prometheus {
                match &prometheus.listen {
                    Some(addr) => lines.push(format!("telemetry prometheus listen {}", addr)),
                    None => lines.push("telemetry prometheus".to_string()),
                }
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    use conf::fs::lock_path_for;
    use conf::testutil::TempDir;

    fn test_shell(config_path: PathBuf) -> Shell {
        Shell::new(HashMap::new(), None, config_path)
    }

    fn enter(shell: &mut Shell) {
        enter_configure(shell).expect("enter");
        shell
            .enter_level(ShellLevel::BgpService)
            .expect("enter service bgp");
    }

    /// `(TempDir, Shell)` already in `Config(BgpService)`. The TempDir is
    /// returned so the rogg.conf path stays alive for the test's lifetime.
    fn setup_bgp() -> (TempDir, Shell) {
        let dir = TempDir::new().unwrap();
        let mut shell = test_shell(dir.path().join("rogg.conf"));
        enter(&mut shell);
        (dir, shell)
    }

    #[test]
    fn test_configure_lifecycle() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("rogg.conf");
        let lock_path = lock_path_for(&config_path);
        let mut shell = test_shell(config_path.clone());
        let uuid = shell.session_uuid;

        enter_configure(&mut shell).expect("enter");
        assert_eq!(shell.levels.last(), Some(&ShellLevel::Configure));
        assert!(shell.candidate.is_some());
        assert!(shell.session_lock.is_some());
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            uuid.to_string()
        );

        // exit from (config): pop Configure → run cleanup, leave Root.
        assert_eq!(shell.exit_level(), None);
        assert_eq!(shell.levels.last(), Some(&ShellLevel::Root));
        assert!(shell.candidate.is_none());
        assert!(shell.session_lock.is_none());
        assert!(!lock_path.exists());

        enter_configure(&mut shell).expect("re-enter");
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            uuid.to_string()
        );
    }

    #[test]
    fn test_enter_fails_when_locked() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("rogg.conf");
        let _holder = conf::fs::acquire_exclusive_lock(&config_path, uuid::Uuid::new_v4()).unwrap();

        let mut shell = test_shell(config_path);
        let err = enter_configure(&mut shell).expect_err("should fail when locked");
        assert!(
            err.contains("another configure session is active"),
            "got: {}",
            err
        );
        assert_eq!(shell.levels.last(), Some(&ShellLevel::Root));
    }

    #[test]
    fn test_exit_at_root_quits_shell() {
        let dir = TempDir::new().unwrap();
        let mut shell = test_shell(dir.path().join("rogg.conf"));
        // Stack starts at [Root]; exit pops Root and signals shell quit.
        assert_eq!(shell.exit_level(), Some(0));
    }

    #[test]
    fn test_failed_enter_does_not_clobber_holders_uuid() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("rogg.conf");
        let lock_path = lock_path_for(&config_path);
        let holder_uuid = uuid::Uuid::new_v4();
        let _holder = conf::fs::acquire_exclusive_lock(&config_path, holder_uuid).unwrap();

        let mut shell_b = test_shell(config_path);
        enter_configure(&mut shell_b).expect_err("ggsh-B enter rejected");

        let content = std::fs::read_to_string(&lock_path).unwrap();
        assert_eq!(content, holder_uuid.to_string());
    }

    #[test]
    fn test_exit_from_bgp_service_keeps_candidate() {
        let (_dir, mut shell) = setup_bgp();
        apply_set_top(&mut shell, TopKey::Asn, "65001").unwrap();

        // Stack: [Root, Configure, BgpService]. Pop BgpService → Configure.
        assert_eq!(shell.exit_level(), None);
        assert_eq!(shell.levels.last(), Some(&ShellLevel::Configure));
        assert!(shell.candidate.is_some());
        let Service::Bgp(body) = &shell.candidate.as_ref().unwrap().services[0];
        assert!(body.settings.contains(&Setting::Asn(65001)));
    }

    #[test]
    fn test_exit_from_configure_releases_lock() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("rogg.conf");
        let mut shell = test_shell(config_path.clone());
        enter_configure(&mut shell).expect("enter");
        // Stack: [Root, Configure]. Pop Configure → cleanup; Root remains.
        assert_eq!(shell.exit_level(), None);
        assert_eq!(shell.levels.last(), Some(&ShellLevel::Root));
        assert!(!lock_path_for(&config_path).exists());
    }

    #[test]
    fn test_apply_set_top() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_top(&mut shell, TopKey::Asn, "65001").unwrap();
        apply_set_top(&mut shell, TopKey::RouterId, "1.2.3.4").unwrap();
        apply_set_top(&mut shell, TopKey::HoldTime, "120").unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        assert!(body.settings.contains(&Setting::Asn(65001)));
        assert!(body
            .settings
            .contains(&Setting::RouterId("1.2.3.4".parse().unwrap())));
        assert!(body.settings.contains(&Setting::HoldTime(120)));
    }

    #[test]
    fn test_apply_set_top_replaces() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_top(&mut shell, TopKey::Asn, "65001").unwrap();
        apply_set_top(&mut shell, TopKey::Asn, "65002").unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        let asns: Vec<_> = body
            .settings
            .iter()
            .filter(|s| matches!(s, Setting::Asn(_)))
            .collect();
        assert_eq!(asns.len(), 1);
        assert!(body.settings.contains(&Setting::Asn(65002)));
    }

    #[test]
    fn test_apply_set_top_originate_appends_dedups() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_top_originate(&mut shell, "10.0.0.0/24", "192.168.1.1").unwrap();
        apply_set_top_originate(&mut shell, "10.0.1.0/24", "192.168.1.1").unwrap();
        // Same prefix, different nexthop -- last write wins.
        apply_set_top_originate(&mut shell, "10.0.0.0/24", "192.168.1.2").unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        let originates: Vec<_> = body
            .settings
            .iter()
            .filter_map(|s| match s {
                Setting::Originate(r) => Some((r.prefix.clone(), r.nexthop.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(
            originates,
            vec![
                ("10.0.1.0/24".to_string(), "192.168.1.1".to_string()),
                ("10.0.0.0/24".to_string(), "192.168.1.2".to_string()),
            ]
        );
    }

    #[test]
    fn test_apply_set_peer_creates_block() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_peer(&mut shell, PeerKey::RemoteAs, "10.0.0.1", "65001").unwrap();
        apply_set_peer(&mut shell, PeerKey::Interface, "10.0.0.1", "eth0").unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        assert_eq!(body.peers.len(), 1);
        let peer = &body.peers[0];
        assert_eq!(peer.address, "10.0.0.1");
        assert!(peer.settings.contains(&Setting::RemoteAs(65001)));
        assert!(peer.settings.contains(&Setting::Interface("eth0".into())));
    }

    #[test]
    fn test_apply_set_peer_replaces_setting() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_peer(&mut shell, PeerKey::RemoteAs, "10.0.0.1", "65001").unwrap();
        apply_set_peer(&mut shell, PeerKey::RemoteAs, "10.0.0.1", "65002").unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        let peer = &body.peers[0];
        let asns: Vec<_> = peer
            .settings
            .iter()
            .filter(|s| matches!(s, Setting::RemoteAs(_)))
            .collect();
        assert_eq!(asns.len(), 1);
        assert!(peer.settings.contains(&Setting::RemoteAs(65002)));
    }

    #[test]
    fn test_apply_set_peer_family_directive() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_peer_family(
            &mut shell,
            FamilyDirectiveKey::ExportPolicy,
            "10.0.0.1",
            "ipv4",
            "unicast",
            "mine-only",
        )
        .unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        let peer = &body.peers[0];
        assert_eq!(peer.families.len(), 1);
        assert_eq!(peer.families[0].afi, Afi::Ipv4);
        assert_eq!(peer.families[0].safi, Safi::Unicast);
        assert!(matches!(
            &peer.families[0].directives[0],
            FamilyDirective::ExportPolicy(name) if name == "mine-only"
        ));
    }

    #[test]
    fn test_apply_set_policy_match_then_default() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_policy_match(&mut shell, "mine-only", "my-prefixes", "accept").unwrap();
        apply_set_policy_default(&mut shell, "mine-only", "reject").unwrap();
        // Replace match for same set:
        apply_set_policy_match(&mut shell, "mine-only", "my-prefixes", "reject").unwrap();
        // New match for different set is appended:
        apply_set_policy_match(&mut shell, "mine-only", "other", "accept").unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        assert_eq!(body.policies.len(), 1);
        let policy = &body.policies[0];
        assert_eq!(policy.rules.len(), 3);
        assert!(policy.rules.iter().any(|r| matches!(r,
            PolicyRule::Match { set_name, action } if set_name == "my-prefixes" && action == "reject")));
        assert!(policy.rules.iter().any(|r| matches!(r,
            PolicyRule::Match { set_name, action } if set_name == "other" && action == "accept")));
        assert!(policy.rules.iter().any(|r| matches!(r,
            PolicyRule::Default { action } if action == "reject")));
    }

    #[test]
    fn test_apply_set_prefix_list_appends_dedups() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_prefix_list_entry(&mut shell, "p", "10.0.0.0/24").unwrap();
        apply_set_prefix_list_entry(&mut shell, "p", "10.0.1.0/24").unwrap();
        apply_set_prefix_list_entry(&mut shell, "p", "10.0.0.0/24").unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        let prefixes: Vec<&str> = body.prefix_lists[0]
            .prefixes
            .iter()
            .map(|e| e.prefix.as_str())
            .collect();
        assert_eq!(prefixes, vec!["10.0.0.0/24", "10.0.1.0/24"]);
    }

    #[test]
    fn test_apply_set_bmp_server() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_bmp_server(
            &mut shell,
            BmpServerKey::StatisticsTimeout,
            "127.0.0.1:1790",
            "60",
        )
        .unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        assert_eq!(body.bmp_servers[0].address, "127.0.0.1:1790");
        assert_eq!(body.bmp_servers[0].statistics_timeout, Some(60));
    }

    #[test]
    fn test_apply_set_rpki_cache_partial_update() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_rpki_cache(&mut shell, RpkiCacheKey::Preference, "127.0.0.1:323", "1").unwrap();
        apply_set_rpki_cache(&mut shell, RpkiCacheKey::Transport, "127.0.0.1:323", "ssh").unwrap();
        apply_set_rpki_cache(
            &mut shell,
            RpkiCacheKey::SshUsername,
            "127.0.0.1:323",
            "rtr",
        )
        .unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        let rpki = &body.rpki_caches[0];
        assert_eq!(rpki.preference, Some(1));
        assert!(matches!(rpki.transport, Some(TransportType::Ssh)));
        assert_eq!(rpki.ssh_username.as_deref(), Some("rtr"));
        assert!(rpki.ssh_private_key_file.is_none());
    }

    #[test]
    fn test_apply_set_bgp_ls() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_bgp_ls(&mut shell, BgpLsKey::InstanceId, "99").unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        assert_eq!(body.bgp_ls.as_ref().unwrap().instance_id, 99);
    }

    #[test]
    fn test_apply_set_telemetry() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_telemetry_json(&mut shell).unwrap();
        apply_set_telemetry_prometheus(&mut shell).unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        let telemetry = body.telemetry.as_ref().unwrap();
        assert!(telemetry.json);
        assert_eq!(telemetry.prometheus, Some(PrometheusBlock { listen: None }));

        // json blocks cloudwatch-emf and vice versa.
        let err = apply_set_telemetry_cloudwatch_emf(&mut shell, "Rogg/Bgpgg").unwrap_err();
        assert!(err.contains("mutually exclusive"));

        apply_unset_telemetry_json(&mut shell).unwrap();
        apply_set_telemetry_cloudwatch_emf(&mut shell, "Rogg/Bgpgg").unwrap();
        let err = apply_set_telemetry_json(&mut shell).unwrap_err();
        assert!(err.contains("mutually exclusive"));

        let body = bgp_body_mut(&mut shell).unwrap();
        let telemetry = body.telemetry.as_ref().unwrap();
        assert!(!telemetry.json);
        assert_eq!(
            telemetry.cloudwatch_emf.as_ref().unwrap().namespace,
            "Rogg/Bgpgg"
        );
    }

    fn prometheus_listen(shell: &mut Shell) -> Option<String> {
        let body = bgp_body_mut(shell).unwrap();
        let telemetry = body.telemetry.as_ref().unwrap();
        telemetry.prometheus.as_ref().unwrap().listen.clone()
    }

    #[test]
    fn test_apply_set_telemetry_prometheus_listen() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_telemetry_prometheus_listen(&mut shell, "0.0.0.0:9273").unwrap();
        assert_eq!(
            prometheus_listen(&mut shell).as_deref(),
            Some("0.0.0.0:9273")
        );

        // Bare `telemetry prometheus` keeps the configured listen.
        apply_set_telemetry_prometheus(&mut shell).unwrap();
        assert_eq!(
            prometheus_listen(&mut shell).as_deref(),
            Some("0.0.0.0:9273")
        );

        apply_unset_telemetry_prometheus_listen(&mut shell).unwrap();
        assert!(prometheus_listen(&mut shell).is_none());
    }

    #[test]
    fn test_apply_unset_telemetry() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_telemetry_json(&mut shell).unwrap();
        apply_set_telemetry_prometheus(&mut shell).unwrap();

        apply_unset_telemetry_prometheus(&mut shell).unwrap();
        let body = bgp_body_mut(&mut shell).unwrap();
        assert!(body.telemetry.as_ref().unwrap().prometheus.is_none());

        apply_unset_telemetry(&mut shell).unwrap();
        let body = bgp_body_mut(&mut shell).unwrap();
        assert!(body.telemetry.is_none());

        for err in [
            apply_unset_telemetry(&mut shell),
            apply_unset_telemetry_json(&mut shell),
            apply_unset_telemetry_cloudwatch_emf(&mut shell),
            apply_unset_telemetry_prometheus(&mut shell),
            apply_unset_telemetry_prometheus_listen(&mut shell),
        ] {
            assert!(err.is_err(), "expected unset error");
        }
    }

    #[test]
    fn test_flatten_telemetry() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_telemetry_json(&mut shell).unwrap();
        apply_set_telemetry_prometheus(&mut shell).unwrap();

        let mut lines = flatten(shell.candidate.as_ref().unwrap());
        lines.sort();
        assert_eq!(
            lines,
            vec![
                "telemetry json".to_string(),
                "telemetry prometheus".to_string()
            ]
        );

        apply_set_telemetry_prometheus_listen(&mut shell, "0.0.0.0:9273").unwrap();
        let lines = flatten(shell.candidate.as_ref().unwrap());
        assert!(lines.contains(&"telemetry prometheus listen 0.0.0.0:9273".to_string()));
    }

    #[test]
    fn test_apply_unset_top() {
        let (_dir, mut shell) = setup_bgp();
        apply_set_top(&mut shell, TopKey::Asn, "65001").unwrap();

        apply_unset_top(&mut shell, TopKey::Asn).unwrap();
        let body = bgp_body_mut(&mut shell).unwrap();
        assert!(!body.settings.iter().any(|s| matches!(s, Setting::Asn(_))));

        let err = apply_unset_top(&mut shell, TopKey::Asn).unwrap_err();
        assert!(err.contains("not set"));
    }

    #[test]
    fn test_apply_unset_peer_removes_block() {
        let (_dir, mut shell) = setup_bgp();
        apply_set_peer(&mut shell, PeerKey::RemoteAs, "10.0.0.1", "65001").unwrap();

        apply_unset_peer(&mut shell, "10.0.0.1").unwrap();
        let body = bgp_body_mut(&mut shell).unwrap();
        assert!(body.peers.is_empty());

        let err = apply_unset_peer(&mut shell, "10.0.0.1").unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_apply_unset_peer_setting() {
        let (_dir, mut shell) = setup_bgp();
        apply_set_peer(&mut shell, PeerKey::RemoteAs, "10.0.0.1", "65001").unwrap();
        apply_set_peer(&mut shell, PeerKey::Interface, "10.0.0.1", "eth0").unwrap();

        apply_unset_peer_setting(&mut shell, PeerKey::Interface, "10.0.0.1").unwrap();
        let body = bgp_body_mut(&mut shell).unwrap();
        let peer = &body.peers[0];
        assert!(peer.settings.contains(&Setting::RemoteAs(65001)));
        assert!(!peer
            .settings
            .iter()
            .any(|s| matches!(s, Setting::Interface(_))));
    }

    #[test]
    fn test_apply_unset_policy() {
        let (_dir, mut shell) = setup_bgp();
        apply_set_policy_default(&mut shell, "p", "reject").unwrap();
        apply_unset_policy(&mut shell, "p").unwrap();

        let body = bgp_body_mut(&mut shell).unwrap();
        assert!(body.policies.is_empty());
    }

    #[test]
    fn test_apply_unset_prefix_list_entry() {
        let (_dir, mut shell) = setup_bgp();
        apply_set_prefix_list_entry(&mut shell, "p", "10.0.0.0/24").unwrap();
        apply_set_prefix_list_entry(&mut shell, "p", "10.0.1.0/24").unwrap();

        apply_unset_prefix_list_entry(&mut shell, "p", "10.0.0.0/24").unwrap();
        let body = bgp_body_mut(&mut shell).unwrap();
        let prefixes: Vec<&str> = body.prefix_lists[0]
            .prefixes
            .iter()
            .map(|e| e.prefix.as_str())
            .collect();
        assert_eq!(prefixes, vec!["10.0.1.0/24"]);
    }

    #[test]
    fn test_apply_unset_rpki_cache_setting() {
        let (_dir, mut shell) = setup_bgp();
        apply_set_rpki_cache(&mut shell, RpkiCacheKey::Preference, "127.0.0.1:323", "1").unwrap();
        apply_set_rpki_cache(&mut shell, RpkiCacheKey::Transport, "127.0.0.1:323", "tcp").unwrap();

        apply_unset_rpki_cache_setting(&mut shell, RpkiCacheKey::Transport, "127.0.0.1:323")
            .unwrap();
        let body = bgp_body_mut(&mut shell).unwrap();
        assert_eq!(body.rpki_caches[0].preference, Some(1));
        assert!(body.rpki_caches[0].transport.is_none());
    }

    #[test]
    fn test_apply_unset_bgp_ls() {
        let (_dir, mut shell) = setup_bgp();
        apply_set_bgp_ls(&mut shell, BgpLsKey::InstanceId, "5").unwrap();

        apply_unset_bgp_ls(&mut shell).unwrap();
        let body = bgp_body_mut(&mut shell).unwrap();
        assert!(body.bgp_ls.is_none());
    }

    #[test]
    fn test_apply_unset_not_found_errors() {
        let (_dir, mut shell) = setup_bgp();

        for err in [
            apply_unset_top(&mut shell, TopKey::Asn),
            apply_unset_peer(&mut shell, "10.0.0.1"),
            apply_unset_policy(&mut shell, "p"),
            apply_unset_prefix_list(&mut shell, "p"),
            apply_unset_bmp_server(&mut shell, "127.0.0.1:1790"),
            apply_unset_rpki_cache(&mut shell, "127.0.0.1:323"),
            apply_unset_bgp_ls(&mut shell),
        ] {
            assert!(err.is_err(), "expected unset error");
        }
    }

    #[test]
    fn test_flatten_sorted_deterministic() {
        let (_dir, mut shell) = setup_bgp();

        apply_set_top(&mut shell, TopKey::Asn, "65001").unwrap();
        apply_set_peer(&mut shell, PeerKey::RemoteAs, "10.0.0.1", "65002").unwrap();
        apply_set_peer(&mut shell, PeerKey::Interface, "10.0.0.1", "eth0").unwrap();
        apply_set_top(&mut shell, TopKey::RouterId, "1.2.3.4").unwrap();

        let mut lines = flatten(shell.candidate.as_ref().unwrap());
        lines.sort();
        let expected = vec![
            "asn 65001".to_string(),
            "peer 10.0.0.1 interface eth0".to_string(),
            "peer 10.0.0.1 remote-as 65002".to_string(),
            "router-id 1.2.3.4".to_string(),
        ];
        assert_eq!(lines, expected);
    }
}
