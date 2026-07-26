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

use std::collections::HashMap;
use std::path::PathBuf;

use bgpgg::grpc::BgpClient;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use crate::cmd_bgp;
use crate::cmd_config;
use crate::cmd_configure;
use crate::cmd_rpki;
use crate::cmd_show;
use crate::grammar;
use crate::parser::{self, BgpggCommand, Command, ParseResult, ServiceKind, TabCompleter};
use crate::util::{parse_afi, parse_safi};

const HISTORY_FILENAME: &str = "ggsh_history";

/// Stack frame for the shell's current context. `[Root]` = operational
/// (`ggsh>`). `[Root, Configure]` = `ggsh(config)>`.
/// `[Root, Configure, BgpService]` = `ggsh(config-bgp)>`. Popping `Root`
/// exits the shell; popping `Configure` ends the configure session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellLevel {
    Root,
    Configure,
    BgpService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    Bgpgg,
}

pub enum Client {
    Bgpgg(BgpClient),
}

pub struct Shell {
    grpc_addrs: HashMap<Service, String>,
    command: Option<Vec<String>>,
    tree_op: Vec<crate::grammar::Node>,
    tree_cfg_root: Vec<crate::grammar::Node>,
    tree_cfg_bgp: Vec<crate::grammar::Node>,
    clients: HashMap<Service, Client>,
    /// Always non-empty during the shell's lifetime: starts as `[Root]`.
    /// `enter_configure` / `enter_service_bgp` push; `exit_level` pops.
    pub levels: Vec<ShellLevel>,
    pub candidate: Option<conf::language::Root>,
    pub session_uuid: uuid::Uuid,
    /// EX flock on `<config>.lock` held for the configure session.
    pub session_lock: Option<std::fs::File>,
    pub config_path: PathBuf,
}

impl Shell {
    pub fn new(
        grpc_addrs: HashMap<Service, String>,
        command: Option<Vec<String>>,
        config_path: PathBuf,
    ) -> Self {
        Shell {
            grpc_addrs,
            command,
            tree_op: grammar::tree(),
            tree_cfg_root: grammar::tree_config(),
            tree_cfg_bgp: grammar::tree_config_bgp(),
            clients: HashMap::new(),
            levels: vec![ShellLevel::Root],
            candidate: None,
            session_uuid: conf::fs::make_session_uuid(),
            session_lock: None,
            config_path,
        }
    }

    fn current_tree(&self) -> &[crate::grammar::Node] {
        match self.levels.last() {
            Some(ShellLevel::Root) | None => &self.tree_op,
            Some(ShellLevel::Configure) => &self.tree_cfg_root,
            Some(ShellLevel::BgpService) => &self.tree_cfg_bgp,
        }
    }

    /// Push a level onto the stack. Validates the current top is the
    /// required parent for the new level.
    pub fn enter_level(&mut self, level: ShellLevel) -> Result<(), String> {
        let required_top = match level {
            ShellLevel::Root => return Err("cannot enter root".into()),
            ShellLevel::Configure => ShellLevel::Root,
            ShellLevel::BgpService => ShellLevel::Configure,
        };
        if self.levels.last() != Some(&required_top) {
            return Err(format!("cannot enter {:?} from here", level));
        }
        self.levels.push(level);
        Ok(())
    }

    /// Pop one stack frame. Returns `Some(0)` if the shell should quit
    /// (popped `Root` or stack was already empty). Otherwise `None`.
    pub fn exit_level(&mut self) -> Option<i32> {
        match self.levels.pop() {
            Some(ShellLevel::BgpService) => None,
            Some(ShellLevel::Configure) => {
                self.exit_configure_mode();
                None
            }
            Some(ShellLevel::Root) | None => Some(0),
        }
    }

    fn exit_configure_mode(&mut self) {
        let _ = std::fs::remove_file(conf::fs::lock_path_for(&self.config_path));
        self.session_lock = None;
        self.candidate = None;
    }

    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(command) = self.command.take() {
            let tokens: Vec<&str> = command.iter().map(|s| s.as_str()).collect();
            return self.run_single(&tokens).await;
        }
        self.run_interactive().await
    }

    async fn connect(&mut self, service: Service) -> Result<(), String> {
        if self.clients.contains_key(&service) {
            return Ok(());
        }
        let addr = self
            .grpc_addrs
            .get(&service)
            .ok_or_else(|| format!("no gRPC address configured for {:?}", service))?;
        let connected = match service {
            Service::Bgpgg => BgpClient::connect(addr).await.map(Client::Bgpgg),
        };
        match connected {
            Ok(client) => {
                self.clients.insert(service, client);
                Ok(())
            }
            Err(err) => Err(format!(
                "Failed to connect to {:?} at {}: {}",
                service, addr, err
            )),
        }
    }

    pub(crate) async fn bgp(&mut self) -> Result<&BgpClient, String> {
        self.connect(Service::Bgpgg).await?;
        match self.clients.get(&Service::Bgpgg) {
            Some(Client::Bgpgg(c)) => Ok(c),
            _ => Err("not connected to BGP daemon".into()),
        }
    }

    /// Dispatch a parsed command. Returns `Ok(None)` to continue,
    /// `Ok(Some(code))` to exit with the given code, `Err` on failure.
    async fn execute(&mut self, cmd: Command, args: &[String]) -> Result<Option<i32>, String> {
        match cmd {
            Command::Exit => return Ok(self.exit_level()),
            Command::Configure => cmd_configure::enter_configure(self)?,
            Command::Version => cmd_show::show_version().await.map_err(|e| e.to_string())?,
            Command::Bgpgg(c) => self.execute_bgpgg(c, args).await?,

            Command::EnterService(ServiceKind::Bgp) => self.enter_level(ShellLevel::BgpService)?,
            Command::Commit => cmd_configure::commit_configure(self).await?,
            Command::ShowDiff => cmd_configure::show_diff(self).await?,
            Command::ShowRunningConfig => cmd_configure::show_running_config(self).await?,
            Command::ShowCandidate => cmd_configure::show_candidate(self)?,

            Command::SetTop(key) => cmd_configure::apply_set_top(self, key, &args[0])?,
            Command::SetTopOriginate => {
                cmd_configure::apply_set_top_originate(self, &args[0], &args[1])?
            }
            Command::SetPeer(key) => cmd_configure::apply_set_peer(self, key, &args[0], &args[1])?,
            Command::SetPeerFamily(directive) => cmd_configure::apply_set_peer_family(
                self, directive, &args[0], &args[1], &args[2], &args[3],
            )?,
            Command::SetPolicyMatch => {
                cmd_configure::apply_set_policy_match(self, &args[0], &args[1], &args[2])?
            }
            Command::SetPolicyDefault => {
                cmd_configure::apply_set_policy_default(self, &args[0], &args[1])?
            }
            Command::SetPrefixListEntry => {
                cmd_configure::apply_set_prefix_list_entry(self, &args[0], &args[1])?
            }
            Command::SetBmpServer(key) => {
                cmd_configure::apply_set_bmp_server(self, key, &args[0], &args[1])?
            }
            Command::SetRpkiCache(key) => {
                cmd_configure::apply_set_rpki_cache(self, key, &args[0], &args[1])?
            }
            Command::SetBgpLs(key) => cmd_configure::apply_set_bgp_ls(self, key, &args[0])?,
            Command::SetTelemetryJson => cmd_configure::apply_set_telemetry_json(self)?,
            Command::SetTelemetryCloudwatchEmf => {
                cmd_configure::apply_set_telemetry_cloudwatch_emf(self, &args[0])?
            }
            Command::SetTelemetryPrometheus => cmd_configure::apply_set_telemetry_prometheus(self)?,
            Command::SetTelemetryPrometheusListen => {
                cmd_configure::apply_set_telemetry_prometheus_listen(self, &args[0])?
            }

            Command::UnsetTop(key) => cmd_configure::apply_unset_top(self, key)?,
            Command::UnsetTopOriginate => cmd_configure::apply_unset_top_originate(self, &args[0])?,
            Command::UnsetPeer => cmd_configure::apply_unset_peer(self, &args[0])?,
            Command::UnsetPeerSetting(key) => {
                cmd_configure::apply_unset_peer_setting(self, key, &args[0])?
            }
            Command::UnsetPeerFamily => {
                cmd_configure::apply_unset_peer_family(self, &args[0], &args[1], &args[2])?
            }
            Command::UnsetPeerFamilyDirective(directive) => {
                cmd_configure::apply_unset_peer_family_directive(
                    self, directive, &args[0], &args[1], &args[2],
                )?
            }
            Command::UnsetPolicy => cmd_configure::apply_unset_policy(self, &args[0])?,
            Command::UnsetPrefixList => cmd_configure::apply_unset_prefix_list(self, &args[0])?,
            Command::UnsetPrefixListEntry => {
                cmd_configure::apply_unset_prefix_list_entry(self, &args[0], &args[1])?
            }
            Command::UnsetBmpServer => cmd_configure::apply_unset_bmp_server(self, &args[0])?,
            Command::UnsetBmpServerSetting(key) => {
                cmd_configure::apply_unset_bmp_server_setting(self, key, &args[0])?
            }
            Command::UnsetRpkiCache => cmd_configure::apply_unset_rpki_cache(self, &args[0])?,
            Command::UnsetRpkiCacheSetting(key) => {
                cmd_configure::apply_unset_rpki_cache_setting(self, key, &args[0])?
            }
            Command::UnsetBgpLs => cmd_configure::apply_unset_bgp_ls(self)?,
            Command::UnsetBgpLsSetting(key) => {
                cmd_configure::apply_unset_bgp_ls_setting(self, key)?
            }
            Command::UnsetTelemetry => cmd_configure::apply_unset_telemetry(self)?,
            Command::UnsetTelemetryJson => cmd_configure::apply_unset_telemetry_json(self)?,
            Command::UnsetTelemetryCloudwatchEmf => {
                cmd_configure::apply_unset_telemetry_cloudwatch_emf(self)?
            }
            Command::UnsetTelemetryPrometheus => {
                cmd_configure::apply_unset_telemetry_prometheus(self)?
            }
            Command::UnsetTelemetryPrometheusListen => {
                cmd_configure::apply_unset_telemetry_prometheus_listen(self)?
            }
        }
        Ok(None)
    }

    async fn execute_bgpgg(&mut self, cmd: BgpggCommand, args: &[String]) -> Result<(), String> {
        let stringify = |e: Box<dyn std::error::Error>| e.to_string();
        let client = self.bgp().await?;
        match cmd {
            BgpggCommand::BgpSummary => cmd_bgp::show_summary(client).await.map_err(stringify),
            BgpggCommand::BgpInfo => cmd_bgp::show_info(client).await.map_err(stringify),
            BgpggCommand::BgpPeers => cmd_bgp::show_peers(client).await.map_err(stringify),
            BgpggCommand::BgpPeer => cmd_bgp::show_peer(client, &args[0])
                .await
                .map_err(stringify),
            BgpggCommand::BgpPeerIn => cmd_bgp::show_peer_rib(
                client,
                &args[0],
                "in",
                parse_afi(args.get(1)),
                parse_safi(args.get(2)),
            )
            .await
            .map_err(stringify),
            BgpggCommand::BgpPeerOut => cmd_bgp::show_peer_rib(
                client,
                &args[0],
                "out",
                parse_afi(args.get(1)),
                parse_safi(args.get(2)),
            )
            .await
            .map_err(stringify),
            BgpggCommand::BgpRoute => cmd_bgp::show_bgp_route(client, args)
                .await
                .map_err(stringify),
            BgpggCommand::RpkiCaches => cmd_rpki::show_caches(client).await.map_err(stringify),
            BgpggCommand::RpkiRoa => cmd_rpki::show_roa(client).await.map_err(stringify),
            BgpggCommand::RpkiValidate => {
                let prefix = args.first().ok_or("missing prefix")?;
                let origin_as: u32 = args
                    .get(1)
                    .ok_or("missing ASN")?
                    .parse()
                    .map_err(|_| "invalid ASN".to_string())?;
                cmd_rpki::show_validate(client, prefix, origin_as)
                    .await
                    .map_err(stringify)
            }
            BgpggCommand::ConfigHistory => {
                cmd_config::show_history(client).await.map_err(stringify)
            }
        }
    }

    async fn run_interactive(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut editor = Editor::new()?;
        editor.set_helper(Some(TabCompleter {
            tree: grammar::tree(),
        }));

        if let Some(path) = history_path() {
            let _ = editor.load_history(&path);
        }

        println!("ggshell {}\n", env!("CARGO_PKG_VERSION"));

        loop {
            let prompt = match self.levels.last() {
                Some(ShellLevel::Root) | None => "ggsh> ",
                Some(ShellLevel::Configure) => "ggsh(config)> ",
                Some(ShellLevel::BgpService) => "ggsh(config-bgp)> ",
            };
            // Refresh completer to match the active mode's grammar.
            editor.set_helper(Some(TabCompleter {
                tree: self.current_tree().to_vec(),
            }));
            match editor.readline(prompt) {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let _ = editor.add_history_entry(trimmed);
                    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                    let result = parser::parse(self.current_tree(), &tokens);
                    if self.handle_result(result).await == Some(0) {
                        break;
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
                Err(err) => {
                    eprintln!("Error: {}", err);
                    break;
                }
            }
        }

        if let Some(path) = history_path() {
            let _ = editor.save_history(&path);
        }
        Ok(())
    }

    async fn run_single(&mut self, tokens: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let result = parser::parse(self.current_tree(), tokens);
        if let Some(code) = self.handle_result(result).await {
            if code != 0 {
                std::process::exit(code);
            }
        }
        Ok(())
    }

    /// Handle a parse result. Returns Some(exit_code) to stop, None to continue.
    async fn handle_result(&mut self, result: ParseResult) -> Option<i32> {
        match result {
            ParseResult::Execution { cmd, args } => match self.execute(cmd, &args).await {
                Ok(Some(code)) => Some(code),
                Ok(None) => {
                    println!();
                    None
                }
                Err(err) => {
                    eprintln!("Error: {}", err);
                    Some(1)
                }
            },
            ParseResult::Help { ref entries } => {
                if entries.is_empty() {
                    println!("  No further completions");
                } else {
                    for entry in entries {
                        println!("  {:<20} {}", entry.keyword, entry.description);
                    }
                }
                None
            }
            ParseResult::Error(ref msg) => {
                if !msg.is_empty() {
                    eprintln!("% {}", msg);
                }
                Some(1)
            }
        }
    }
}

fn history_path() -> Option<PathBuf> {
    let dir = conf::fs::user_state_dir();
    let _ = std::fs::create_dir_all(&dir);
    Some(dir.join(HISTORY_FILENAME))
}
