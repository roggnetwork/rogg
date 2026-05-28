// Copyright 2025 bgpgg Authors
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

use bgpgg::grpc::proto::bgp_service_server::BgpServiceServer;
use bgpgg::grpc::BgpGrpcService;
use bgpgg::server::BgpServer;
use clap::Parser;
use conf::fs::{self as conf_fs, DaemonKind, StatusFile};
use std::path::PathBuf;
use std::process;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio_stream::wrappers::TcpListenerStream;
use tracing::{error, info};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser)]
#[command(name = "bgpggd")]
#[command(about = "BGP daemon server", version)]
struct Args {
    /// Path to rogg.conf. Defaults to `/etc/rogg/rogg.conf`.
    #[arg(short, long, default_value_os_t = conf::fs::default_config_path())]
    config: PathBuf,

    /// Directory where the daemon publishes its discovery file
    /// (`bgpggd.json`). Defaults to `/run/rogg/`, provisioned in
    /// production by `RuntimeDirectory=rogg` in the systemd unit.
    #[arg(long)]
    runtime_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let server = BgpServer::new(args.config.clone()).unwrap_or_else(|err| {
        eprintln!(
            "Error: failed to start BGP server from {}: {}",
            args.config.display(),
            err
        );
        process::exit(1);
    });

    for peer_config in &server.config.peers {
        if let Err(err) = peer_config.validate() {
            eprintln!(
                "Error: invalid peer configuration ({}): {}",
                peer_config.address, err
            );
            process::exit(1);
        }
    }

    let level = match server.config.log_level.to_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => LevelFilter::INFO,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .json()
        .with_current_span(false)
        .with_span_events(FmtSpan::NONE)
        .init();

    let grpc_listener = TcpListener::bind(&server.config.grpc_listen_addr).await?;
    let grpc_bound = grpc_listener.local_addr()?;

    let runtime_dir = conf_fs::rogg_runtime_dir(args.runtime_dir.as_deref());
    conf_fs::write_status(
        &runtime_dir,
        DaemonKind::Bgp,
        &StatusFile {
            grpc_addr: grpc_bound.to_string(),
        },
    )?;

    info!(
        bgp_addr = %server.config.listen_addr,
        grpc_addr = %grpc_bound,
        asn = server.config.asn,
        router_id = %server.config.router_id,
        status_file = %runtime_dir.join(DaemonKind::Bgp.filename()).display(),
        "BGP daemon starting"
    );

    let grpc_service = BgpGrpcService::new(server.mgmt_tx.clone());

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                error!(error = %e, "BGP server error");
            }
        },

        result = tonic::transport::Server::builder()
            .add_service(BgpServiceServer::new(grpc_service))
            .serve_with_incoming(TcpListenerStream::new(grpc_listener)) => {
            if let Err(e) = result {
                error!(error = %e, "gRPC server error");
            }
        },

        _ = sigterm.recv() => {
            info!("received SIGTERM; shutting down");
        },

        _ = sigint.recv() => {
            info!("received SIGINT; shutting down");
        },
    }

    conf_fs::remove_status(&runtime_dir, DaemonKind::Bgp);
    Ok(())
}
