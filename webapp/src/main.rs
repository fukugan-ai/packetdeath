//! `packetdeath-webapp`: the browser console. `webapp/docs/design.ja.md`.
//!
//! ```text
//! packetdeath-webapp --data DIR --config DIR --logs DIR [--static DIR] [--listen ADDR] [--allow-remote] [--secure]
//! ```
//!
//! It listens on 127.0.0.1:8088 unless told otherwise, and refuses an address
//! beyond this machine unless `--allow-remote` is given.

use std::net::SocketAddr;
use std::process::ExitCode;

use packetdeath_webapp::app::{build, parse_args, router};

async fn serve(listen: SocketAddr, app: axum::Router) -> Result<(), String> {
    let socket = tokio::net::TcpListener::bind(listen).await.map_err(|e| format!("{listen}: {e}"))?;
    let service = app.into_make_service_with_connect_info::<SocketAddr>();
    let stop = async {
        if tokio::signal::ctrl_c().await.is_err() {
            eprintln!("webapp: the stop signal could not be awaited; stop the process to end it");
            std::future::pending::<()>().await;
        }
    };
    axum::serve(socket, service).with_graceful_shutdown(stop).await.map_err(|e| e.to_string())
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = parse_args(&args)?;
    let state = build(&config)?;
    println!("{{\"event\":\"webapp.listen\",\"addr\":\"{}\"}}", config.listen);
    serve(config.listen, router(state)).await
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("packetdeath-webapp: {why}");
            ExitCode::from(2)
        }
    }
}
