use std::error::Error;

use clap::Parser;
mod cli;
mod client;
mod config;
mod server;
mod verifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = cli::Cli::parse();
    let config = args.to_config();

    if args.verbose {
        tracing_subscriber::fmt::init();
    }
    tracing::info!("Verbose mode enabled");
    tracing::debug!("Using configuration: {:?}", config);

    match args.command {
        cli::Commands::Server { bind, .. } => server::invoke(bind, config).await,
        cli::Commands::Client { addr, .. } => client::invoke(addr, config).await,
    }
}
