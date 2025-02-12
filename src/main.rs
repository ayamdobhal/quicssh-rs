use clap::Parser;
use quicssh::cli::{Cli, Commands};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();
    let config = args.to_config();

    if args.verbose {
        tracing_subscriber::fmt::init();
    }
    tracing::info!("Verbose mode enabled");
    tracing::debug!("Using configuration: {:?}", config);

    match args.command {
        Commands::Server { bind, .. } => quicssh::server::invoke(bind, config).await,
        Commands::Client { addr, .. } => quicssh::client::invoke(addr, config).await,
    }
}
