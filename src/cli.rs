use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    version,
    about,
    long_about = "A QUIC Proxy for SSH with enhanced features"
)]
pub(crate) struct Cli {
    /// Enable verbose logging
    #[arg(short, long, default_value = "false")]
    pub(crate) verbose: bool,

    /// Keep-alive interval in seconds
    #[arg(long, default_value = "15")]
    pub(crate) keep_alive: u64,

    /// Idle timeout in seconds
    #[arg(long, default_value = "30")]
    pub(crate) idle_timeout: u64,

    /// Buffer size in kilobytes
    #[arg(long, default_value = "16")]
    pub(crate) buffer_size: usize,

    /// Maximum number of connection retries
    #[arg(long, default_value = "3")]
    pub(crate) max_retries: u32,

    /// Retry interval in seconds
    #[arg(long, default_value = "5")]
    pub(crate) retry_interval: u64,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    Server {
        /// Address to bind to
        #[arg(default_value = "127.0.0.1:4242")]
        bind: SocketAddr,

        /// SSH server port
        #[arg(long, default_value = "22")]
        ssh_port: u16,

        /// Path to TLS certificate file
        #[arg(long)]
        cert: Option<String>,

        /// Path to TLS key file
        #[arg(long)]
        key: Option<String>,
    },
    Client {
        /// Address to connect to
        #[arg(default_value = "127.0.0.1:4242")]
        addr: SocketAddr,

        /// Verify server certificate
        #[arg(long, default_value = "false")]
        verify_cert: bool,
    },
}

impl Cli {
    pub fn to_config(&self) -> crate::config::Config {
        let mut config = crate::config::Config::new()
            .with_keep_alive(Duration::from_secs(self.keep_alive))
            .with_idle_timeout(Duration::from_secs(self.idle_timeout))
            .with_buffer_size(self.buffer_size * 1024)
            .with_retry_settings(Duration::from_secs(self.retry_interval), self.max_retries);

        match &self.command {
            Commands::Server {
                ssh_port,
                cert,
                key,
                ..
            } => {
                config = config.with_ssh_port(*ssh_port);
                if let (Some(cert), Some(key)) = (cert, key) {
                    config = config.with_certificate(cert.clone(), key.clone());
                }
            }
            Commands::Client { verify_cert, .. } => {
                config = config.with_certificate_verification(*verify_cert);
            }
        }

        config
    }
}
