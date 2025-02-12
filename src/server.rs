use crate::config::Config;
use quinn::{IdleTimeout, VarInt};
use std::sync::Arc;
use std::{error::Error, fs, net::SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"xyz"];

/// Load or generate TLS certificates
pub(crate) fn load_certificates(
    config: &Config,
) -> Result<(rustls::Certificate, rustls::PrivateKey), Box<dyn Error>> {
    if let (Some(cert_path), Some(key_path)) = (&config.cert_path, &config.key_path) {
        // Load certificate and key from files
        let cert_data = fs::read(cert_path)?;
        let key_data = fs::read(key_path)?;
        Ok((rustls::Certificate(cert_data), rustls::PrivateKey(key_data)))
    } else {
        // Generate self-signed certificate
        info!("No certificate provided, generating self-signed certificate");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let key = cert.serialize_private_key_der();
        let cert = cert.serialize_der()?;
        Ok((rustls::Certificate(cert), rustls::PrivateKey(key)))
    }
}

/// Handle an individual client connection
pub(crate) async fn handle_connection(
    stream: TcpStream,
    send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    config: Config,
) {
    let (ssh_read, ssh_write) = stream.into_split();

    // QUIC -> SSH
    let quic_to_ssh = {
        let mut ssh_write = ssh_write;
        async move {
            let mut buffer = vec![0u8; config.buffer_size];
            loop {
                match recv_stream.read(&mut buffer).await {
                    Ok(Some(n)) => {
                        if let Err(e) = ssh_write.write_all(&buffer[..n]).await {
                            error!("Failed to write to SSH: {}", e);
                            break;
                        }
                        debug!("Forwarded {} bytes to SSH", n);
                    }
                    Ok(None) => {
                        info!("QUIC stream closed");
                        break;
                    }
                    Err(e) => {
                        error!("Failed to read from QUIC stream: {}", e);
                        break;
                    }
                }
            }
        }
    };

    // SSH -> QUIC
    let ssh_to_quic = {
        let mut ssh_read = ssh_read;
        let mut send_stream = send_stream;
        async move {
            let mut buffer = vec![0u8; config.buffer_size];
            loop {
                match ssh_read.read(&mut buffer).await {
                    Ok(0) => {
                        info!("SSH connection closed");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = send_stream.write_all(&buffer[..n]).await {
                            error!("Failed to write to QUIC stream: {}", e);
                            break;
                        }
                        debug!("Forwarded {} bytes to QUIC", n);
                    }
                    Err(e) => {
                        error!("Failed to read from SSH: {}", e);
                        break;
                    }
                }
            }
        }
    };

    let _ = tokio::join!(tokio::spawn(quic_to_ssh), tokio::spawn(ssh_to_quic));

    info!("Transfer completed");
}

/// Start the QUIC SSH server
pub async fn invoke(bind: SocketAddr, config: Config) -> Result<(), Box<dyn Error>> {
    let (cert, key) = load_certificates(&config)?;
    let certs = vec![cert];

    info!("Configuring server");
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.keep_alive_interval(Some(config.keep_alive_interval));
    transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(
        config.idle_timeout.as_millis() as u32,
    ))));
    server_config.use_retry(true);

    info!("Starting server on {}", bind);
    let endpoint = quinn::Endpoint::server(server_config, bind)?;
    info!("Server listening on {}", endpoint.local_addr()?);

    let config = Arc::new(config);

    while let Some(conn) = endpoint.accept().await {
        let peer_addr = conn.remote_address();
        info!("New connection from {}", peer_addr);

        let config = Arc::clone(&config);
        tokio::spawn(async move {
            match conn.await {
                Ok(connection) => {
                    info!(
                        "Connection established from {}",
                        connection.remote_address()
                    );

                    let (send_stream, recv_stream) = match connection.accept_bi().await {
                        Ok(streams) => {
                            info!("Accepted bidirectional stream");
                            streams
                        }
                        Err(e) => {
                            error!("Failed to accept bidirectional stream: {}", e);
                            return;
                        }
                    };

                    let ssh_addr = format!("127.0.0.1:{}", config.ssh_port);
                    match TcpStream::connect(&ssh_addr).await {
                        Ok(ssh_stream) => {
                            info!("Connected to SSH server at {}", ssh_addr);
                            handle_connection(
                                ssh_stream,
                                send_stream,
                                recv_stream,
                                (*config).clone(),
                            )
                            .await;
                        }
                        Err(e) => {
                            error!("Failed to connect to SSH server at {}: {}", ssh_addr, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}
