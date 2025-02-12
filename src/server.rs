use quinn::{IdleTimeout, VarInt};
use std::sync::Arc;
use std::{error::Error, net::SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

// Change ALPN token to match quicssh-go
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"xyz"];

pub(crate) async fn invoke(bind: SocketAddr) -> Result<(), Box<dyn Error>> {
    info!("Generating server certificate");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = cert.serialize_private_key_der();
    let cert = cert.serialize_der().unwrap();
    let key = rustls::PrivateKey(key);
    let certs = vec![rustls::Certificate(cert)];

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
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(60_000)))); // 60 seconds
    server_config.use_retry(true);

    info!("Starting server on {}", bind);
    let endpoint = quinn::Endpoint::server(server_config, bind)?;
    info!("Server listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
        info!("New connection from {}", conn.remote_address());

        tokio::spawn(async move {
            match conn.await {
                Ok(connection) => {
                    info!(
                        "Connection established from {}",
                        connection.remote_address()
                    );

                    loop {
                        match connection.accept_bi().await {
                            Ok((send_stream, recv_stream)) => {
                                info!("New bidirectional stream accepted");

                                match TcpStream::connect("127.0.0.1:22").await {
                                    Ok(ssh_stream) => {
                                        info!("Connected to SSH server");

                                        let (ssh_read, ssh_write) = ssh_stream.into_split();

                                        // QUIC -> SSH
                                        let quic_to_ssh = {
                                            let mut ssh_write = ssh_write;
                                            async move {
                                                let mut buffer = [0u8; 1024];
                                                let mut recv_stream = recv_stream;
                                                loop {
                                                    match recv_stream.read(&mut buffer).await {
                                                        Ok(Some(n)) => {
                                                            if let Err(e) = ssh_write
                                                                .write_all(&buffer[..n])
                                                                .await
                                                            {
                                                                error!(
                                                                    "Failed to write to SSH: {}",
                                                                    e
                                                                );
                                                                break;
                                                            }
                                                            debug!("Forwarded {} bytes to SSH", n);
                                                            if let Err(e) = ssh_write.flush().await
                                                            {
                                                                error!(
                                                                    "Failed to flush SSH write: {}",
                                                                    e
                                                                );
                                                                break;
                                                            }
                                                        }
                                                        Ok(None) => {
                                                            info!("QUIC stream closed by client");
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
                                            async move {
                                                let mut buffer = [0u8; 1024];
                                                let mut send_stream = send_stream;
                                                loop {
                                                    match ssh_read.read(&mut buffer).await {
                                                        Ok(0) => {
                                                            info!("SSH connection closed");
                                                            break;
                                                        }
                                                        Ok(n) => {
                                                            if let Err(e) = send_stream
                                                                .write_all(&buffer[..n])
                                                                .await
                                                            {
                                                                error!("Failed to write to QUIC stream: {}", e);
                                                                break;
                                                            }
                                                            debug!("Forwarded {} bytes to QUIC", n);
                                                            if let Err(e) =
                                                                send_stream.flush().await
                                                            {
                                                                error!("Failed to flush QUIC stream: {}", e);
                                                                break;
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!(
                                                                "Failed to read from SSH: {}",
                                                                e
                                                            );
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        };

                                        // Run both transfer directions concurrently
                                        let (quic_result, ssh_result) = tokio::join!(
                                            tokio::spawn(quic_to_ssh),
                                            tokio::spawn(ssh_to_quic)
                                        );

                                        if let Err(e) = quic_result {
                                            error!("QUIC to SSH task failed: {}", e);
                                        }
                                        if let Err(e) = ssh_result {
                                            error!("SSH to QUIC task failed: {}", e);
                                        }

                                        info!("Transfer completed for stream");
                                    }
                                    Err(e) => {
                                        error!("Failed to connect to SSH server: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to accept bidirectional stream: {}", e);
                                break;
                            }
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
