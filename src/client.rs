use crate::config::Config;
use crate::server::ALPN_QUIC_HTTP;
use crate::verifier::{create_custom_cert_verifier, SkipServerVerification};
use quinn::{IdleTimeout, VarInt};
use std::sync::Arc;
use std::{error::Error, net::SocketAddr, time::Duration};
use tokio::io::{stdin, stdout, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info};

async fn try_connect(
    endpoint: &mut quinn::Endpoint,
    addr: SocketAddr,
    name: &str,
    retry: u32,
    retry_interval: Duration,
) -> Result<quinn::Connection, Box<dyn Error>> {
    let mut attempts = 0;
    loop {
        match endpoint.connect(addr, name) {
            Ok(connecting) => match connecting.await {
                Ok(conn) => {
                    info!(
                        "Successfully established QUIC connection to {}",
                        conn.remote_address()
                    );
                    return Ok(conn);
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= retry {
                        error!("Failed to establish connection after {} attempts", retry);
                        return Err(Box::new(e));
                    }
                    error!("Connection attempt {} failed: {}", attempts, e);
                    tokio::time::sleep(retry_interval).await;
                    continue;
                }
            },
            Err(e) => return Err(Box::new(e)),
        }
    }
}

pub(crate) async fn invoke(addr: SocketAddr, config: Config) -> Result<(), Box<dyn Error>> {
    info!("Starting client connection to {}", addr);

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(if config.verify_certificate {
            create_custom_cert_verifier()
        } else {
            SkipServerVerification::new()
        })
        .with_no_client_auth();

    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(config.keep_alive_interval));
    transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(
        config.idle_timeout.as_millis() as u32,
    ))));

    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    info!("Creating endpoint");
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config.clone().into());

    let conn = try_connect(
        &mut endpoint,
        addr,
        "localhost",
        config.max_retries,
        config.retry_interval,
    )
    .await?;

    info!("Opening bidirectional stream");
    let (send_stream, recv_stream) = match conn.open_bi().await {
        Ok((send, recv)) => {
            info!("Successfully opened bidirectional stream");
            (send, recv)
        }
        Err(e) => {
            error!("Failed to open bidirectional stream: {}", e);
            return Err(Box::new(e));
        }
    };

    let stdin = stdin();
    let stdout = stdout();

    // Create separate tasks for sending and receiving
    let send_task = {
        let mut stdin = stdin;
        let mut send_stream = send_stream;
        let buffer_size = config.buffer_size;
        tokio::spawn(async move {
            let mut buffer = vec![0u8; buffer_size];
            loop {
                match stdin.read(&mut buffer).await {
                    Ok(0) => {
                        info!("stdin closed");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = send_stream.write_all(&buffer[..n]).await {
                            error!("Failed to send data: {}", e);
                            break;
                        }
                        debug!("Sent {} bytes", n);
                    }
                    Err(e) => {
                        error!("Failed to read from stdin: {}", e);
                        break;
                    }
                }
            }
        })
    };

    let recv_task = {
        let mut stdout = stdout;
        let mut recv_stream = recv_stream;
        let buffer_size = config.buffer_size;
        tokio::spawn(async move {
            let mut buffer = vec![0u8; buffer_size];
            loop {
                match recv_stream.read(&mut buffer).await {
                    Ok(Some(n)) => {
                        if let Err(e) = stdout.write_all(&buffer[..n]).await {
                            error!("Failed to write to stdout: {}", e);
                            break;
                        }
                        debug!("Received {} bytes", n);
                    }
                    Ok(None) => {
                        info!("Server closed connection");
                        break;
                    }
                    Err(e) => {
                        error!("Failed to receive data: {}", e);
                        break;
                    }
                }
            }
        })
    };

    // Wait for either task to complete
    let _ = tokio::select! {
        r = send_task => r,
        r = recv_task => r,
    };

    info!("Closing connection");
    conn.close(VarInt::from_u32(0), b"Client closing connection");
    Ok(())
}
