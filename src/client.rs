use crate::server::ALPN_QUIC_HTTP;
use crate::verifier::SkipServerVerification;
use quinn::{IdleTimeout, VarInt};
use std::sync::Arc;
use std::{error::Error, net::SocketAddr};
use tokio::io::{stdin, stdout, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info};

pub(crate) async fn invoke(addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    info!("Starting client connection to {}", addr);

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(30_000))));

    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    info!("Creating endpoint");
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config.clone().into());

    info!("Attempting to connect to {}", addr);
    let connecting = endpoint.connect(addr, "localhost")?;

    let conn = match connecting.await {
        Ok(conn) => {
            info!(
                "Successfully established QUIC connection to {}",
                conn.remote_address()
            );
            conn
        }
        Err(e) => {
            error!("Failed to establish QUIC connection: {}", e);
            return Err(Box::new(e));
        }
    };

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
        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
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
        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
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
