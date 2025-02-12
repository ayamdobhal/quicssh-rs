pub mod cli;
pub mod client;
pub mod config;
pub mod server;
pub mod verifier;

// Re-export main types and functions for easier access
pub use client::invoke as connect_client;
pub use config::Config;
pub use server::invoke as start_server;

#[cfg(test)]
mod tests {

    mod test_utils {
        use std::net::SocketAddr;
        use tokio::net::TcpListener;

        pub async fn find_available_port() -> SocketAddr {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        }

        pub fn create_test_certificate() -> (Vec<u8>, Vec<u8>) {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der().unwrap();
            (cert, key)
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[tokio::test]
            async fn test_find_available_port() {
                let addr1 = find_available_port().await;
                let addr2 = find_available_port().await;
                assert_ne!(addr1.port(), addr2.port());
            }

            #[test]
            fn test_create_certificate() {
                let (cert, key) = create_test_certificate();
                assert!(!cert.is_empty());
                assert!(!key.is_empty());
            }
        }
    }

    mod config_tests {
        use crate::config::Config;
        use std::time::Duration;

        #[test]
        fn test_default_config() {
            let config = Config::default();
            assert_eq!(config.keep_alive_interval, Duration::from_secs(15));
            assert_eq!(config.idle_timeout, Duration::from_secs(30));
            assert_eq!(config.buffer_size, 1024 * 16);
            assert_eq!(config.ssh_port, 22);
            assert_eq!(config.max_retries, 3);
            assert!(!config.verify_certificate);
        }

        #[test]
        fn test_config_builder() {
            let config = Config::new()
                .with_keep_alive(Duration::from_secs(30))
                .with_idle_timeout(Duration::from_secs(60))
                .with_buffer_size(32 * 1024)
                .with_ssh_port(2222)
                .with_retry_settings(Duration::from_secs(10), 5)
                .with_certificate_verification(true);

            assert_eq!(config.keep_alive_interval, Duration::from_secs(30));
            assert_eq!(config.idle_timeout, Duration::from_secs(60));
            assert_eq!(config.buffer_size, 32 * 1024);
            assert_eq!(config.ssh_port, 2222);
            assert_eq!(config.retry_interval, Duration::from_secs(10));
            assert_eq!(config.max_retries, 5);
            assert!(config.verify_certificate);
        }

        #[test]
        fn test_config_certificate_settings() {
            let cert_path = "test_cert.pem".to_string();
            let key_path = "test_key.pem".to_string();

            let config = Config::new().with_certificate(cert_path.clone(), key_path.clone());

            assert_eq!(config.cert_path, Some(cert_path));
            assert_eq!(config.key_path, Some(key_path));
        }
    }

    mod verifier_tests {
        use crate::verifier::{create_custom_cert_verifier, SkipServerVerification};
        use rustls::client::ServerCertVerifier;
        use rustls::{Certificate, ServerName};
        use std::time::SystemTime;

        #[test]
        fn test_skip_verification() {
            let verifier = SkipServerVerification::new();
            let result = ServerCertVerifier::verify_server_cert(
                verifier.as_ref(),
                &Certificate(vec![]), // empty cert for testing
                &[],                  // no intermediates
                &ServerName::try_from("localhost").unwrap(),
                &mut std::iter::empty(),
                &[],
                SystemTime::now(),
            );
            assert!(result.is_ok());
        }

        #[test]
        fn test_custom_verifier_creation() {
            let verifier = create_custom_cert_verifier();
            // Test that it verifies an empty certificate differently than SkipServerVerification
            let skip_result = ServerCertVerifier::verify_server_cert(
                SkipServerVerification::new().as_ref(),
                &Certificate(vec![]),
                &[],
                &ServerName::try_from("localhost").unwrap(),
                &mut std::iter::empty(),
                &[],
                SystemTime::now(),
            );

            let custom_result = ServerCertVerifier::verify_server_cert(
                verifier.as_ref(),
                &Certificate(vec![]),
                &[],
                &ServerName::try_from("localhost").unwrap(),
                &mut std::iter::empty(),
                &[],
                SystemTime::now(),
            );

            // Custom verifier should reject invalid certificates while skip verifier accepts them
            assert!(skip_result.is_ok());
            assert!(custom_result.is_err());
        }
    }

    mod cli_tests {
        use crate::cli::{Cli, Commands};
        use clap::Parser;
        use std::net::SocketAddr;
        use std::str::FromStr;

        #[test]
        fn test_default_server_command() {
            let cli = Cli::parse_from(&["quicssh", "server"]);

            assert!(!cli.verbose);
            assert_eq!(cli.keep_alive, 15);
            assert_eq!(cli.idle_timeout, 30);
            assert_eq!(cli.buffer_size, 16);

            match cli.command {
                Commands::Server {
                    bind,
                    ssh_port,
                    cert: None,
                    key: None,
                } => {
                    assert_eq!(bind, SocketAddr::from_str("127.0.0.1:4242").unwrap());
                    assert_eq!(ssh_port, 22);
                }
                _ => panic!("Expected Server command"),
            }
        }

        #[test]
        fn test_custom_client_command() {
            let cli = Cli::parse_from(&[
                "quicssh",
                "--verbose",
                "--keep-alive",
                "30",
                "--buffer-size",
                "32",
                "client",
                "--verify-cert",
                "192.168.1.1:4242",
            ]);

            assert!(cli.verbose);
            assert_eq!(cli.keep_alive, 30);
            assert_eq!(cli.buffer_size, 32);

            match cli.command {
                Commands::Client { addr, verify_cert } => {
                    assert_eq!(addr, SocketAddr::from_str("192.168.1.1:4242").unwrap());
                    assert!(verify_cert);
                }
                _ => panic!("Expected Client command"),
            }
        }

        #[test]
        fn test_server_with_cert() {
            let cli = Cli::parse_from(&[
                "quicssh",
                "server",
                "--cert",
                "test.crt",
                "--key",
                "test.key",
                "--ssh-port",
                "2222",
            ]);

            match cli.command {
                Commands::Server {
                    bind: _,
                    ssh_port,
                    cert,
                    key,
                } => {
                    assert_eq!(ssh_port, 2222);
                    assert_eq!(cert.unwrap(), "test.crt");
                    assert_eq!(key.unwrap(), "test.key");
                }
                _ => panic!("Expected Server command"),
            }
        }
    }

    mod integration_tests {
        use crate::config::Config;
        use std::net::SocketAddr;
        use std::str::FromStr;
        use std::time::Duration;

        #[tokio::test]
        async fn test_server_startup() {
            let addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
            let config = Config::default();

            let server_handle = tokio::spawn(async move {
                let result = crate::server::invoke(addr, config).await;
                assert!(result.is_ok());
            });

            tokio::time::sleep(Duration::from_millis(100)).await;

            server_handle.abort();
        }

        #[tokio::test]
        async fn test_client_connection_failure() {
            let addr = SocketAddr::from_str("127.0.0.1:1").unwrap();
            let config = Config::new().with_retry_settings(Duration::from_millis(100), 2);

            let result = crate::client::invoke(addr, config).await;
            assert!(result.is_err());
        }
    }
}
