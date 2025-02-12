use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    // Connection settings
    pub keep_alive_interval: Duration,
    pub idle_timeout: Duration,
    pub buffer_size: usize,
    pub ssh_port: u16,
    pub retry_interval: Duration,
    pub max_retries: u32,

    // Server specific
    pub cert_path: Option<String>,
    pub key_path: Option<String>,

    // Security settings
    pub verify_certificate: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            keep_alive_interval: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(30),
            buffer_size: 1024 * 16, // 16KB buffer
            ssh_port: 22,
            retry_interval: Duration::from_secs(5),
            max_retries: 3,
            cert_path: None,
            key_path: None,
            verify_certificate: false,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_keep_alive(mut self, interval: Duration) -> Self {
        self.keep_alive_interval = interval;
        self
    }

    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    pub fn with_ssh_port(mut self, port: u16) -> Self {
        self.ssh_port = port;
        self
    }

    pub fn with_retry_settings(mut self, interval: Duration, max_retries: u32) -> Self {
        self.retry_interval = interval;
        self.max_retries = max_retries;
        self
    }

    pub fn with_certificate(mut self, cert_path: String, key_path: String) -> Self {
        self.cert_path = Some(cert_path);
        self.key_path = Some(key_path);
        self
    }

    pub fn with_certificate_verification(mut self, verify: bool) -> Self {
        self.verify_certificate = verify;
        self
    }
}
