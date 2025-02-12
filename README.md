# QuicSSH-RS

A Rust implementation of SSH over QUIC, inspired by quicssh-go. This tool provides a secure way to tunnel SSH connections over QUIC protocol, offering better performance and connection stability.

## Features

- SSH tunneling over QUIC protocol
- Configurable connection parameters
- TLS certificate verification (optional)
- Connection retry mechanism
- Custom buffer sizes for optimization
- Support for custom certificates
- Detailed logging options

## Installation

```bash
git clone https://github.com/yourusername/quicssh-rs.git
cd quicssh-rs
cargo build --release
```

## Usage

### Server Mode

Start the server with default settings:

```bash
cargo run -- server
```

Start with custom settings:

```bash
cargo run -- --verbose --buffer-size 32 --keep-alive 30 server --ssh-port 2222
```

Server options:

- `--cert`: Path to TLS certificate file
- `--key`: Path to TLS key file
- `--ssh-port`: SSH server port (default: 22)
- `bind`: Address to bind to (default: 127.0.0.1:4242)

### Client Mode

Connect with default settings:

```bash
cargo run -- client
```

Connect with custom settings:

```bash
cargo run -- --verbose --max-retries 5 --retry-interval 10 client --verify-cert
```

Client options:

- `--verify-cert`: Enable certificate verification
- `addr`: Address to connect to (default: 127.0.0.1:4242)

### Global Options

- `--verbose`: Enable verbose logging
- `--keep-alive <SECS>`: Keep-alive interval in seconds (default: 15)
- `--idle-timeout <SECS>`: Connection idle timeout in seconds (default: 30)
- `--buffer-size <KB>`: Buffer size in kilobytes (default: 16)
- `--max-retries <NUM>`: Maximum connection retry attempts (default: 3)
- `--retry-interval <SECS>`: Interval between retry attempts in seconds (default: 5)

## Example Usage

1. Start the server:

```bash
cargo run -- --verbose server --ssh-port 22
```

2. In another terminal, connect using the client:

```bash
cargo run -- --verbose client
```

3. Use SSH as normal - the connection will be tunneled through QUIC.

## Security Considerations

- By default, certificate verification is disabled for development ease
- For production use, enable certificate verification with `--verify-cert`
- Use custom certificates in production environments
- Keep your SSH server properly configured and secured

## Development

### Building from Source

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Debug Logging

Enable verbose logging with the `--verbose` flag for detailed connection information.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

# License

© 2024 Sumit Kumar - [GNU GPL V3](./LICENSE)
