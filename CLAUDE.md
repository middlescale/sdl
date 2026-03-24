# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Architecture Overview

The VNT project is a Virtual Network Tunnel system with a client-server architecture written in Rust. It supports multiple transport protocols and various encryption algorithms for secure communication across NAT networks.

### Project Structure
- `vnt/`: Main client library with core tunneling functionality
- `vnt-cli/`: Command-line interface for the client
- `vnt-dns/`: DNS-related functionality
- `vn-link/`: Link layer integration
- `common/`: Shared utilities and common code
- `vnt/packet/`: Packet handling and processing

### Key Features
- Multiple transport protocols: UDP, TCP, QUIC, WS, WSS
- Multiple encryption algorithms: AES (CBC, ECB, GCM), SM4, ChaCha20/Poly1305
- Compression support: LZ4 (default), ZSTD (optional)
- NAT traversal and P2P connectivity
- Built-in IP proxy and port mapping
- TUN/TAP device integration

## Development Commands

### Build
```bash
make                    # Default build (debug version)
make build             # Explicit debug build
make release           # Release build
cargo build -p vnt-cli # Build specific package
cargo build -p vnt-cli --no-default-features # Minimal build
```

### Testing
```bash
cargo test                               # Run all tests
cargo test -p vnt --lib                 # Test specific package (library tests)
cargo test -p vnt-cli                   # Test vnt-cli package
cargo test --workspace                  # Test entire workspace
```

### Features
The project uses Cargo features for conditional compilation:
- Default features: aes_cbc, aes_ecb, aes_gcm, sm4_cbc, chacha20_poly1305, server_encrypt, ip_proxy, port_mapping, log, command, file_config, lz4, ws, wss, quic
- Optional features: openssl, openssl-vendored, zstd, upnp

## Core Components

### Transport Layer
- `channel/`: Implementation of different transport protocols (UDP, TCP, QUIC, WS)
- `protocol/`: Core protocol definitions and packet handling
- `util/`: Utility functions for networking and protocol handling

### Security Layer
- `cipher/`: Encryption algorithms and key management
- `compression/`: Data compression implementations
- `core/`: Core connection and session management

### Network Layer
- `handle/`: Various handlers for different aspects of the tunnel (handshaking, NAT traversal, maintenance)
- `tun_tap_device/`: TUN/TAP device integration for packet interception
- `nat/`: NAT traversal and hole punching mechanisms

## Key Concepts

### NAT Traversal
- NAT type detection (symmetric/cone)
- Hole punching mechanisms for P2P connections
- Relay fallback for restricted NATs

### Protocol Features
- Capability negotiation during handshake
- Periodic status reporting including NAT type and traffic statistics
- Dynamic virtual IP assignment
- P2P list maintenance for reachability determination
- Status reporting: Clients periodically report `ClientStatusInfo` to the control plane (first after 60s, then every 10 minutes). The current report includes NAT type, traffic information, and `p2p_list`. Control plane `DataPlaneReachable` is currently determined based on whether `p2p_list` is non-empty (meaning偏向"P2P Reachable").

### Security Model
- RSA-AES256GCM encryption for control plane
- Per-client secret for data plane encryption
- Certificate fingerprint verification

### Command Line Interface
The vnt-cli provides extensive command-line options:
- Authentication: `-k <token>` for token, `-d <id>` for device id, `-n <name>` for device name
- Transport: `-s <server>` for server address (only `quic://` protocol currently supported)
- Network: `-a` for TAP mode (instead of TUN), `--nic <name>` for specifying interface name
- Proxy: `-i <in-ip>` and `-o <out-ip>` for IP proxy configuration
- Encryption: `-W` for client-to-server encryption
- Advanced: `--use-channel <relay/p2p>` for forcing relay or P2P mode, `--compressor <lz4>` for enabling compression

## Build Targets
- `vnt-cli`: Main client executable
- `vnt`: Core library
- `vnt-dns`: DNS server functionality
- `vn-link`: Link-level integration

## Troubleshooting
- On Linux, Ctrl+C may not properly exit due to TUN device `SyncDevice::Shutdown()` method differences on Unix-like systems
- Service address protocol currently only supports `quic://`, e.g., `./vnt-cli -k <token> -d <device_id> -s quic://control.example.com:4433`
