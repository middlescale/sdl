# SDL

[日本語](README.ja.md)

SDL stands for **Software Defined LAN**. It connects machines across WAN, Internet, and NAT environments into an overlay LAN using a control plane plus P2P or relay data paths.

The product idea is inspired by Tailscale's simple private-network experience. SDL uses its own control plane and data-plane implementation, and started from the [vnt-dev/vnt](https://github.com/vnt-dev/vnt) codebase. It has since been substantially changed for the Middlescale control plane, service workflow, authentication model, gateway relay behavior, and the `sdl` / `sdl-service` client split.

## Components

| Binary | Purpose |
| --- | --- |
| `sdl-service` | Long-running local service. It starts the SDL runtime, TUN interface, control connection, P2P, relay, and local command socket. |
| `sdl` | Local CLI frontend. It talks to `sdl-service` for status, auth, resume, suspend, gateway selection, and rename operations. |

## Security And Encryption

SDL keeps control-plane identity and data-plane traffic separate, with a stronger key lifecycle than the original static-password model:

- Each device owns a persistent local private key. The private key stays on the device and is never uploaded to the control plane.
- Registration and authentication use the device public key plus signed challenge responses, so control can verify the device without receiving its private key.
- Peer data packets are encrypted before they leave the TUN path. Incoming peer packets that should be encrypted are dropped if they arrive without the encrypted packet flag or fail decryption.
- Unlike the original VNT-style fixed-password deployment model, SDL can use control-plane state to issue and refresh data-plane encryption material dynamically.

## Quick Install

Build release binaries first:

```bash
cargo build -p sdl-cli --release
```

Install as a system service:

```bash
# Linux/macOS
sudo ./install.sh --source-dir ./target/release --user "$USER"
```

### Windows installation and upgrade

Download `sdl-x86_64-pc-windows-msvc-<version>.zip` from the
[GitHub Releases](https://github.com/middlescale/sdl/releases) page and extract
it. Open **PowerShell as Administrator**, change into the extracted directory,
then install (or upgrade) with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -PreserveConfig
```

`-PreserveConfig` is the default, but specifying it for upgrades makes the
intent clear: the installer keeps `C:\Program Files\SDL\env\config.json`,
`device-id`, and `device.key`. This preserves both the device identity and its
existing control-plane configuration.

Windows commonly blocks unsigned local scripts with an error such as
"running scripts is disabled on this system." The command above uses
`-ExecutionPolicy Bypass` only for that installer process; it does not change
the machine-wide or user-wide execution-policy setting. Do not use a permanent
`Set-ExecutionPolicy` change just to install SDL.

After installation, verify the service and version:

```powershell
Get-Service sdl-service
& 'C:\Program Files\SDL\sdl.exe' version
& 'C:\Program Files\SDL\sdl.exe' status --json
```

The Windows installer installs `sdl.exe`, `sdl-service.exe`, and `wintun.dll`
under `C:\Program Files\SDL`, registers the automatic `sdl-service` Windows
service, and starts it unless `-NoStart` is supplied. Service logs are stored
at `C:\Program Files\SDL\log\sdl-service.log`.

On Linux and macOS, the installer:

- installs `sdl` and `sdl-service` under `/opt/sdl`
- links commands into `/usr/local/bin`
- preserves persistent files under `/opt/sdl/env`
- installs a Linux `systemd` service named `sdl-service`
- installs a macOS `launchd` service named `net.middlescale.sdl-service`

To replace an existing `/opt/sdl/env/config.json` with the installer copy:

```bash
sudo ./install.sh --source-dir ./target/release --user "$USER" --overwrite-config
```

## Run Manually

`sdl-service` requires administrator or root privileges because it creates and manages a virtual network interface.

```bash
sudo sdl-service \
  -g default.ms.net \
  -n my-laptop \
  -s https://control.middlescale.net/control
```

After the first successful start, the service writes its effective configuration to `env/config.json`. Later starts can run without arguments and reuse that saved configuration.

## Configuration

The service reads configuration in this order:

1. command line options
2. `-f <config.yaml>`
3. local `env/config.json`
4. built-in defaults

Minimal config example:

```yaml
config_version: 2
group: default.ms.net
device_id: my-device-id
name: my-laptop
server_address: https://control.middlescale.net/control
ports:
  - 29873
use_channel: auto
punch_model: all
p2p_heartbeat_interval_sec: 10
p2p_route_idle_timeout_sec: 30
```

Notes:

- `server_address` must use `https://host[:port]/control`.
- `ports` controls local UDP listen ports. If missing, SDL fills it with `29873`.
- `use_channel` can be `auto`, `p2p`, or `relay`.
- `group` defaults to `default.ms.net`.
- `device_id` is generated or reused from local state when not set explicitly.

## Common Commands

```bash
sdl status
sdl status --json
sdl list
sdl list --json
sdl gateway --json
sdl gateway --set auto
sdl gateway --set <gateway-name>
sdl route --json
sdl channel_change --type relay
sdl channel_change --json
sdl auth --userId <user-id> [--group default.ms.net] <ticket>
sdl rename <new-name>
sdl suspend
sdl resume
```

Command summary:

- `sdl status` shows local service, authentication, network, route, and gateway state.
- `sdl auth` submits a device auth ticket to the running local service.
- `sdl rename` updates the display name stored by control; restart `sdl-service` to apply it locally.
- `sdl suspend` pauses local traffic handling without exiting the service process.
- `sdl resume` resumes an existing runtime or recreates it from saved config.
- `sdl gateway --set auto` returns gateway selection to automatic mode.
- `sdl route --json` shows the current forwarding path.
- `sdl channel_change --type relay` switches the local runtime to relay mode.
- If a device is waiting for authentication, `sdl status --json` exposes `auth_pending` and `last_error`.

## Build

Debug build:

```bash
cargo build -p sdl-cli
```

Release build:

```bash
cargo build -p sdl-cli --release
```

Minimal build without default features:

```bash
cargo build -p sdl-cli --no-default-features
```

Windows local build helper:

```bash
./build-windows-local.sh
```

## Platform Notes

- Linux uses `systemd` when installed through `install.sh`.
- macOS uses `launchd` when installed through `install.sh`.
- Windows uses a native SCM service when installed through `install.ps1` (run in an elevated PowerShell). `sdl-service.exe` already implements the service entrypoint; the installer lays out binaries, registers the service, and attempts to start it as a best-effort check. Use `.\install.ps1 -NoStart` to register without starting. After installation, normal `sdl` CLI commands can run as a non-admin user.
- Installers generate `<install_dir>/env/device-id` and `<install_dir>/env/device.key` only when missing, and never overwrite existing installed identity files. Linux and macOS preserve identity from the install directory's `env`; Windows also migrates legacy `device-id` / `device.key` from the unpacked release directory's `env` when the target files are missing. `sdl-service` uses `<install_dir>/env/device.key` through `SDL_DEVICE_KEY_PATH`, so device identity survives reinstall as long as the installed `env` directory is preserved.
- DNS profile integration is implemented for Linux, macOS, and Windows.
- `sdl-service` prints an error when privileges are insufficient; it does not prompt for sudo automatically.
- Service logs: on Linux `sdl-service` logs to stderr (captured by journald, view with `journalctl -u sdl-service`); on macOS and Windows it writes a rolling file at `<install_dir>/log/sdl-service.log` (10MB × 5 archives, level via `RUST_LOG`, default `info`). An optional `<install_dir>/env/log4rs.yaml` overrides this on every platform.
