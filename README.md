# SDL

> Planned public branding: **SDL (Software Defined LAN)**.

## Middlescale 版 SDL

* fixed:
Linux下ctrl+c 不能退出，因为使用了tun `SyncDevice::Shutdown()`,这个方法在类Unix系统不同用



### 编译
缺省 `make`是 `make build` 编译 debug 版
`make push` 也是上传 debug 版

`make release`是 build release

### 安装服务

- `install.sh` 现同时支持：
  - Linux `systemd`
  - macOS `launchd`
- 默认会把 `sdl` / `sdl-service` 安装到 `/opt/sdl`，并把命令链接到 `/usr/local/bin`
- 安装时会尽量保留 `env/` 下的持久文件（如 `config.json`、`device-id`、`device.key`）

示例：

```bash
cd sdl
sudo ./install.sh --source-dir ./target/release --user "$USER"
```

- Linux 安装后会启用 `systemd` unit：`sdl-service`
- macOS 安装后会写入 `/Library/LaunchDaemons/net.middlescale.sdl-service.plist`

### 项目定位（当前阶段）

- 当前工作区和二进制已切到 `sdl` / `sdl-service`，产品定位是 **SDL / Software Defined LAN**，而不是传统意义上的 SD-WAN。
- 目标是通过控制面、认证、P2P/relay 和 overlay 数据面，把分散在 WAN / Internet / NAT 后的节点组织成统一的 LAN 体验。
- 因此后续文档会逐步使用：
  - `SDL`
  - `Software Defined LAN`
  - `overlay LAN`

### 状态上报说明（当前实现）

- 客户端会周期上报 `ClientStatusInfo` 到控制面（默认先在 60s 后首次上报，之后每 10min 一次）。
- 当前上报包含 NAT 类型、流量信息和 `p2p_list`。
- 目前控制面 `DataPlaneReachable` 的判定基于 `p2p_list` 是否非空（即当前语义偏向“P2P 可达”）。


### 自行编译

<details> <summary>点击展开</summary>

前提条件:安装rust编译环境([install rust](https://www.rust-lang.org/zh-CN/tools/install))

```
到项目根目录下执行 cargo build -p sdl-cli

也可按需编译，将得到更小的二进制文件，使用--no-default-features排除默认features

cargo build -p sdl-cli --no-default-features
```

`sdl-service` 无参数启动时，会默认使用：

- group：`default.ms.net`
- server：`https://control.middlescale.net/control`

如果 `env/config.json` 已存在，则会优先读取这个保存下来的配置；首次带参数启动成功后也会自动写入它，后续无参数即可直接启动。

如果需要覆盖，再显式传参数。服务端地址当前使用 `https://host[:port]/control`，例如：

```
./target/debug/sdl-service -g default.ms.net -d <device_id> -s https://control.example.com/control
```

前台命令可以在服务运行后修改节点显示名：

```bash
./target/debug/sdl rename office-laptop
```


</details>
