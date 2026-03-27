# VNT

> Planned public branding: **SDL (Software Defined LAN)**.
> In the current transition phase, the repository and binaries still use the historical `vnt` name, while the product direction is an overlay LAN built across WAN/Internet.

## Middlescale 版 vnt

* fixed:
Linux下ctrl+c 不能退出，因为使用了tun `SyncDevice::Shutdown()`,这个方法在类Unix系统不同用



### 编译
缺省 `make`是 `make build` 编译 debug 版
`make push` 也是上传 debug 版

`make release`是 build release

### 项目定位（当前阶段）

- 当前代码名仍为 `vnt`，但产品定位更接近 **SDL / Software Defined LAN**，而不是传统意义上的 SD-WAN。
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
到项目根目录下执行 cargo build -p vnt-cli

也可按需编译，将得到更小的二进制文件，使用--no-default-features排除默认features

cargo build -p vnt-cli --no-default-features
```

服务端地址协议当前仅支持 `quic://`，例如：

```
./vnt-cli -k <token> -d <device_id> -s quic://control.example.com:4433
```

features说明

| feature           | 说明                             | 是否默认 |
|-------------------|--------------------------------|------|
| openssl           | 使用openssl中的加密算法                | 否    |
| openssl-vendored  | 从源码编译openssl                   | 否    |
| aes_cbc           | 支持aes_cbc加密                    | 是    |
| aes_ecb           | 支持aes_ecb加密                    | 是    |
| aes_gcm           | 支持aes_gcm加密                    | 是    |
| sm4_cbc           | 支持sm4_cbc加密                    | 是    |
| chacha20_poly1305 | 支持chacha20和chacha20_poly1305加密 | 是    |
| port_mapping      | 端口映射                           | 是    |
| log               | 日志                             | 是    |
| command           | list、route等命令                  | 是    |
| file_config       | yaml配置文件                       | 是    |
| lz4               | lz4压缩                          | 是    |
| zstd              | zstd压缩                         | 否    |
| upnp              | upnp协议                         | 否    |
| ws                | ws协议                           | 是    |
| wss               | wss协议                          | 是    |
| quic              | quic协议                         | 是    |

</details>
