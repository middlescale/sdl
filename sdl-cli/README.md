## 模块介绍

体积小，可以在服务器、路由器等环境使用

## 当前推荐入口

当前推荐把 SDL 拆成：

- `sdl-service`：常驻后端，负责启动网络 runtime、TUN 和本地控制接口
- `sdl`：前端命令，负责调用本地服务并输出结果

从产品定位上，这套结构更接近 **SDL (Software Defined LAN)**：通过控制面与 overlay 数据面，把分散在 WAN / Internet 上的节点组织成统一的 LAN 体验。当前文档已按 `sdl` / `sdl-service` 入口整理。

### `sdl-service` 启动方式

`sdl-service` 的参数可以有三种来源，优先级从高到低如下：

- 直接在命令行里指定
- 通过 `-f <config.yaml>` 指定配置文件
- 读取本地 `env/config.json`

如果既没有命令行参数，也没有 `-f` 配置文件，则会先尝试读取本地 `env/config.json`；如果仍不存在，再使用默认值：

- group：`default.ms.net`
- server：`https://control.middlescale.net/control`
- device_id：自动生成或复用本机已有 device id
- name：主机名

示例：

```bash
sudo sdl-service -g <group> -n <name> -s <server>
sudo sdl-service -f /path/to/config.yaml
```

`sdl-service` 负责带参数启动；首次带参数启动成功后，会把启动配置写入 `env/config.json`。`sdl resume` 只负责恢复已经存在的本地 service runtime，不再接受启动参数。

如果 `sdl-service` 已经在本机启动过，那么：

- `sdl suspend`：只挂起当前 runtime 的本地收发，不退出 `sdl-service` 进程
- `sdl resume`：不带 service 参数时，恢复已存在的 runtime；如果 runtime 已退出，则按保存配置重建

### 前端命令示例

```bash
sdl resume
sdl rename office-laptop
sdl list
sdl list --json
sdl info --json
sdl gateway --json
sdl route --json
sdl auth --userId <user-id> [--group default.ms.net] <ticket>
sdl channel_change --type relay
sdl channel_change --json
sdl suspend
```

- `sdl-service ...`：按参数或配置文件启动 daemon
- `sdl resume`：恢复本地收发服务；优先恢复已有 runtime
- `sdl suspend`：挂起本地收发服务，但保留内存中的 runtime 状态
- `sdl rename <name>`：修改当前节点显示名；成功后会同步到 control，并写回本地保存配置，需重启 `sdl-service` 后对外生效
- `sdl list/info/gateway/route`：查询当前本地服务状态，其中 `sdl gateway` 用于查看当前 gateway candidates 与 active gateway
- `sdl auth ...`：向本地 `sdl-service` 提交设备认证；`--group` 不传时默认使用 `default.ms.net`；认证完成后会把状态写回本地状态文件
- control 服务器地址由 `sdl-service ... -s <server>` 决定
- 如果设备处于待认证状态，可用 `sdl info --json` 查看 `auth_pending` 和 `last_error`

### 权限说明

- `sdl-service` 需要管理员/root权限
- Linux/macOS 下请显式使用 `sudo sdl-service ...`
- Windows 下请使用管理员权限启动
- `sdl-service` 检测到权限不足时只会提示，不会自动弹出 sudo 密码框
- SDL DNS profile 现支持 Linux（`resolvectl`）、macOS（`/etc/resolver`）和 Windows（NRPT split DNS）

## 详细参数说明

### -g `<group>`

一个虚拟局域网分组标识，在同一服务器下，相同 group 的设备会组建一个局域网，例如 `default.ms.net`

### -n `<name>`

设备名称，方便区分不同设备

### -d `<id>`

设备id，每台设备的唯一标识，注意不要重复

### -s `<server>`

注册和中继服务器地址，控制面使用 `https://host[:port]/control`；以`TXT:`开头时表示先解析 TXT 记录，TXT 记录内容必须是 `host:port` 形式的服务器地址

### -e `<stun-server>`

使用stun服务探测客户端NAT类型，不同类型有不同的打洞策略

### -a

加了此参数表示使用tap网卡，默认使用tun网卡，tun网卡效率更高

注意：仅在windows上支持使用tap，用于兼容低版本windows系统（低版本windows不支持wintun）

使用tap模式需要手动创建tap网卡，使用--nic参数指定已经创建好的tap网卡名称

### --nic `<tun0>`

指定虚拟网卡名称，默认tun模式使用sdl-tun，tap模式使用sdl-tap

### -i `<in-ip>`、-o  `<out-ip>`

配置点对网(IP代理)时使用，例如A(虚拟ip:10.26.0.2)通过B(虚拟ip:10.26.0.3,本地出口ip:192.168.0.10)访问C(
目标网段192.168.0.0/24)，

则在A配置 **'-i 192.168.0.0/24,10.26.0.3'** ,表示将192.168.0.0/24网段的数据都转发到10.26.0.3节点

在B配置 **'-o 192.168.0.0/24'**  ,表示允许将数据转发到 192.168.0.0/24 ,允许转发所有网段可以使用 **'-o 0.0.0.0/0'**

-i和-o参数均可使用多次，来指定不同网段，例如 **'-o 192.168.1.0/24 -o 192.168.2.0/24'**
表示允许转发目标为192.168.1.0/24或192.168.2.0/24这两个网段的数据

### -W

开启和服务端通信的数据加密，采用rsa+aes256gcm加密客户端和服务端之间通信的数据，可以避免 group 泄漏、中间人攻击

注意：

1. -W 用于开启客户端-服务端之间的加密

### -u `<mtu>`

设置虚拟网卡的mtu值，大多数情况下使用默认值效率会更高，也可根据实际情况微调这个值，不加密默认为1450，加密默认为1410

### ~~--tcp~~

~~和服务端使用tcp通信。有些网络提供商对UDP限制比较大，这个时候可以选择使用TCP模式，提高稳定性。一般来说udp延迟和消耗更低~~

当前控制面连接使用 `-s https://host[:port]/control`

### --ip `<IP>`

指定虚拟ip,指定的ip不能和其他设备重复,必须有效并且在服务端所属网段下,默认情况由服务端分配

### --par `<parallel>`

任务并行度(必须为正整数),默认值为1,该值表示处理网卡读写的任务数,组网设备数较多、处理延迟较大时可适当调大此值

### --punch `<punch>`

取值ipv4/ipv6，选择只使用ipv4打洞或者只使用ipv6打洞，默认两者都会使用

### --ports `<port1,port2>`

指定本地监听的端口组，多个端口使用逗号分隔，多个端口可以分摊流量，增加并发、减缓流量限制，tcp会监听端口组的第一个端口，用于tcp直连。默认监听 `29873`

- 例1：‘--ports 12345,12346,12347’ 表示udp监听12345、12346、12347这三个端口，tcp监听12345端口
- 例2：‘--ports 0,0’ 表示udp监听两个未使用的端口，tcp监听一个未使用的端口

### --latency_first

优先使用低延迟通道，默认情况下优先使用p2p通道，某些情况下可能p2p比客户端中继延迟更高，可使用此参数进行优化传输

### --mapping `<udp:0.0.0.0:80-10.26.0.10:80>`

端口映射,可以设置多个映射地址，例如 '--mapping udp:0.0.0.0:80-10.26.0.10:80 --mapping tcp:0.0.0.0:80-10.26.0.11:81'
表示将本地udp 80端口的数据转发到10.26.0.10:80，将本地tcp 80端口的数据转发到10.26.0.11:81，转发的目的地址可以使用域名+端口

### --compressor `<lz4>`

启用压缩，默认仅支持lz4压缩，开启压缩后，如果数据包长度大于等于128，则会使用压缩，否则还是会按原数据发送

也支持开启zstd压缩，但是需要自行编译，编译时加入参数--features zstd

如果宽度速度比较慢，可以考虑使用高级别的压缩

### -f `<conf>`

指定配置文件
配置文件采用yaml格式，可参考：

```yaml
# 全部参数
tap: false #是否使用tap 仅在windows上支持使用tap
group: default.ms.net #组网分组
device_id: xxx #当前设备id
name: windows 11 #当前设备名称
server_address: https://control.middlescale.net/control #控制面地址
stun_server: #stun服务器
  - stun1.l.google.com:19302
  - stun2.l.google.com:19302
in_ips: #代理ip入站
  - 192.168.1.0/24,10.26.0.3
out_ips: #代理ip出站
  - 0.0.0.0/0
mtu: 1420  #mtu
tcp: false #tcp模式
ip: 10.26.0.2 #指定虚拟ip
use_channel: relay #relay:仅中继模式.p2p:仅直连模式
parallel: 1 #任务并行度
cipher_model: aes_gcm #客户端加密算法
punch_model: ipv4 #打洞模式，表示只使用ipv4地址打洞，默认会同时使用v6和v4
ports:
  - 29873 #默认监听端口，tcp监听此端口
latency_first: false #是否优先低延迟通道，默认为false，表示优先使用p2p通道
device_name: sdl-tun #网卡名称
packet_loss: 0 #指定丢包率 取值0~1之间的数 用于模拟弱网
packet_delay: 0 #指定延迟 单位毫秒 用于模拟弱网
mapping:
  - udp:0.0.0.0:80-10.26.0.10:80 # 映射udp数据
  - tcp:0.0.0.0:80-10.26.0.10:81 # 映射tcp数据
  - tcp:0.0.0.0:82-localhost:83 # 映射tcp数据
disable_stats: false # 为true表示关闭统计
```

或者需要哪个配置就加哪个，当然 group 是必须的

```yaml
# 部分参数
group: default.ms.net #组网分组
```

### --use-channel `<relay/p2p>`

- relay:仅中继模式，会禁止打洞/p2p直连，只使用服务器转发
- p2p:仅直连模式，会禁止网络数据从服务器/客户端转发，只会使用服务器转发控制包

### --packet-loss `<0>`

模拟丢包，取值0~1之间的小数，程序会按设定的概率主动丢包。在模拟弱网环境时会有帮助。

### --packet-delay `<0>`

模拟延迟,整数,单位毫秒(ms),程序会按设定的值延迟发包,可用于模拟弱网

### --disable-stats

关闭流量统计

### 本地前端命令

后台交互和状态查询请使用新的前端子命令：

- `sdl list`
- `sdl info`
- `sdl route`
- `sdl suspend`
- `sdl resume`
