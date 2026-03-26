## 模块介绍

体积小，可以在服务器、路由器等环境使用

## 当前推荐入口

当前推荐把 VNT 拆成：

- `vnt-service`：常驻后端，负责启动网络 runtime、TUN 和本地控制接口
- `vnt`：前端命令，负责调用本地服务并输出结果

### `vnt-service` 启动方式

`vnt-service` 的参数可以有两种来源：

- 直接在命令行里指定
- 通过 `-f <config.yaml>` 指定配置文件

示例：

```bash
sudo vnt-service -k <token> -n <name> -s <server>
sudo vnt-service -f /path/to/config.yaml
```

`vnt-service` 负责带参数启动；`vnt start` 只负责恢复已经存在的本地 service runtime，不再接受启动参数。

如果 `vnt-service` 已经在本机启动过，那么：

- `vnt stop`：只停止当前 runtime，保留 `vnt-service` 进程
- `vnt start`：不带 service 参数时，按已保存配置恢复 runtime

### 前端命令示例

```bash
vnt start
vnt list
vnt list --json
vnt info --json
vnt route --json
vnt auth <user-id> <group> <ticket>
vnt channel_change --type relay
vnt channel_change --json
vnt stop
```

- `vnt-service ...`：按参数或配置文件启动 daemon
- `vnt start`：当本地 service 已存在且处于 stopped 状态时，恢复收发服务
- `vnt stop`：停止当前收发服务，但不退出 `vnt-service` 进程
- `vnt list/info/route`：查询当前本地服务状态
- `vnt auth ...`：向本地 `vnt-service` 提交设备认证
- control 服务器地址由 `vnt-service ... -s <server>` 决定
- 如果设备处于待认证状态，可用 `vnt info --json` 查看 `auth_pending` 和 `last_error`

### 权限说明

- `vnt-service` 需要管理员/root权限
- Linux/macOS 下请显式使用 `sudo vnt-service ...`
- Windows 下请使用管理员权限启动
- `vnt-service` 检测到权限不足时只会提示，不会自动弹出 sudo 密码框

## 详细参数说明

### -k `<token>`

一个虚拟局域网的标识，在同一服务器下，相同token的设备会组建一个局域网

### -n `<name>`

设备名称，方便区分不同设备

### -d `<id>`

设备id，每台设备的唯一标识，注意不要重复

### -c

关闭控制台交互式命令，后台运行时可以加此参数

### -s `<server>`

注册和中继服务器地址，注册和转发数据，以'TXT:'开头表示解析TXT记录，TXT记录内容必须是'host:port'形式的服务器地址

### -e `<stun-server>`

使用stun服务探测客户端NAT类型，不同类型有不同的打洞策略

### -a

加了此参数表示使用tap网卡，默认使用tun网卡，tun网卡效率更高

注意：仅在windows上支持使用tap，用于兼容低版本windows系统（低版本windows不支持wintun）

使用tap模式需要手动创建tap网卡，使用--nic参数指定已经创建好的tap网卡名称

### --nic `<tun0>`

指定虚拟网卡名称，默认tun模式使用vnt-tun，tap模式使用vnt-tap

### -i `<in-ip>`、-o  `<out-ip>`

配置点对网(IP代理)时使用，例如A(虚拟ip:10.26.0.2)通过B(虚拟ip:10.26.0.3,本地出口ip:192.168.0.10)访问C(
目标网段192.168.0.0/24)，

则在A配置 **'-i 192.168.0.0/24,10.26.0.3'** ,表示将192.168.0.0/24网段的数据都转发到10.26.0.3节点

在B配置 **'-o 192.168.0.0/24'**  ,表示允许将数据转发到 192.168.0.0/24 ,允许转发所有网段可以使用 **'-o 0.0.0.0/0'**

-i和-o参数均可使用多次，来指定不同网段，例如 **'-o 192.168.1.0/24 -o 192.168.2.0/24'**
表示允许转发目标为192.168.1.0/24或192.168.2.0/24这两个网段的数据

### -W

开启和服务端通信的数据加密，采用rsa+aes256gcm加密客户端和服务端之间通信的数据，可以避免token泄漏、中间人攻击

注意：

1. -W 用于开启客户端-服务端之间的加密

### -u `<mtu>`

设置虚拟网卡的mtu值，大多数情况下使用默认值效率会更高，也可根据实际情况微调这个值，不加密默认为1450，加密默认为1410

### ~~--tcp~~

~~和服务端使用tcp通信。有些网络提供商对UDP限制比较大，这个时候可以选择使用TCP模式，提高稳定性。一般来说udp延迟和消耗更低~~

当前控制面连接仅支持 `-s quic://...`

### --ip `<IP>`

指定虚拟ip,指定的ip不能和其他设备重复,必须有效并且在服务端所属网段下,默认情况由服务端分配

### --par `<parallel>`

任务并行度(必须为正整数),默认值为1,该值表示处理网卡读写的任务数,组网设备数较多、处理延迟较大时可适当调大此值

### --model `<model>`

加密模式，可选值
aes_gcm/aes_cbc/aes_ecb/sm4_cbc/chacha20_poly1305/chacha20/xor，默认使用aes_gcm，通常情况aes_gcm和chacha20_poly1305安全性高。
各种加密模式的安全性和速度都不相同，请按需选取

特别说明：xor只是对数据进行简单异或，仅仅避免了明文传输，安全性很差，同时对性能影响也极小；

| 密码位数   | model             | 加密算法              |  
|--------|-------------------|-------------------|
| `< 8`  | aes_gcm           | AES128-GCM        |
| `>= 8` | aes_gcm           | AES256-GCM        |
| `< 8`  | aes_cbc           | AES128-CBC        |
| `>= 8` | aes_cbc           | AES256-CBC        |
| `< 8`  | aes_ecb           | AES128-ECB        |
| `>= 8` | aes_ecb           | AES256-ECB        |
| `> 0`  | sm4_cbc           | SM4-CBC           |
| `> 0`  | chacha20_poly1305 | ChaCha20-Poly1305 |
| `> 0`  | chacha20          | ChaCha20          |
| `> 0`  | xor               | 简单异或混淆            |

### --punch `<punch>`

取值ipv4/ipv6，选择只使用ipv4打洞或者只使用ipv6打洞，默认两者都会使用

### --ports `<port1,port2>`

指定本地监听的端口组，多个端口使用逗号分隔，多个端口可以分摊流量，增加并发、减缓流量限制，tcp会监听端口组的第一个端口，用于tcp直连

- 例1：‘--ports 12345,12346,12347’ 表示udp监听12345、12346、12347这三个端口，tcp监听12345端口
- 例2：‘--ports 0,0’ 表示udp监听两个未使用的端口，tcp监听一个未使用的端口

### --cmd

开启交互式命令，开启后可以直接在窗口下输入命令，如需后台运行请勿开启

### --latency_first

优先使用低延迟通道，默认情况下优先使用p2p通道，某些情况下可能p2p比客户端中继延迟更高，可使用此参数进行优化传输

### --dns `<223.5.5.5>`

设置域名解析服务器地址，可以设置多个。如果使用TXT记录的域名，则dns默认使用223.5.5.5和114.114.114.114，端口省略值为53

当地址解析失败时，会依次尝试后面的dns，直到有A记录、AAAA记录(或TXT记录)的解析结果

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
token: xxx #组网token
device_id: xxx #当前设备id
name: windows 11 #当前设备名称
server_address: ip:port #注册和中继服务器
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
  - 0 #使用随机端口，tcp监听此端口
  - 0
cmd: false #关闭控制台输入
latency_first: false #是否优先低延迟通道，默认为false，表示优先使用p2p通道
device_name: vnt-tun #网卡名称
packet_loss: 0 #指定丢包率 取值0~1之间的数 用于模拟弱网
packet_delay: 0 #指定延迟 单位毫秒 用于模拟弱网
dns:
  - 223.5.5.5 # 首选dns
  - 8.8.8.8 # 备选dns
mapping:
  - udp:0.0.0.0:80-10.26.0.10:80 # 映射udp数据
  - tcp:0.0.0.0:80-10.26.0.10:81 # 映射tcp数据
  - tcp:0.0.0.0:82-localhost:83 # 映射tcp数据
disable_stats: false # 为true表示关闭统计
```

或者需要哪个配置就加哪个，当然token是必须的

```yaml
# 部分参数
token: xxx #组网token
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

### --list

在后台运行时,查看其他设备列表

### --all

在后台运行时,查看其他设备完整信息

### --info

在后台运行时,查看当前设备信息

### --route

在后台运行时,查看数据转发路径

### --stop

停止后台运行
