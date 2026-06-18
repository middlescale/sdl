# SDL

[English](README.md)

SDL は **Software Defined LAN** の略です。コントロールプレーンと P2P / リレーのデータパスを使い、WAN、インターネット、NAT 配下にある複数のマシンを 1 つのオーバーレイ LAN として接続します。

製品コンセプトは、Tailscale のシンプルなプライベートネットワーク体験から着想を得ています。SDL は独自のコントロールプレーンとデータプレーン実装を持ち、[vnt-dev/vnt](https://github.com/vnt-dev/vnt) のコードベースから始まりました。その後、Middlescale のコントロールプレーン、サービス運用、認証モデル、ゲートウェイリレー、そして `sdl` / `sdl-service` のクライアント分離に合わせて大きく変更されています。

## コンポーネント

| バイナリ | 役割 |
| --- | --- |
| `sdl-service` | 常駐するローカルサービスです。SDL runtime、TUN インターフェース、control 接続、P2P、relay、ローカルコマンドソケットを起動します。 |
| `sdl` | ローカル CLI フロントエンドです。`sdl-service` と通信し、status、auth、resume、suspend、gateway 選択、rename などを実行します。 |

## セキュリティと暗号化

SDL はコントロールプレーンの identity とデータプレーンの通信を分離し、元の固定パスワード方式より強い鍵ライフサイクルを採用しています。

- 各 device は永続的なローカル秘密鍵を持ちます。この秘密鍵は device 上に残り、control plane へアップロードされません。
- 登録と認証では device public key と署名付き challenge response を使うため、control は秘密鍵を受け取らずに device を検証できます。
- Peer data packet は TUN 経路から出る前に暗号化されます。暗号化されるべき peer packet が暗号化フラグなしで届いた場合や復号に失敗した場合は破棄されます。
- 元の VNT 風の固定パスワード運用とは異なり、SDL は control-plane state に基づいて data-plane encryption material を動的に発行、更新できます。

## クイックインストール

まず release バイナリをビルドします。

```bash
cargo build -p sdl-cli --release
```

システムサービスとしてインストールします。

```bash
sudo ./install.sh --source-dir ./target/release --user "$USER"
```

インストーラは次を行います。

- `sdl` と `sdl-service` を `/opt/sdl` にインストールします
- `/usr/local/bin` にコマンドリンクを作成します
- `/opt/sdl/env` 配下の永続ファイルを保持します
- Linux では `sdl-service` という `systemd` サービスをインストールします
- macOS では `net.middlescale.sdl-service` という `launchd` サービスをインストールします

既存の `/opt/sdl/env/config.json` をインストーラ側の設定で置き換える場合:

```bash
sudo ./install.sh --source-dir ./target/release --user "$USER" --overwrite-config
```

## 手動起動

`sdl-service` は仮想ネットワークインターフェースを作成、管理するため、管理者権限または root 権限が必要です。

```bash
sudo sdl-service \
  -g default.ms.net \
  -n my-laptop \
  -s https://control.middlescale.net/control
```

初回起動に成功すると、実際に使われた設定が `env/config.json` に保存されます。次回以降は引数なしで起動して、保存済み設定を再利用できます。

## 設定

サービスは次の優先順位で設定を読み込みます。

1. コマンドラインオプション
2. `-f <config.yaml>`
3. ローカルの `env/config.json`
4. 組み込みデフォルト

最小設定例:

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

補足:

- `server_address` は `https://host[:port]/control` 形式で指定します。
- `ports` はローカル UDP listen ポートです。未指定の場合、SDL は `29873` を補います。
- `use_channel` には `auto`、`p2p`、`relay` を指定できます。
- `group` のデフォルトは `default.ms.net` です。
- `device_id` を明示しない場合、ローカル状態から生成または再利用されます。

## よく使うコマンド

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

コマンド概要:

- `sdl status` はローカルサービス、認証、ネットワーク、route、gateway の状態を表示します。
- `sdl auth` は実行中のローカルサービスへ device auth ticket を送信します。
- `sdl rename` は control に保存される表示名を更新します。ローカル反映には `sdl-service` の再起動が必要です。
- `sdl suspend` はサービスプロセスを終了せず、ローカル通信処理を一時停止します。
- `sdl resume` は既存 runtime を再開します。runtime がない場合は保存済み設定から再作成します。
- `sdl gateway --set auto` は gateway 選択を自動モードに戻します。
- `sdl route --json` は現在の転送経路を表示します。
- `sdl channel_change --type relay` はローカル runtime を relay モードへ切り替えます。
- device が認証待ちの場合、`sdl status --json` で `auth_pending` と `last_error` を確認できます。

## ビルド

Debug build:

```bash
cargo build -p sdl-cli
```

Release build:

```bash
cargo build -p sdl-cli --release
```

デフォルト feature なしの最小ビルド:

```bash
cargo build -p sdl-cli --no-default-features
```

Windows ローカルビルド helper:

```bash
./build-windows-local.sh
```

## プラットフォームメモ

- Linux では `install.sh` により `systemd` が使われます。
- macOS では `install.sh` により `launchd` が使われます。
- Windows service は `sdl-service.exe` に実装されています。管理者権限で実行してください。
- DNS profile 連携は Linux、macOS、Windows に対応しています。
- 権限が不足している場合、`sdl-service` はエラーを表示します。sudo パスワード入力は自動で表示しません。
