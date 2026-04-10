[中文](/README.md) | [English](/README_en_US.md) | [日本語](/README_ja_JP.md) | [Русский](/README_ru_RU.md) 

# Caesar 特製 Xray ワンクリックインストール＆管理ツールボックス (Install-Xray-Inbounds)

これは、強力で高度にモジュール化され、優れた互換性を持つ Xray ノードのインストールおよび管理スクリプトのコレクションです。1台のサーバー上で複数の主要プロトコル（VLESS-Reality、VLESS-Encryption、Shadowsocks 2022など）の完全な共存展開をサポートし、便利な設定バックアップ、ルーティング（分岐）管理、Geoデータ更新機能を提供します。

## ✨ コア機能

* **複数プロトコルのスマートな共存**: 基盤となる `jq` 解析を採用し、JSON設定をスマートに追記します。異なるプロトコルや複数ポートのノードを自由自在にインストールでき、元のノード設定を**絶対に上書きしません**。
* **究極のシステム互換性**: Debian / Ubuntu などの Systemd ベースの主要システムを完璧にサポートするだけでなく、**Alpine Linux (OpenRC) とも深い互換性**を持ち、極限まで無駄を省いた軽量システムにも対応しています。
* **NAT / DDNS フレンドリー**: 独立した接続アドレスのカスタマイズ機能を内蔵しています。動的ポートを使用する NAT 環境でも、DDNS ドメイン名前解決を利用していても、ワンクリックで正確な共有リンクを生成でき、手動でアドレスを変更する煩わしさから解放されます。
* **最先端プロトコルのサポート**: 最新の VLESS Encryption（Post-Quantum 純粋な耐量子暗号）および VLESS-Reality（Vision）をサポートし、ネイティブキーをより互換性の高いランダムキーに自動変換します。
* **ワンストップ管理**: 全体統合型の管理メニュー (`xray-manager`)、ルーティング設定ツール (`xray-routing`)、および設定バックアップ・復元ツール (`xray-restore`) を提供します。
* **安全かつ正確な削除**: ポートとプロトコルに基づき、特定のノード設定を正確に識別して削除できます。他の設定を誤って削除することは絶対にありません。

-----

## 🚀 クイックスタート（推奨）

最も完全な管理機能を体験したい場合は、\*\*統合管理センター（Xray Manager）\*\*を直接インストールすることをお勧めします。

以下のコマンドを実行するだけで、グローバル管理メニューをダウンロードして呼び出すことができます：

```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_manager.sh -o xray_manager.sh && chmod +x xray_manager.sh && sudo ./xray_manager.sh
```

**💡 ヒント：**
統合管理ツールをインストールすると、自動的にグローバルコマンドが登録されます。以降は、ターミナルで以下のコマンドを入力するだけで、いつでも簡単にメインメニューを呼び出すことができます：

```bash
xray-manager
```

`xray-manager` メニューからは、以下のすべての独立した機能をワンクリックで直接呼び出すことができ、スクリプトを個別にダウンロードする必要はありません。

-----

## 📦 各機能モジュールの独立インストールガイド

このプロジェクトの特定の機能のみを使用したい場合は、以下の個別のインストールコマンドを直接使用することもできます。

### 1\. VLESS-Reality (Vision) ノード管理

X25519キーペアの自動生成をサポートし、デフォルトで `xtls-rprx-vision` フロー制御を使用します。安定しており、隠蔽性に優れています。

```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/install_vless_reality.sh -o install_vless_reality.sh && chmod +x install_vless_reality.sh && sudo ./install_vless_reality.sh
```

### 2\. VLESS-Encryption (Post-Quantum) ノード管理

最新の耐量子暗号プロトコル (ML-KEM-768) を展開し、ランダムキーを自動生成および最適化して、将来のネットワークセキュリティを保護します。

```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/install_vless_encryption.sh -o install_vless_encryption.sh && chmod +x install_vless_encryption.sh && sudo ./install_vless_encryption.sh
```

### 3\. Shadowsocks 2022 & 従来の SS ノード管理

超高速な 2022-blake3-aes などの次世代暗号化プロトコルをサポートし、従来の aes-gcm 暗号化との下位互換性も備え、強力なランダムパスワードを自動生成します。

```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/install_ss2022.sh -o install_ss2022.sh && chmod +x install_ss2022.sh && sudo ./install_ss2022.sh
```

### 4\. サーバー側ルーティング（分岐）ツール (Xray Routing)

強力なサーバー側のアウトバウンドルーティング制御パネルです。外部設定リンクのインポートをサポートし、ssおよびvlessの共有リンク内の各種パラメータの解析をサポートします（現在はss、ss2022、vless vision reality、およびvless encryptionのみサポート）。InboundsからOutboundsへのIP/ドメインベースの分岐ルールを視覚的に設定できます。

```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_routing.sh -o xray_routing.sh && chmod +x xray_routing.sh && sudo ./xray_routing.sh
```

*インストール後は、いつでも `xray-routing` コマンドで呼び出せます。*

### 5\. バックアップと復元ツール (Xray Restore)

誤って設定を変更してしまった？設定を移行したい？このツールを使用すると、直接リンクURLから設定ファイルをインポートしたり、コンソールを開いて手動で `config.json` を貼り付けたりできます。エラーを防ぐための安全テスト機能が組み込まれています。

```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/xray_restore.sh -o xray_restore.sh && chmod +x xray_restore.sh && sudo ./xray_restore.sh
```

*インストール後は、いつでも `xray-restore` コマンドで呼び出せます。*

### 6\. 完全アンインストールツール

解決できない深刻な問題に直面した場合、またはサーバーを完全にクリーンアップしたい場合は、このスクリプトを使用できます。システムサービス（Systemd/OpenRC）、バイナリファイル、ログ、および残留設定を極めてきれいにクリーンアップします。

```bash
curl -L https://raw.githubusercontent.com/RomanovCaesar/Install-Xray-Inbounds/main/uninstall_xray.sh -o uninstall_xray.sh && chmod +x uninstall_xray.sh && sudo ./uninstall_xray.sh
```

-----

## 🛠️ よくある質問 (FAQ)

**Q: サーバーが NAT VPS である、または入口の IP と出口の IP が異なり、生成されたノードが通信できません。どうすればよいですか？**

**A:** 任意のインストールメニュー（またはメイン管理メニュー）で **「接続アドレスの設定 (NAT/DDNS)」** オプションを選択してください。実際に外部接続に使用する IP アドレスまたは DDNS ドメイン名を入力します。設定完了後、スクリプトが自動生成する共有リンクには指定したアドレスが使用され、NAT 環境での直接接続問題が完全に解決されます。

**Q: Xray の実行ログを確認するにはどうすればよいですか？**

**A:** 各インストール管理スクリプトのメニューに **「Xray ログの表示」** オプションがあります。これを選択すると、リアルタイムで実行ログを確認できます。`Ctrl + C` を押すと表示を停止してメニューに戻ります。

**Q: GeoIP および GeoSite のルーティングルールファイルを更新するにはどうすればよいですか？**

**A:** `xray-routing` (サーバー側ルーティングツール) を使用している場合、スケジュールタスクのワンクリック自動設定機能が含まれており、毎日深夜に自動的に更新されます。また、メイン管理ツール (`xray-manager`) から手動で即時更新を実行することもできます。
