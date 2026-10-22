# packetdeath

日本語 | [English](README.md)

広告と悪いサイトへの通信を、ブラウザの外で動く見張り役のプログラムが止めます。
見張り役は、通信の宛先の名前を一覧と照合して、載っている名前への接続だけを断ちます。

ブラウザの拡張機能ではないので、ブラウザの中身を書き換えません。
同じ見張り役に、家の中の別の端末(iPhone など)の通信を向けることもできます。

## 困りごと

- 広告や追跡の通信が多く、ページが重い。
- ブラウザの拡張機能に頼った広告ブロッカーは、ブラウザの仕様変更で動かなくなることがある。
- 端末ごとに対策を入れて回るのが手間である。
- 悪いサイトとして公開されている宛先に、うっかり接続してしまうのを減らしたい。

packetdeath は、これらを「宛先の名前の一覧」で止めます。
一覧に載っていない通信と、名前が読み取れない通信は止めません。
一覧は人が書き換えられます。
書き換えると約0.3秒で反映され、再起動は要りません。

## 仕組み

HTTPS(鍵マークの付いた暗号化通信)は、通信の中身が暗号化されます。
ただし、接続の最初に「どのサイトに繋ぐか」という名前だけは、暗号化される前に相手へ伝わります。
packetdeath の見張り役は、この名前を見ます。
通信の中身は読みません。

```
端末 ---(example.org へ繋ぎたい)---> 見張り役 ---名前が一覧に載っている---> 接続を断つ
                                        |
                                        +---載っていない / 読めない-----> そのまま通す
                                        |
                                        +---どちらの場合も 1 件 1 行で記録 (flows.jsonl)
```

図の結論は、一覧に載った名前だけを止め、それ以外は通す、である。

見張り役が判断に使う材料は3つです。

- **SNI**：接続の最初に平文で伝わる、接続先のサイトの名前。
- **CNAME**：DNS(名前から住所を引く仕組み)の答えに入る別名。
  広告の会社が、サイト自身の名前の別名として自社を隠していることがある。
- **宛先 IP**：接続先の住所。
  名前が無い通信(IP を直接指定した接続)に効く。

用語を2つ足します。

- **blocklist**：止める宛先の一覧。
  1行に1つの名前を書く。
  `example.org` と書くと、`example.org` と `*.example.org` に当たる。
- **allowlist**：何があっても通す宛先の一覧。
  書式は blocklist と同じで、blocklist より必ず先に効く。

見張り役を置く方式は3つあります。

| 方式 | 見張り役の置き場 | 管理者権限 | 動かした実績 |
|---|---|---|---|
| `proxy` | 通信の中継役(**proxy**)。端末のブラウザや iPhone の proxy 欄をこの中継役へ向ける | 要らない | Linux |
| `block` | Linux の核(kernel)が通信を見張り役へ渡す仕組み(**nfqueue**)を使う。端末から出る通信を見る | 要る(root) | Linux |
| Windows サービス | Windows 標準の通信記録道具(**pktmon**)が残した記録を読み、確立済みの接続を切る | 要る | Windows 11 |

## 確かめた結果と限界

最短手順(後の節)と同じ command を、Linux の端末で打って確かめました。

| 打った通信 | 結果 |
|---|---|
| 一覧に載せた `example.org` へ、見張り役を通して接続 | `curl: (7) CONNECT tunnel failed, response 403`。記録は `"decision":"block","reason":"sni"` |
| 一覧に載せていない `example.com` へ、同じ見張り役を通して接続 | HTTP ステータス `200`。記録は `"decision":"pass"` |

この結果が示すのは、仕組みが動くことだけです。
広告をどれだけ減らせるか、悪いサイトをどれだけ防げるかは、一覧の質で決まり、この結果からは言えません。

名前が見えない通信は止められません。

- **ECH**：接続先の名前まで暗号化する新しい仕組み。
  使われると、見張り役には名前が見えない。
- **QUIC**(UDP 443 の通信)は、数えて記録するだけで、止めません。
- 動画の中に縫い込まれた広告、サイト自身の名前で配られる広告、広告ブロックの検知を回避する動作は、対象外です。
- DNS を HTTPS で引くアプリ(**DoH**)の DNS 通信は、見分けられません。

「マルウェアを防げる」とは言えません。
止められるのは、一覧に載っている宛先と、検査の道具(Suricata と ClamAV)が検知したものまでです。
検知率は、一覧と検査の道具の質で決まります。

## 向く場面と向かない場面

| | 向く | 向かない |
|---|---|---|
| 管理 | 自分が管理する端末と、自分の家の中の端末 | 他人の端末の通信を、本人の同意なく通す。ルーターに置く |
| 求めるもの | 宛先の名前の一覧で止め、止めた記録を残す | 通信の中身を見て広告を消す、ページの要素を隠す |
| 操作 | command と設定ファイルで動かす | 画面(UI)で操作する(画面は作っていない) |
| OS | Linux、WSL、Windows 11 | macOS(動かした実績が無い) |

使う前に、利用者の責任で確かめる点があります。
広告遮断ソフトの扱いは、国や場面で異なります。
設計文書にも、法的な位置づけの未確認の点を残しています。
動画サイトなど、各サイトの利用規約が遮断を禁じているかも、サイトごとに確かめてください。

## 必要な物

| 方式 | 必要な物 |
|---|---|
| 共通 | Rust(`cargo`)。[rustup](https://rustup.rs) で入れる |
| `proxy` | 管理者権限は要らない |
| `block` | root と `iptables`。Linux の核が nfqueue を持つこと |
| Windows サービス | 管理者権限と pktmon。Windows 用の実行 file は、Linux から `cargo build --release --target x86_64-pc-windows-gnu` で作る手順だけを確かめている |
| 検査(任意) | ClamAV の `clamd`(HTTPS の download の検査に使う) |

## 最短で試す

この手順は、OS の設定を何も変えません。
見張り役は `127.0.0.1`(この機械の中)だけで待ち受けます。
通信が見張り役を通るのは、`curl` の `-x` で指定したときだけです。

1. Rust を入れる。
   `cargo --version` が版を返せばよい。
2. リポジトリを取得して build する。

   ```
   git clone <このリポジトリの URL>
   cd packetdeath
   cargo build --release
   ```

   実行 file は `target/release/packetdeath` に出る。

3. 作業用の場所と、止める宛先の一覧を作る。

   ```
   mkdir -p pdtrial/log
   printf 'example.org\n' > pdtrial/blocklist.txt
   ```

4. 見張り役を起動する。
   起動の行が出て、そのまま待つ。

   ```
   ./target/release/packetdeath proxy --listen 127.0.0.1:8899 --blocklist pdtrial/blocklist.txt --deny 403 --log-dir pdtrial/log
   ```

5. 別の端末(窓)で、止める宛先へ接続する。
   `403` で断たれる。

   ```
   curl -sS -x http://127.0.0.1:8899 https://example.org/
   ```

   出力は `curl: (7) CONNECT tunnel failed, response 403` になる(文言は curl の版で変わる)。

6. 一覧に無い宛先へ接続する。
   `200` で通る。

   ```
   curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.com/
   ```

7. 記録を読む。

   ```
   tail -2 pdtrial/log/flows.jsonl
   ```

   `example.org` の行に `"decision":"block"` と `"reason":"sni"`、`example.com` の行に `"decision":"pass"` が出る。

8. 見張り役の窓で `Ctrl+C` を押して止める。
   `rm -r pdtrial` で作業用の場所を消せば、元に戻る。

起動の行の言葉は、環境変数 `LC_ALL` か `LANG` が `ja` で始まれば日本語、それ以外は英語になります。
手順4の `--deny 403` を外すと、止める宛先への接続は「繋がったふり」をして黙る形(**blackhole**)になります。
この形では、`curl` に `--max-time 5` を付けると、5秒後に `exit=28` で終わります。

## 自分の端末で使い続ける

- ブラウザの proxy 設定は、利用者が手で `127.0.0.1:8899` へ向ける。
  packetdeath は、自分の動く端末の proxy 設定にも、信頼する証明書の置き場にも触らない。
- 家の中の別の端末から使うには、`--listen` に、この機械の LAN の IP(例：`192.0.2.10:8899`)を指定する。
  接続を受けるのは、既定では `127.0.0.1` と家庭用の私的な IP の範囲(10.x、172.16 から 172.31、192.168.x)だけである。
  広げるには `--allow-from <CIDR>` を足す。
- iPhone や Windows には、proxy の自動設定の URL `http://192.0.2.10:8899/proxy.pac` を入れる。
  この設定は、LAN の中の宛先を中継役の外へ通す。
  見張り役が止まっても、`DIRECT`(直接接続)へ倒れる。
- 止める宛先の一覧は、EasyList(広告ブロッカーが使う一覧の形式)から変換できる。
  `./target/release/packetdeath filterlist --in <EasyList の file> --out <blocklist の file>` が変換だけをして、一覧の取得はしない。
  EasyList は利用者が自分で入手する(このリポジトリには同梱しない)。
- 正規のサイトが止まったら、その名前を allowlist に1行足す。
  再起動は要らない。

allowlist を渡す起動の例です。

```
./target/release/packetdeath proxy --listen 127.0.0.1:8899 --blocklist pdtrial/blocklist.txt --allowlist pdtrial/allowlist.txt --deny 403 --log-dir pdtrial/log
```

同梱の一覧は次のとおりです。

| file | 中身 | 出所 |
|---|---|---|
| `blocklists/telemetry-windows.txt` | Windows と Office の診断データ送信の宛先 6 件 | 実機の記録から選んだ短い列 |
| `allowlists/microsoft-required.txt` | Microsoft が公開している、動作に必要な宛先 | Microsoft 公式の公開 API を変換 |
| `allowlists/pihole-common.txt` | Pi-hole で定番の「止めてはいけない」宛先 | `anudeepND/whitelist` を変換した物(ライセンスは配布元に従う。NOT VERIFIED、配布元の表示を確かめる) |
| `allowlists/user-named.txt` | 利用者が名指しした宛先 | 手書き |

## 詳細な動作

| したいこと | 使う物 |
|---|---|
| 止めずに記録だけ取る | `packetdeath observe`(Linux) |
| Linux で端末から出る通信を止める | `packetdeath block`(root) |
| 別の端末の通信を中継して止める | `packetdeath proxy` |
| Windows で常駐させる | `packetdeath service-install` と `packetdeath service-uninstall` |
| 止めた率と誤って止めた率を測る | `packetdeath eval --labels <tsv>` |
| 過去の記録に新しい一覧を当てて、誤爆の見込みを数える | `packetdeath defense-report --flows <flows.jsonl> --blocklist <一覧>` |
| 公開の一覧から悪性の宛先の一覧を作る | `scripts/pd-malware-feed.sh`(次の節) |

`packetdeath` を引数なしで打つと、全 command の使い方が出ます。

記録の置き場は `--log-dir` で指定します。

- `flows.jsonl`：通信 1 件につき 1 行。
  時刻、送信元と宛先の IP とポート、SNI、判定を持つ。
- `dns.jsonl`：`--dns` を付けたときの DNS 応答。
- `watch.jsonl`：見張りの option を付けたときの当たり。

記録は、端末が繋いだ宛先をすべて含みます。
秘密として扱い、共有しないでください。
packetdeath は記録を外へ送りません。

### 通信の中身を検査する(任意)

`--mitm-list` と `--ca-dir` と `--clamd` の3つを揃えたときだけ、`--mitm-list` に書いた宛先に限って、HTTPS を復号して download を検査します。
復号には、packetdeath が作った認証局(**CA**)の証明書を、利用者が自分で端末に信頼させる必要があります。
packetdeath は、この証明書を端末へ入れません。

`ca.key`(CA の秘密鍵)を読める人は、その証明書を信頼する端末に、任意のサイトを名乗れます。
`ca.key` はリポジトリの外に置き、権限を `0600` にします。
銀行やパスワード管理ソフトなど、証明書を固定して使うアプリの宛先は、`--mitm-list` に入れません。
手順は `docs/mitm-runbook.md` と、`docs/design.md` の「段階8 MITM」の節にあります。

### 不信の証明書を止める(任意)

ブラウザの配布元などが不正と告知した証明書(身分証にあたる物)を出すサイトへの接続を、止める option があります。
まず `--watch-distrust` で、止めずに記録だけ取ることから始めます。
`defense-report --watch` の結果を見てから、`--distrust` に移します。
詳細は `docs/design.md` の「段階10 能動防御」の節にあります。

## 外の一覧の取り込み

`scripts/pd-malware-feed.sh --out <出力先> [--auth <鍵の file>]` が、公開の一覧を取って、packetdeath が読む形に変換します。
packetdeath 自身は、この script も一覧の取得も起動しません。
`curl` と `sh` があれば動きます。

| 一覧 | 鍵 | 利用条件 |
|---|---|---|
| Feodo Tracker(悪性サーバーの IP) | 要らない | CC0(誰でも自由に使える。商用でもよい) |
| SSL Blacklist | 要らない | CC0 |
| ThreatFox | 要る | abuse.ch の認証した利用者だけに提供される |
| URLhaus | 要る | abuse.ch の認証した利用者だけに提供される |
| OneCRL(Mozilla の失効した証明書の一覧) | 要らない | 配布元の条件に従う |

ThreatFox と URLhaus は、abuse.ch の認証の鍵が要ります。
鍵は、curl の設定の形で書いた file に入れ、権限を `0600` にして、`--auth` で渡します。
鍵の file が無いか、権限が緩いときは、この2つへ request を1件も出しません。
その場合は `[warn]` を出し、前回の一覧をそのまま残します。
一覧が古くなる方を選んでいます。

利用条件は配布元が変えることがあります。
取り込む前に、各配布元の利用条件を読んでください。
一覧の中身は、このリポジトリに入れません。

毎日取得する設定の例は、`scripts/systemd/pd-malware-feed.service` と `pd-malware-feed.timer` にあります。
入れる操作は人が打ちます。

## 安全と戻し方

### 見張り役が止まったとき

| 方式 | 止まったときの通信 |
|---|---|
| `block`(Linux) | 素通しになる。ただし、規則に `--queue-bypass` を付けたときだけで、付け忘れると、見張り役が居ない間、通信が全部止まる |
| Windows サービス | 素通しになる(見張り役は通信の途中に居ないため) |
| `proxy` | 中継役に繋がらなくなる。proxy の欄を外すか、自動設定(proxy.pac)を使うと、`DIRECT` へ倒れる |

判定できない通信(名前が読めない、組み立てられない)は、どの方式でも通します。

### 一部を戻す

| 起きたこと | 戻す操作 | 効くまで |
|---|---|---|
| 正規のサイトが1つ止まった | allowlist に名前を1行足す | 約0.3秒 |
| 不信の証明書の一覧による遮断が、通信を止めすぎる | `--defense-off <path>` で指定した file を作る(`touch <path>`)。消せば戻る | 約0.3秒 |
| 1つの一覧が一度に多くの宛先を止める | 安全装置(breaker)が、その一覧を自動で見張り(記録だけ)へ落とす | 当たった次の判定 |
| 全部を止めたい | 見張り役の process を止める | 即時 |

`--defense-off` の file が在る間、止まるのは、不信の証明書の一覧と、鎖の確認(`--probe-chains`)による遮断だけです。
その当たりは、止めずに `watch.jsonl` へ記録します。
広告の blocklist と allowlist の動きは変わりません。

### Linux の `block` を使うとき

規則は利用者が入れ、利用者が消します。
packetdeath は `iptables` を打ちません。
見張り役が落ちたとき、規則だけが残る事故を避けるためです。

入れる(443 番の TCP を見張り役へ回す)：

```
sudo iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1808 --queue-bypass
sudo ./target/release/packetdeath block --queue 1808 --blocklist <blocklist の file> --log-dir <記録の置き場>
```

`sudo` の下では `$HOME` が変わるので、`--log-dir` を必ず渡します。

消す(入れた規則の `-I` を `-D` に変えて、同じ引数で打つ)：

```
sudo iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1808 --queue-bypass
sudo iptables -S | grep -c 1808
```

2行目の出力が `0` なら、規則は残っていません。
これらの規則の手順は設計文書(`docs/design.md` の PK-1 から PK-4)にあります。
この README の作成時には、`block` の規則を打ち直していません(NOT VERIFIED)。

### Windows で使うとき

pktmon の捕獲は、止め忘れると記録の file が際限なく大きくなります。
後始末を先に確認してから始めます。

```
pktmon stop
pktmon filter remove
pktmon status
```

捕獲した file(`.etl` と変換後の `.pcapng`)は消します。
中身は、端末が繋いだ宛先を含みます。
これらの出力の文言は、設計文書でも未確認なので、初めて打つときに確かめます(NOT VERIFIED)。

Windows サービスを外すときは、`packetdeath service-uninstall` を打ちます。
サービスは、追加の driver を入れません。
再起動後の自動起動は、実走を測っていません(NOT VERIFIED)。

### 記録と鍵

- 記録(`flows.jsonl`、`dns.jsonl`、`av.jsonl`)は、端末が繋いだ宛先を含む。
  秘密として扱う。
- CA の秘密鍵(`ca.key`)は、リポジトリに入れない(`.gitignore` が `*.key` と `*.crt` を除いている)。
- 通信の中継とは別に、packetdeath と同梱の script が外へ張る接続は2つだけである。
  一覧を取る script の通信と、`--probe-chains` を付けたときに見張り役が張る確認の接続(宛先の名前を送る)。

## 文書

- `docs/design.md`：設計と受入 ID(日本語)。
  何を測れば通りかが、command と期待する出力で書いてある。
- `docs/mitm-runbook.md`：通信の中身を検査する方式の運用手順(日本語)。
- `blocklists/README.md`：同梱の blocklist の出所と、止めてはいけない物。
- `allowlists/README.md`：同梱の allowlist の出所と件数。

## ライセンス

本体は、`Cargo.toml` に `MIT OR Apache-2.0` と宣言しています。
Suricata と ClamAV は GPLv2 で、packetdeath は別の process として使い、組み込みません。
`scripts/clamav-2g.patch` と `scripts/clamav-64/` は、ClamAV の source への差分です。
この2つは ClamAV のライセンス(GPLv2)に従い、本体の `MIT OR Apache-2.0` は及びません。
同梱の一覧のライセンスは、各一覧の出所(上の表)に従います。
