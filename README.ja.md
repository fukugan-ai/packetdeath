# packetdeath

日本語 | [English](README.md)

広告と悪いサイトへの通信を、ブラウザの外で動く見張り役のプログラムが止めます。
見張り役は、通信の宛先の名前を一覧と照合して、載っている名前への接続だけを断ちます。

ブラウザの拡張機能ではないので、ブラウザの中身を書き換えません。
同じ見張り役に、家の中の別の端末(iPhone など)の通信を向けることもできます。

command と option の意味は「command と option の一覧」の節にあります。
Windows で使う人は、先に「Windows で使う」の節を読んでください。
実行 file の入手、置き場、自動起動、外し方までを順に書いています。

## できること(10 段)

packetdeath は、段を重ねて作ってあります。
段の番号は `docs/design.md` の「段階」と同じです。
どの段も、option を渡したときだけ働きます。

| 段 | できること | 使う option |
|---|---|---|
| 1 観測 | 通信を止めずに、宛先を記録する(Windows 版は 1w。pktmon の記録を読む) | `observe`、Windows は `--pcapng`(`block` と `service-install` の option) |
| 2 遮断 | 一覧に載った宛先の名前への接続を断つ。一覧に載っていても、allowlist の名前は通す | `--blocklist` `--allowlist` |
| 3 CNAME | DNS の別名の先が一覧に載っている接続を断つ(Linux の `block`。`proxy` は受けない) | `--dns` |
| 4 IDS/IPS | 検知の道具 Suricata の警告を読み、重い警告を出した宛先を断つ(Linux の `block`) | `--eve` `--ips-severity` `--ips-sids` `--ips-ttl` |
| 5 宛先 IP | 住所(IP)の一覧に載った宛先を、名前が無い通信でも断つ | `--iplist` |
| 6 外の検査の結果を読む | 外の検査の道具が `av.jsonl` に書いた「悪い」の結果を読んで、その宛先を断つ(`block` と `proxy`)。8 の `av.jsonl` を渡すのは、CDN の共有 IP を巻き込むので、既定の運用ではない | `--av` |
| 7 proxy | 別の端末の通信を中継して、2 の blocklist と allowlist、5 の iplist、6 の `--av` を当てる(`--dns` と `--eve` と `--ips-*` は受けない) | `proxy --listen` `--deny` |
| 8 MITM と antivirus | 指定した宛先に限り、暗号化された通信を開いて、download した file を ClamAV で検査する | `--mitm-list` `--ca-dir` `--clamd` |
| 9 malware feed | 公開の悪性の一覧を毎日取り込み、2 の blocklist と 5 の iplist で断つ | `scripts/pd-malware-feed.sh`、`--blocklist` と `--iplist`(複数回) |
| 10 能動防御 | 不信と告知された証明書の鎖を使う宛先を断つ。止める側は 1 操作で見張りに戻せる | `--distrust` `--watch-distrust` `--probe-chains` `--defense-off` `--breaker-hosts` |

4 から 10 の詳しい説明は、「詳細な動作」と「能動防御」の節にあります。
4 は Suricata、8 は ClamAV と利用者が入れる証明書を使います。
Suricata と ClamAV は別に入れる道具で、このリポジトリには入っていません。

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
| Windows サービス | Windows 標準の通信記録道具(**pktmon**)が残した記録を読み、確立済みの接続を切る設計。記録までは動いたが、切ることは確かめられていない(PW-7 不通過) | 要る | Windows 11(記録まで) |

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
| IDS/IPS(任意) | Suricata(別に入れる。Linux の `block` で使う) |
| 検査(任意) | ClamAV の `clamd`(HTTPS の download の検査に使う)と、端末に入れる packetdeath の証明書 |

## 最短で試す

この手順は、OS の設定を何も変えません。
見張り役は `127.0.0.1`(この機械の中)だけで待ち受けます。
通信が見張り役を通るのは、`curl` の `-x` で指定したときだけです。

1. Rust を入れる。
   `cargo --version` が版を返せばよい。
2. リポジトリを取得して build する。

   ```
   git clone https://github.com/fukugan-ai/packetdeath.git
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
  範囲を変えるには `--allow-from <CIDR>` を渡す(1 つでも渡すと、既定の範囲は使われず、渡した範囲だけになる)。
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
| `blocklists/telemetry-windows.txt` | Windows と Office の診断データ送信の宛先 5 件 | 実機の記録から選んだ短い列 |
| `allowlists/microsoft-required.txt` | Microsoft が公開している、動作に必要な宛先 | Microsoft 公式の公開 API を変換 |
| `allowlists/pihole-common.txt` | Pi-hole で定番の「止めてはいけない」宛先 | `anudeepND/whitelist` を変換した物(ライセンスは配布元に従う。NOT VERIFIED、配布元の表示を確かめる) |
| `allowlists/user-named.txt` | 利用者が名指しした宛先 | 手書き |

## Windows で使う

結論：Windows だけで使うなら、方法 A(Windows の中で proxy を動かす)を勧めます。
WSL や Linux の機械を持っていない人は、A を選びます。
同じ LAN に Linux か WSL の機械があるなら、方法 B(別の機械の proxy を使う)も選べます。
方法 C(Windows サービス)は、宛先を記録できますが、接続を止められることは確かめられていません(受入 PW-7 が不通過)。
止めたいときは A か B を使います。

方法 A の起動、遮断、PAC の配信は、Windows の実機で確かめました(2026-10-22)。
条件は、管理者の権限で `127.0.0.1:18899` に待たせ、PAC は `curl` で取得し、OS の proxy 設定は入れていない、です。
非管理者での実走は確かめていません(NOT VERIFIED)。
結果は、`example.com` が `200`、`events.data.microsoft.com` への `CONNECT` が `403`、`/proxy.pac` が `200` で本文は `PROXY 127.0.0.1:18899; DIRECT` でした。
通信の中身の検査と能動防御の `[warn]` が 2 行出て、起動は続きました。
タスク スケジューラへの登録、OS の PAC 設定、`C:\Program Files` への配置は、確かめていません(NOT VERIFIED)。
proxy は全 OS で build されます(`src/lib.rs` の `pub mod proxy;`)。

| | A：Windows の中の proxy(勧める) | B：別の機械の proxy | C：Windows サービス(試験的) |
|---|---|---|---|
| 見張り役の置き場 | Windows の中。Linux も WSL も要らない | 同じ LAN の Linux か WSL | Windows の中 |
| 宛先を止める | 止める。Windows の実機で `CONNECT` が `403` になった(条件は上) | 止める。Linux から `curl` で確かめた。Windows の proxy 設定を通した実走は NOT VERIFIED | 確かめられていない。切断に失敗すると `flows.jsonl` は `pass` のままで、接続は続く(PW-7 不通過。2026-10-04 の実機で `rc=87`) |
| 通信の中身の検査(ウイルス検査)と能動防御 | 使えない。付けると `[warn]` を出して、その機能だけ無効のまま起動する | 使える(Linux 側で動かすとき) | 使えない |
| 再起動のあと | タスク スケジューラが、ログオン時に起動する。実走は NOT VERIFIED | Windows の設定は残る。proxy 側は、Linux 側で見張り役を起動し直す | サービスは自動で上がる設計。実走は NOT VERIFIED(PW-8 未実施) |
| 利用者が回す物 | なし | proxy 側の見張り役の起動 | pktmon の捕獲と変換(方法 C の手順 6)。回さない間は何も記録も遮断もしない |

Windows 側の自動起動にあたるのは、A ではタスク スケジューラの登録、B では Windows の proxy 設定、C ではサービスの登録です。

```
A：Release から exe を落とす -> 置く -> proxy を起動 -> PAC の URL を入れる -> タスクで自動起動 -> 確かめる -> 外す
B：Linux で見張り役を起動 -> Windows に PAC の URL を入れる -> 確かめる -> 外す
C：exe を build -> 置く -> 登録 -> pktmon を回す -> 確かめる -> 外す
```

図の結論は、実行 file を Windows に置くのは A と C のときだけ、である。
B の見張り役は Linux 側で動きます。

### 実行 file(packetdeath.exe)を手に入れる

配布用の実行 file は、GitHub の Release に置きます。
最新の Release に `packetdeath-x86_64-windows.exe` が無いとき(一覧が空のとき)は、下の「自分で作る」を使います。

1. ブラウザで <https://github.com/fukugan-ai/packetdeath/releases/latest> を開き、`packetdeath-x86_64-windows.exe` と `packetdeath-x86_64-windows.exe.sha256` を `Downloads` に保存する。
2. PowerShell を開き、`Downloads` へ移る。

   ```
   cd "$HOME\Downloads"
   ```

3. 落とした file のハッシュ値(file の指紋)が、`.sha256` に書かれた値と同じかを比べる。
   `.sha256` の中身は `<英数字 64 文字>  packetdeath-x86_64-windows.exe` の形です(2026-10-22 に確かめた)。
   次の command は、同じなら `True`、違えば `False` を出す。
   PowerShell の `-eq` は、大文字と小文字を区別しない。

   ```
   (Get-FileHash .\packetdeath-x86_64-windows.exe -Algorithm SHA256).Hash -eq ((Get-Content .\packetdeath-x86_64-windows.exe.sha256) -split ' ')[0]
   ```

4. `True` が出たら、名前を `packetdeath.exe` に変える。
   `False` なら、使わずに消す。

   ```
   Rename-Item .\packetdeath-x86_64-windows.exe packetdeath.exe
   ```

初めて実行すると、Windows の SmartScreen(知らない実行 file を警告する仕組み)が警告を出すことがあります。
出たら「詳細情報」を選び、出てくる「実行」を選びます。
画面の文言は NOT VERIFIED です(Microsoft Learn の頁で文言を確かめられませんでした)。

#### 自分で作る

Linux か WSL で、自分で作ります。

1. mingw-w64 の linker を確かめる。
   `x86_64-w64-mingw32-gcc --version` が版を返せばよい。
   無いときは、Debian と Ubuntu では `sudo apt install gcc-mingw-w64-x86-64` で入る(パッケージ名は NOT VERIFIED)。
2. Windows 向けの標準ライブラリを足す。

   ```
   rustup target add x86_64-pc-windows-gnu
   ```

3. build する。

   ```
   cargo build --release --target x86_64-pc-windows-gnu
   ```

4. 出来上がりを確かめる。
   `target/x86_64-pc-windows-gnu/release/packetdeath.exe` ができる。
   `file` の出力に `PE32+ executable` が入っていればよい。

   ```
   file target/x86_64-pc-windows-gnu/release/packetdeath.exe
   ```

5. USB メモリや共有フォルダで、この file を Windows の `Downloads` へ渡す。

### 方法 A：Windows の中で proxy を動かす

手順 3 から 5 の起動、遮断、PAC の配信は、Windows の実機で確かめました(条件は、この節の冒頭に書いた)。
手順 1 の `C:\Program Files` への配置、手順 5 の OS への PAC 設定、手順 6 のタスク スケジューラは、確かめていません(NOT VERIFIED)。

Windows の proxy が使えるのは、SNI と宛先での遮断です。
`--mitm-list`、`--ca-dir`、`--clamd`(通信の中身の検査)と、能動防御の option(`--distrust` など)は、Windows では無効になり、`[warn]` を出します(`src/main.rs` の `proxy` の起動)。

1. 管理者の PowerShell を開き、実行 file を置き場へ移す。
   手順は方法 C の手順 1 と 2 と同じ。
2. 記録と一覧の置き場を作り、止める宛先を 1 行書く。
   手順は方法 C の手順 3 と同じ。
3. 見張り役を前面で起動する。
   起動の行が出て、そのまま待つ。
   止めるときは、その窓で `Ctrl+C` を押す。

   ```
   & 'C:\Program Files\packetdeath\packetdeath.exe' proxy --listen 127.0.0.1:8899 --blocklist 'C:\ProgramData\packetdeath\blocklist.txt' --deny 403 --log-dir 'C:\ProgramData\packetdeath'
   ```

   初めて起動すると、Windows Defender ファイアウォールが「許可しますか」と確認の窓を出すことがあります。
   Microsoft Learn の文書では、許可の規則が無いアプリが初めて待ち受けるとき、確認の窓が出て、「いいえ」を選ぶか閉じると、遮断の規則ができます(取得 2026-10-22)。
   `127.0.0.1`(この機械の中)だけで待つなら、許可は要らない見込みです。
   窓が出るかと、遮断の規則が `127.0.0.1` の通信に効くかは、NOT VERIFIED です。
   出たときは、ネットワークへの許可は付けません。
4. 別の PowerShell の窓で、止める宛先へ接続する。
   `403` で断たれる。

   ```
   curl.exe -sS -x http://127.0.0.1:8899 https://example.org/
   ```

   出力は `curl: (7) CONNECT tunnel failed, response 403` になる(Windows の `curl.exe` でのこの文言は NOT VERIFIED。実機では `CONNECT` が `403` になることを確かめた)。
   一覧に載せていない普通のサイトが開くことも確かめる。
   `200` が出ればよい。

   ```
   curl.exe -sS -o NUL -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.com/
   ```

   記録は `C:\ProgramData\packetdeath\flows.jsonl` に、通信 1 件につき 1 行で残る。
   止めた宛先の行には `"decision":"block"` が、通した宛先の行には `"decision":"pass"` が入る。

   ```
   Get-Content 'C:\ProgramData\packetdeath\flows.jsonl' -Tail 4
   ```

5. Windows の proxy 設定に、自動設定の URL を入れる。
   画面の辿り方は方法 B の手順 2 から 6 と同じで、スクリプト アドレスだけ `http://127.0.0.1:8899/proxy.pac` にする。
   見張り役が `/proxy.pac` を配ることは、`curl` で確かめた(`PROXY 127.0.0.1:18899; DIRECT` を返した)。
   Windows の設定がそれを読んで通信を回すかは、NOT VERIFIED です。
6. ログオン時に自動で起動するよう、タスク スケジューラに登録する。
   コマンド プロンプトを管理者で開いて打つ。
   開き方は、スタートメニューで「cmd」を検索し、「管理者として実行」を選ぶ(画面の文言は NOT VERIFIED)。
   PowerShell では引用符の扱いが変わるので使わない(NOT VERIFIED)。
   `/sc onlogon` は、ユーザーがログオンするたびに実行する指定です。
   `/tr` は実行する command で、パスを含めて 262 文字までです。

   ```
   schtasks /create /tn "packetdeath proxy" /sc onlogon /tr "\"C:\Program Files\packetdeath\packetdeath.exe\" proxy --listen 127.0.0.1:8899 --blocklist C:\ProgramData\packetdeath\blocklist.txt --deny 403 --log-dir C:\ProgramData\packetdeath"
   ```

   手順 3 の窓を `Ctrl+C` で止めてから、ログオンし直さずにすぐ起動するには、次を打つ。

   ```
   schtasks /run /tn "packetdeath proxy"
   ```

   `schtasks` の引数は Microsoft Learn の `schtasks create` の頁で確かめました(取得 2026-10-22)。
   引用符の入れ子(`\"`)と、起動した見張り役の窓の見え方は NOT VERIFIED です。
   ログオンする前の通信は、見張り役が居ないので止まりません。
7. 手順 4 の `curl.exe` を打ち直し、ブラウザで一覧に載せた宛先が開かないことを確かめる。
8. 外すときは、設定とタスクと置き場を消す。
   最初に、手順 5 の画面で「セットアップ スクリプトを使う」をオフにして保存する。

   ```
   schtasks /end /tn "packetdeath proxy"
   schtasks /delete /tn "packetdeath proxy" /f
   Remove-Item -Recurse 'C:\Program Files\packetdeath'
   Remove-Item -Recurse 'C:\ProgramData\packetdeath'
   ```

   最初の 2 行はコマンド プロンプトで、後の 2 行は管理者の PowerShell で打ちます。
   見張り役が止まっても、自動設定は `DIRECT`(直接接続)へ倒れるので、通信は止まりません。

### 方法 B：別の機械の proxy を使う

proxy は、通信の中継役です。
**自動設定の URL**(PAC)は、どの通信を中継役へ回すかを書いた小さな file の場所です。
見張り役が `/proxy.pac` で配ります。

1. Linux か WSL で見張り役を起動する。
   `--listen` に、その機械の LAN の IP を指定する(IP は `hostname -I` で見える)。
   WSL の場合は、Windows からその IP に届くかを確かめる(NOT VERIFIED)。

   ```
   ./target/release/packetdeath proxy --listen 192.0.2.10:8899 --blocklist pdtrial/blocklist.txt --deny 403 --log-dir pdtrial/log
   ```

   一覧と記録の置き場の作り方は「最短で試す」の手順 3 にあります。
   再起動のあとも常駐させるには、この command を Linux 側で自動起動に登録します。
   proxy 用の systemd の unit は同梱していません(`scripts/systemd/` にあるのは `block` 用の `packetdeath-block.service` と一覧取り込み用の 2 つです)。
2. Windows 11 の「設定」を開く。
3. 「ネットワークとインターネット」の「プロキシ」を選ぶ。
4. 「セットアップ スクリプトを使う」の横の「セットアップ」を選ぶ。
5. 「セットアップ スクリプトを使う」をオンにする。
6. 「スクリプト アドレス」に `http://192.0.2.10:8899/proxy.pac` を入れて「保存」を選ぶ。

画面の文言は、Microsoft サポートの文書に書かれた日本語に合わせています(取得 2026-10-22)。
Windows の版で変わることがあり、実機の画面は NOT VERIFIED です。

確かめ方は 2 つです。

- ブラウザで、一覧に載せた宛先(例：`https://example.org/`)を開く。
  開かずにエラーが出ればよい。
- 一覧に載せていない普通のサイト(例：`https://example.com/`)を開く。
  開けばよい。

見張り役が止まっても、自動設定は `DIRECT`(直接接続)へ倒れるので、通信は止まりません。

外すときは、手順 4 の画面で「セットアップ スクリプトを使う」をオフにして保存します。

### 方法 C：Windows サービスとして登録する

登録するだけでは何も止まりません。
宛先を記録するには、利用者が pktmon で捕獲して pcapng に変換する作業を回し続ける必要があります。
packetdeath は pktmon を起動しません(止め忘れの事故を避けるため)。
接続を止められることは、PW-7 が不通過のため、確かめられていません。
切断に失敗すると、通信は続き、`flows.jsonl` の `decision` は `pass` のままです。

1. 管理者の PowerShell を開く。
   スタートメニューで「PowerShell」を検索し、「管理者として実行」を選ぶ(画面の文言は NOT VERIFIED)。
2. 実行 file を置き場へ移す。

   ```
   New-Item -ItemType Directory -Force 'C:\Program Files\packetdeath'
   Copy-Item "$HOME\Downloads\packetdeath.exe" 'C:\Program Files\packetdeath\packetdeath.exe'
   ```

   置いてから登録するのは、サービスが登録する実行 file の場所が、登録を打った実行 file の場所そのものだからです。
   `Downloads` から登録すると、その仮の場所が登録されます。
3. 記録と一覧の置き場を作り、止める宛先を 1 行書く。

   ```
   New-Item -ItemType Directory -Force 'C:\ProgramData\packetdeath'
   Set-Content -Path 'C:\ProgramData\packetdeath\blocklist.txt' -Value 'example.org' -Encoding ascii
   ```

4. サービスを登録する。
   `--log-dir` は必須です。
   `--pcapng` には、手順 6 で作る `capture.pcapng` の場所を渡します。

   **pcapng**：通信の記録を入れる file の形式。Wireshark など多くの解析ソフトが読む。
   pktmon の記録(`.etl`)を `pktmon etl2pcap` で直したものが `capture.pcapng` で、サービスはこの file を約 0.3 秒ごとに読み直し、中の接続の宛先の名前を blocklist と照らします。
   `--pcapng` を渡さないと、読む物が無いので、サービスは何も記録も遮断もしません(起動して、停止の合図を待つだけ)。
   `--pcapng` の詳しい説明は、「command と option の一覧」の節の「`--pcapng`：pktmon の記録を読む入口」にあります。

   ```
   & 'C:\Program Files\packetdeath\packetdeath.exe' service-install --log-dir 'C:\ProgramData\packetdeath' --pcapng 'C:\ProgramData\packetdeath\capture.pcapng' --blocklist 'C:\ProgramData\packetdeath\blocklist.txt'
   ```

   登録の種類は、自動起動の遅延あり(delayed-auto)、アカウントは LocalSystem です。
   落ちたときは、5 秒、30 秒、60 秒の間隔で自動再起動し、24 時間たつと数え直します。
5. サービスを起こして確かめる。
   登録しただけでは起動しません(`service-install` に起動の呼び出しが無い)。

   ```
   Start-Service packetdeath
   Get-Service packetdeath
   ```

   Microsoft の文書では、`Get-Service` は `Status`、`Name`、`DisplayName` の 3 列を出します。
   `Status` が `Running` ならよい。
   この service の行の実際の出力は NOT VERIFIED です。
6. pktmon で捕獲し、pcapng に変換する。
   Windows 標準の通信記録道具が **pktmon** です。
   `.etl` は pktmon の記録の形式、`.pcapng` は packetdeath が読む形式です。

   ```
   pktmon filter add pd7 -t TCP -p 443
   pktmon start --capture --comp nics --pkt-size 0 --flags 0x010 --file-name C:\ProgramData\packetdeath\capture.etl
   ```

   通信を起こしてから、止めて変換します。

   ```
   pktmon stop
   pktmon etl2pcap C:\ProgramData\packetdeath\capture.etl --out C:\ProgramData\packetdeath\capture.pcapng
   ```

   サービスは `capture.pcapng` を約 0.3 秒ごとに見て、変わっていれば読み直します。
   この捕獲と変換を自動で繰り返す仕組みは、同梱していません。
   再起動のあとは、手順 6 を打ち直さない限り、サービスは何も記録しません。
   pktmon の出力の文言は、設計文書でも未確認です(NOT VERIFIED)。
7. 記録を読む。

   ```
   Get-Content 'C:\ProgramData\packetdeath\flows.jsonl' -Tail 5
   ```

   サービスの動作の記録は `C:\ProgramData\packetdeath\service.log` にあります。
8. 後始末をする。
   pktmon の捕獲は、止め忘れると記録の file が際限なく大きくなります。
   `.etl` と `.pcapng` には、端末が繋いだ宛先が入っているので、消します。

   ```
   pktmon stop
   pktmon filter remove
   pktmon status
   Remove-Item 'C:\ProgramData\packetdeath\capture.etl', 'C:\ProgramData\packetdeath\capture.pcapng'
   ```

9. サービスを外すときは、止めてから登録を消す。

   ```
   Stop-Service packetdeath
   & 'C:\Program Files\packetdeath\packetdeath.exe' service-uninstall
   Remove-Item -Recurse 'C:\Program Files\packetdeath'
   Remove-Item -Recurse 'C:\ProgramData\packetdeath'
   ```

   サービスは追加の driver を入れないので、消すものは登録と、この 2 つの置き場だけです。
   `C:\ProgramData\packetdeath` を消すと、記録も消えます。

## command と option の一覧

`packetdeath` の使い方は `packetdeath <command> [option ...]` の形です。
**command**：何をするかを選ぶ最初の語(`proxy` や `block` など)。
**option**：command の動きを変える指定で、`--` で始まる語。
多くは値を 1 つ取る(`--listen 127.0.0.1:8899`)。

値の書き方の見方です。

- `<path>`：file か folder の場所。
- 「複数回」：同じ option を並べて渡せる。
  渡した一覧は合わせて使われる(和集合)。
- **CIDR**：IP の範囲の書き方(`192.168.0.0/16` は 192.168.0.0 から 192.168.255.255)。
- 一覧の file は、行頭が `#` の行を無視する。
  一覧(blocklist、allowlist、iplist、`--mitm-list`)は、実行中に書き換えると読み直される。
  読み直しの間隔は、経路で違う。
  Linux の `block`(nfqueue の経路)、`proxy`、Windows サービスは約 0.3 秒(サービスは固定の 300 ミリ秒)である。
  `block --pcapng` は、`--pcapng` の file を読み直す poll ごと(`--poll-ms`、既定 1000 ミリ秒)である。
  読めない一覧は、空の一覧として扱われ、`[warn]` が出る(起動は止まらない)。
  例外が 2 つある。
  `--av` の file が読めないときは、空として扱うが、`[error]` を出す。
  `defense-report` は、読めない file が 1 つでもあると、空にせず失敗する(空の一覧では `hits=0` になり、問題が無いように見えるため)。

この一覧は `src/main.rs` の引数の読み取りと、`src/i18n.rs` の使い方の行から書きました。
引数なしで `packetdeath` を打つと、使い方の行が出ます。

| command | 何をするか | OS |
|---|---|---|
| `observe` | 通信を止めず、宛先を `flows.jsonl` に記録する | Linux だけ。Windows では「未実装」と出て終わる |
| `block` | 一覧に載った宛先の通信を断つ | Linux(nfqueue)。Windows では `--pcapng` が必須 |
| `eval` | 記録を正解の表と突き合わせ、止めた率と誤って止めた率を出す | どちらも |
| `filterlist` | EasyList 形式の一覧を blocklist の形に変換する | どちらも |
| `allowlist-convert` | 公開の allowlist を allowlist の形に変換する | どちらも |
| `service-install` | Windows サービスとして登録する | Windows だけ |
| `service-uninstall` | サービスの登録を消す | Windows だけ |
| `service-run` | サービスの本体。サービスの管理画面(SCM)が起動する物で、利用者は打たない | Windows だけ |
| `proxy` | 中継役として通信を受け、一覧に載った宛先を断つ | どちらも。ただし通信の中身の検査と能動防御は Linux だけ |
| `defense-report` | 見張りの記録を数え、止める側へ移してよいかを示す | Linux だけ |

記録の置き場 `--log-dir` を渡さないと、Linux は `$XDG_STATE_HOME/packetdeath`(無ければ `$HOME/.local/state/packetdeath`)、Windows は `%LOCALAPPDATA%\packetdeath` になります。
`service-install` と `service-run` だけは、サービスが SYSTEM 権限で動いて `%LOCALAPPDATA%` が変わるため、`--log-dir` が必須です。

### observe：止めずに記録する

nfqueue に回された通信の宛先を記録します。
止めることはしません。

| option | 値 | 何をするか | 既定値 | 必須 |
|---|---|---|---|---|
| `--queue` | 番号 | 通信を受け取る nfqueue の番号。iptables の規則の `--queue-num` と同じ値にする | 1808 | 任意 |
| `--filter` | 式 | 受け取るが使わない option。Linux では無視して `[warn]` を出す。Windows では `observe` 自体が未実装 | なし | 任意 |
| `--log-dir` | `<path>` | `flows.jsonl` を置く folder | 上の既定の場所 | 任意 |

```
sudo iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1808 --queue-bypass
sudo ./target/release/packetdeath observe --queue 1808 --log-dir ./log
```

### block：一覧に載った宛先を断つ

Linux では nfqueue に回された通信を判定して断ちます。
Windows では、`--pcapng` で渡した記録を読んで判定します(次の節の説明を参照)。

| option | 値 | 何をするか | 既定値 | 必須 | OS |
|---|---|---|---|---|---|
| `--queue` | 番号 | 通信を受け取る nfqueue の番号 | 1808 | 任意 | Linux |
| `--blocklist` | `<path>` | 止める名前の一覧。複数回 | なし(空の一覧) | 任意 | どちらも |
| `--allowlist` | `<path>` | 何があっても通す名前の一覧。blocklist より先に効く | なし(空の一覧) | 任意 | どちらも |
| `--iplist` | `<path>` | 止める IP と CIDR の一覧(1 行に 1 つ)。複数回 | なし(空の一覧) | 任意 | どちらも |
| `--av` | `<path>` | 外の検査の道具が書いた `av.jsonl`。`malicious` の行の「IP とポート」の組を止める | なし(空) | 任意 | どちらも |
| `--dns` | 値なし | DNS の別名(CNAME)の先が一覧に載っている接続も断つ。DNS の答えを `dns.jsonl` に記録する | 切 | 任意 | Linux。`--pcapng` を付けた経路では使われない |
| `--eve` | `<path>` | Suricata が警告を書く `eve.json` の場所 | なし(警告による遮断は 0 件) | 任意 | Linux。`--pcapng` を付けた経路では使われない |
| `--ips-sids` | `<path>` | 止める警告の規則番号(sid)の一覧。1 行に 1 つ | なし | 任意 | Linux。同上 |
| `--ips-severity` | 1 から 3 | この値以下の重さの警告を止める。1 が最も重い | なし(重さでは止めない) | 任意 | Linux。同上 |
| `--ips-ttl` | 秒 | 警告で止めた宛先を止め続ける秒数 | 300 | 任意 | Linux。同上 |
| `--pcapng` | `<path>` | pktmon の記録を `pktmon etl2pcap` で変えた file の場所(次の節) | なし | Windows では必須 | Windows は遮断する。Linux は判定と記録だけで遮断せず `[warn]` を出す |
| `--poll-ms` | ミリ秒 | `--pcapng` の file を読み直す間隔 | 1000 | 任意 | `--pcapng` と一緒のとき |
| `--log-dir` | `<path>` | `flows.jsonl` と `dns.jsonl` を置く folder | 上の既定の場所 | 任意 | どちらも |

`--pcapng` を付けた経路で使われる option は、`--blocklist`、`--allowlist`、`--iplist`、`--av`、`--poll-ms`、`--log-dir` です(`src/main.rs` の `run_block`)。

```
sudo ./target/release/packetdeath block --queue 1808 --blocklist blocklist.txt --allowlist allowlist.txt --log-dir ./log
```

### --pcapng：pktmon の記録を読む入口

**pcapng** は、通信の記録を入れる file の形式です。
Wireshark など多くの解析ソフトが読みます。
Windows の pktmon が捕まえた記録は `.etl` という別の形式で残るので、`pktmon etl2pcap` で `.pcapng` に直します。
packetdeath が読めるのは、この `.pcapng` の方です。

```
通信 -> pktmon が捕まえる(capture.etl) -> pktmon etl2pcap で直す(capture.pcapng) -> --pcapng で packetdeath に渡す
```

図の結論は、`--pcapng` は「読む記録の file の場所」であり、packetdeath が通信を自分で捕まえることはない、である。

packetdeath は、`--pcapng` の file を一定の間隔で読み直し、中の接続の宛先の名前(SNI)を一覧と照らします。
読み直す間隔は、`block` では `--poll-ms`(既定 1000 ミリ秒)、Windows サービスでは固定の 300 ミリ秒です。
file の大きさが前回と同じなら、読み直しを省きます。

`--pcapng` を渡さないと、読む物が無いので、サービスは何も記録せず、何も遮断しません。
サービスは起動して、停止の合図を待つだけになります。
`block` に `--pcapng` を渡さないと、Windows では「未実装」と出て終わり、Linux では nfqueue の経路で動きます。

pktmon の捕獲と変換を回し続ける仕組みは、このリポジトリに同梱していません。
packetdeath が `pktmon` を起動しないのは、packetdeath が落ちたあとに捕獲だけが残って file が際限なく大きくなる事故を避けるためです。
`src/win_service.rs` の注記には、利用者の PC で pktmon の記録の切り替え(rotate)の周期を 3 秒に詰めて試した旨があります。
その周期を回す script は、リポジトリにありません。
`capture.pcapng` が更新されない間は、新しい通信は判定されません。

### eval：止めた率を測る

`flows.jsonl` を、「host と ad か ok」の表(labels)と突き合わせます。

| option | 値 | 何をするか | 既定値 | 必須 |
|---|---|---|---|---|
| `--labels` | `<path>` | 正解の表。1 行に「host、タブ、`ad` か `ok`」。形の合わない行は無視する | なし | 必須 |
| `--log-dir` | `<path>` | `flows.jsonl` を読む folder。無ければ 0 件として数える | 上の既定の場所 | 任意 |

```
./target/release/packetdeath eval --labels labels.tsv --log-dir ./log
```

### filterlist と allowlist-convert：一覧を変換する

どちらも file を読んで書くだけで、ネットワークには出ません。
`filterlist` は EasyList 形式を blocklist に、`allowlist-convert` は公開の allowlist(Microsoft の JSON、1 行 1 domain、Adblock Plus の `@@` 形式)を allowlist に変えます。

| option | 値 | 何をするか | 既定値 | 必須 |
|---|---|---|---|---|
| `--in` | `<path>` か `-` | 読む file。`-` は標準入力 | なし | 必須 |
| `--out` | `<path>` か `-` | 書く file。`-` は標準出力 | なし | 必須 |

```
./target/release/packetdeath filterlist --in easylist.txt --out blocklist.txt
```

### service-install と service-uninstall：Windows サービスの登録と削除

`service-install` は管理者の PowerShell で打ちます。
受け取った option は、サービスの起動の引数に書き込まれ、`service-run` に渡ります。
`service-uninstall` は option を取りません。

| option | 値 | 何をするか | 既定値 | 必須 |
|---|---|---|---|---|
| `--log-dir` | `<path>` | サービスが `flows.jsonl` と `service.log` を置く folder | なし | 必須 |
| `--pcapng` | `<path>` | 読む記録の file(前の節)。渡さないと、サービスは何も記録も遮断もしない | なし | 任意 |
| `--blocklist` | `<path>` | 止める名前の一覧。1 つだけ | なし(空の一覧) | 任意 |
| `--allowlist` | `<path>` | 何があっても通す名前の一覧。1 つだけ | なし(空の一覧) | 任意 |

```
& 'C:\Program Files\packetdeath\packetdeath.exe' service-install --log-dir 'C:\ProgramData\packetdeath' --pcapng 'C:\ProgramData\packetdeath\capture.pcapng' --blocklist 'C:\ProgramData\packetdeath\blocklist.txt'
& 'C:\Program Files\packetdeath\packetdeath.exe' service-uninstall
```

### proxy：中継役として通信を受ける

管理者権限は要りません。
Windows でも動きます。

| option | 値 | 何をするか | 既定値 | 必須 | OS |
|---|---|---|---|---|---|
| `--listen` | `addr:port` | 通信を受ける IP とポート。`0.0.0.0` を黙って開かないよう、既定を置いていない | なし | 必須 | どちらも |
| `--blocklist` | `<path>` | 止める名前の一覧。複数回 | なし(空の一覧) | 任意 | どちらも |
| `--allowlist` | `<path>` | 何があっても通す名前の一覧 | なし(空の一覧) | 任意 | どちらも |
| `--iplist` | `<path>` | 止める IP と CIDR の一覧。複数回 | なし(空の一覧) | 任意 | どちらも |
| `--av` | `<path>` | 外の検査の道具が書いた `av.jsonl` | なし(空) | 任意 | どちらも |
| `--deny` | `blackhole` か `403` | 止めたときの返し方。`blackhole` は繋がったふりをして黙る。`403` は `403 Forbidden` を返して閉じる | `blackhole` | 任意 | どちらも |
| `--allow-from` | CIDR | 接続を受ける相手の範囲。複数回。1 つでも渡すと既定は使われず、渡した範囲だけになる。CIDR として読めない値は `[warn]`(「--allow-from の値が CIDR として読めない」)を出して捨てる。全部が読めないと 0 件になり、誰の接続も受け付けない | `127.0.0.0/8`、`::1/128`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` | 任意 | どちらも |
| `--log-dir` | `<path>` | `flows.jsonl` などを置く folder | 上の既定の場所 | 任意 | どちらも |
| `--mitm-list` | `<path>` | 暗号化された通信を開く宛先の一覧。`--ca-dir` と `--clamd` の 3 つが揃ったときだけ働く | なし | 任意 | Linux。Windows では `[warn]` を出して無効 |
| `--ca-dir` | `<path>` | 通信を開くための CA(証明書を発行する側)の鍵と証明書を置く folder | なし | 3 つ組 | Linux。同上 |
| `--clamd` | socket の path か `addr:port` | ウイルス検査の `clamd` の場所 | なし | 3 つ組 | Linux。同上 |
| `--distrust` | `<path>` | 不信な証明書の一覧。載った証明書の鎖を使う宛先を断つ。複数回 | なし | 任意 | Linux。Windows では `[warn]` を出して無効 |
| `--watch-distrust` | `<path>` | `--distrust` と同じ一覧を、止めずに `watch.jsonl` へ記録するだけにする。複数回 | なし | 任意 | Linux。同上 |
| `--watch-blocklist` | `<path>` | blocklist の当たりを、止めずに `watch.jsonl` へ記録するだけにする。複数回 | なし | 任意 | Linux。同上 |
| `--watch-iplist` | `<path>` | iplist の当たりを、止めずに `watch.jsonl` へ記録するだけにする。複数回 | なし | 任意 | Linux。同上 |
| `--probe-chains` | 値なし | 通信を開かない宛先にも、packetdeath が別に TLS を張って証明書の鎖を読む。宛先の名前を平文の SNI で送る | 切 | 任意 | Linux。同上 |
| `--defense-off` | `<path>` | この file が在る間、不信の一覧と鎖の確認による遮断を止め、記録だけにする(`touch <path>` で入り、消せば戻る) | なし | 任意 | Linux。同上 |
| `--breaker-hosts` | 1 以上の整数 | 1 つの一覧が 10 分に止めてよい宛先の数。超えるとその一覧を見張りだけに落とす | 5 | 任意 | Linux。同上 |

```
./target/release/packetdeath proxy --listen 127.0.0.1:8899 --blocklist blocklist.txt --allowlist allowlist.txt --deny 403 --log-dir ./log
```

`--mitm-list`、`--ca-dir`、`--clamd` は、1 つか 2 つだけ渡すと開く機能が無効のまま起動し、足りない option の名前を `[warn]` に出します。
詳しい説明は「暗号化された通信を開く仕組み(MITM)」と「能動防御」の節にあります。

### defense-report：見張りの記録を数える

記録を読むだけで、通信も file も変えません。
`--flows` か `--watch` のどちらか 1 つを必ず渡します(両方でも、どちらも無しでも失敗する)。

| option | 値 | 何をするか | 既定値 | 必須 |
|---|---|---|---|---|
| `--flows` | `<path>` | `flows.jsonl`。過去の記録に一覧を当てて、当たる数を数える | なし | `--flows` か `--watch` |
| `--watch` | `<path>` | `watch.jsonl`。source ごとに当たりを数え、止める側へ移してよいかを `promote=yes` か `no` で示す | なし | 同上 |
| `--blocklist` | `<path>` | `--flows` と一緒に使う blocklist。複数回 | なし | 任意 |
| `--iplist` | `<path>` | `--flows` と一緒に使う iplist。複数回 | なし | 任意 |
| `--allowlist` | `<path>` | 当たりのうち allowlist に載る数を別に数える。複数回 | なし | 任意 |
| `--distrust` | `<path>` | `--watch` と一緒に使う不信の一覧。公開の信頼の起点(root)の行に `root=yes` を付ける。複数回 | なし | 任意 |
| `--days` | 日数 | 移してよいと言うために要る記録の日数の下限。実際の記録の日数は、この値で水増しできない | 0(最低 7 日の記録が要る) | 任意 |

```
./target/release/packetdeath defense-report --flows ./log/flows.jsonl --blocklist blocklist.txt
./target/release/packetdeath defense-report --watch ./log/watch.jsonl --days 7
```

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
全 command と全 option の意味は、前の「command と option の一覧」の節にあります。

記録の置き場は `--log-dir` で指定します。

- `flows.jsonl`：通信 1 件につき 1 行。
  時刻、送信元と宛先の IP とポート、SNI、判定を持つ。
- `dns.jsonl`：`--dns` を付けたときの DNS 応答。
- `watch.jsonl`：見張りの option を付けたときの当たり。

記録は、端末が繋いだ宛先をすべて含みます。
秘密として扱い、共有しないでください。
packetdeath は記録を外へ送りません。

### 侵入の検知と遮断(IDS/IPS)

**IDS**(侵入検知)は、怪しい通信を見つけて知らせる仕組みです。
**IPS**(侵入防止)は、見つけた通信を止める仕組みです。
packetdeath は、怪しい通信を見分ける規則を自分では持ちません。
規則を持つ検知の道具 **Suricata** が警告(alert)を `eve.json` という file に書き、packetdeath の `block` がその警告を読んで、宛先を止めます。

Suricata は別に入れます。
packetdeath は Suricata を起動しません。
Suricata は検知だけをする設定(IDS モード)で動かし、止める役は packetdeath が受け持ちます。
入れ方と起動の方法は、Suricata の文書(<https://docs.suricata.io/>)に従ってください。

止める警告の選び方は、2 つの option のどちらかです。

- `--ips-severity <N>`：警告の重さが N 以下の警告を止める。
  重さは `alert.severity` で、1 から 3 の値を取り、1 が最も重い。
- `--ips-sids <file>`：載っている番号の警告を止める。
  file には、規則の番号(sid)を 1 行に 1 つ書く。

両方を渡すと、どちらかに当たれば止めます。
どちらも渡さなければ、警告を理由にした遮断は 0 件です。
`--eve <path>` で `eve.json` の場所を渡します。
止めた宛先は `--ips-ttl <秒>`(既定 300)のあいだ止め続けます。

```
sudo iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1808 --queue-bypass
sudo ./target/release/packetdeath block --queue 1808 --eve <eve.json の場所> --ips-severity 1 --log-dir <記録の置き場>
```

この仕組みの限界は 4 つあります。

- 警告は通信が通った後に書かれるので、警告を出した最初の packet は通り、止まるのはそれ以後の同じ宛先です。
- 止められるのは、iptables の規則が見張り役へ回した通信だけです(上の例は TCP 80 番)。
- 警告の重さは、Suricata の規則の分類(classtype)で決まります。
  設計文書の実測では、ある機械の警告 30 件がすべて重さ 3 の内部の通知で、`--ips-severity 1` ではどれも止まりませんでした。
- 検知率は Suricata の規則の質で決まるので、「マルウェアを防げる」とは言えません。

Suricata が止まっても、通信は止まりません。
警告が増えなくなるだけです。
この段は Linux の `block` の option です。
Windows での Suricata の使い方は、設計文書でも未確認です(NOT VERIFIED)。

### 暗号化された通信を開く仕組み(MITM)

**MITM**(中間者方式)は、中継役が通信の途中で暗号をいったん解き、中身を見てから、また暗号化して続ける方式です。
悪用すれば盗み見になるので、packetdeath では、利用者が自分の端末に packetdeath の証明書を入れて許したときだけ働きます。

`--mitm-list` と `--ca-dir` と `--clamd` の 3 つを揃えたときだけ、`--mitm-list` に書いた宛先に限って、暗号化された通信(HTTPS)を開きます。
1 つか 2 つだけ渡すと、開く機能は無効のまま起動し、足りない option の名前を `[warn]` に出します。
Windows では 3 つとも無視して、`[warn]` を出します。

開いた通信で見るのは、download した file だけです。
開く条件は、次の 6 つが全部そろった接続です。

1. 3 つの option がそろい、CA(証明書を発行する側)を読めている。
2. ブロックの判定(blocklist、iplist、av)に当たっていない。
3. allowlist に載っていない。
4. `--mitm-list` に載っている。
5. 接続先が 443 番で、IP を直接指定した接続ではない。
6. その端末と宛先の組が、開くのをやめて 1 時間覚えている組(「証明書を入れないと起きること」の節)に入っていない。

#### 証明書を入れないと起きること

`--mitm-list` の宛先に、証明書を入れていない端末が繋ぐと、ブラウザが証明書の警告を出して、最初の 1 回は繋がりません。
packetdeath はその端末と宛先の組を 1 時間覚え、次の接続からは開かずに、そのまま通します。
一覧に載っていない宛先は、証明書の有無に関係なく、これまでどおり開かずに通ります。

#### 証明書の危うさ

packetdeath は、この証明書を端末へ入れません。
入れるのは、利用者の手です。

`ca.key`(CA の秘密鍵)を読める人は、その証明書を入れた端末に、任意のサイトを名乗れます。
つまり、`ca.key` が漏れると、その端末の暗号化された通信を開けるようになります。
`ca.key` はリポジトリの外に置き、権限を `0600` にします。
CA の有効期間は 730 日です。

銀行、パスワード管理ソフト、Apple のサービス、Microsoft の認証と Windows Update のように、証明書を固定して使うアプリの宛先は、`--mitm-list` に入れません。
開くと、そのアプリが繋がらなくなります。
一覧に迷ったら、入れません。

#### 入れ方と外し方

証明書 `ca.crt` は、3 つの option をそろえて起動した proxy が `http://<proxy の IP>:<port>/ca.crt` で配ります。
`ca.key` は配りません。

- Windows(現在のユーザーにだけ入れる)：保存した `ca.crt` に対して `certutil -user -addstore Root "<path>\ca.crt"` を打つ。
  外すときは、`certmgr.msc` を開き、「信頼されたルート証明機関」の `packetdeath CA <日付>` を削除する。
- iPhone：Safari で上の URL を開き、プロファイルをインストールして、「証明書信頼設定」で有効にする。
  外すときは、設定の「VPN とデバイス管理」で、そのプロファイルを削除する。
  画面の文言は設計文書でも記憶に基づくので、初めて打つときに確かめてください(NOT VERIFIED)。
- Firefox は独自の信頼の置き場を持つので、対象外です。

`ca.key` が漏れたときは、次の順に打ちます。

1. 全部の端末から、古い証明書を外す。
2. proxy を止める。
3. `--ca-dir` の中身を消す。
4. proxy を起動する。
   新しい CA が作られ、起動の記録に新しい指紋が出る。
5. 新しい `ca.crt` を、全部の端末に入れ直す。

手順 1 から 5 のあいだ、開く機能は失敗して検査なしの通信に戻り、通信は止まりません。
日々の運用(宛先の追加、再起動、誤検知の救い方)は、`docs/mitm-runbook.md` にあります。
設計は `docs/design.md` の「段階8 MITM」の節にあります。

### ウイルス検査(antivirus)

開いた通信の download は、**ClamAV**(無料のウイルス検査の道具)に渡して検査します。
ClamAV の常駐部分(`clamd`)は、別に入れます。
packetdeath は `--clamd` で、`clamd` の socket の path か `addr:port` を受け取ります。

```
./target/release/packetdeath proxy --listen 127.0.0.1:8899 --blocklist pdtrial/blocklist.txt --mitm-list pdtrial/mitm-list.txt --ca-dir pdtrial/ca --clamd <clamd の socket の path> --deny 403 --log-dir pdtrial/log
```

検査の結果は 3 通りです。

| 結果 | 利用者に起きること |
|---|---|
| 悪い file と判定(FOUND) | file の代わりに `403` を返す。記録は `flows.jsonl` の `"reason":"av"` と `av.jsonl` の `malicious` |
| 問題なし(OK) | file をそのまま渡す。`av.jsonl` に `clean` を書く |
| 検査できなかった(clamd が答えない、時間切れ、上限超え) | file をそのまま渡し、`[warn]` を出す |

検査できなかったときは、通す側に倒れます(fail-open)。
検査の道具が止まっても、利用者の download は止まらないからです。
その代わり、検査できなかった file は、検査なしで届きます。

検査の対象は、次の条件をすべて満たす応答です。

- `GET` の `200` の応答で、`Content-Length` が 1 byte 以上 8191 MiB 以下。
  `Content-Length` が無い応答も検査し、本文が 8191 MiB を超えた時点で検査を諦める。
- `Content-Disposition: attachment` が付いているか、`Content-Type` が page の部品(`text/html`、`image/*`、`video/*`、`application/json` など)でない。
- `Content-Encoding` が無いか `identity` である。

速さへの配慮は、次の 3 つです。

- 検査するのは download だけで、page の部品や動画は検査せずに流します。
- 悪い file を `403` に差し替えるために、本文を全部受け取ってから検査します。
  だから、検査の対象の file は、検査が終わるまで 1 byte も端末に届きません。
- 待つ上限は 1260 秒で、超えたら検査を諦めて file を渡します。
  新しい zip を初めて検査するときは、16 file の zip で 4.6 秒、679 file の zip で 9 から 10 秒かかりました(実測、2026-10-03)。

検査されずに通る file があります。

- 8191 MiB を超える file。
- 途中から再開する download(`206`)。
- パスワード付きの archive。
- `br` や `gzip` で圧縮されて届く応答。
- page の部品を名乗っている file。
- 検査の予算(同時に溜める本文の合計 8 GiB)が尽きている間の download。

検知率は ClamAV の署名の質で決まります。
「マルウェアを防げる」とは言えません。
検査するのは、`--mitm-list` の宛先から届く file だけです。
USB から入った file や、proxy を通らない通信の file は、検査しません。

### 暗号化された通信の中の広告

できること：暗号化された通信でも、繋ぐ先の名前(SNI)と宛先 IP で、広告の通信を接続ごと止める。
できないこと：開いた通信の中身から、広告の部分だけを消すこと。

packetdeath が暗号化された通信を開くのは、download した file を検査するためだけです。
広告かどうかは、開いたあとの中身ではなく、これまでどおり名前と宛先で決めます。
サイト自身の名前で配られる広告や、動画に縫い込まれた広告は、止められません。

## 能動防御(証明書の事故への備え)

**能動防御**(段 10)は、公開の告知や一覧で「悪い」とされた証明書と宛先を、先回りして通信に当てる仕組みです。
きっかけは、認証局 eMudhra の中間証明書が侵害された事故です。

**中間証明書**は、認証局(身分証を発行する側)が下請けの発行者に渡す証明書です。
侵害された中間証明書を持つ者は、それを信頼する端末に、本物そっくりの偽のサイトを見せられます。

事故について、確かめた事実と、確かめていない事実を分けて書きます。

| 事実 | 確かめ方 |
|---|---|
| 侵害は秘密鍵の漏れで、弱い鍵ではなく、複数(multiple)の中間証明書が侵害され、署名した root(最上位の証明書)は「Comodo AAA Services」と「emSign ECC Root CA - G3」の 2 つで、Red Hat の製品の信頼の置き場に入っており、Go の側では CVE-2026-111943 として追跡されている | Red Hat の告知 RHSB-2026-012 を読んだ(取得 2026-10-22) |
| 侵害された中間証明書が 8 枚である | 確認できていない(NOT VERIFIED)。Red Hat の告知に枚数は無く、Mozilla の告知は取得できず、設計文書は 8 を転記として扱っている |
| Mozilla の失効の一覧(OneCRL)に載った eMudhra と emSign の record の数 | feed が `onecrl emudhra=<n>` の 1 行を記録する。数は読んで確かめる(NOT VERIFIED) |

packetdeath の備えは、4 つです。

1. **不信の一覧を毎日取り込む**：`scripts/pd-malware-feed.sh` が、OneCRL(Mozilla の失効した証明書の一覧)と SSL Blacklist の証明書の指紋を取り、`distrust-onecrl.txt` と `sslbl-certs.txt` に変換する。
2. **その鎖を使う宛先を止める**：`--distrust <file>` に渡した一覧に載った証明書を、宛先の証明書の鎖(root から宛先までの連なり)が含むとき、その接続を断つ。
   開いた通信(段 8)では、宛先との TLS の鎖を照合する。
   開かない通信では、`--probe-chains` を付けると、packetdeath が同じ宛先へ別に TLS を張って鎖を読み、不信の鎖の宛先を以後の接続で止める。
   この確認の接続は、client が ECH で隠した宛先の名前も、平文の SNI で送る。
   経路の途中の観測者には、隠したはずの名前が見える(Chrome が proxy 越しに ECH を使うかは NOT VERIFIED)。
3. **まず見張る**：`--watch-distrust`、`--watch-blocklist`、`--watch-iplist` は、当たりを `watch.jsonl` に書くだけで、止めない。
   `packetdeath defense-report --watch <watch.jsonl>` が、source ごとに当たりを数え、記録が 7 日分あり、allowlist の当たりが 0 などの条件を満たすと `promote=yes` を出す。
   止める側へ移すのは、人が決める。
4. **止めすぎを防ぐ**：後の節に書く。

文章だけの告知(機械で読める一覧が無い物)は、運用者が `distrust-manual.txt` に 1 行足します。
この file は、見張り(`--watch-distrust`)から始めます。
文章を機械が読んで一覧に入れる仕組みは、誤って入れた 1 行が通信を止めるので、作っていません。

### 侵害された eMudhra の証明書を避ける流れ

OS とブラウザは、侵害された中間証明書の上にある root(「Comodo AAA Services」など)を、いまも信頼の置き場に持っています。
そのため、侵害された中間証明書で作られた偽のサイトは、OS とブラウザの検査だけでは「正しい証明書」に見えます。
packetdeath は、その手前で次の順に止めます。

1. 毎日、`scripts/pd-malware-feed.sh` が Mozilla の OneCRL(失効させた証明書の一覧)を取り、`distrust-onecrl.txt` に書きます。
   一覧の 1 行は、証明書の公開鍵の指紋(`spki-sha256`)か、発行者の名前と通し番号の組(`issuer-serial`)です。
   eMudhra と emSign の行の数は、feed の log に `onecrl emudhra=<n>` と出ます。
2. PC の通信が proxy を通ると、packetdeath は宛先が見せた証明書の鎖(サイトの証明書、中間証明書、その上の root)を、1 枚ずつこの一覧と照らします。
   開かない通信では、`--probe-chains` が同じ宛先へ別に TLS を張って鎖を読みます。
3. 鎖のどこかに一覧の 1 行と同じ証明書があれば、その宛先への接続を断ち、`flows.jsonl` に `"reason":"chain"` と記録します。
   OS が root を信頼していても、侵害された中間証明書を通る鎖はここで止まります。
4. 同じ root の下でも、侵害されていない中間証明書を使う正規のサイトは、一覧に当たらないので止まりません。

この流れは、OneCRL に侵害された中間証明書が載っていることを前提にしています。
載る前の偽のサイトと、`--probe-chains` が鎖を読む前の最初の接続は通ります(前の「限界」の節を参照)。

### 止めすぎたときの戻し方

| 起きたこと | 戻す操作 | 効くまで |
|---|---|---|
| 1 つの宛先が誤って止まった | allowlist に名前を 1 行足す。allowlist は不信の鎖にも勝つ | 約 0.3 秒 |
| 能動防御の止める側を全部、見張りに戻したい | `--defense-off <path>` で指した file を作る(`touch <path>`)。消せば戻る | 約 0.3 秒 |
| 1 つの一覧が、10 分に `--breaker-hosts`(既定 5)を超える宛先を止めた | 安全装置(breaker)が、その一覧だけを自動で見張りに落とす | 当たりの次の判定 |

`--defense-off` の file が在る間に止まらなくなるのは、不信の一覧と鎖の確認(`--probe-chains`)による遮断だけです。
広告の blocklist と allowlist は、そのまま働きます。
`--breaker-hosts` の既定値 5 は仮の値で(ASSUMPTION)、見張りの記録を見て決め直します。

### 取り込みの規約

OneCRL、Feodo Tracker、SSL Blacklist は、鍵なしで取れます。
ThreatFox と URLhaus は、abuse.ch の認証を受けた利用者だけが使えるので、`--auth <鍵の file>` の file が無いか、権限が `0600` より緩いか、鍵が 40〜64 桁の 16 進でないときは、request を 1 件も出しません。
その間、`malware-domains.txt` と `malware-ips.txt` は前の内容のまま古くなり、script は `rc=1` で終わります。
鍵の発行には、利用者自身が abuse.ch で認証を受ける手続きが要ります。

### 限界

- 最初の接続は通ります。
  鎖の確認は、通した後に走るからです。
- 能動防御は `proxy` に配線されているので、proxy を通らない通信(自動設定を読まない道具)と、Windows サービスの経路には届きません。
- `block` の経路(この機械の道具の通信)には、鎖の確認を載せていません。
- 一覧は、OneCRL、SSL Blacklist、手で足した行だけで、Chrome の失効の一覧(CRLSet)と Microsoft の不信の一覧は入っていません。
- Mozilla の告知の本文は、設計文書の作成時に読めていません(NOT VERIFIED)。

設計と受入の ID は、`docs/design.md` の「段階10 能動防御」の節にあります。

## 外の一覧の取り込み

`scripts/pd-malware-feed.sh --out <出力先> [--auth <鍵の file>]` が、公開の一覧を取って、packetdeath が読む形に変換します。
packetdeath 自身は、この script も一覧の取得も起動しません。
`curl` と `sh` と `jq` があれば動きます。

| 一覧 | 鍵 | 利用条件 |
|---|---|---|
| Feodo Tracker(悪性サーバーの IP) | 要らない | CC0(誰でも自由に使える。商用でもよい) |
| SSL Blacklist | 要らない | CC0 |
| ThreatFox | 要る | abuse.ch の認証した利用者だけに提供される |
| URLhaus | 要る | abuse.ch の認証した利用者だけに提供される |
| OneCRL(Mozilla の失効した証明書の一覧) | 要らない | 配布元の条件に従う |

ThreatFox と URLhaus は、abuse.ch の認証の鍵が要ります。
鍵は、`header = "Auth-Key: <あなたの鍵>"` の 1 行だけを書いた file に入れ、権限を `0600` にして、`--auth` で渡します。
abuse.ch は鍵を取得先の URL の途中に入れる作りです。
script はその URL を curl の標準入力で渡すので、鍵は `ps` にも log にも出ません。
鍵の file が無いか、権限が緩いか、鍵の形が合わないときは、この2つへ request を1件も出しません。
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

pktmon の後始末(`pktmon stop`、`pktmon filter remove`、`pktmon status`、捕獲した file の削除)と、サービスの外し方は、「Windows で使う」の節の方法 C の手順 8 と 9 にあります。
サービスは、追加の driver を入れません。
再起動後の自動起動は、実走を測っていません(NOT VERIFIED)。
サービスが接続を切ることは、確かめられていません(PW-7 不通過)。

### 記録と鍵

- 記録(`flows.jsonl`、`dns.jsonl`、`av.jsonl`、`watch.jsonl`)は、端末が繋いだ宛先を含む。
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
