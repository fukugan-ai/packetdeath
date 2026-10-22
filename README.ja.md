# packetdeath

日本語 | [English](README.md)

広告と悪いサイトへの通信を、ブラウザの外で動く見張り役のプログラムが止めます。
見張り役は、通信の宛先の名前を一覧と照合して、載っている名前への接続だけを断ちます。

ブラウザの拡張機能ではないので、ブラウザの中身を書き換えません。
同じ見張り役に、家の中の別の端末(iPhone など)の通信を向けることもできます。

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
| `blocklists/telemetry-windows.txt` | Windows と Office の診断データ送信の宛先 5 件 | 実機の記録から選んだ短い列 |
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
ThreatFox と URLhaus は、abuse.ch の認証を受けた利用者だけが使えるので、`--auth <鍵の file>` の file が無いか、権限が `0600` より緩いときは、request を 1 件も出しません。
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
