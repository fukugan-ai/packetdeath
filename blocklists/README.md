# blocklists/

用途ごとに分けた blocklist を置く。形式は `src/blocklist.rs` が正本 ──
1行1 domain、`#` で始まる行はコメント、`example.org` は `example.org` 自体と
`*.example.org`（任意深さのサブドメイン）に当たる（`Blocklist::matches`）。

## telemetry-windows.txt

Windows / Office / MSN の診断データ送信を止める。
squid の proxy 設定を使わず、packetdeath の
SNI 判定（段階2「遮断」）で同じ遮断を行う。

### 出所

実機 Windows 11 の `flows.jsonl`（3776行）に実際に出た
Microsoft 系 SNI から、診断データ送信に絞って選んだ5行。同じ実機の log を対象に、
この5行が「止めたい7件」を全部 当て「止めてはいけない7件」を1件も当てないことを、
`tests/independent_telemetry_blocklist.rs` が `Blocklist::load` /
`Blocklist::matches` を直接 呼んで確かめる。

推測で有名な telemetry ブロックリストを丸ごと持ってきていない。この端末で
実際に出た宛先だけを入れる。出ていないものを足しても効かず、誤爆の種にしか
ならない（`docs/design.md`「制約」の「遮断できないときは素通しに倒す」と同じ
思想）。

### 何を止めるか

| domain | 何を止めるか |
|---|---|
| `events.data.microsoft.com` | 診断データ送信本体。`v10.` `mobile.` `self.` 等のサブドメインをまとめて当てる |
| `settings-win.data.microsoft.com` | 診断設定の取得 |
| `ecs.office.com` | Office の実験設定配信 |
| `events.data.msn.com` | MSN / Edge の利用統計送信（`browser.events.data.msn.com` を当てる） |
| `assets.msn.com` | MSN のコンテンツ配信 |
| `tsfe.trafficshaping.dsp.mp.microsoft.com` | 診断データ送信のトラフィック制御 |

### 実機の log に出たが、絶対に入れないもの

| domain | 何のための通信か | 止めない理由 |
|---|---|---|
| `wdcp.microsoft.com` | Defender のクラウド保護（Microsoft Active Protection Service）。`検索`（GitHub `nsacyber/HTTP-Connectivity-Tester` と Microsoft Learn の Defender 記事）で確認 | antivirus と malware 対策を将来 持たせる方針に反する。**Defender を殺すのは本末転倒。絶対に入れない** |
| `fe2cr.update.microsoft.com` | Windows Update 本体 | 更新が止まる。セキュリティ更新も止まる |
| `fe3cr.delivery.mp.microsoft.com` | 更新の配信 | 同上 |
| `storeedge.microsoft.com` | Microsoft Store | Store が使えなくなる |
| `array611` / `array612` / `array614` / `kv601` / `cp601` / `geo` の `*.prod.do.dsp.mp.microsoft.com` | 配信最適化（Delivery Optimization）の peer 発見・matching。`検索`（Microsoft Learn の Delivery Optimization 記事）で確認 | 更新のダウンロードが劣化する（再ダウンロード・破損・帯域削減の喪失） |

### 判断を保留した host

`my.microsoftpersonalcontent.com` は入れていない。`検索`（Netify /
Microsoft Q&A）で OneDrive の個人コンテンツ配信（Azure Front Door 経由の
OneDrive 個人ファイルダウンロード API）と判った。これは「診断データ送信」で
はなく実データの配信であり、止めると OneDrive の同期やダウンロードが壊れる
恐れが在る。この blocklist は用途を「診断データ送信」に絞っているため入れない。
将来 OneDrive 専用の blocklist を別に作るときの候補として、ここに書き残す。

### 検討して採らなかった手段

packet の層で広告を抑える案から始まり、squid で止める案もあった。この blocklist は
squid の proxy 設定を使わず、packetdeath が既に持つ SNI 判定（段階2）へ乗せる
形で答える。それ以外に検討して採らなかった手段は次のとおり。

| 採らなかった手段 | 理由 |
|---|---|
| **squid・proxy 設定で遮断する** | 禁じ手（`docs/design.md`「禁じ手」）。ブラウザや OS の proxy 設定を変える手段そのものを、この project は最初から排除している |
| **`hosts` file の書き換え** | OS の file を触る。この blocklist の範囲外 |
| **有名な telemetry ブロックリスト（`StevenBlack/hosts` 等）を丸ごと持ってくる** | この端末に出ていない宛先まで含み、誤爆の種にしかならない（実測に接地したものだけを入れる方針） |
| **`wdcp.microsoft.com` を入れる** | Defender のクラウド保護を止めてしまう。antivirus と malware 対策を将来 持たせる方針に反する |
| **Windows Update・配信最適化・Store の host を入れる** | 更新とセキュリティパッチが止まる |
| **判定に迷う host（`my.microsoftpersonalcontent.com`）を、判断できないまま入れる** | 誤って入れると OneDrive が壊れる。判断できないなら入れず、この節で保留を明記する |

## malware feed の運用チェックリスト

公開の malware feed（abuse.ch の ThreatFox、URLhaus、Feodo Tracker）から、悪性の domain と IP の list を作り、packetdeath に読ませる。
antivirus 機能のうち、「悪い接続先を落とす」にあたる。
設計は `docs/design.md` の「段階9 malware feed」節が正本である。

list の中身は repo に入れない。`scripts/pd-malware-feed.sh` が feed から作り、置き場は `~/pd/` である。
feed の license と利用条件は配布元のものなので、各 feed の file 先頭にある「Terms Of Use」を利用者が読む。
落とせるのは、list に載っている domain と IP への接続だけである。載っていない悪性の接続先は落とせず、検知率は feed の網羅率で決まる。

### 手順

1. 取る：`scripts/pd-malware-feed.sh --out ~/pd --auth ~/pd/abuse-ch.curl`（`--auth` を付けないと ThreatFox と URLhaus は取らない）。毎日の取得は `scripts/systemd/pd-malware-feed.timer` が行う。install の command は `.service` の冒頭にあり、install は人が打つ。
2. 行数を見る：`wc -l ~/pd/malware-domains.txt ~/pd/malware-ips.txt`。script は、行数が下限（domain 1000、IP 100）に届かなければ前の file を残して rc=1 で終わる。rc が 1 のときは `~/pd/log/pd-malware-feed.log` を読み、どの feed が取れなかったかを確かめる。
3. proxy の引数に足す：`packetdeath proxy ... --blocklist ~/pd/blocklist.txt --blocklist ~/pd/malware-domains.txt --iplist ~/pd/malware-ips.txt`。自分の blocklist と feed の blocklist は別 file のまま、`--blocklist` を2回 渡して和集合にする。
4. 再起動する：引数を足した最初の1回だけ要る。以後は、list が書き換わると 300 ms 以内に自動で読み直すので、再起動は要らない。
5. 測る：feed の先頭の domain へ `curl -sS --max-time 5 -x http://<proxy>:<port> https://<domain>/` を打ち、`~/pd/log/flows.jsonl` の最後の行に `"decision":"block"` と `"reason":"sni"` が出ることを見る。IP は `http://<IP>/` へ同じ形で打ち、`"reason":"iplist"` を見る。受入 ID は PK-90 から PK-94 である。
6. 誤遮断は allowlist で救う：正規の site が落ちたら、その domain を `~/pd/allowlist.txt` に1行 足す。allowlist は blocklist と iplist のどちらより先に効き、再起動は要らない。proxy へ IP で繋ぐ client が落ちたときは、その IP 文字列を allowlist に1行 足す（`--iplist` へ載せた `127.0.0.1` が、allowlist の1行で `pass` になることを測ってある）。

### 知っておくこと

- ThreatFox と URLhaus は abuse.ch の認証した利用者にだけ提供される。key を `~/pd/abuse-ch.curl`（`header = "Auth-Key: <40〜64 桁の 16 進>"` の 1 行。権限 `0600`）に置くまで、script はこの 2 つへ request を出さず、`malware-domains.txt` と `malware-ips.txt` は前の内容のまま古くなり、毎日 rc=1 で終わる。Feodo Tracker、SSL Blacklist、OneCRL は key なしで取る。
- feed が1つ取れなかった日は、取れた feed だけで list を書き換える（行数が下限以上のとき）。rc=1 の日が続くときは、その feed が止まったか、配布元が認証を求めるようになった可能性がある。
- ThreatFox の `url` の行は取り込まない。URL の host が無料の file 置き場や正規の site のことがあり、host ごと落とすと誤遮断になる。
- private、loopback、link-local、CGNAT、multicast の IP は list に入らない。feed が汚染されても、LAN と proxy 自身は落ちない。
- 手で編集しても、次の取得で上書きされる。残したい例外は allowlist に書く。

## IPS の policy を本番へ入れる運用チェックリスト

`packetdeath block` に `--ips-policy` を渡す。設計は `docs/design.md` の「段階12 IDS/IPS の業務水準化」節が正本である。最初は記録だけの policy（`drop` を含まない）で入れ、`ips.jsonl` で効き方を見てから `drop` を足す。

### 手順

1. policy を書く：`~/pd/ips-policy.jsonl` に `{"action":"alert"}` の 1 行だけを置く（どの警告も記録だけになる）。
2. 配備前に確かめる：`packetdeath ips-test --policy ~/pd/ips-policy.jsonl --alerts <eve.json から抜いた alert の行> ; echo rc=$?`。
3. 入れる：`systemctl edit packetdeath-block` の drop-in に、既存の `ExecStart` の末尾へ `--ips-policy %h/pd/ips-policy.jsonl --ips-state %h/pd/ips-state.jsonl` を足す。`--ips-sids` と `--ips-severity` を同時に渡している行は先に外す（併用は起動時に拒否される）。再起動は 1 回だけ要る。
4. 見る：`jq -r .event ~/pd/log/ips.jsonl | sort | uniq -c`。`observed` の行が出れば動いている。`packetdeath ips-report --log-dir ~/pd/log` で、記録だけだった署名（`drop` の候補）と、守られた宛先（policy の向け先の誤り）を読む。
5. `drop` を足す：候補の署名を 1 つずつ `{"sid":<番号>,"action":"drop","ttl":600}` として policy の先頭へ足す。policy は 1 秒ほどで読み直されるので、再起動は要らない。読めない行を書くと、前の policy のまま `[warn]` が出る。
6. 戻す：drop-in の削除（`systemctl revert packetdeath-block`）と再起動。状態 file の `~/pd/ips-state.jsonl` は消してよい。policy を `{"action":"alert"}` の 1 行に戻すだけでも、新しく落とすのは止まる（すでに落としている宛先は、その ttl の間は残る）。

### 知っておくこと

- loopback、link-local、multicast、この機械の address、gateway、resolver、private の宛先は、policy が `drop` でも落ちない。private を落としたいときだけ `--ips-allow-private` を足す。
- Suricata が止まると `eve.json` が増えない。`--eve-stale`（既定 900 秒）の後に `stale` が `ips.jsonl` と標準エラーに 1 回出る。
- `ips.jsonl` に署名の文と通信の中身は書かない。

## 管理画面と WAF の canary を本番へ入れる運用チェックリスト

管理画面（`webapp/`）と、記録だけの WAF（`--mode detect`）を、無害な upstream の前に置く手順である。どれも `systemctl disable --now` の 1 つで戻る。

1. 管理画面：`webapp/deploy/packetdeath-webapp.service` の雛形の account 名と path を替えて `/etc/systemd/system/` に置く。binary は `webapp/` の `cargo build --release`、画面は `webapp/ui/build.sh` で作る。`systemctl enable --now packetdeath-webapp` の後に `curl -s http://127.0.0.1:8088/healthz` が `ok` を返す。
2. 最初の管理者：`needs_register` が `true` の間は、127.0.0.1 に届く誰でも最初の管理者になれる。unit を起こしたら、すぐ自分で登録する。
3. WAF の canary：無害な静的ページ（`miniserve` など）を 127.0.0.1 の別 port に置き、`packetdeath waf --listen 127.0.0.1:9100 --upstream 127.0.0.1:9101 --mode detect --log-dir <dir>` を unit にする。clean な request が `pass`、攻撃の形の request が `detect`（forward される）で `waf.jsonl` に出る。
4. 画面から見る：`waf.jsonl` を、管理画面の `--logs` の folder に link する（`ln -s <dir>/waf.jsonl <logs>/waf.jsonl`）。
5. 戻す：`systemctl disable --now packetdeath-webapp packetdeath-waf-canary`。`--mode block` へ上げるのは、`waf-report` で誤検知を読み、`--exclusions` で外してからにする。
