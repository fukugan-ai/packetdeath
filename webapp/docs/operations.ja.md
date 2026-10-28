## WebApp の運用手順（`webapp/`）

ブラウザから IPS、IDS、WAF、アンチウイルスの設定を編集し、WAF と IPS の状況を見るための画面である。
本体（`packetdeath`）は WebApp を起動も停止もしない。
WebApp は本体が読み直す設定 file を、本体と同じ読み取り器で検査してから書き換える。

### 最短の手順

1. 画面を build する：`cd webapp/ui && ./build.sh`（`webapp/ui/dist/` ができる。`wasm32-unknown-unknown` の target と、版が 0.2.129 の `wasm-bindgen` が要る）。
2. server を build する：`cd webapp && cargo build --release`。
3. 起動する：`webapp/target/release/packetdeath-webapp --data <dir> --config <dir> --logs <dir> --static webapp/ui/dist`。
4. `http://127.0.0.1:8088/` を開く。利用者がいないときは「管理者を登録」の形で開くので、最初の管理者を作る。

### 引数

| 引数 | 値 | 意味 | 既定 | 必須 |
|---|---|---|---|---|
| `--data` | `<dir>` | `users.json` と `webapp.jsonl` を置く場所 | なし | 必須 |
| `--config` | `<dir>` | 編集する設定 file と、世代（`backups/`）を置く場所 | なし | 必須 |
| `--logs` | `<dir>` | `waf.jsonl` と `ips.jsonl` を読む場所 | なし | 必須 |
| `--static` | `<dir>` | 画面の file（`webapp/ui/dist/`） | なし | 任意（無ければ画面は 404、API は動く） |
| `--listen` | `<addr:port>` | 待ち受け | `127.0.0.1:8088` | 任意 |
| `--allow-remote` | なし | `127.0.0.1` 以外で待つことを許す | 許さない | 任意 |
| `--secure` | なし | cookie に `Secure` を付ける（TLS の後ろに置くとき） | 付けない | 任意 |

TLS は持たない。外から使うときは、TLS を終端する reverse proxy の後ろに置き、`--allow-remote` と `--secure` を付ける。

### 役

| 役 | できること |
|---|---|
| 閲覧者（viewer） | 状態と設定を読む |
| 運用者（operator） | 設定を保存する |
| 管理者（admin） | 利用者を作る、役を変える、無効にする、password を再設定する、消す |

最後の有効な管理者は、消す、無効にする、役を下げるのどれもできない。
サインインに 5 回失敗した account と、20 回失敗した接続元は、15 分待たされる。

### 設定の保存

1. 画面で IPS、IDS、WAF、アンチウイルスの tab を開き、file を選んで書く。
2. 保存すると、server が本体と同じ読み取り器で検査する。読めない行があれば file を書かず、行番号と理由を返す。
3. 通れば、直前の内容を `<config>/backups/<id>.<時刻>.bak` に残し（直近 20 世代）、一時 file に書いて rename で入れ替える。
4. `<data>/webapp.jsonl` に、誰が、どの設定を、旧と新の sha256 で変えたかを残す（password と設定の中身は書かない）。
5. 本体は 1 秒ほどで読み直す。起動時にだけ読む file（`ids-sids`、`mitm-list`）は、画面に「次の起動で反映」と出る。

戻すとき：`<config>/backups/` の世代を、設定 file へ `cp` で戻す（本体が読み直す）。

### 本番の unit

`deploy/packetdeath-webapp.service`（`127.0.0.1:8088`）は雛形である。account 名と `/opt/packetdeath` の path を自分の環境に替えて入れる。`ProtectSystem=strict` で、書けるのは `ReadWritePaths` の 1 つだけである。
戻し方は 1 つ：`sudo systemctl disable --now packetdeath-webapp`。
動作の確認：`curl -s http://127.0.0.1:8088/healthz` が `ok` を返す。

### 守っていること

- 役と CSRF の判定は `app.rs` の `reader` と `writer` の 2 関数だけが行い、画面は隠すだけである。
- password は argon2id で保存し、サインインの失敗は account の有無を応答に出さない。
- 応答に `Content-Security-Policy`（`script-src 'self' 'wasm-unsafe-eval'`）、`X-Frame-Options: DENY`、`nosniff` を付ける。

### 限界

- 起動時にだけ読む本体の option（`--queue`、`--eve` など）は、WebApp から変えられない。
- 本体の process の起動、停止、再起動は WebApp からできない。
- TLS の終端は WebApp の外の仕事である。
