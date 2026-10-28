## 段階13 WebApp（`webapp/`）

ブラウザから、IPS、IDS、WAF、アンチウイルスの設定を見て変え、各部の動きを読む。ログイン画面と利用者の管理は、同じ作者の別の project（動画制作の管理画面）の画面の作りを手本にし、印と色を作り直す。

### 作る物と作らない物

| 作る | 作らない | 理由 |
|---|---|---|
| `webapp/` に別の Cargo package `packetdeath-webapp`（Axum の server）と、`webapp/ui/` に Dioxus の島（WASM） | `packetdeath` 本体への組み込み | 本体は tokio を持たない。server は別の process にして、本体の依存と起動を重くしない |
| 設定は、本体が既に読み直す file（IPS の policy と never の一覧、WAF の rule と除外と IP の一覧、blocklist、allowlist、iplist、av の一覧）を、検証してから atomic に書く | 設定を持つ DB | 本体が読む物が正本。2 つ目の正本を作ると食い違う |
| 本体の起動 option（`--mode`、`--listen` など）は表示だけ | WebApp から本体の process を起動、停止する | 「packetdeath は pktmon も iptables も scanner も起動しない」と同じ線。option を変える人は unit を編集する |
| 利用者は管理者が作る（自己登録なし）。最初の 1 人だけ、利用者が 0 人のときの登録で管理者になる | 自己登録、メールでの再設定 | 外へ出る連絡手段を持たない。password を忘れたら管理者が再設定する |

### 構成

```
ブラウザ ── HTTP ──> packetdeath-webapp (Axum, 127.0.0.1 が既定)
                       ├ 認証：利用者の file（argon2id）、session、CSRF
                       ├ 設定 API：検証（本体と同じ parser）→ 一時 file → rename
                       ├ 状態 API：log を読む（waf.jsonl、ips.jsonl、flows.jsonl）
                       └ 監査：webapp.jsonl（誰が、何を、いつ）
                     assets/ (Dioxus の島を wasm-bindgen で出した js と wasm)
```

- 画面：サインイン、状態、IPS、IDS、WAF、アンチウイルス、利用者。サインインと利用者は手本の画面の作り（1 枚の枠に、account と password の 2 欄、表示の切り替え、言語、明暗）を写し、印と色は作り直す。
- 色：低彩度の藍灰の地に、強調を 1 色（琥珀）だけ使う。印は、盾の中に 3 本の線（流れる packet）。
- 本体と同じ parser を使うため、`packetdeath` を library として依存に取る（`path = ".."`）。policy の検査は `ips::policy::Policy::parse`、WAF の rule と除外は `waf::rules` と `waf::engine` の読み込み、一覧は `iplist::IpList::parse` と `blocklist`。

### module

| module | 役 |
|---|---|
| `users` | 利用者の file。argon2id、役、最後の管理者を守る |
| `session` | session と CSRF の token、サインインの失敗の数え方（時刻を渡す） |
| `audit` | `webapp.jsonl`。digest だけを書く |
| `settings` | 設定の一覧（12 種）、検証、世代つきの atomic な保存 |
| `status` | `waf.jsonl` と `ips.jsonl` の集計を `waf-report` と `ips-report` と同じ関数で返す |
| `app` | 共有の状態、router、認証と CSRF と役の判定（`reader` と `writer` の 2 関数だけが行う）、応答の header |
| `account` | サインイン、サインアウト、最初の管理者の登録、利用者の一覧と変更の道 |
| `setting` | 設定の一覧と読み書きの道。保存の前に tool の parser で検証し、読めない行を 422 で返す |
| `pages` | `/healthz`、状態の道、画面の静的 file |

### 島の module（`webapp/ui/`）

画面は 1 つの Dioxus の島（cdylib、wasm32）で、server の `/api/` だけと話す。CSP が inline の script と style を許さないので、読み込みは `boot.js`、見た目は `style.css` に分ける。

| module | 役 |
|---|---|
| `api` | fetch の薄い包み。変更には `X-CSRF-Token` を付け、422 の `lines` を行番号つきの誤りとして返す |
| `i18n` | 日本語と英語の語。語が無い key は key をそのまま画面に出す（欠けが見える） |
| `theme` | 明暗と言語の記憶（localStorage）と、`<html>` への反映 |
| `mark` | 盾の中に 3 本の線の印と、2 つの icon |
| `signin` | サインインと最初の管理者の登録（同じ枠、同じ 2 欄） |
| `shell` | 上の帯（印、画面の切り替え、言語、明暗、サインアウト）と、画面の差し替え |
| `status` | WAF と IPS の集計と、Suricata の停止の表示 |
| `editor` | 部（ips、ids、waf、av）ごとの設定の編集。保存の前の誤りを行番号で示す |
| `users` | 利用者の一覧、作成、役、無効、password、削除 |

### 画面

| 画面 | 誰が | 何が見えて、何ができるか |
|---|---|---|
| サインイン | 全員 | account と password の 2 欄、表示の切り替え、言語、明暗。最初の利用者がいないときだけ、管理者の登録の形になる |
| 状態 | 全員 | WAF の処置の件数、IPS の出来事の件数、Suricata が止まっていないか（`stale`）、直近の変更 |
| IPS | operator 以上が変更 | policy と never の一覧の編集。保存の前に、読めない行を行番号で示す。「1 秒ほどで反映」と出す |
| IDS | operator 以上が変更 | 止める sid の一覧、blocklist、allowlist、iplist。sid の一覧は「次の起動で反映」と出す |
| WAF | operator 以上が変更 | rule、除外、許可と拒否の IP の一覧、信頼する中継の一覧 |
| アンチウイルス | operator 以上が変更 | MITM で開く宛先の一覧（「次の起動で反映」）。av の結果は外の道具が書くので、読むだけ |
| 利用者 | admin | 一覧、作成、役の変更、無効化、password の再設定、削除 |

### 認証と権限

- 利用者の file は `users.json`（atomic に書く）。password は argon2id で hash し、平文を持たない。
- session は乱数 256 bit の id を server が持ち、cookie は `HttpOnly`、`SameSite=Strict`、TLS の背後では `Secure`。寿命は 8 時間、無操作 1 時間。
- 書き換えの request は `X-CSRF-Token` を要る。token は session ごとに乱数で、サインインの応答で返す。
- 役：`admin`（利用者の管理と設定）、`operator`（設定）、`viewer`（読むだけ）。役の判定は server 側だけで行い、画面は隠すだけ。
- サインインの失敗は、account の有無を応答に出さない。同じ account は 5 回失敗で 15 分、同じ接続元は 20 回失敗で 15 分の待ちにする。表は上限つき。
- 既定の bind は `127.0.0.1:8088`。他の address に bind するときは `--allow-remote` を明示する。TLS の後ろに置くときは `--secure` を付け、cookie に `Secure` を足す。

### 設定の書き方

1. 画面が値を送る。2. server が本体と同じ parser で検証する。読めない行があれば file を書かず、行番号つきで返す。3. 一時 file に書き、fsync し、rename する。4. 直前の内容を `webapp/backups/` に世代つきで残す（直近 20 世代）。5. 書いた事実を `webapp.jsonl` に残す（file の名前、旧と新の sha256、利用者。中身は書かない）。6. 本体は既存の読み直しで 1 秒ほどで反映する。

読み直しをしない file（起動時にだけ読む物）は、画面に「次の起動で反映」と出す。

### 受入 ID

| ID | 受入条件 | 打つ command | 通ったと判る出力 |
|---|---|---|---|
| **PK-190** | 利用者が 0 人のとき最初の登録だけが管理者になる。2 人目の自己登録は拒否される | `cargo test -p packetdeath-webapp --test auth` | 全部 ok |
| **PK-191** | password は argon2id で保存され、file に平文が無い。誤った password は account の有無に関わらず同じ応答 | 同上 | `grep -c <password> users.json` が 0。応答が同一 |
| **PK-192** | CSRF token の無い書き換えは 403。session の無い request は 401。viewer の書き換えは 403 | 同上 | 状態コードが期待どおり |
| **PK-193** | 同じ account の 5 回失敗で待ち。待ちの間は正しい password も拒否。待ちが明けると通る（時刻を注入） | 同上 | 期待の列 |
| **PK-194** | IPS の policy を保存する：読めない行を含むと保存されず行番号が返る。正しければ file が書き換わり、旧い内容が backup に残る | `cargo test -p packetdeath-webapp --test settings` | 期待どおり |
| **PK-195** | WAF の除外、rule、IP の一覧、IDS の sid の一覧、blocklist、allowlist、iplist、av の一覧の保存が、同じ型で通る | 同上 | 期待どおり |
| **PK-196** | 保存の途中で死んでも、元の file が壊れない（一時 file のまま残り、元は無傷） | 同上（書き込みを失敗させる hook） | 元の sha256 が不変 |
| **PK-197** | 監査：設定の保存と利用者の変更が `webapp.jsonl` に残り、password と設定の中身を含まない | 同上 | `grep -c` で 0 |
| **PK-198** | 状態：`waf.jsonl` と `ips.jsonl` の集計を API が返す（`waf-report` と `ips-report` と同じ数） | `cargo test -p packetdeath-webapp --test status` | 同じ数 |
| **PK-199** | 利用者の管理：管理者だけが作る、役を変える、無効にする、password を再設定する。最後の管理者は消せない | `--test auth` | 期待どおり |
| **PK-200** | 画面：島が wasm に build でき、サインイン、状態、5 つの設定、利用者の画面が browser で開く | 画面試験の席（`screen-test-engineer`）が DOM を測る | 通った |
| **PK-201** | 手本の画面と同じ作りであること：サインインに account と password の欄、表示の切り替え、言語、明暗が在る | 画面試験の席 | 通った |
| **PK-202** | 本番への反映：`127.0.0.1` で起動し、`systemd` の unit で上がり、戻し方は unit の停止 1 つ | 本番の手順（`blocklists/README.md` の運用チェックリスト） | `curl -s http://127.0.0.1:<port>/healthz` が 200 |

### 画面試験の結果と直し

画面試験（PK-200、PK-201）の S-01 から S-25 のうち、S-21 が落ちた。最初の管理者を登録した直後にサインアウトすると、サインインではなく登録の形が残った。原因は、利用者がいるかどうかを起動時に 1 回しか決めていなかったことにある。直しは、誰かがサインインしたら「利用者がいる」に切り替えることである。同じ試験で、役の選択欄が現在の役ではなく admin を示す表示のずれも見つかり、現在の役を選ぶ形に直した。S-25 の期待は、手順が自分で起こす 422 と 403 を数えていなかったため、製品の欠陥は 409 の 1 件だけだった。

ブラウザの password 自動入力と強いパスワードの提案が効くよう、サインインと登録の欄、利用者の作成の欄、password の再設定の欄に `id` と `name` と `autocomplete`（登録と新規は `new-password`）を付け、再設定の欄は利用者名を持つ form に入れた。

運用の手順は `operations.ja.md`、本番の unit は `deploy/packetdeath-webapp.service` にある。

### エラー番号

server の拒否は、すべて `{"error": 文, "code": 番号}` で返る。番号は `PD_<部位>_<理由>` で、画面は「言葉 [番号] server の文」の 1 行で見せる。番号から、どの検査が止めたかが分かる。framework が返す拒否（JSON の欄が足りないなど）は `PD_HTTP_<状態>`、server に届かないときは `PD_UI_NETWORK` になる。

| 番号 | 状態 | 止めた検査 |
|---|---|---|
| `PD_AUTH_NO_COOKIE` | 401 | session の cookie が無い |
| `PD_AUTH_SESSION_ENDED` | 401 | session が切れた、または無い |
| `PD_AUTH_LOGIN` | 401 | account か password が違う（有無は区別しない） |
| `PD_AUTH_LIMITED` | 429 | 失敗が続いたため待たされている |
| `PD_AUTH_ROLE` | 403 | 役が足りない |
| `PD_AUTH_CSRF` | 403 | CSRF token が無い、または違う |
| `PD_AUTH_COOKIE`、`PD_AUTH_SESSION_START` | 500 | cookie または session を作れない |
| `PD_USER_NAME` | 422 | 名前が 1 から 128 文字の英数字と `.` `_` `-` `@` `+` ではない |
| `PD_USER_PASSWORD` | 422 | password が 12 から 256 文字ではない |
| `PD_USER_EXISTS` | 409 | その名前は使われている |
| `PD_USER_REGISTER_CLOSED` | 409 | 利用者がいるので最初の管理者の登録はできない |
| `PD_USER_LAST_ADMIN` | 409 | 最後の有効な管理者を消す、無効にする、役を下げる |
| `PD_USER_NOT_FOUND` | 404 | その利用者がいない |
| `PD_USER_STORE` | 500 | 利用者の file を書けない |
| `PD_SETTING_UNKNOWN` | 404 | その設定の種類は無い |
| `PD_SETTING_TOO_LARGE` | 413 | 1 MiB を超える |
| `PD_SETTING_INVALID` | 422 | 読めない行がある（行番号つき） |
| `PD_SETTING_IO` | 500 | 設定の file を書けない |
| `PD_STATUS_READ` | 500 | log を読めない |
| `PD_PAGE_NOT_FOUND` | 404 | 画面の file が無い |

### 採らない手段

| 採らない | 理由 |
|---|---|
| 設定を DB に持つ | 本体が読む file が正本。2 つ目の正本は食い違う |
| 本体の process を WebApp が起動、停止する | 本体の「他の process を起動しない」線に反する |
| 外部の認証（OAuth、メール） | 外へ出る連絡手段を持たない。単独の host で閉じる |
| 画面を JavaScript で書く | 画面は Dioxus（Rust / WASM）にそろえる |

### 残る穴

- 起動時にだけ読む option は WebApp から変えられない。
- TLS は終端を別の物（reverse proxy）に任せる。WebApp 自身は TLS を持たない。
