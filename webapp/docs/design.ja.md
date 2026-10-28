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

ブラウザの password 自動入力と強いパスワードの提案が効くよう、サインインと登録の欄、利用者の作成の欄、password の再設定の欄に `id` と `name` と `autocomplete`（登録と新規は `new-password`）を付け、再設定の欄は利用者名を持つ form に入れた。最初の管理者の登録と利用者の作成は、新しいパスワードの欄と確認の欄の 2 つを `new-password` で並べる（browser は 2 つの password 欄を持つ form を登録の form と判定しやすく、強いパスワードの提案を両方に入れる）。2 つが違えば server に送らない。

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
| `PD_AUTH_TICKET` | 401 | 第二段階の券が無い、期限（5 分）切れ、または 5 回の失敗で失効した |
| `PD_AUTH_SECOND` | 401 | 第二段階の code（TOTP または回復 code）が違う、または使用済み |
| `PD_AUTH_MFA_REQUIRED` | 403 | 運用者以上が第二要素を入れる前に変更しようとした（`--second-factor-optional` で外せる） |
| `PD_MFA_ON` | 409 | 第二要素はすでに有効 |
| `PD_MFA_NONE` | 409 | 確認待ちの秘密が無い |
| `PD_MFA_CODE` | 422 | 確認の code が違う |
| `PD_MFA_STORE` | 500 | 秘密を読み戻せない |
| `PD_USER_NAME` | 422 | 名前が 1 から 128 文字の英数字と `.` `_` `-` `@` `+` ではない |
| `PD_USER_PASSWORD` | 422 | password が 128 から 256 文字ではない（新しい password の長さ。サインインは長さを見ない） |
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

### 段階14 第二要素（TOTP、回復コード、passkey の server と画面を実装済み）

**最新情報** 取得 2026-10-28。NIST SP 800-63B-4（https://pages.nist.gov/800-63-4/sp800-63b.html）は、AAL2 で「少なくとも 1 つの phishing 耐性のある選択肢を出す」ことを求め、AAL3 では非エクスポートの暗号鍵だけを認める。メールは「out-of-band 認証に使ってはならない」とあり、アドレスの確認コードと回復 code は認証ではない。手で入力する code（OTP、out-of-band）は phishing 耐性とは数えない。

結論は次の 3 点である。

- メールの link は認証の手段にしない。受け取る口が password だけで開く場合があり、傍受と DNS の付け替えも受けるため、password の上に重ねても第二要素にならない。この host には送信路も無く、足せば外へ出る口が増える。
- 第一の第二要素は WebAuthn（passkey、security key）にする。鍵が origin に結び付くので、中継する偽サイトでは署名が通らない。
- 第二は TOTP（RFC 6238）、あわせて回復 code を 10 本発行する。TOTP は中継に弱いので、WebAuthn が使えない場合の代替に置く。
- 管理者は第二要素を登録するまで、設定の変更と利用者の管理ができない。

passkey の経路は `src/passkey.rs`（登録の開始と完了、サインインの第二段階の開始と完了。`--rp-id` と `--origin` を両方与えたときだけ有効）にある。部品は `src/totp.rs`（RFC 6238 の計算と照合）、`src/webauthn.rs`（登録と署名の検証）、`src/cbor.rs`（authenticator の応答を読む最小の CBOR 読み取り。整数、バイト列、文字列、配列、写像だけ、長さが決まった形だけ、深さに上限）で、どれも画面を持たない土台である。CBOR の読み取りを自前にするのは、候補の `ciborium` の最終更新が 2024-01-24 で止まっているためである（crates.io の API で読んだ）。TOTP は HMAC-SHA1 の `hmac` `sha1` と `subtle`、WebAuthn の署名検証は ES256（P-256）だけを `p256` で行う。`webauthn-rs` は採らない。その下の `webauthn-rs-core` が openssl を必須の依存に持つためである。

**別の PC から入る場合。**WebAuthn は secure context（HTTPS、または localhost）でしか動かない（MDN の Web Authentication API は HTTPS を要件としている。localhost の扱いは仕様の側の記述で、今回は読んでいない）。LAN の IP に http で入ると `navigator.credentials` が無く、passkey は出ない。別の PC から使える形は次の 2 つである。

- reverse proxy で終端した HTTPS の名前で入る。起動時に `--rp-id` と `--origin` で 1 つの名前に固定し、passkey はその名前に結び付く。別の名前で入ると使えない。
- SSH の転送で、その PC の localhost に出す。rp_id は `localhost` になる。

TOTP と回復 code は secure context を要らず、どの PC の http でも動く。物理の security key（USB、NFC）は、上のどちらの入り方でも別の PC へ持ち運べる。

画面は 3 つ増える。人からの見え方は次のとおりである。

- **サインインの第二段階**：password が通ると同じ枠の中で入れ替わる。欄は 1 つで、`autocomplete="one-time-code"`、`inputmode="numeric"`、6 桁。passkey を登録済みなら「passkey で確かめる」ボタンが先に並ぶ。回復 code を入れる小さな折りたたみが下にある。
- **第二要素の登録**（帯の「セキュリティ」の画面、`ui/src/security.rs`。全員が自分の分を開ける。運用者以上で第二要素が無いと、帯の下に「有効にするまで変更できません」の注意が出る）：TOTP は秘密の文字列と `otpauth://` のリンクを出し、確認コードを 1 回通すと有効になる。QR は描かない（描画の部品を足さず、文字列とリンクで足りる）。passkey は「追加」ボタン 1 つで browser の確認が開く。
- **パスワード管理への引き渡し**：サインインと最初の管理者の登録が成功した時点で、アカウントとパスワードを `PasswordCredential` と `navigator.credentials.store` でブラウザに渡す（Chromium、secure context のとき）。第二段階があるときは、最初の段階で入れたパスワードを第二段階の終わりまで画面の中に保ち、成功、「パスワードに戻る」、券の失効で消す。失敗では渡さない。この API が無いブラウザでは、欄の `autocomplete` に任せる。
- **回復 code の表示**：10 本を 1 回だけ並べ、「控えました」を押すまで閉じない。再表示はできず、作り直すと古い組は無効になる。

| 受入 ID | 受入 | 測り方 |
|---|---|---|
| **PK-210** | TOTP の秘密は、確認コードを 1 回通すまで有効にならない | server の test |
| **PK-211** | password が合っても、第二要素を通すまで session が作られない | server の test |
| **PK-212** | 使った TOTP コードの再利用と、±1 窓の外のコードを断る | server の test |
| **PK-213** | 回復 code は hash で保存され、1 回で消える。TOTP を持たず passkey だけの利用者も、回復 code でサインインできる | server の test（`pk214_a_recovery_code_signs_in_a_user_who_has_only_a_passkey`） |
| **PK-214** | WebAuthn は rp_id と origin に束縛され、署名回数が戻る応答を断る | server の test |
| **PK-215** | 第二要素が未登録の管理者は、設定の変更と利用者の管理を断られる | server の test |
| **PK-216** | 画面：登録、サインインの第二段階、回復 code の表示が browser で動く | 画面試験の席 |

### 残る穴

- 起動時にだけ読む option は WebApp から変えられない。
- 第二要素を失った管理者の回復は、host 上の管理者が `users.json` の該当欄を消す手順（`operations.ja.md`）になる。メールで取り戻す道は持たない。
- TLS は終端を別の物（reverse proxy）に任せる。WebApp 自身は TLS を持たない。
