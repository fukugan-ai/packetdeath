# allowlists/

「当たっても通す」allowlist を置く。形式は `src/allowlist.rs` が正本 ──
1行1 domain、`#` で始まる行はコメント、`example.org` は `example.org` 自体と
`*.example.org`（任意深さのサブドメイン）に当たる（`Allowlist::matches`）。
`judge::run_judges_with_allowlist` / `block_loop::judge_and_log` が、
blocklist・CNAME・宛先 IP・IDS・av のどれよりも先にこの allowlist をチェックする
（`docs/design.md`「判定を差し込む口」）。

遮断すると OneDrive やブラウザの同期（履歴、パスワード）が壊れる宛先を、
block から外すための allowlist である。公開されている「壊してはいけない」リストを
`packetdeath allowlist-convert --in <path> --out <path>` で変換して置いた。

## microsoft-required.txt

### 出所

Microsoft 公式 API（`https://endpoints.office.com/endpoints/worldwide?clientRequestId=<GUID>`）
から 2026-09-11 01:10:25 UTC に取得した JSON（27,805 byte、service 63 個、
`urls` 190 件）を `packetdeath allowlist-convert` で変換した。形式は
`[{"urls":["*.auth.microsoft.com", ...]}, ...]`。`urls` を集め、先頭の `*.` を
剥がして採用する。

### 件数

採用 182 domain、捨て 2 件。捨てた2件は `*` が先頭以外（`*.` の形でない
先頭ワイルドカードを含む）に在るもの ──
`autodiscover.*.onmicrosoft.com`（中間に `*`）、`*cdn.onenote.net`（`*` の
直後が `.` でない）。`Allowlist::matches` はサフィックス一致しか表現できず、
この2形のワイルドカードを再現できないため（`src/blocklist.rs:87-93` と
同じ理由）。

## pihole-common.txt

### 出所

`anudeepND/whitelist`（Pi-hole で定番の allowlist）
`https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt`
から 2026-09-11 01:10:25 UTC に取得した平文（191行、1行1 domain）を
`packetdeath allowlist-convert` で変換した。

### 件数

採用 191 domain、捨て 0 件。平文形式なので変換で失われるものは無い。

## 検討して含めなかったもの

`hagezi/dns-blocklists` の `whitelist-referral.txt`
（`https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt`。
2026-09-11 01:10:25 UTC 取得、941行、Adblock Plus 形式 `@@||example.com^`）は
`packetdeath allowlist-convert` で変換できることを確認した（採用 865 domain、
捨て 67 件。`*` が先頭以外に在る行。例：`@@||*-go.kelkoogroup.net^`）。
用途がアフィリエイト・追跡リダイレクトの解除であり、利用者が名指しした
OneDrive / Chrome 同期 / 認証の経路（このディレクトリの2 file が救う対象）と
異なるため、`allowlists/` には含めない。変換自体は
`src/filterlist.rs` の `convert_allowlist`（`AllowSource::Adblock` 分岐）の
test と、実装時の手動変換で確認済み。
