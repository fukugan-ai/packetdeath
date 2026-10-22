# packetdeath の設計と受入 ID

## 何を作るか

Windows と Linux の両方で動く、Rust 製のパケット層の広告遮断器である。
段階1〜7 は TLS を復号しない。
段階8 だけが、利用者が端末へ入れた CA で HTTPS を復号して file を検査する（「段階8 MITM」節）。
packetdeath 自身は、OS の信頼ストアにも、ブラウザや OS の proxy 設定にも触らない。
判定材料は、TLS ClientHello の SNI（平文）、DNS 応答の CNAME チェーン、宛先 IP の3つに限る。
IDS/IPS は Suricata を IDS モードで並走させ、その alert を packetdeath が読んで落とす。

守る対象は Windows 上の Chrome Canary である（下の前提表）。
Linux では同じ判定 code を nfqueue のガワで動かす。
画面（UI）は作らない（「UI の有無」の節）。

## 前提

この表の値は実測である（Windows 側の行は Windows の端末で、WSL 側の行は WSL で打つ）。
`$CANARY` は Windows 上の Chrome Canary の directory（`Application` と `User Data` を持つ）である。
実際の絶対 path は文書に書かない。利用者が手元で `CANARY` に設定してから打つ。

| 値 | 測った command | どこで |
|---|---|---|
| Chrome Canary `155.0.8050.0` | `ls -d "$CANARY/Application"/*/` | Windows |
| 拡張は Google 純正の2つのみ。広告ブロッカーは0件 | `ls "$CANARY/User Data/Default/Extensions"` | Windows |
| `cargo 1.98.0` | `cargo --version` | WSL |
| mingw の linker `(GCC) 13-win32` が在る | `x86_64-w64-mingw32-gcc --version` | WSL |
| Windows 向け cross build が 54.08s で通る | `cargo build --release --target x86_64-pc-windows-gnu` | WSL |
| WSL は `networkingMode=mirrored` | `cat "$(wslpath "$(powershell.exe -NoProfile -Command '$env:USERPROFILE' \| tr -d '\r')")/.wslconfig"` | WSL |
| WSL の kernel は NFQUEUE を module で持つ（`CONFIG_NETFILTER_NETLINK_QUEUE=m`、`CONFIG_NETFILTER_XT_TARGET_NFQUEUE=m`、`CONFIG_NFT_QUEUE=m`） | `zcat /proc/config.gz \| grep -E '^CONFIG_(NETFILTER_NETLINK_QUEUE\|NETFILTER_XT_TARGET_NFQUEUE\|NFT_QUEUE)='` | WSL |
| WSL に `iptables` `dig` `curl` は在る。`nft` と `suricata` は無い | `for t in iptables nft suricata dig curl; do command -v $t \|\| echo "$t none"; done` | WSL |

uBlock Origin は 2026-08-31 に Chrome Web Store から削除され、Chrome Canary 155 は MV2 拡張を読み込まない（`検索`。一次資料は未読）。

## 禁じ手

次の3つは、設計のどの段階でも使わない。ただし1番は、段階8 の範囲で利用者が自分で端末へ CA を入れる手順に限って外してある。

1. **CA 証明書を OS の信頼ストアへ入れること**。段階8 だけが、利用者が自分で端末へ CA を入れる手順を採る。packetdeath 自身が自分の動く端末の信頼ストアへ CA を入れる操作は、禁じ手2と同じ理由で採らない（「段階8 MITM」節）。
2. packetdeath が、自分の動く端末の OS やブラウザの proxy 設定を書き換えること。利用者が別の端末（iPhone 等）の proxy 欄へ packetdeath を手で指すのは利用者自身の選択であり、この禁じ手には当たらない（「段階7 proxy」節）。
3. 中国の組織が署名した driver を使うこと（「採らない手段」の表を見よ）。

## 採らない手段

| 採らない手段 | 理由 | 出所 |
|---|---|---|
| WinDivert | `WinDivert64.sys` の署名者が `C=CN` の組織である。禁じ手3に触れる。同梱の `WinDivert.dll` / `windivertctl.exe` / `passthru.exe` は `NotSigned` | `実測`（`Get-AuthenticodeSignature`。`Signer` が `O=…, C=CN`、`Issuer` が Sectigo。陽性対照の `notepad.exe` は `CN=Microsoft Windows`） |
| Npcap | kernel driver の追加が要る。無料版に再配布制限が在る | `検索` |
| 自前の kernel driver | EV 証明書と Microsoft の attestation が要る | `検索` |
| WFP の user-mode API だけ | driver は要らないが、パケットの中身を見て判定するには callout driver（kernel）が要る。user-mode で出来るのは IP / port 単位の静的フィルタまでで、SNI が見えない | `検索` |
| DNS を自前 resolver へ向ける | 禁じ手2（packetdeath が自分の端末の proxy / resolver 設定を書き換えない）に当たる | ─ |
| MITM proxy（`hudsucker` 系） | 段階1〜7 では、CA を信頼ストアへ入れる禁じ手1と proxy 設定の禁じ手2の両方を要求するので採らない。段階8 は利用者が自分で CA を入れる形に限って MITM を採る。`hudsucker` と tokio は段階8 でも採らない（理由は「段階8 MITM」節の「採らない手段」の表）。**復号しない CONNECT proxy（段階7）はこの行の対象外**である。TLS を割らないので CA が要らず、proxy 設定は利用者が別端末へ手で入れるだけで packetdeath 自身は自分の端末の設定を書き換えない | ─ |
| Suricata の WinDivert IPS モード | Suricata 8.0.0 と Windows 11 の組で drop が効かない不具合が未解決である。`fast.log` は `wDrop` を出すが `eve.json` は `"action":"allowed"` になり、timestamp が約30分ずれる | `検索` https://forum.suricata.io/t/suricata-ips-mode-not-working-with-windivert-on-windows-11/5948 |
| Suricata を Linux だけ NFQUEUE の IPS モードで使う | 1つの NFQUEUE 番号は1つの process しか掴めない。packetdeath と Suricata で queue を分けて直列に繋ぐと、Windows 側と分割の形が変わる。両 OS で同じ分割（Suricata は IDS、落とすのは packetdeath）にする | `推測`。NFQUEUE の排他は `記憶` |
| 署名ベースの IDS/IPS エンジンの自作 | Rust に署名エンジンを持つ crate が見当たらない（`rshark` は dissection のみ、`net-sift` はパーサのみ、`pcap` は捕獲のみ）。ET Open 相当のルールセットも自前になる | `検索` |
| ブラウザ拡張 | Chrome Canary 155 で MV2 が動かない。uBlock Origin は 2026-08-31 に Web Store から削除された | `検索` |
| DNS 応答だけで落とす（sinkhole 型） | app が DoH を hard-code すると素通りする。ECH の鍵配布も DNS の HTTPS record 経由なので、DNS が見えない経路では判定材料が丸ごと消える。DNS は判定材料の1つに留め、落とす位置は packet にする | `検索`（`docs/research/prior-art.md:81`）、`実読`（`docs/research/foci-ech.txt:110-112`） |
| eBPF / XDP を最初から使う | driver 層で速いが、判定材料は L3/L4 まで。段階1〜4 は nfqueue で作り、性能が足りないと測れたときに移す | `検索`（`docs/research/prior-art.md:82`） |
| `unsafe_code` を `deny` へ緩める | 必要が無い。遮断は常駐 PowerShell 経由で行い、温まった後は 27〜32 マイクロ秒で足りる（「Windows 方式の判断」）。`SetTcpEntry` を Rust から呼ばないので unsafe が0件になり、`forbid` のままで通る | `実測`（常駐 PowerShell の遮断） |
| Rust から `SetTcpEntry` を直接 呼ぶ | unsafe が要る。常駐 PowerShell の C# から `ref` 渡しで同じ API を safe context のまま呼べる（「Windows 方式の判断」） | `実測`（同上） |
| PowerShell を遮断のたびに起動する | 1回 200 ms かかる（`実測`。毎回 起動が 263 / 191 / 199 ms）。常駐させれば温まった後は 27〜32 マイクロ秒 | `実測` |
| タスクスケジューラで常駐させる | 落ちたときの自動再起動が無い。起動時に実際に走るかを再起動せずに測れない。Windows サービスは `sc failure` で自動再起動でき `sc query` で状態が見える | ─ |

## 採る方式

透過的にパケットへ作用する。TLS を復号しない。

| 層 | Windows | Linux |
|---|---|---|
| パケットの掴み | pktmon（Windows 標準。追加 driver ゼロ）で ClientHello を含む未加工パケットを ETL へ捕獲し、`pktmon etl2pcap` で pcapng へ変換する。packetdeath は pcapng を読むだけで、捕獲はしない | nfqueue（`--queue-bypass` 必須。「fail-open」の節）。将来 eBPF / XDP |
| 広告の遮断 | packetdeath が接続の4つ組（`src_ip` `src_port` `dst_ip` `dst_port`）を常駐 PowerShell へパイプで送り、PowerShell が `SetTcpEntry` で該当 TCP 接続を切る（`MIB_TCPROW` の `dwState` に `12` = `MIB_TCP_STATE_DELETE_TCB`。IPv4 TCP 専用。port は network byte order。管理者権限、サービスは SYSTEM が要る） | packetdeath が nfqueue の verdict で packet を落とす |
| IDS/IPS の検知 | `未確認`（Suricata の Windows での capture 方式。Npcap を採らないため。「採らない手段」の表） | Suricata を IDS モードで並走（AF_PACKET） |
| IDS/IPS の遮断 | Suricata の `eve.json` の alert を packetdeath が読み、接続の4つ組を常駐 PowerShell へ送って `SetTcpEntry` で切る（Windows の検知が未確認） | alert を packetdeath が読み、nfqueue で落とす |

pktmon は観測専用で、packet を落とす機能を持たない。
Windows での遮断は、確立済みの TCP 接続を常駐 PowerShell 経由の `SetTcpEntry` で切る別経路で行う。
packetdeath は経路の途中に居ないので、落ちても通信は止まらない（「fail-open」の節）。

Linux ではこの分割で、Suricata の IPS モード（「採らない手段」の表）を使わずに IPS 相当になる。
Windows の Suricata capture は `未確認` である。

WSL の nfqueue は Windows のパケットを掴めないので、Windows 実装は省略できない。
`networkingMode=mirrored` でも WSL と Windows は別の network namespace であり、
WSL 側で見えるのは WSL 内の process の接続だけである（実測④。
WSL の `ss -tnp state established '( dport = :443 )'` で 19 件、うち全件が `users:` を持つ WSL 内 process、
Windows の `(Get-NetTCPConnection -RemotePort 443 -State Established).Count` で 1 件、
`readlink /proc/self/ns/net` が `net:[4026531833]` と測った）。

### Windows 方式の判断

**遮断の経路 ── packetdeath は `SetTcpEntry` を Rust から呼ばない。常駐させた PowerShell へ接続の4つ組をパイプで送る。**
起動時に1回だけ立ち上げた常駐 PowerShell へ、切る接続の4つ組（`src_ip` `src_port` `dst_ip` `dst_port`）を1行ずつ送る。立ち上げた直後は `0,0,0,0` の 1 行で温め、応答が返ってから使う（「常駐 PowerShell の温め（PK-121）」）。
PowerShell は `Add-Type` で読み込んだ C# の `[DllImport("iphlpapi.dll")] SetTcpEntry(ref MIB_TCPROW)` を呼ぶ。`ref` で struct を渡すので生ポインタを使わず、C# は safe context のまま呼べる。
packetdeath は FFI を持たない。**Rust にも C# にも unsafe は0件で、`Cargo.toml` の `unsafe_code` は `forbid` のままにする。**
温まった後の遮断は 27〜32 マイクロ秒である（`実測`。常駐 PowerShell に命令をパイプで送り、2回目以降が `rc=317 us=27.2`。`rc=317` は「該当する接続が無い」で、`0,0,0,0` を渡したことへの正しい応答。1回目は `Add-Type` の JIT 込みで `us=92317.5`、起動を含む全体で 632 ms。陰性対照は1行目に `READY_CHECK` を送ると uint32 変換 error で弾かれた）。
`SetTcpEntry` の API 自体は 100 回で1回あたり 0 ms、毎回 PowerShell を起動すると 200 ms かかる（同 測定。毎回 起動が 263 / 191 / 199 ms）ので、常駐させる。

**常駐は Windows サービスにする。タスクスケジューラは採らない（「採らない手段」）。**
`sc failure` で落ちたときに自動再起動でき、`sc query` で状態が見え、起動時に走らせられる。
`windows-service` crate は `forbid(unsafe_code)` の下で使える（`実測`。probe project の `Cargo.toml` に `windows-service = "0.8"` と `[lints.rust] unsafe_code = "forbid"`、`src/main.rs` に `#![forbid(unsafe_code)]` と `define_windows_service!` を置き、`cargo build --target x86_64-pc-windows-gnu` が unsafe の error 0 で通った。出た警告は `dead_code` だけ）。
🔴 **起動時（boot）に実際に走るかは `未確認`。**利用者の端末を再起動しない条件のため、再起動しての実走を1度も測れていない（`未確認`。schtasks の SYSTEM 実行で `<UserId>S-1-5-18</UserId>` `<RunLevel>HighestAvailable</RunLevel>` `<BootTrigger><Delay>PT30S</Delay></BootTrigger>` の登録・遅延・撤去が通ることは測れている。撤去後と陰性対照が同じ error「The system cannot find the file specified」）。
解消は、利用者の端末を再起動せずに済ませる ── 再起動してよい別の端末か使い捨て VM で boot start の実走を1回 測るか、利用者が別の理由で再起動する機会に `sc query` で `RUNNING` を確かめる。この実走が取れるまで PW-8 は `未確認` のままにする。

**サービスは SYSTEM で走るので、`--log-dir` を必ず明示する。**
SYSTEM のとき `%LOCALAPPDATA%` は `C:\WINDOWS\system32\config\systemprofile\AppData\Local` になる（`実測`。schtasks で SYSTEM 実行したタスクが `Run As User: SYSTEM`、`Last Result: 0`、`LOCALAPPDATA=C:\WINDOWS\system32\config\systemprofile\AppData\Local` を出した。陰性対照は走る前に出力 file が無いことを `Test-Path → False` で確認）。
既定の置き場に頼ると log が systemprofile の下に落ちて見つけにくいので、サービスの起動引数にも受入 ID の command にも `--log-dir <path>` を必ず渡す。

**判断2 ── packetdeath は pktmon を起動しない。利用者が打つ。**
`linux.rs` が iptables を打たないのと同じ理由である（「制約」）。
packetdeath が `pktmon start` を呼んだ後に落ちると、`pktmon stop` が呼ばれないまま capture session が残り、
ETL が際限なく肥大化する（実測①で無 filter の capture が 369 MB になり、`イベントが失われました: 178213` が出た）。
落ちたとき rule だけが残る事故（Linux 側で避けた性質）を、Windows 側だけ持ち込む理由が無い。
pktmon の運用（`filter add` → `start` → `stop` → `etl2pcap`）は利用者が行う。

**判断3 ── ETL からパケットを取り出す経路は `pktmon etl2pcap` で pcapng へ変換して読む。**
ETL は Microsoft 非公開のバイナリ形式で版依存が高い。
pcapng は IETF の公開仕様で、変換は Microsoft 公式の command が行う。
pktmon のリアルタイム表示をプログラムから購読する経路は `未確認`。

**判断4 ── ClientHello を組み立て直す（`src/reassemble.rs::Reassembler`。Linux・Windows 共通）。**
実測（2026-09-11 08:42〜08:45、実機 Windows 11 の Chrome）で、443 宛て flow の
73.8%（559/757）が `sni_state":"fragmented"` になった。実際の pcapng を parse
すると、ClientHello を含む18 packet のうち15件（83%）が複数 TCP segment に
割れていた。原因は耐量子鍵交換（X25519MLKEM768）の公開鍵が ClientHello に
約1200 byte 乗り、宣言長が 2139〜2301 byte の山を作るため（1 TCP segment
約1460 byte に収まらない）。`FlowKey` 単位で TCP payload をつなぎ直す
`Reassembler` は、Windows（pktmon 経由の `block_loop.rs`）と Linux
（nfqueue 経由の `linux.rs::run` / `run_block`）の両方へ配線している。
`sni_state` の3値・`flows.jsonl` の field は増やさない。組み立てに失敗しても
`fragmented` を返すだけで、判定できない flow は通す（fail-open）。

守る境界は3つ。1接続あたり 16 KiB（実測の宣言長の山・最大 2301 byte に
十分な余裕）を超えたら諦めて `fragmented` を確定する。同時に溜めておける
接続数は 4096 で、超えたら最も古い接続から黙って捨てる（`[warn]` を出す）。
バッファの寿命は 30 秒で、ClientHello は接続の最初に来るのでそれ以上 待つ
意味が無い。どちらも上限に当たったら `[warn]` を出す。

TCP の seq 番号は見る。同じ接続の payload を素朴な受信順で連結すると、
再送（同じ seq の重複）や順序違反（reorder）で誤った SNI を読む危険が
在るため、`base_seq` から連続する seq のセグメントだけを連結し、過去
（再送）・未来（ギャップ）のセグメントは無視して次を待つ（安全側に倒す）。

**443 宛て flow の 49.5% を占めていた戻り（サーバ→クライアント）方向の
packet は、flow として記録しない。**ClientHello はクライアント→サーバの
向きにしか出ないため、`windows.rs::is_client_to_server` が宛先 port が
送信元 port より小さい packet だけを対象にする（TCP の正確な向き判定には
SYN フラグを追った状態管理が要るが、TLS/HTTP の「クライアントの一時 port
からサーバの well-known port へ」という通信形に限れば十分な近似になる。
実測で戻りパケットの宛先 port は `32348` のような一時 port だった）。
両方が高い port の通信は対象外になるが、fail-open の範囲内であり誤って
遮断する側には倒れない。段階5（`--iplist`）は Windows 側でも `--pcapng`
経路から使えるが、対応する受入 ID は無い（PK-50〜53 は Linux 固有）。
Linux（`linux.rs`）はこの問題を持たない。iptables の rule が
`-I OUTPUT --dport 443` のみで戻り方向（`INPUT`）を最初から nfqueue に
乗せていないため、`linux.rs` は変更していない。

判定材料と、それが CA 無しで見える根拠は次のとおり。

- **SNI**：TLS ClientHello は handshake の最初の平文 message で、SNI extension に domain 名を平文で運ぶ（`実読` `docs/research/foci-ech.txt:12-17`）。Suricata の `tls.sni` keyword も同じ平文を見ている。rule の形（`検索`）は次のとおり。

```
drop tls $HOME_NET any -> $EXTERNAL_NET any (msg:"..."; tls.sni; dotprefix;
  content:".doubleclick.net"; nocase; endswith; ssl_state:client_hello; sid:1; rev:1;)
```

- **DNS 応答の CNAME チェーン**：CNAME cloaking（first-party の subdomain を tracker の domain へ CNAME で向ける）は、Tranco Top 10K の 9.98% が使う（`検索`。`docs/research/prior-art.md:38`）。SNI は first-party の名前なので、DNS 応答の CNAME 先を見ないと当たらない。
- **宛先 IP**：CNAME で解決した IP と、Suricata の alert が指す IP を、以後の flow の遮断に使う。

IPS の遮断は反応型である。
alert は packet が通った後に `eve.json` へ書かれるので、alert を出した最初の packet は通る。
packetdeath は alert の 5-tuple（`src_ip` `dest_ip` `src_port` `dest_port` `proto`）と `dest_ip` を drop 集合へ入れ、以後の packet を落とす。
drop 集合の寿命は `--ips-ttl <秒>`（既定 300）。

落とす alert の選び方は2つあり、どちらかに当たれば落とす。

- **`--ips-sids`**：列挙した `sid` の alert。
- **`--ips-severity <N>`**：`alert.severity` が N 以下の alert（N は 1〜3）。Suricata の severity は 1 が最も重い。severity は rule の `classtype` の priority で決まり（`/etc/suricata/classification.config`）、`metadata: signature_severity` では決まらない。

どちらも渡さなければ IDS 由来の遮断は0件である。
`--ips-severity` が当たる rule は、priority 1 の classtype を持つ有効な alert rule である。
実測では、priority 1 の classtype は15個あった（`grep -E '^config classification' /etc/suricata/classification.config` の末尾の列が `1`）。
`suricata.rules` の有効な alert 53145 本（`grep -cE '^alert'`）のうち、35700 本がその15個のどれかを `classtype:(<15個を | で連結>);` で持つ。
`metadata: signature_severity Critical` を持つ 5404 本とは別の集合である。
この host の `eve.json` にある alert 30 件（`grep -a '"event_type":"alert"'`）は、すべて severity 3 の decoder event（`SURICATA STREAM ...` など）だった。
`--ips-severity 1` を指定しても、これらは落とさない。

採らない手段は3つある。
alert の全件を落とすと、severity 3 の decoder event が LAN 内の宛先まで落とす。
sid の一覧を生成して file に書くと、rule の更新に一覧が追従しない。
Suricata を NFQUEUE の IPS にする手段は、上の「採らない手段」の表にある。

## 名前と置き場

実装はここで決めた名前に従う。受入 ID の command がこの名前に依存する。

- **CLI**：`packetdeath observe [--queue <N>] [--filter <式>]`（段階1。落とさない）、`packetdeath block [--queue <N>] [--blocklist <path>]... [--allowlist <path>] [--dns] [--eve <path>] [--ips-sids <path>] [--ips-severity <1-3>] [--ips-ttl <秒>] [--pcapng <path>] [--poll-ms <ミリ秒>]`（段階2〜4）、`packetdeath eval --labels <tsv>`、`packetdeath filterlist --in <path> --out <path>`（EasyList 形式を blocklist 形式へ変換する。「EasyList からの変換」の節。`--log-dir` を持たない）、`packetdeath allowlist-convert --in <path> --out <path>`（Microsoft 公式 API の JSON／平文1行1domain／Adblock Plus の `@@` 形式を allowlist 形式へ変換する。「allowlist（当たっても通す）」の節。`--log-dir` を持たない）、`packetdeath service-install --log-dir <path> [--pcapng <path>] [--blocklist <path>] [--allowlist <path>]`（登録するサービスの起動引数へ渡す。渡さなければ従来どおり `--log-dir` だけの起動引数になり、遮断 loop を回さない）。`filterlist` / `allowlist-convert` を除く全 subcommand に共通の `--log-dir <path>` を持つ。Windows では packetdeath は pktmon が作った pcapng を読む。capture の filter は pktmon 側で利用者が設定する（次の「pktmon の filter」）ので、`--filter` は Windows の capture を制御しない。Windows での pcapng 入力の渡し方は段階1w の実装で確定する（`未確認`）。
- **root**：nfqueue は root が要る。Linux では `sudo packetdeath ...` で起動する。`sudo` 下では `$HOME` が変わるので、受入 ID の command は `--log-dir` を必ず渡す。
- **NFQUEUE 番号**：既定 `1808`。iptables の rule は利用者が打つ（下の表）。packetdeath は rule を足さない。rule を足す side effect を持つと、落ちたときに rule だけが残る。
- **pktmon の filter**：利用者が capture 前に設定する（packetdeath は打たない。判断2）。`pktmon filter add pd7 -t TCP -p 443` で TCP 443 に絞り、`pktmon start --capture --comp nics --pkt-size 0 --flags 0x010 --file-name <path>` で捕獲する。`--comp nics`（監視対象をネットワークアダプターに限る）が本命で、既定の `all` だと HTTP.SYS の内部エッジまで拾い、IP ヘッダの無い層のカウンターばかりになってパケット本体が0件になる（実測②。既定だと 1423 件が内部エッジだった）。`-i <IP>` で宛先 IP を絞らない。宛先の A レコードがラウンドロビンで変わり（実測②で `example.com` が `172.66.147.243` → `104.20.23.154`）、filter の IP と実接続先がズレる。`--flags 0x010`（未加工パケットのみ）で filter 込みなら 3.8 MB。filter 無しは 369 MB になり `イベントが失われました: 178213` が出る（実測①）。
- **log の置き場**：`--log-dir` が無いとき、Linux は `${XDG_STATE_HOME:-$HOME/.local/state}/packetdeath/`、Windows は `%LOCALAPPDATA%\packetdeath\`。以下 `<log dir>` と書く。Windows サービスは SYSTEM で走り、そのとき `%LOCALAPPDATA%` は systemprofile の下（`C:\WINDOWS\system32\config\systemprofile\AppData\Local`）になる（「Windows 方式の判断」）ので、サービスにも受入 ID の command にも `--log-dir <path>` を必ず渡す。
- **flow log**：`<log dir>/flows.jsonl`。1 flow 1行。field は `ts`, `proto`（`tcp` か `udp`）, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `sni`（無ければ `null`）, `sni_state`（`ok` / `none` / `fragmented`）, `decision`（`observe` / `pass` / `block`）, `reason`（`sni` / `cname` / `ip` / `ids` / `null`）。開発中は stdout にも同じ行を出す。
- **DNS log**：`<log dir>/dns.jsonl`。1 応答 1行。field は `ts`, `qname`, `chain`（CNAME の配列。順序どおり）, `addrs`, `matched`（blocklist に当たった chain 要素。無ければ `null`）。
- **watch log**：`<log dir>/watch.jsonl`。段階10 の見張りが当てた 1 件 1行。field は `ts`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `sni`（無ければ `null`）, `source`（当てた list の file 名、または `probe`）, `kind`（`blocklist` / `iplist` / `distrust` / `chain`）, `mode`（`watch` / `breaker` / `off`）, `allowlisted`（その flow の SNI が allowlist に当たったか。`true` / `false`）。IP を出す理由と出さない物は次の行（flow log と同じ）に従う。段階10 の option を渡さなければ file を作らない（「段階10 能動防御」節）。
- **service log**：`<log dir>/service.log`。Windows の `service-run` だけが書く。`[info]` / `[warn]` / `[error]` の行を、RFC 3339 の時刻（その機械の local offset 付き。取れなければ UTC の `Z`）、空白、行の順で 1 行ずつ追記する。`[debug]` の行は file に書かない（「Windows サービスの log（PK-120）」）。Linux と、Windows の前景の subcommand は従来どおり stderr に出す。
- **log へ書くものと書かないもの**：認証 cookie、session、password、API key、token、接続文字列、authorization header、メールアドレス、入力本文は出さない。一般の web service の log では IP アドレスも出さないが、packetdeath は通信そのものを観測して遮断する道具なので、IP アドレスは例外として出す。IP は送信元と宛先の両方を出す。出すのは `flows.jsonl` の `src_ip` / `src_port` と `dst_ip` / `dst_port`、`dns.jsonl` の `addrs`（`src/dns.rs:217` の `DnsLogEntry`。CNAME 解決先の IP）である。送信元も要るのは、同じ宛先へ複数の端末や複数の process から出た通信を送信元無しでは区別できず、どれを切ったのかを後から追えないからである。送信元は `src/flow.rs` の `FlowKey` が既に持ち、Linux（`src/linux.rs` の `classify_packet`）、Windows（`src/windows.rs` の `parse_frame`）、proxy（`src/proxy.rs` の `log_flow` を呼ぶ側。`peer` の IP と port）が埋めている。用途は 1 flow 1回の重複排除、Windows で常駐 PowerShell へ送る4つ組（`src/windows.rs` の `build_tcp_row_spec`。「Windows 方式の判断」）、そしてこの log の3つである。`FlowLogEntry` は 10 field とも書く（test `entry_json_keys_match_current_ten_field_contract` が key の集合を、`entry_carries_the_source_of_the_key` が送信元の値を検査する。受入は PK-110）。`src_ip` / `src_port` を持たない古い形式の行が残っている file では、8 key の行と 10 key の行が混ざる。手で読むときは `jq '.src_ip // empty'` の形で引く（これを固定して読む consumer は repo 内に無い。`src/eval.rs` の `FlowRecordView` は `sni` と `decision` だけを読む）。関数名は `grep -n 'fn <名前>'` で引き直す（行番号は書かない）。payload、HTTP header、DNS 応答の本体は従来どおり出さない。出すのは上の2行の field（SNI、送信元、宛先、判定結果）までである。
- **blocklist の形式**：1行1 domain。`#` で始まる行は無視。`example.org` は `example.org` と `*.example.org` に当たる（Suricata の `dotprefix` と同じ意味）。packetdeath 本体（`src/blocklist.rs`）は EasyList の構文を読まない（「公開の検討」の節）。EasyList を食わせるには、利用者が先に `packetdeath filterlist` で blocklist 形式へ変換する（次の「EasyList からの変換」）。
- **allowlist の形式（「当たっても通す」）**：blocklist と同じ1行1 domain・`#` コメント・サフィックス一致（`src/allowlist.rs`）。判定は「① allowlist に当たる → 通す（何があっても通す） → ② blocklist に当たる → 落とす → ③ どちらでもない → 通す」の順で、allowlist は blocklist・CNAME・宛先 IP・IDS・av のどの判定よりも必ず先に効く（`judge::run_judges_with_allowlist`。次の「判定を差し込む口」）。`--allowlist` を渡さなければ空の allowlist（何も救わない）＝従来どおりの挙動。`flows.jsonl` の field は増やさない ── allowlist で通した flow も `decision` は `pass`、`reason` は `null` のままで、当たったことは `[debug]` の log にだけ出す。詳しい節は「allowlist（当たっても通す）」。
- **`blocklists/`**：用途別の blocklist を同梱する置き場。中身は third-party の list を変換したものではなく、実機の実測から選んだ独自の短い host 名の列挙（著作物性の在る創作物ではない）なので、「公開の検討」の「blocklist の中身を repo に1行も入れない」（EasyList・malware list 等 third-party 著作物の話）の対象にしない。第一弾は `blocklists/telemetry-windows.txt`（Windows / Office / MSN の診断データ送信。squid で行っていた遮断を proxy 設定なしで代替する。出所と、Defender / Windows Update / 配信最適化 / Store を止めない理由は `blocklists/README.md`）。独立検証は `tests/independent_telemetry_blocklist.rs` が持つ。
- **`allowlists/`**：公開の allowlist を変換して同梱する置き場。EasyList・malware list とは逆に third-party の著作物を変換したものだが、対象は「壊してはいけない」宛先の列挙（Microsoft 公式 API・Pi-hole 定番 whitelist）であり、出所と取得日時・採用/除外件数は `allowlists/README.md` に書く。独立検証は `tests/independent_allowlist.rs` が持つ。
- **段階8 の置き場**（「段階8 MITM」節が正本）：
  - `ca.crt` と `ca.key`：`--ca-dir` の直下。`ca.crt` は端末へ配る証明書、`ca.key` はその秘密鍵で、権限は `0600`。どちらも repo の外に置く（`.gitignore` は `*.crt` と `*.key` を既に除外している）。
  - **`--mitm-list` の形式**：blocklist と同じ1行1 domain、`#` で始まる行は無視、サフィックス一致。走行中に読み直す。
  - `<log dir>/av.jsonl`：段階8 の proxy が追記する scan の記録。形式は段階6 の `--av` が読む形式と同じ（「段階5 以降と受入 ID の予約」節）。
- **`--ips-sids` の形式**：1行1 `sid`。この file に無い alert では落とさない。file を渡さなければ IDS 由来の遮断は0件になる（段階4の陰性対照）。
- **`--ips-severity` の形式**：1〜3 の整数1つ。`alert.severity` がこの値以下の alert を落とす。
  `--ips-sids` と併用すると、どちらかに当たれば落とす。
  渡さなければ severity では落とさない（PK-36a の陰性対照）。
  1〜3 以外は起動時の引数 error になる。
  `alert.severity` を持たない alert は、severity では落とさない。
- **`sni_state`**：ClientHello が複数 TCP segment に割れても `Reassembler`（`src/reassemble.rs`。判断4）が組み立て直す。組み立ての上限（1接続 16 KiB・同時 4096 接続・寿命 30秒）に当たったときだけ `fragmented` にし、`sni` は `null` にする。段階2は `fragmented` を落とさない（「fail-open」の節）。
- **rule の置き場（Linux）**：段階ごとに利用者が打つ。全行に `--queue-bypass` を付ける。

| 段階 | 打つ rule |
|---|---|
| 1, 2 | `sudo iptables -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1808 --queue-bypass` |
| 1, 2（QUIC の観測） | `sudo iptables -I OUTPUT -p udp --dport 443 -j NFQUEUE --queue-num 1808 --queue-bypass` |
| 3 | `sudo iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1808 --queue-bypass` |
| 4 | `sudo iptables -I OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1808 --queue-bypass`。段階4で落とせる範囲は、rule が queue へ回す範囲に限る。alert の port を queue へ回す rule が無ければ、その alert では落ちない |
| 消す | 上の各行の `-I` を `-D` に変えて同じ引数で打つ。`sudo iptables -S \| grep -c 1808` が `0` |

本番の proxy が同じ host で動いている間に段階2、3 の受入（PK-10、PK-11、PK-20〜PK-22）を打つときは、OUTPUT の rule に `-d <試す host の A>` を足して、その宛先だけを queue へ回す。INPUT の DNS の rule は絞れないので、窓を数分に限る。A は打つ直前に `dig +short` で 1 つに固定し、curl は `--resolve <host>:443:<A>` で同じ IP へ繋ぐ（SNI は host のまま）。PK-22 の host は、CNAME 先が qname の親でない物を選ぶ（親だと blocklist の親 domain 探索で SNI の判定が先に当たり、`cname` の理由が出ない）。PK-10 の期待は `200` ではなく、rule を打つ前に同じ curl で採った status（host によっては `302`）。process を起こした直後は `sleep 1` を置く（bind 前の packet は bypass で素通しになる）。止めるときは `pgrep -f` の一致から `ps -o comm=` が `sudo` か `packetdeath` の pid だけを `kill` する（同じ語を含む自分の shell にも当たる）。

## i18n（log と CLI の文言）

公開するので、log 出力も含めて i18n する。
log の行（stderr と `service.log` へ出す物）の全件と CLI の使い方・エラーメッセージは `LANG` / `LC_ALL` で切り替える（`LC_ALL` を優先。値が `ja` で始まれば日本語、それ以外・空・未設定・未対応の言語は英語が既定。Windows の `GetUserDefaultUILanguage` は呼ばない ── `unsafe` が要るため）。
判定は起動時に1回だけ行い、結果を `[info] locale=ja` / `locale=en` として log へ出す。起動後の log が何語で出ているかを log だけで追えるようにするためである。
実装は `src/i18n.rs`（依存 crate を足さず std だけ。`Locale::Ja` / `Locale::En` の2値 enum と、メッセージ1つにつき専用の関数）。

**`flows.jsonl` / `dns.jsonl` の field 値（`decision` / `reason` / `sni_state` 等）と、log の level tag（`[error]` `[warn]` `[info]` `[debug]`）は機械が読む値であり、翻訳しない**（この file が固定する。上の「名前と置き場」節）。
この節より前の節に書いた log の日本語文言（例：「blocklist を読み直した path=... domains=N（前は M）」）は**設計時点の意図の例示**であり、実際に出る文言は起動時の locale に従う（英語版は `src/i18n.rs` を見よ）。

## EasyList からの変換

EasyList の構文（`||example.com^$third-party` など）は blocklist 本体が読まないので、変換する道具を持つ。
`packetdeath filterlist --in <path> --out <path>`（`--in` / `--out` に `-` を渡すと stdin / stdout を使う）が、EasyList 形式の text を1行ずつ読み、`src/blocklist.rs` の1行1 domain 形式へ変換する（実装は `src/filterlist.rs`）。
この subcommand は file の変換だけを行う。EasyList のダウンロードは行わない（利用者が落とした file を渡す。「制約」の「rule と pktmon は利用者が入れる」と同じ思想）。`--log-dir` を持たず、`flows.jsonl` 等の運用 log とは無関係である。

**SNI 方式で原理的に効かないもの（変換で捨てる）**：TLS を復号しないので、見えるのは宛先の SNI（domain 名）だけである。次の3種は変換時に捨てる。

| 種別 | なぜ効かないか |
|---|---|
| 要素隠し（`##` / `#@#` / `#?#` / `#$#` を含む行） | 通信を止める話ではない。ページ内の要素を隠すもの |
| path 指定（`/` を含む行） | HTTPS では URL が暗号化されている。見えるのは SNI だけ |
| `$` 修飾子の一部（`third-party` / `3p` / `all` / `document` 以外） | `domain=` や Referer が要る条件は TLS の外から見えない |

**変換の規則**（`src/filterlist.rs` の `convert` が実装。判定順は空行・comment → 要素隠し → wildcard/否定 → `@@` 例外 → network rule）：

1. `||example.com^` と `||example.com` → `example.com` を採る。
2. `@@||example.com^`（例外）→ blocklist には出さない。`# except: example.com` の形でコメント行として書き残す。
3. `##` `#@#` `#?#` `#$#` を含む行（要素隠し）→ 捨てる。
4. `$` 修飾子つき → 捨てる。ただし `$` の前が純 domain（`/` を含まない）で、修飾子が `third-party` / `3p` / `all` / `document` の**単独**（カンマ区切りの複合は不可）なら domain として採る。
5. `/` を含む（path 指定）→ 捨てる。
6. `!` で始まる行・空行 → 捨てる。
7. `*` や `~` を含む行 → 捨てる（ワイルドカードと否定は SNI 照合では扱えない）。
8. 出力は重複を除いて domain を sort する。
9. 出力の冒頭に、入力 file 名・行数・種別ごとの採用/除外件数・変換した日時をコメントで書く。

**`@@` の例外の扱い（判断と理由）**：`example.com` を採り、`@@||sub.example.com^` が在る場合、`sub.example.com` を出力に含めなくても `src/blocklist.rs:87-93` のサフィックス一致で `example.com` の行に当たってしまう ── blocklist 形式には「`example.com` を落とすが `sub.example.com` だけは除く」を表す型が無い。
**`sub.example.com` を出さないのではなく、`example.com` の方を出力から落とす。**理由は2つ。1つは、blocklist 形式の表現力の限界（上記）。もう1つは `docs/design.md`「制約」の「判定できない flow は通す」「遮断できないときは素通しに倒す」という既定方針で、EasyList の作者が明示的に許可した通信を誤って遮断し続けるより、広告1件を見逃す方を選ぶ。落とした domain は出力に書かず、`Stats::dropped_by_exception` の件数にだけ残す。「例外を別 file にする」は採らない ── `Blocklist::load` は1 file を1行1 domain として読むだけで、否定（サブドメインだけ除く）を表現する仕組みを持たないため、別 file にしても packetdeath 側では合成できない。

## allowlist（当たっても通す）

allowlist は、遮断すると利用者の機能が壊れる宛先（OneDrive、ブラウザの同期など）を、blocklist から外して通すための仕組みである。

`--allowlist <path>` が `block` / `service-install` / `service-run` に生える（1行1 domain・`#` コメント・サフィックス一致。`src/allowlist.rs`）。判定は次の順で、allowlist が blocklist より必ず先に効く。

1. allowlist に当たる → 通す（何があっても通す。blocklist・CNAME・宛先 IP・IDS・av のどれに当たっていても関係ない）
2. blocklist に当たる → 落とす
3. どちらでもない → 通す

`--allowlist` を渡さなければ空の allowlist（何も救わない）＝従来どおりの挙動。`flows.jsonl` の field は増やさない（`decision` は `pass`、`reason` は `null` のまま）。allowlist で救ったことは `[debug]` の log に出す。

**Microsoft 公式 API・平文1行1domain・Adblock Plus の `@@` 形式の3種類を変換できる**：`packetdeath allowlist-convert --in <path> --out <path>`（`src/filterlist.rs` の `convert_allowlist` / `detect_allow_source` が実装。network へは出ない。file の変換だけ）。

| 形式 | 中身 | 変換 |
|---|---|---|
| Microsoft 公式 API の JSON | `[{"urls":["*.auth.microsoft.com", ...]}, ...]` | `urls` を集めて `*.` を剥がす |
| 平文 1行1 domain | `1drv.com` | そのまま（`#` コメントは無視） |
| Adblock Plus の allow rule | `@@||example.com^` | `example.com` を取り出す（`filterlist.convert` の EasyList→blocklist 変換とは意味が逆 ── ここでは `@@` の中身こそが採用対象） |

**`*` が先頭以外に在るもの（`foo.*.example.com` や `*cdn.example.com` のように `*.` の形でない先頭ワイルドカード）は捨てる。**`Allowlist::matches` はサフィックス一致しか表現できないため。捨てた件数は出力の冒頭コメントに残す。

**変換した結果は `allowlists/` に置く**（出所・取得日時・採用/除外件数は `allowlists/README.md`）。独立検証は `tests/independent_allowlist.rs` が持つ。

### blocklist / allowlist の走行中の読み直し（続きを頼む節）

`--blocklist` / `--allowlist` の path は、起動時の1回だけでなく、`--pcapng` の poll（`PCAPNG_POLL_INTERVAL` = 300 ms、`src/win_service.rs:76`）と**同じ loop の中**で監視し、file が書き換わったら読み直す（`src/reload.rs`。`block_loop::WatchInputs` が経路を持つ）。運用中に人が書き換える list は、再起動なしで反映する。反映に `install.ps1` の打ち直し（管理者権限）は要らない。

**検知は `mtime` と `len` の組（指紋）。**file 全体の hash も候補だったが（47,677 行で 26 ms。`実測`。file を丸ごと読む必要が在る）、`metadata()` だけで済む方が安く、pcapng の再読み込み要否を `len()` で判定しているのと同じ発想を踏襲できる。

**書き換え途中を読む危険は、読み込みの直前と直後の両方で指紋を取り、一致したときだけ採用することで塞ぐ。**一致しなければ書き込み側がまだ書いている最中に読んだ可能性が在るので、その poll では諦めて次の poll で改めて確かめる（state は更新せず、log も出さない ── 継続的な書き込みのたびに warn が出ると溢れるため）。

**読み直しに失敗しても落ちない。**file 消失・IO error・不正 UTF-8 のどれでも、前の blocklist / allowlist を使い続ける（fail-open。`docs/design.md`「制約」の「判定できない flow は通す」と同じ思想）。読み直したときだけ `[info]` で「blocklist を読み直した path=... entries=N（前は M）」を出す（iplist も同じ形。N と M は domain 数か IP/CIDR 数）。失敗したときは `[warn]`。**変化が無い poll では log を出さない**（300 ms ごとに出すと溢れるため）。

`--pcapng` を渡さない経路（Linux の nfqueue 本経路）も対象である。`linux.rs::run_block` が `block_loop::WatchInputs` を `&mut` で受け取り、同じ間隔（300 ms）で `poll_reloads` を呼んで blocklist / allowlist を読み直す。`flows.jsonl` の field は増やさない。独立検証は `tests/independent_reload.rs` が持つ。

`--allowlist` は `block` の全経路（`--pcapng` 前景経路・Windows サービス・Linux の nfqueue 本経路）で効く。判定は `judge::run_judges_with_allowlist` が行い、allowlist が blocklist・CNAME・IDS・IP・av のどれよりも先に効く（「判定を差し込む口」節）。

### flow の集合の上限（PK-119）

`linux.rs::run` と `run_block` が持つ「1 flow 1 行」の集合（`seen`）と「一度 block した flow」の集合（`blocked`）は、process が生きている間 flow の数だけ育つ。上限は寿命で置く（個数の上限ではない。個数は到着率 × 寿命まで育つ）。集合は `FlowKey` から「最後に payload の在る packet を見た時刻」への map にし、lookup は「見つけたら時刻を更新する」`touch` だけを持つ（`contains` を持たない。Drop の経路で更新を書き忘れる形を書けなくするため）。`EXPIRE_CHECK_INTERVAL`（1 秒）の確認のときに `sweep` で、最後の packet から `FLOW_SET_IDLE_TTL`（600 秒）を超えた flow を落とし、落とした数が 0 より大きいときだけ `[debug]` を 1 行 出す（1 秒に 1 行が上限）。値の根拠：reassembler の `FLOW_TTL`（30 秒。handshake の途中の flow の寿命）より長く、TCP の keepalive の既定（7200 秒）より短く、Linux の data の再送間隔の上限（RTO 120 秒）より長い。「idle」は payload の在る packet が来ないことで、ACK だけの packet は `inspect_ip_packet` が `None` に落とすので数えない。

採らない手段：集合の大きさに固定の上限を置いて満杯で `clear` する（block した flow を忘れると後続の packet が通る。reassembler が個数の上限を持てるのは、捨てても組み立て直すだけで済むから）。LRU の crate を足す（map と時刻で足りる）。`cname_matched_qnames` に同じ TTL を置く（CNAME の行き先が blocklist に当たった応答の qname の集合で、qname の種類の数だけ育つ。本件の対象外。「残る穴」）。

忘れたときの影響。block した flow：ClientHello の data segment を落とされた client は、Linux なら `tcp_retries2`（既定 15）まで約 15 分 再送し、間隔は RTO の上限 120 秒を超えないので、再送のたびに時刻が更新され、諦めた後に落ちる（3-way handshake の packet は payload が無いので通り、落とすのは data だけ）。再送の間隔が 600 秒を超える client が在れば、複数 segment の ClientHello の末尾が新しい flow として `feed` に入り、`NotHandshakeRecord` で `None` になって通る（「残る穴」）。通した flow：600 秒 payload を出さずに再開した flow は `seen` から落ちているので log が 1 行 増え、`run_block` では `SniState::None` で判定が走り直す。allowlist は SNI にしか効かないので、allowlist で通した接続でも IP・IDS・av に当たれば切れる（「allowlist が先に効く」が再開した flow には成り立たない）。client が ACK しか出さない長い download は idle と数えられ、この経路に入る。block の経路は本番に配備しておらず、process の restart でも同じことが起きるので、許容して「残る穴」に書く。

### Windows サービスの log（PK-120）

Windows の `service-run` は SCM が起動する process なので stderr の先が無く、`[info]` / `[warn]` / `[error]` / `[debug]` の行（blocklist と allowlist の読み直し、pcapng の切れ、常駐 PowerShell の spawn の失敗、遮断の結果）はどこにも残らない。これらの行の書き先を 1 つの sink（`flow::ServiceLog`）にまとめ、既定は stderr のまま、`service-run` だけが起動の最初（dispatcher を呼ぶ前）に `<log dir>/service.log` へ向け直す。向け直しは process に 1 回で、`OnceLock` に積む（`win_service.rs` の `SERVICE_CONFIG` と同じ構え。向け直さない process では sink は stderr と同じ振る舞いなので、Linux の出力は 1 行も変わらない）。

行の形は `<RFC 3339> packetdeath: [level] message` で、時刻はその機械の local offset 付き（`2026-10-04T12:34:56.789+09:00` の形。人が画面の時計と同じ時刻で読めるようにする。`flows.jsonl` の `ts` は UTC なので、突合は offset を含めた RFC 3339 として比べる）。offset は `service-run` が sink を開くときに 1 回だけ取って `ServiceLog::open` に渡し（`Option<UtcOffset>`。sink は受け取った offset で時刻を直すだけで、自分では取らない。Linux の unit で `+09:00` の形も `Z` の形も測れるようにするため）、取れなければ UTC（`Z`）で書き、そのことを `[warn]` 1 行（i18n `service_log_utc_fallback`）で file に出す。Windows 以外（Linux の test）では offset を取らず UTC で書く（`time` の `local-offset` feature は Windows の target にだけ足し、Linux の本番 binary には入れない）。

file に書くのは `[info]` / `[warn]` / `[error]` だけで、`[debug]` の行は向け直した後は捨てる（stderr の既定の経路では従来どおり出す）。`[debug]` は 1 flow 1 行では抑えられないからである。`extract_sni` の `sni_absent` は、`process_pcapng_snapshot` が処理済みの flow を除く前に `inspect_captured_frame` が `feed` を呼ぶので、上り方向の payload の在る packet 1 つにつき、snapshot を読み直すたびに 1 行 出る（行数は packet 数 × 読み直しの回数）。rotation の無い file へその速さで書くわけにはいかない。`[info]` / `[warn]` / `[error]` の多くは出来事（読み直し、open の失敗、spawn の失敗）ごとに出るが、`feed` の中で出る `[warn]`（`reassemble_buffer_overflow`、`reassemble_flow_limit_reached`）は読み直しのたびに履歴の flow の分だけ出るので、pcapng が大きいまま読み直されると育ち、snapshot ごとの `pcapng_truncated` は読み直し 1 回に 1 行 出る（読み直しは pcapng の長さが変わった poll だけなので、止まった壊れ file では 1 行で止まる）（「残る穴」。受入で bytes/分 を pcapng の大きさと並べて記録する）。stderr へ出すときは時刻を付けない（Linux では journald が付ける）。file は append で開き、1 行を 1 回の `write_all` で書く（`File` は buffer を持たないので flush は要らない。1 回で書くのは、他の書き手と行が混ざらないようにするため）。開けないときは stderr に `[warn]` を 1 行 出してそのまま走る（log が無いことでサービスを止めない。fail-open）。書けないときはその行を stderr へ落とし、次の行は再び file へ書く（disk の一時的な満杯で以後の行を全部 失わないため。mutex が poison していても `into_inner` で中身を取って書き続ける）。`<log dir>` は作らない（`flows.jsonl` と同じ。dir が無ければ開けず `[warn]` になる。typo の dir を SYSTEM が黙って作らないため）。

対象は、`service-run` の経路が通る 10 module（`win_service`、`block_loop`、`ps_bridge`、`reload`、`reassemble`、`blocklist`、`allowlist`、`windows`、`judge`、`sni`）の `eprintln!` 26 箇所と、`main.rs` の Windows 版 `run_service_run` の dispatcher 失敗の 1 箇所で、全部を `flow::service_log` へ置き換える。stderr のまま残すのは、`flow.rs` の fallback 2 箇所、`main.rs` の CLI（parse error、`locale=` の `[info]`、`observe` / `block` / `proxy` の経路）、`linux.rs`、`proxy.rs`、`mitm.rs`（Linux 専用）、`eval.rs`、`filterlist.rs`（CLI 専用）、`av.rs`、`iplist.rs`、`ids.rs`（`service-run` は空の集合で走り、これらの読み手を呼ばない）、`i18n.rs`（`locale=` の行）である。これら以外の file に `eprintln!` が無いことを受入で数える。`locale=` の `[info]` は dispatcher の前に出るので `service.log` には入らず、locale は後続の行の言語で読む。

採らない手段：stderr の fd を差し替える（`SetStdHandle` / `dup2` は unsafe の FFI）。worker を子 process にして `Command::stderr(File)` で受ける（常駐 PowerShell が孫 process になり、親の kill で残る。停止が 2 段になる）。Windows Event Log（source の登録に registry と unsafe が要り、file より読みにくい）。`log` / `tracing` の crate（sink が 1 つで足りる）。sink を引数で貫通させる（`Reassembler::feed`、`Blocklist::load`、`reload` の signature が変わり、`linux.rs` にも波及する）。`[debug]` を file へ書く（上の段落。packet 数 × 読み直しの回数で育つ）。`[debug]` を出す側で抑える（`sni.rs` と `judge.rs` は Linux の nfqueue の経路でも使われ、そちらの出力を変えることになる）。rotation（flows.jsonl にも無い。「残る穴」）。起動時に生存だけを示す `[info]` を 1 行 足す（既存の読み直しの行で locale と生存が見える。常駐 PowerShell の温めの `[info]` は出来事の記録であり、これに当たらない）。

### 常駐 PowerShell の温め（PK-121）

常駐 PowerShell（`ps_bridge.rs` の `PsBridge`）は spawn の直後に `powershell.exe` の起動と `kill_tcp.ps1` 冒頭の `Add-Type` を済ませるまで応答できず、その長さは起動を含めて 600 ms 台である（「Windows 方式の判断」の実測）。一方、1 行の応答を待つ上限 `RESPONSE_TIMEOUT` は 500 ms で、これは温まった後の 27〜32 マイクロ秒に対する余裕として決めた値である。spawn 直後の 1 行目をこの上限で待つと、1 行目は必ず timeout になり、bridge は poisoned として捨てられ、次の呼び出しがまた spawn して同じ 1 行目で timeout する。`RespawningPsBridge`（`block_loop.rs`）は遅延 spawn なので、この形では遮断が 1 件も成立しない。

spawn と最初の行の間に温めの段を置く。`PsBridge::warm_up(timeout)` は `0,0,0,0` の 1 行（該当する接続が無い 4 つ組）を送り、`STARTUP_TIMEOUT`（5 秒）を上限に応答を待つ。応答が形として読めれば温まったとみなし、以後の行は `RESPONSE_TIMEOUT` のままで送る。`rc` の値は合否に使わず、温めの `[info]`（i18n `ps_bridge_warmed`。かかった ms と `rc` を含む）に出して実機で読む（SYSTEM で走るサービスでは `rc=317`「該当する接続が無い」、非昇格の user では `rc=87`「引数が不正」が返る。どちらも形として読める応答で、権限や P/Invoke の欠陥はこの `rc` で見つける）。温めが timeout か I/O の失敗なら、その bridge は捨てて `[error]`（i18n `ps_bridge_warm_up_failed`、timeout の長さを含む）を 1 行 出し、その packet は fail-open で通す。温めの行は spawn 1 回につき 1 行で、flow の数に比例しない。

`RespawningPsBridge::ensure_bridge` は spawn の直後に `warm_up` を呼び、温まった bridge だけを `Some` で返す。温めは loop の起動時にも 1 回 打つ（`RespawningPsBridge::prepare`。`RespawningPsBridge::new` を呼んでいる既存の箇所の直後で呼ぶ）。これで最初の広告の接続が起動の時間を払わない。起動時の温めが失敗しても loop は始める。

温めが失敗した後は `WARM_UP_BACKOFF`（60 秒）の間は spawn せず、`try_block` は即 `false` を返す（fail-open）。これが無いと、温めが毎回 失敗する機械では広告の flow 1 本ごとに spawn と 5 秒の待ちが起き、`process_pcapng_snapshot` は 1 snapshot を同期で処理するので、サービスの停止も遅れる。backoff の間は log を出さない（失敗の `[error]` が 60 秒に 1 行で、flow の数に比例しない）。

`STARTUP_TIMEOUT` を 5 秒にするのは、1 行目の応答までの実測（利用者の PC で 483〜539 ms、Windows 11 の host で起動を含めて 632 ms）に antivirus が `powershell.exe` の起動を検査する時間の揺れを乗せても収まり、かつ spawn が本当に hang したときの遅れを spawn 1 回あたり 5 秒に抑えるためである。温まった後の行の上限は変えない。

test が配線まで捕まえるように、`RespawningPsBridge` は spawn の口を差し替えられる形にする（`RespawningPsBridge::with_spawner(script_path, spawner, startup_timeout, backoff)`。`spawner` は `fn(&Path) -> io::Result<PsBridge>` で、`new` は `PsBridge::spawn_powershell` と `STARTUP_TIMEOUT`、`WARM_UP_BACKOFF` を渡す）。Linux の unit は `sh -c` の偽の子を spawner に渡し、`try_block` 越しに温めと backoff を測る。

受入 PK-121 は、unit（`ps_bridge.rs` の 3 本、`block_loop.rs` の 2 本、i18n の 2 本）、cross build、実機（利用者の PC。`install.ps1` の後に `service.log` に温めの `[info]` が在り `rc` が読める。blocklist に当たる host へ TLS の接続を張ったまま 12 秒 保持し、その間に `@(Get-NetTCPConnection -LocalPort <port> -State Established).Count` が 1 から 0 になり（`@()` で包む。空の結果の `.Count` は何も出さない）、保持した stream への書き込みが失敗し、`flows.jsonl` に `"decision":"block"` と `"reason":"sni"` が出る。`[warn]` の「500ms 以内に来なかった」が install の後に増えない）で受ける。短い `curl` では測れない（pcapng の rotate が 4 秒、poll が 300 ms なので、0.1 秒で終わる接続は切る前に終わる）。PW-7 はこの形で打つ。

採らない手段：`RESPONSE_TIMEOUT` を 5 秒に伸ばす（hang した bridge が接続ごとに 5 秒 止める。温めの上限と行の上限は別の値である）。`Add-Type` を script の最初の行の処理の中へ遅らせる（同じ時間が 1 行目に移るだけ）。script が `READY` の行を先に出す（protocol が増える。`0,0,0,0` の行がそのまま probe になる）。行ごとに `powershell.exe` を起こす（1 回 200 ms。「Windows 方式の判断」）。`SetTcpEntry` を Rust から呼ぶ（unsafe）。spawn を loop の起動時だけにして再 spawn をやめる（hang から戻れない）。失敗のたびに即 再 spawn する（flow 1 本ごとに 5 秒 待つ）。短い `curl` で実機の受入を測る（切る前に接続が終わる）。

### 遮断の結果の見せ方（PK-122）

`try_block` は、常駐 PowerShell が応答した事実ではなく、`SetTcpEntry` の戻り値 `rc` で成否を返す。`rc=0` のときだけ `true`（切れた）を返し、`[debug]` に `rc` と所要時間を残す。`rc≠0` のときは `false` を返し、`[warn]`（i18n `tcp_cut_rejected`。`rc` と所要時間を含む）を `service.log` に 1 行 書く。`judge_and_log` は変えない。`false` が返れば `decision` は `pass`、`reason` は `null` になる（「`decision` は実際に何が起きたかを書く」の契約どおり）。

これが要るのは、`SetTcpEntry` が接続を切らずに返す場合（権限が無い、4 つ組が一致しない、API が受け付けない）に、`flows.jsonl` の `block` と `service.log` のどちらにも痕跡が残らないからである。`rc` は `[debug]` にしか出ず、`service.log` は `[info]` / `[warn]` / `[error]` だけを書くので、実機では「`block` と書いてあるのに接続が生きている」状態を log から見つけられない。

`[warn]` は `rc≠0` が返った flow 1 本につき 1 行で、まとめない。`[warn]` の数が「`SetTcpEntry` が切らなかった接続の数」であり、その数で見つける。backoff の間、bridge が Poisoned のとき、`send_tcp_row` が `Err`（Timeout、Io、Parse。`[error]` の `tcp_block_failed` に出る）のとき、IPv6 と UDP の flow、`NoopBlocker` は `[warn]` を書かずに `pass` になるので、この数には入らない。`[warn]` の文は ja「SetTcpEntry が接続を切らなかった rc=<n> us=<f>。素通しに倒す」、en「SetTcpEntry did not cut the connection rc=<n> us=<f>; falling through (fail-open)」で、実機の数はこの文の語（「切らなかった」/ `did not cut`）で採る（`500ms` や `pcapng` の `[warn]`、温めの `[info] rc=` と混ざらない）。`[warn]` に flow の識別は無く、直後の `flows.jsonl` の行と時刻と順序で対応づける。

`rc=317`（該当する接続が無い）も `rc≠0` として扱う。接続が切れる前に終わった短い接続と、4 つ組の変換の誤りが同じ `317` を返すので、`block` に数えると変換の誤りが隠れる。

既存の unit の偽の子（`respawning_bridge_warms_a_slow_child_before_the_first_row` など）は行に `rc=317` を返しているので、行には `rc=0` を返す形に直す（温めの応答の `rc` は合否に使わないので、温めの偽の子は変えない）。

受入 PK-122 は、unit（`block_loop.rs` の 2 本、i18n の 1 本）、integration（`tests/independent_cut_result.rs` の 1 本。別 binary で `service.log` の sink を file に向け、`rc=0` の行の後に「切らなかった」の行が 0、`rc=317` の行の後に 1 で `rc=317` が入ることを数える。unit からは process 全体の sink を読めないので、level と置き場所はこの 1 本で固定する）、`judge_and_log` の既存の test（`pi1_blocklisted_sni_calls_try_block_once_and_logs_block` と `pi2_bridge_err_does_not_stop_processing_of_next_packet`。`try_block` が `false` なら `pass`）、配線（本番 code に literal `317` が無い。`rc=317` を成功側に書くとここで落ちる）、cross build、実機（利用者の PC。PW-7 の形で打ち、「切らなかった」の行の数を前後で採る。接続が切れなければ 1 行 増えて `flows.jsonl` は `pass`。切れれば増えず `block`。`rc=0` なのに接続が生きる形は実機でしか測れない）で受ける。

採らない手段：`rc=317` を成功に数える（変換の誤りが隠れる）。`[warn]` をまとめる・間引く（数が指標である）。`rc≠0` の行を送り直す（`SetTcpEntry` の失敗は一時的でない）。`kill_tcp.ps1` を書き換える（`rc` はもう返している）。`judge_and_log` に `rc` を渡す（`try_block` の `bool` の契約で足りる）。

## 段階

前の段階の受入 ID が通るまで、次へ行かない。
段階1は Linux で先に作る。同じ判定 code へ pktmon（pcapng を読むガワ）を足して Windows へ持って行く。
Linux の段階は Linux の受入 ID だけで進む。Windows の段階は追加 driver を入れないので、driver 導入の GO は要らない。
常駐 PowerShell 経由で実際に接続を切る PW-7 は、PK-121（常駐 PowerShell の温め）と同じ窓で打つ。

| 段階 | 何ができたら次へ行くか | 受入 ID |
|---|---|---|
| **1. 観測（Linux）** | SNI を取り出して log に出す。遮断は0件 | PK-0, PK-1, PK-2, PK-3, PK-4, PK-5, PK-110（送信元の field） |
| **1w. 観測（Windows）** | 同じ code が Windows で build でき、pktmon が作った pcapng から SNI を log に出す。QUIC の flow 数を記録する | PK-6, PK-7, PW-0〜PW-8 |
| **2. 遮断** | blocklist に当たる SNI を落とし、それ以外を通す。遮断率と誤遮断率を測る | PK-10, PK-11, PK-12, PK-13 |
| **3. CNAME チェーン解決** | DNS 応答を見て、CNAME 先が blocklist に当たる flow を落とす | PK-20, PK-21, PK-22 |
| **4. IPS 化** | Suricata の `eve.json` の alert を読み、指定 sid の 5-tuple を落とす。`--ips-severity` を渡せば、severity が指定値以下の alert の 5-tuple も落とす | PK-30, PK-31, PK-32, PK-36 |

段階3で first-party 配信（server-side tagging）に当たる材料は、いまの資料に無い（`実読` SoK、`docs/research/prior-art.md:36, :80`）。
ML 判定（AdVersa 系）は段階4の後に別設計とする。

## 受入 ID

command は Linux（WSL）を前提に書く。Windows 側は PK-6, PK-7 と「Windows 側の受入 ID（PW-*）」の節で打つ。
先に `LOGDIR=$PWD/pdlog; mkdir -p "$LOGDIR"` と打ち、`packetdeath` の起動には毎回 `--log-dir "$LOGDIR"` を渡す。表では省く。
`<log>` は `$LOGDIR/flows.jsonl` に置き換える。
`wc -l < <log>` を打つ前の値を `N0` と書く。file が無ければ `N0` は `0` である。

PK-0 から PK-2 は陰性対照である。先に打ち、期待どおりの結果になることを確かめてから PK-3 以降へ進む。
PK-0 が通らないなら、以降の log の増分は成果ではない。

| ID | 受入条件 | 打つ command | 通ったと判る出力 |
|---|---|---|---|
| **PK-0** | **陰性対照**。rule 無し、packetdeath 未起動で log が増えない | `sudo iptables -S \| grep -c 1808; pgrep -xc packetdeath; wc -l < <log>; curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/; wc -l < <log>` | `0`、`0`、`N0`、`200`、`N0` |
| **PK-1** | **陰性対照**。`--queue-bypass` 付きの rule だけ在り、packetdeath 未起動でも通信が通る | 段階1の rule（tcp 443）を打った後に `curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' https://example.com/; echo "exit=$?"; wc -l < <log>` | `200`、`exit=0`、`N0` |
| **PK-2** | **罠が実在することの確認**。`--queue-bypass` 無しの rule は、packetdeath 未起動で通信を止める | PK-1 の rule を `-D` で消し、`--queue-bypass` を外した同じ rule を `-I` で打ち、`curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' https://example.com/; echo "exit=$?"`、直後にその rule を `-D` で消し、`--queue-bypass` 付きを打ち直す | `000` と `exit=28`。消した後は PK-1 と同じ |
| **PK-3** | SNI を1 flow 1行で log に出す。遮断は0件 | `sudo packetdeath observe &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/; tail -1 <log>; grep -c '"decision":"block"' <log>` | `200`、`"sni":"example.com"` と `"sni_state":"ok"` と `"decision":"observe"` を含む1行、`0` |
| **PK-4** | packetdeath を殺しても通信が通る（fail-open） | `sudo pkill -x packetdeath; sleep 1; curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' https://example.com/; echo "exit=$?"` | `200`、`exit=0` |
| **PK-5** | ClientHello が複数 segment に割れても落とさず、組み立て直して SNI を記録する | `sudo iptables -t mangle -I OUTPUT -p tcp --dport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 200` の後に PK-3 の curl と `tail -1 <log>`、直後に同じ rule を `-D` で消す | `200`、`"sni":"example.com"` と `"sni_state":"ok"` と `"decision":"observe"` を含む1行 |
| **PK-6** | Windows 向けに cross-build できる | `cargo build --release --target x86_64-pc-windows-gnu && file target/x86_64-pc-windows-gnu/release/packetdeath.exe` | `PE32+ executable` を含む1行。実機で pcapng から SNI を出すのは PW-6 |
| **PK-7** | UDP 443（QUIC）の flow を数えて記録する。遮断しない | 段階1の udp 443 rule を足し、Windows の Chrome で任意の page を1つ開いた後に `grep '"proto":"udp"' <log> \| grep -c '"dst_port":443'`（Linux で測るときは `curl --http3` が使える curl が要る。無ければ Windows 側で PK-6 と一緒に測る） | 件数を記録する。gate にしない。`grep -c '"decision":"block"' <log>` は `0` |
| **PK-10** | **陰性対照**。`--blocklist` 無しでは1件も落ちない | `sudo packetdeath block &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' https://example.org/; grep -c '"decision":"block"' <log>` | `200`、`0` |
| **PK-11** | blocklist に当たる SNI を落とし、当たらない SNI を通す | `printf 'example.org\n' > bl.txt; sudo packetdeath block --blocklist bl.txt &` の後に `curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' https://example.org/; echo "exit=$?"; curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/; tail -2 <log>` | `000` と `exit=28`、`200`、log の1行が `"sni":"example.org"` と `"decision":"block"` と `"reason":"sni"`、もう1行が `"sni":"example.com"` と `"decision":"pass"` |
| **PK-12** | 組み立て不能（1接続 16 KiB 超・寿命 30 秒 内に揃わない）の ClientHello は `fragmented` として落とさない。curl 1本では作れないので `cargo test` の名指しで受ける | `cargo test -- judge::tests::sni_judge_does_not_match_fragmented_state judge::tests::run_judges_with_allowlist_falls_through_when_sni_has_no_host reassemble::tests::gives_up_when_buffer_exceeds_capacity reassemble::tests::expire_stale_returns_flow_after_ttl_and_forgets_it linux::tests::two_segments_inspected_from_raw_frames_reassemble_into_sni` | 5本とも `ok`（前2本が「`fragmented` を判定材料にしない」、後3本が「諦める条件と組み立て」） |
| **PK-13** | 遮断率と誤遮断率を出す command が在る | `packetdeath eval --labels labels.tsv`（tsv は `host<TAB>ad` か `host<TAB>ok` の行。`flows.jsonl` と突き合わせる） | `ad total=<N> blocked=<B> block_rate=<B/N>` と `ok total=<M> blocked=<F> false_block_rate=<F/M>` の2行。ラベル無し行があれば `skipped=<K>` を3行目に出す |
| **PK-110** | `flows.jsonl` の1行に `src_ip` と `src_port` が出て、proxy 経路では proxy へ繋いだ client の peer と一致する（値まで見る。key の集合だけでは `src_ip: key.dst_ip` の取り違えを捕まえない） | `packetdeath proxy --listen 127.0.0.1:8899 --log-dir "$LOG" &` の後に `curl -sS --local-port 45678 -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.com/; tail -1 "$LOG/flows.jsonl" \| jq -r '[.src_ip, .src_port] \| @tsv'`。unit は `cargo test -- flow::tests::entry_carries_the_source_of_the_key flow::tests::entry_json_keys_match_current_ten_field_contract` | `200` の次の行が `127.0.0.1<TAB>45678`（`--local-port` で固定した client の port と同じ）。unit は `test result: ok. 2 passed` |
| **PK-20** | **陰性対照**。`--dns` 無しでは `dns.jsonl` が増えない | 段階3の rule を打ち、`sudo packetdeath block --blocklist bl.txt &` の後に `wc -l < $LOGDIR/dns.jsonl; dig +short example.com >/dev/null; wc -l < $LOGDIR/dns.jsonl` | 2つの値が同じ |
| **PK-21** | CNAME チェーンを1 応答 1行で記録する | `sudo packetdeath block --dns --blocklist bl.txt &` の後に、`dig +noall +answer <host> \| grep -c CNAME` が `1` 以上になる `<host>` を1つ選び、`dig +short <host> >/dev/null; tail -1 $LOGDIR/dns.jsonl` | `"qname":"<host>"` と、`dig` が出した CNAME 先を同じ順で並べた `"chain":[...]` を含む1行 |
| **PK-22** | CNAME 先が blocklist に当たる flow を落とす | PK-21 の `<host>` の CNAME 先（最後の要素）を `bl.txt` に足し、`sudo packetdeath block --dns --blocklist bl.txt &` の後に `curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' https://<host>/; echo "exit=$?"; tail -1 <log>` | `000` と `exit=28`、log が `"sni":"<host>"` と `"decision":"block"` と `"reason":"cname"` |
| **PK-30** | **陰性対照**。`--ips-sids` 無しでは Suricata が alert を出しても落とさない | 段階4の rule（tcp 80）を打ち、Suricata を IDS モードで起動し、`sudo packetdeath block --eve <eve.json> &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' http://testmynids.org/uid/index.html; sleep 2; grep -c '"signature_id":2100498' <eve.json>; grep -c '"reason":"ids"' <log>` | `200`、`1` 以上、`0` |
| **PK-31** | 指定 sid の alert で、以後の同じ宛先を落とす | `printf '2100498\n' > sids.txt; sudo packetdeath block --eve <eve.json> --ips-sids sids.txt &` の後に PK-30 の curl を2回 打つ（間に `sleep 2`）。2回目は `--max-time 5` と `; echo "exit=$?"` を足す | 1回目 `200`。2回目 `000` と `exit=28`。`tail -1 <log>` が `"decision":"block"` と `"reason":"ids"` |
| **PK-32** | drop 集合が `--ips-ttl` で消える | PK-31 の後に `--ips-ttl 5` で起動し直し、PK-31 を繰り返し、`sleep 6` の後に3回目の curl | 3回目が `200` |
| **PK-36a** | `--ips-severity` の判定。severity 1 の alert は `--ips-severity 1` で落とす集合に入り、severity 2 は入らない。`--ips-severity` 無しでは severity 1 でも入らない（陰性対照） | `cargo test --release --lib -- ids::tests::ips_rule` | 4本とも `ok`。名前は `ips_rule_drops_severity_at_or_below_the_limit`, `ips_rule_without_severity_limit_drops_no_severity_1_alert`, `ips_rule_never_drops_an_alert_without_severity_by_severity`, `ips_rule_drops_on_either_listed_sid_or_severity` |
| **PK-36b** | 引数の読み。`--ips-severity` は 1〜3 だけを受け、無ければ `None` | `cargo test --release --bin packetdeath -- ips_severity` | 4本が `ok`（`parses_block_args_ips_severity`, `block_args_without_ips_severity_do_not_drop_by_severity`, `rejects_ips_severity_outside_one_to_three`, `ips_severity_without_a_value_is_missing_value`）。`cargo test` と `cargo clippy --all-targets` の warning は0 |
| **PK-36c** | 本番で通信が壊れない | `--ips-severity 1` を付けた unit を再起動した後に `curl -sS -o /dev/null -m 8 -w '%{http_code}\n' https://api.anthropic.com/; curl -sS -o /dev/null -m 8 -w '%{http_code}\n' http://example.com/; getent hosts github.com` | 再起動の前に採った値と同じ（`404`、`200`、アドレス1行以上） |
| **PK-36d** | unit が起動し、起動の行に severity の値が出る | `systemctl is-active packetdeath-block packetdeath-proxy suricata; sudo journalctl -u packetdeath-block -n 5 --no-pager \| grep -c 'ips_severity=Some(1)'` | `active` が3行、`1` 以上 |
| **PK-40** | 公開前の gate | 「公開の検討」の節の「公開前に打つ command」 | 全行が節に書いた出力 |

PK-30 の `testmynids.org` と sid `2100498` は `記憶` である（ET Open の `GPL ATTACK_RESPONSE id check returned root`）。
初めて打つときに `eve.json` で sid を確かめ、違えばこの表を直す。

テスト担当は、実装した本人以外が務める。
command を実際に打てる者が務める。

### Windows 側の受入 ID（PW-*）

PW-0 から PW-5 は管理者権限の Windows 端末で打つ。
値の行には測った command を併記する。PW-2 と PW-3 の pktmon の filter は「名前と置き場」の「pktmon の filter」の command を使う。
PW-6 と PW-8 は実機の受入で、まだ実施していない（下の「未実施」）。PW-7 は実施済みで不通過（常駐 PowerShell は 500 ms 以内に答え `flows.jsonl` に `block` が付くが、接続は 12 秒 後も生きて write が通る。`SetTcpEntry` の rc は `[debug]` で `service.log` に出ないため未読。管理者で rc を読む probe の結果で、行の形の問題か権限か API の問題かを分ける）。

| ID | 受入条件 | 打つ command | 通ったと判る出力 |
|---|---|---|---|
| **PW-0** | pktmon.exe が Microsoft 署名である | `Get-AuthenticodeSignature C:\Windows\System32\pktmon.exe` | `Status : Valid`、`Signer : CN=Microsoft Windows, O=Microsoft Corporation, ..., C=US` |
| **PW-1** | **陰性対照**。「採らない手段」の表の driver（Npcap を含む）が未導入である | `sc.exe query npcap`、および「採らない手段」の表の driver の service 名を `sc.exe query <名>` で問う | いずれも `FAILED 1060`（未導入） |
| **PW-2** | pktmon が `--comp nics` で ClientHello を含む未加工パケットを捕獲する | 「pktmon の filter」の filter add / start を打ち、`curl.exe -sS --no-keepalive -o NUL -w '%{http_code}' https://example.com/`、`pktmon stop`、捕獲 file の byte 数を数える | curl が `200`、stop が「イベントは失われていません」、file が約 3.8 MB（3819828 bytes） |
| **PW-3** | 捕獲した file に SNI が平文で、ClientHello が記録される | `grep -c -a 'example\.com' <path>` と `grep -c -a -P '\x16\x03\x01' <path>` | 前者 `1`（SNI が平文）、後者 `1`（ClientHello） |
| **PW-4** | `SetTcpEntry` で確立済みの IPv4 TCP 接続が切れる（常駐 PowerShell が呼ぶのと同じ API） | 管理者権限で、`MIB_TCPROW` の `dwState` に `12`（`MIB_TCP_STATE_DELETE_TCB`）、port を network byte order で入れ、C# から `ref` 渡しで `SetTcpEntry` を呼ぶ probe を打ち、切る前後で該当接続数を数える | `SetTcpEntry` の戻り値 `0`（`NO_ERROR`）、該当接続数が `2` から `1` へ減る |
| **PW-5** | **陰性対照**。WSL の nfqueue は Windows のパケットを掴めない（Windows 実装が要る根拠） | 「採る方式」の実測④の command | WSL 側 established 19 件が全件 WSL 内 process、Windows 側 established 1 件、`readlink /proc/self/ns/net` が `net:[4026531833]` |
| **PW-6** | **実機**。利用者が pktmon で捕獲して `pktmon etl2pcap` で変換した pcapng を packetdeath が読み、SNI を log に出す。遮断は0件 | 「pktmon の filter」で捕獲し `pktmon stop` の後に `pktmon etl2pcap <etl> <pcapng>`、packetdeath が pcapng を読む（入力の渡し方は `未確認`）、`flows.jsonl` の末尾1行と `grep -c '"decision":"block"'` | `"sni":"example.com"` と `"decision":"observe"` を含む1行、block は `0`。**未実施**（pcapng 入力の実装確定が要る） |
| **PW-7** | **実機**。blocklist に当たる SNI の TCP 接続を、packetdeath が接続の4つ組を常駐 PowerShell へ送り `SetTcpEntry` で切る | サービスが動いている機械で、blocklist に当たる host を 1 つ選び（`grep -c '^<host>$' C:\pd\blocklist.txt` が 1 か、親 domain が在る）、PK-121 の実機の command（`TcpClient` と `SslStream` で TLS を張って 12 秒 保持し、`@(Get-NetTCPConnection -LocalPort <port> -State Established).Count` を前後で数え、保持した stream へ書く）を打ち、`flows.jsonl` のその host の末尾 1 行と `service.log` の末尾を見る。陰性対照は blocklist に無い host で同じ形 | 接続数が `1` → `0`、書き込みが `write failed`、`flows.jsonl` が `"decision":"block"` と `"reason":"sni"`、`service.log` に「500ms 以内に来なかった」の `[warn]` が増えない。陰性対照は `1` → `1`、`write ok`、`"decision":"pass"`。PK-121 と同じ窓で打つ |
| **PW-8** | **実機**。Windows サービスの登録・起動・自動再起動・撤去が1往復する | `sc create` で登録、`sc start`、`sc query` で `RUNNING`、`sc failure` を設定後に process を kill して自動再起動を確認、`sc stop` と `sc delete` で撤去し `sc query` が `FAILED 1060` | 登録・起動・自動再起動・撤去が順に通る。起動時（boot）の実走は `未確認`（「Windows 方式の判断」。利用者の端末を再起動しない条件のため）。**未実施** |

### 測って記録するだけの値

この表の値は gate にしない。

| 値 | 打つ command |
|---|---|
| nfqueue を通した接続の遅延 | rule 無しと `observe` 起動中で `curl -sS -o /dev/null -w '%{time_connect} %{time_appconnect}\n' https://example.com/` を各10回。中央値を並べる |
| Windows の Chrome で捕獲した pcapng に占める広告 domain の割合 | 「pktmon の filter」で捕獲した pcapng を packetdeath が読み、`grep -c '"reason":"sni"' <log>` を `wc -l < <log>` と並べる |
| Suricata の版 | `suricata -V` |

## fail-open

packetdeath が死んだとき、通信は止まらずに素通しになる。これを fail-open と呼ぶ。
逆に、packetdeath が死ぬと通信が全部 止まる形を fail-closed と呼ぶ。
広告遮断器が fail-closed だと、落ちた瞬間に端末が offline になる。これは事故である。

**Linux（nfqueue）**：`-j NFQUEUE` は、queue を掴む process が居ないと packet を落とす。
`--queue-bypass` を付けると、掴む process が居ないときだけ素通しになる。
だから全 rule に `--queue-bypass` を付ける（「名前と置き場」の表）。
付け忘れは PK-1 と PK-2 の対で捕まえる。PK-2 は罠が実在することを先に確かめる行であり、これが通らないなら PK-1 の `200` は `--queue-bypass` の効果ではない。

process が生きたまま `recv` を止めたとき（hang）は、`--queue-bypass` では救われない。
kernel 側の queue が溢れた packet は落ちる（`記憶`）。
段階2で hang を検知する watchdog を入れるかは、PK-4 の後に `kill -STOP` で hang を作って測ってから決める。

**flow 単位の fail-open**：判定できない flow は通す。
`sni_state` が `none` か `fragmented` の flow は、段階2で落とさない（PK-12）。
落とすのは、blocklist に当たると判定できた flow だけである。

**Windows（pktmon）**：packetdeath は経路の途中に居ない。
pktmon は packet を捕獲するだけで落とす機能を持たず、packetdeath は捕獲した pcapng を読んで、接続の4つ組を常駐 PowerShell へ送り `SetTcpEntry` で接続を切るだけである。
だから packetdeath.exe が死んでも、通信は素通しになる（fail-open）。この点は Linux の nfqueue と違って「掴む process が居ないと落ちる」構造ではないので、`--queue-bypass` に当たる仕掛けが要らない。

ただし別の問題が在る。pktmon の capture session は packetdeath とは独立に動き続ける。
packetdeath が死んでも、あるいは利用者が `pktmon stop` を打ち忘れても、capture session は残り、ETL が際限なく肥大化する（判断2。実測①で無 filter が 369 MB）。
遮断が止まって素通しになる（安全側）のと引き換えに、止め忘れた session が disk を食う。後始末は「導入と後始末」の節で行う。

## ECH と QUIC の扱い

この節の出所は `docs/research/foci-ech.txt`（FOCI 2025 の ECH 論文）である。行番号は同 file を指す。
論文は検閲の文脈で書かれている。この設計へ当てはめるときは、検閲者の位置に packetdeath を置き換えて読む。検閲者に見えるものは packetdeath にも見え、検閲者に見えないものは packetdeath にも見えない。

### ECH がこの方式にどう効くか

ECH は ClientHello 全体を暗号化し、その暗号文を平文の外側の ClientHello の extension に入れる（`実読` :113-126）。
外側の ClientHello にも SNI が在り、server の ECH config が広告する名前を入れることになっている（`実読` :184-200）。
Cloudflare はこの外側 SNI に `cloudflare-ech.com` を要求し、省略や無効な値を受け付けない（`実読` :346-351）。
だから、Cloudflare 上の domain へ ECH で繋ぐ flow を packetdeath が見ると、SNI は `cloudflare-ech.com`、宛先 IP は Cloudflare の範囲で、どの domain かは見えない（`実読` :331-337, :537-539）。

proxy 設定が無いので、Chrome は ECH を張れる server へは ECH で handshake する（`実読` :182-183。ECH は Chrome の既定で有効）。
ECH を張るかどうかは、Chrome が DNS の HTTPS record から ECH config を取れたかで決まる（`実読` :110-112, :158-159）。

Chrome は全 ClientHello に GREASE ECH（中身が乱数の ECH extension）を付ける（`実読` :136-140, :202-207）。
ECH extension が在ることは ECH を張っている印にならない。
packetdeath は ECH extension の有無を判定に使わず、SNI の値だけを見る。

ECH で隠れる範囲は次の数で見積もる。

| 数 | 出所 |
|---|---|
| Tranco Top 1M の TLS 1.3 server のうち、Cloudflare の ECH config で handshake が成立するのは 278,040 台（43%）。非 Cloudflare の config で成立したのは 6 台 | `実読` :258-263 |
| ECH config を DNS に広告している server は Tranco list の 18% 未満。2024-11 の約 180,000 から 2025-04 の約 150,000 へ減っている | `実読` :286-294 |
| Cloudflare の ECH で handshake できる server の 37.26% は、config を DNS に広告していない | `実読` :301-302 |

Chrome が ECH を張るのは config を広告している server だけなので、隠れるのは上の 18% 未満のうち広告配信に使われる domain である。
広告 domain に限った割合は `未確認`。段階2の測定で `grep -c '"sni":"cloudflare-ech.com"' <log>` を `wc -l < <log>` と並べ、割合を記録する。

### ECH に対して段階3で打つ手

Chrome が ECH config を取れなければ、ECH は張られず SNI は平文に戻る（`実読` :39-40, :143-146。論文は検閲者の手段として書いている。packetdeath は自分の端末で同じ操作をする）。
段階3の `--dns` は DNS 応答を見ているので、blocklist に当たる `qname` の HTTPS record 応答を落とす手が打てる。
この手は段階3の受入に入れず、PK-22 が通った後に別 ID を振る。
理由は2つある。
1つは、Chrome が HTTPS record を平文 DNS（port 53）で引くかが `未確認` であること。
Chrome が DoH を使うなら port 53 に query は出ず、この手は効かない。論文は「Firefox と Chrome は DoH resolver の domain だけを平文 DNS で引く」と述べている（`実読` :203-206）。Chrome Canary がこの端末で DoH を使っているかは、段階3の最初に `grep -c '"qname"' dns.jsonl` を Windows の Chrome で page を開きながら測って確かめる。
もう1つは、HTTPS record を落とすと、その domain への接続が ECH 無しへ倒れるのか失敗するのかが `未確認` であること。

TLS 1.2 の flow は server 証明書が平文なので domain が見える（`実読` :104-105）。
TLS 1.2 の証明書からの判定は採らない。ECH は TLS 1.3 専用であり、隠れる flow は TLS 1.3 なので、TLS 1.2 を見ても隠れた flow は戻らない。

### QUIC（UDP 443）

QUIC の ClientHello にも SNI が在り、検閲者は QUIC の SNI で遮断している（`実読` :372 の Table 1「QUIC SNI」行、:411-413, :418, :510-512）。
QUIC の Initial packet から SNI を取り出す手順は、この論文には書かれていない。`未確認`。

段階1と2は TCP 443 だけを判定する。
UDP 443 は数えて記録するだけで、落とさない（PK-7）。
QUIC で広告が抜ける割合は、Windows の Chrome で PK-7 の件数を `"proto":"tcp"` の件数と並べて測る。
その割合を見てから、QUIC Initial の SNI 取り出しを設計するか、UDP 443 を落として TCP へ倒すかを別 ID で決める。
UDP 443 を落としたとき Chrome が TCP へ倒れるかは `未確認`。

DoH と DoH3 は port 443 を通常の TLS と共有し、DoT と DoQ は port 853 で見分けられる（`実読` :197-201）。
packetdeath は DoH を見分けない。DoH の resolver の SNI が blocklist に当たらない限り、素通しになる。

## 導入と後始末

Windows は追加 driver を入れない（pktmon は Windows 標準。「採る方式」）。
だから不可逆操作は無く、driver 導入の GO も要らない。
pktmon の capture session と、常駐 PowerShell 経由の `SetTcpEntry` は、どちらも管理者権限（サービスは SYSTEM）で動く。

### Windows（pktmon の後始末）

pktmon の capture session と filter は packetdeath とは独立に残る。
止め忘れると ETL が際限なく肥大化する（判断2。実測①で無 filter が 369 MB）ので、必ず後始末する。
この節の command は `記憶` である（`stop` と `filter remove` の文言。PW-6 で初めて実機に打ち、出力をこの節に上書きする）。

| 手順 | command | 期待する出力 |
|---|---|---|
| capture を止める | `pktmon stop` | `ログ ファイル: <path>`。捕獲が確定する |
| filter を消す | `pktmon filter remove` | filter list が空になる |
| 残っていないか確かめる | `pktmon status` | 動いている session が無い |
| ETL を消す | 捕獲した `.etl` と変換後の `.pcapng` を削除する | file が無くなる。両方とも端末が繋いだ domain を含むので秘密として扱う |

常駐 PowerShell も `SetTcpEntry` も driver を残さない。撤去は、サービスを `sc stop` して `sc delete` で登録解除し、packetdeath.exe を消せば終わる（常駐 PowerShell はサービスの子 process なので、サービスの停止で一緒に終わる）。

サービスの `[info]` / `[warn]` / `[error]` の行は `<log dir>\service.log` に在る（`[debug]` は file に無い）。読むのは `Get-Content <log dir>\service.log -Encoding UTF8 -Tail 20`、blocklist の読み直しが効いたかは `Select-String -Path <log dir>\service.log -Encoding UTF8 -Pattern '読み直した|reloaded' | Select-Object -Last 1` で見る（`-Encoding UTF8` が無いと Windows PowerShell 5.1 は BOM 無しの UTF-8 を ANSI として読み、日本語の行が合わない）。file が無いときは、サービスが `--log-dir` の dir を開けなかったか、向け直す前（引数の parse）で止まっている。

### Linux

nfqueue は kernel module であり、driver の導入は無い。
戻す操作は iptables の rule を消すことだけである。

| 手順 | command | 期待する出力 |
|---|---|---|
| 入れる前の件数 | `sudo iptables -S \| grep -c 1808` | `0` |
| 入れる | 「名前と置き場」の表の rule | 件数 command が rule の本数 |
| 効いている | PK-3 | PK-3 と同じ |
| 抜く | 各 rule の `-I` を `-D` にして打つ | 件数 command が `0` |
| 戻った | PK-0 | PK-0 と同じ |

Linux 側の往復は WSL で先に打つ。Windows の往復より前に打ち、手順の穴を先に見つける。

### 捨てるとき

rule を抜き pktmon の後始末をしても `flows.jsonl` と `dns.jsonl` は disk に残る。段階8 を使ったなら `av.jsonl` と `--ca-dir` の CA も残る。
packetdeath を使わなくなったら全部 消し、端末に入れた CA を信頼ストアから抜く。
`flows.jsonl` は端末が繋いだ domain を全部 含む。`av.jsonl` は download ごとの宛先 IP と sha256 を含む。どちらも秘密として扱う。

## 制約

- **言語は Rust**。nfqueue は既存の binding crate を使う。Windows は pktmon が作った pcapng を自前で読み、遮断は常駐 PowerShell 経由の `SetTcpEntry` で行う。サービス化は `windows-service` crate を使う（`forbid` の下で通る。「Windows 方式の判断」）。署名エンジンは書かない。
- **unsafe は既定禁止のまま。**`Cargo.toml` の `unsafe_code` は `forbid` にする。packetdeath は `SetTcpEntry` を Rust から呼ばず、接続の4つ組を常駐 PowerShell へ送って切る（「Windows 方式の判断」）ので、Rust にも C# にも unsafe が要らない。局所許可（`#[allow(unsafe_code)]`）も書かず、受入条件は `src/` に `#[allow(unsafe_code)]` が0件であることとする。
- **段階1〜7 は TLS を復号しない。**CA を生成しない。秘密鍵を持たない。段階8 だけが例外で、`--mitm-list` と `--ca-dir` と `--clamd` が3つ揃ったときに限り、CA を生成して鍵を持つ（「段階8 MITM」節）。
- **rule と pktmon は利用者が入れる。**packetdeath は iptables も pktmon も打たない（判断2）。抜き忘れ・止め忘れが packetdeath の side effect にならない形にする。
- **判定できない flow は通す。**`sni_state` が `none` か `fragmented` の flow を落とさない。
- **外部が更新する crate、blocklist、ルールセット、Suricata の版や sha256 を、動作の gate にしない。**測って記録するだけにする。
- **対象外**：ECH で Cloudflare へ繋ぐ flow の内側の domain（「ECH と QUIC の扱い」の節）、QUIC（段階2まで）、SSAI で stream に縫い込まれた広告（`検索`。packet が分かれないので判定できない）、server-side tagging（first-party の subdomain。DNS でも SNI でも区別できない。`検索`）、anti-adblock script の回避、DoH を hard-code した app の DNS。

## 作る順番

このプロジェクトの順序は 設計 → UI/UX → テスト項目 → 実装 → テスト担当 である。

| 工程 | この project での扱い |
|---|---|
| 設計 | この file |
| UI/UX | 無い（次の節） |
| テスト項目 | 「受入 ID」の節。実装より先に確定した |
| 実装 | 設計とは別の担当。`src/` と `Cargo.toml` を持つ |
| テスト担当 | 実装した本人以外 |

## UI の有無

**UI は無い。**
操作は CLI（`observe` / `block` / `eval`）と、log file の閲覧だけで足りる。
designer への相談は `N/A` とする。

- **理由**：段階1〜4の受入 ID は、全部 command と file で測れる。画面が在っても測り方は変わらない。
- **判断責任者**：プロジェクトの管理者。
- **再評価条件**：遮断の内訳を画面で見たいと利用者が求めたとき。そのときは Dioxus（Rust / WASM）で作る。

## 公開の検討

**GitHub の public 化は、自走許可があっても利用者本人の明示 GO を得る**。
GO を得るまで private で作る。remote は付けない。

### license

- **本体は `MIT OR Apache-2.0` の dual**（Rust の慣行。`記憶`）。`Cargo.toml` の `license` の行に同じ値を置く。`LICENSE-MIT` と `LICENSE-APACHE` の file は public 化のときに置く（それまで repo に無い）。
- **依存木に GPL だけの crate は無い**（`実測` 2026-10-04。`cargo metadata --format-version 1 --locked \| jq -r '.packages[] \| "\(.license)\t\(.name)"'` の 91 package。GPL を含む物は `r-efi` の `MIT OR Apache-2.0 OR LGPL-2.1-or-later` だけで、OR なので MIT を選べる。`nfq` 0.2.5 と `windows-*` は `MIT OR Apache-2.0`、`aws-lc-rs` / `aws-lc-sys` は ISC と Apache-2.0 と BSD-3-Clause の AND、`webpki-roots` は CDLA-Permissive-2.0）。Linux の binary が動的に link する物は `libc.so.6` と `libgcc_s.so.1` だけ（`ldd`。`実測` 2026-10-04。どちらも system library の例外に当たる）。clamd と Suricata は別 process で、socket と file を介するだけである。
- **target ごとに絞っても GPL 系の crate は無い**（`実測`。`cargo metadata --format-version 1 --filter-platform x86_64-unknown-linux-gnu \| jq -r '.packages[] \| "\(.license)\t\(.name)"' \| rg -i gpl` が rc=1、Windows の `x86_64-pc-windows-gnu` も rc=1。対照は package の総数 70 と 25。`license` 欄の無い package は 0）。
- **clamd（ClamAV、GPLv2）は別 process で、packetdeath は Unix socket で話すだけで link しない。**別 process に GPL は伝播しない、は Suricata と同じ通説で `未確認`。一方、`scripts/clamav-64/` の patch 4 本は ClamAV の source の差分（派生物）なので、その dir の中身だけは GPLv2 である。公開のときは `scripts/clamav-64/COPYING`（GPLv2 の全文）と「この dir は GPLv2。本体の `MIT OR Apache-2.0` は及ばない」の注記を置き、README の license の節に同じ 1 行を書く。64-bit 化した clamd の binary は配布しない（利用者が手順書で build する）。
- **pktmon は Windows の標準 command で、追加の binary を配布しない。**packetdeath は pktmon が作った pcapng を読むだけで、pktmon と link しない。repo に pktmon の binary を入れない。
- **Suricata は GPLv2**（`記憶`）。packetdeath は Suricata と link せず、別 process が書く `eve.json` を読むだけである。file を介した別 process に GPL は伝播しない、は通説である。`未確認`。Suricata は repo に入れず、利用者が入れる。
- **ET Open ルールセットの license は `未確認`。**repo に入れない。Suricata 側の `suricata-update` が取る。
- **`nfq` 系と `windows` crate の license は `MIT OR Apache-2.0`**（上の行の `実測`。`Cargo.lock` が動いたら「公開前に打つ command」で測り直す）。
- **blocklist の中身を repo に1行も入れない。**形式は1行1 domain の自前形式で、EasyList の構文を読まない。EasyList は GPLv3 以降と CC BY-SA 3.0 以降の dual（`実読`。`https://easylist.to/pages/licence.html`）で、変換して同梱すると伝播する。test の fixture は自分で書いた2〜3行のリストを使う。
- README にリスト名と license を明記する。

### README の冒頭に書くこと

順番どおりに、最初の画面に収まる分量で書く。

1. **これは自分の端末の packet を落とす道具である。**Windows では pktmon（Windows 標準。追加 driver ゼロ）で捕獲し、常駐 PowerShell 経由の `SetTcpEntry` で接続を切る（Rust にも C# にも unsafe は0件）。Linux では root で iptables の rule を入れる。TLS は復号しない（段階8 を使うときだけ復号し、その CA は利用者が自分で端末へ入れる）。proxy 設定を変えない。中国の組織が署名した driver を使わない。
2. **落ちたとき通信は素通しになる（fail-open）。**Windows は packetdeath が経路に居ないので素通しになる（「fail-open」）。Linux は `--queue-bypass` を付けないと fail-closed になる。
3. **後始末を、導入手順より先に書く。**この設計書の「導入と後始末」を写す。pktmon の session を止め忘れると ETL が肥大化する。
4. **自分が管理する端末でだけ使う。**他人の通信を通さない。router には置かない。
5. **外へ何も送らない。**log は local の `flows.jsonl` と `dns.jsonl`、段階8 では `av.jsonl` だけ。**log は端末が繋いだ domain を全部 含むので秘密として扱う。**
6. 対象外：ECH で Cloudflare へ繋ぐ flow の内側の domain、QUIC（段階2まで）、SSAI、server-side tagging、anti-adblock の回避、DoH を hard-code した app。
7. Suricata は別 install であり GPLv2 である。packetdeath は `eve.json` を読むだけ。
8. blocklist の名前と license。

### 法的な位置づけ

断定しない。分かることと分からないことを分ける。

**分かること**

- この道具は利用者自身の端末で、利用者自身の通信を、利用者自身の設定で落とす。段階1〜7 は復号しない。段階8 は、利用者が自分で端末へ入れた CA で、利用者が `--mitm-list` に書いた host だけを復号する。第三者の server や通信に触れない。（設計事実）
- ドイツでは Axel Springer 対 Eyeo（Adblock Plus）の著作権訴訟を BGH が 2025-07-31（I ZR 131/23）に OLG Hamburg へ差し戻した。争点はブラウザ拡張が DOM / CSSOM を書き換えることの著作権上の扱いで、確定していない。（`検索`。heise、Norton Rose Fulbright の記事。判決文は未読）
- 日本では、広告ブロッカーを直接 扱った裁判例は検索で見つからなかった。法律事務所の解説1本が「刑事上は抵触する法律が無く、民事上は各 site の規約による」と述べている。（`検索`。一次資料なし）

**分からないこと（未確認）**

- 広告遮断 software を公開する行為が、使う行為と別に争われた例が在るか。未確認。
- packet を落とすだけで page の内容を書き換えない道具が、ドイツの争点と同じ扱いになるか。未確認。
- 日本の不正競争防止法「技術的制限手段」に、広告の遮断が当たるか。未確認。段階1〜4は anti-adblock script を回避しないので、回避に当たる動作は設計上 含まない。
- 電気通信事業法「通信の秘密」が、自分の通信の SNI と DNS 応答を自分で読む個人の道具に及ぶか。未確認。段階7 までの復号しない設計はこの点の露出を狭めるが、消すとは言えない。段階8 は自分の通信の本文を自分で読むので、露出は段階7 より広い。未確認のまま。
- 各 site の利用規約（動画 site を含む）が広告遮断を禁じているか。site ごとに未確認。

公開の可否は、この節の「未確認」が埋まるかどうかとは別に、利用者本人の GO で決まる。

### 公開前に打つ command（PK-40）

| 何を確かめるか | command | 通ったと判る出力 |
|---|---|---|
| 依存木に GPL だけの crate が無い | `cargo metadata --format-version 1 --locked \| jq -r '.packages[] \| .license // "NONE"' \| grep -vE 'MIT\|Apache' \| grep -cE 'GPL\|SSPL'`（OR で MIT か Apache を選べる物は除く）。対照に `cargo metadata --format-version 1 --locked \| jq -r '.packages[] \| .license // "NONE"' \| grep -c MIT` | `0`。対照が 1 以上 |
| 本体の license が manifest に在る | `grep -c '^license = "MIT OR Apache-2.0"' Cargo.toml` | `1` |
| binary が動的に link する物が libc と libgcc_s だけ | `ldd target/release/packetdeath \| grep -vcE 'linux-vdso\|ld-linux\|libc\.so\|libgcc_s'` | `0` |
| unsafe が0件（局所許可も無い） | `grep -rl '#\[allow(unsafe_code)\]' src/ \| wc -l; grep -c 'unsafe_code = "forbid"' Cargo.toml` | `0` と `1` |
| driver の binary が repo に無い | `git ls-files \| grep -ciE '\.(dll\|sys)$'` | `0` |
| 秘密が ignore されている | `git check-ignore flows.jsonl dns.jsonl av.jsonl` | 3行とも出る |
| 秘密が履歴に無い | `git log --all --name-only --pretty=format: \| grep -cE 'flows\.jsonl\|dns\.jsonl'` | `0` |
| README 冒頭 | `head -30 README.md \| grep -c 'fail-open'` | `1` 以上 |
| blocklist の中身が無い | `grep -rlE '^\|\|[a-z0-9.-]+\^' --include='*' . \| grep -v target \| wc -l` | `0` |
| 個人環境情報が無い。code の comment に経緯の印（日付、reviewer、検証者、発注、逐語）が無い。履歴の author と committer が noreply だけである | `./scripts/check-privacy.sh --history; echo rc=$?`（個人の固有名の一覧は repo の外の `${XDG_CONFIG_HOME:-$HOME/.config}/packetdeath/privacy-patterns.txt`。無ければ `--generic-only`） | 項目0〜6 がすべて `OK`、最後の行が `通過。commit してよい`、`rc=0`。項目5 の対象は `src/` と `tests/` の `.rs` と `.ps1` の comment 行と `blocklists/*.txt` の `#` 行 |
| public 化の GO | 利用者本人の GO を記録に残す | 記録が在る |

## 将来の拡張点（IDS/IPS、アンチウイルス、マルウェア対策）

拡張の対象は3つである。①IDS / IPS、②アンチウイルス、③マルウェア対策。

①は段階4「IPS 化」で設計済みである（「採る方式」と「段階」の節）。この節で足すものは無い。
②と③は、後から載せられる構造を今決めるだけで、今は作らない。
この節は、その構造を決め、いま作らない物を名指しする。
段階1〜4 の設計は変えない。

禁じ手のうち proxy 設定を変えないことは②③にも掛かる。CA の禁じ手は、利用者が自分で端末へ入れる形に限って段階8 で外してある（「禁じ手」節）。
TLS を割らずにできるのは、SNI、CNAME、宛先 IP、IDS alert による判定と、平文 HTTP の本文を見ることまでである。
HTTPS の本文を見ること、HTTPS の中の URL path で判定すること、HTTPS で落ちてくる file を到着前に止めることは、TLS を割らないとできない。段階1〜7 では採らない。HTTPS の本文を見て file を scan することだけは、段階8 が利用者の入れた CA で採る。URL path での判定は段階8 でも採らない。

### 将来機能と今 作る物の線

| いま作る（段階2 の着手時から守る構造） | いま作らない（段階5 以降。受入 ID が通るまで CLI にも code にも現れない） |
|---|---|
| 判定器の trait と、判定理由の add-only な列挙（「判定を差し込む口」） | `--iplist`（段階5） |
| drop 集合へ外部の verdict を流し込む型（同上） | `--av` と、外部 scanner との橋渡し program（段階6） |
| | AMSI の呼び出し（PK-63 の測定結果で候補に入れるかを決める） |
| | 常駐の file 監視、署名 engine（「採らない手段（拡張）」の表）。HTTPS の本文 scan は段階8（「段階8 MITM」節。設計済みで未実装） |

段階2〜4 の実装者は、右列の flag や module を先回りして足さない。
足すと、段階2〜4 の陰性対照（PK-10、PK-20、PK-30）が「flag 無しで0件」を測る対象が増え、受入の意味が変わる。

### いまの仕組みで既に届く範囲

②③のうち、新しい機構を足さずに届くものは次の3つである。

| 届くもの | 効く機構 | 測り方 | 測れないこと |
|---|---|---|---|
| malware の domain への TLS 接続を落とす | 段階2 の SNI 遮断。blocklist は1行1 domain なので、公開の malware domain list を同じ形式で足すだけで当たる（`実読` 「名前と置き場」の blocklist 形式） | PK-11 と同じ手順。`bl.txt` に malware list の domain を入れ、`grep -c '"reason":"sni"' <log>` | list に無い domain、ECH で隠れた domain（「ECH と QUIC の扱い」）、QUIC、SNI を持たない接続（IP 直打ちの C2。`sni_state` が `none` なので段階2 は通す。`実読` 「fail-open」の flow 単位の規則） |
| CNAME で隠した malware domain を落とす | 段階3 の CNAME チェーン解決。機構は広告と malware を区別しないので、blocklist の中身が malware なら同じ経路で当たる | PK-22 と同じ手順 | DoH を hard-code した app の DNS（「制約」の対象外） |
| 既知の攻撃通信と C2 通信を、alert の後に落とす | 段階4 の Suricata IDS 連携。ET Open は malware の C2、exploit kit、phishing の rule を含む（`記憶`。rule の分類の一次資料は未読） | PK-31 と同じ手順で、`--ips-sids` に malware 分類の sid を入れる | alert を出した最初の packet（反応型。「採る方式」）。`--ips-sids` に入れなかった sid |

blocklist の中身は repo に入れない（「公開の検討」）。
malware list の license は list ごとに `未確認` であり、利用者が取る。

「マルウェアを防げる」とは書けない。
測れるのは「list に在る domain と IP への flow が落ちる」「指定した sid の alert の後に同じ宛先が落ちる」までである。
検知率は list と rule の性能であり、packetdeath の性能ではない。
list の網羅率を測る手順はこの設計に無い。

### 判定を差し込む口

判定材料は SNI、CNAME、宛先 IP、IDS alert の4つである。
5つ目を足すときに既存の4つを壊さない形を、次のとおり決める。

判定は2種類に分かれる。
1つは packet を受け取った瞬間に答える**同期判定**で、SNI と CNAME と宛先 IP がこれに当たる。
もう1つは別 process が後から出す結果を drop 集合へ流し込む**非同期判定**で、IDS alert がこれに当たる。
口は2つに分けて切る。

- **同期判定の口**：trait `Judge` を切る。入力は `FlowKey` と `SniState` と、段階3 が持つ DNS 由来の情報（`chain`、`addrs`）をまとめた1つの struct。出力は `Option<Reason>`（`Some` なら落とす）。判定器は段階の番号順に並べ、最初に `Some` を返した判定器の `Reason` を log の `reason` に書く。全部 `None` なら `pass`。後から足す判定器は列の後ろに付くので、先に当たっていた flow の `reason` は変わらない。
- **allowlist の口（「当たっても通す」）**：`judge::run_judges_with_allowlist(allowlist, judges, input)` が同期判定の列の**外側**を包む。SNI が allowlist に当たれば `judges`（sni/cname/ids/iplist/av のどれも）を1つも評価せず即座に `None`（pass）を返す。`Reason` は増やさない ── allowlist で救った flow も `decision` は `pass`、`reason` は `null` のままで、当たったことは `[debug]` の log にだけ出す。SNI を持たない flow（`sni_state` が `none` / `fragmented`）は allowlist の対象にできないため、既存の同期判定へそのまま委譲する（fail-open の性質を変えない）。「1 flow あたり定数時間で答える」同期判定の契約は、allowlist も起動時に読んだ local file だけを見るので保たれる。
- **非同期判定の口**：drop 集合 `DropSet` へ入れる値の型を1つに決める。中身は宛先（5-tuple、`dst_ip`、`dst_ip` と `dst_port` の組のどれか）、`Reason`、期限（`--ips-ttl`）である。`eve.json` の reader はこの型を作る側の1つであり、段階6 の `--av` の reader も同じ型を作る。drop 集合の照合は `Judge` の1つとして同期判定の列に並ぶ。
- **`Reason` は add-only の列挙**：値は `sni`、`cname`、`ip`、`ids`（段階1〜4。「名前と置き場」の一覧）に、`iplist`（段階5）と `av`（段階6）と `chain`（段階10。不信の証明書を含む鎖）を足す。既存の値を改名しない。受入 ID の `grep -c '"reason":"sni"'` がこの値に依存する。`flows.jsonl` の field は増やさない。
- **fail-open は判定器ごとに守る**：判定器が error を返した flow は `pass` にし、`reason` は `null` にする。段階2 の実装者は、これを unit test で持つ。判定器の中で I/O をしない。file の読み込みは起動時と、非同期側の reader thread だけで行う。

process 内に置くか別 process にするかは、次の規則で決める。

- **process 内（`Judge`）**：材料が packet と起動時に読んだ local file だけで、1 flow あたり定数時間で答えられる判定。
- **別 process（`DropSet` の供給元）**：自前の engine と定義 file を持つもの、license が GPL 系のもの、1回の判定に時間が掛かるもの。Suricata と ClamAV がこれに当たる。

別 process にする理由は3つある。
外部 process が死んでも drop 集合が増えなくなるだけで通信は止まらず、fail-open が保たれる。
GPL 系の engine を file 経由の別 process に置く形は、Suricata で既に採った形と同じである（license の伝播は「公開の検討」のとおり `未確認`）。
unsafe を1行も書かない（`unsafe_code = "forbid"`）ので、plugin の動的 load（FFI）のように unsafe が広く要るものは持たず、判定器は compile 時に列挙する（`実読` `src/lib.rs:1`）。

### TLS を割らずに file の実体へ届く経路

経路は在る。ただし平文 HTTP に限り、反応型である。
HTTPS の本文には届かない（段階6 は復号しない。届くのは段階8 で、`--mitm-list` の host に限る）。

| 経路 | 届くか | 条件 | 出所 |
|---|---|---|---|
| HTTP（平文、tcp 80）の download | 届く | 段階4 の tcp 80 rule が queue へ回していること。本文を1つの file に戻すには TCP の組み立て直しと HTTP の decode（chunked、gzip）が要り、段階1〜4 はどちらも持たない（`実読` 「名前と置き場」の `sni_state`）。組み立て直しは packetdeath に足さず、Suricata の file 抽出（`file-store`。`fileinfo` event が 5-tuple と sha256 を持つ）に任せる | Suricata の `file-store` と `fileinfo` は `記憶`。Windows 版で動くかは `未確認` |
| ClamAV との連携 | 届く（HTTP の範囲で） | 呼ぶ場所は packetdeath の外である。Suricata が保存した file を `clamdscan` で見て、結果を `av.jsonl`（下の形式）に書く小さな橋渡し program を別に置く。名前は段階6 の着手時に決める。packetdeath は `--av <path>` でそれを読み、`malicious` の宛先を drop 集合へ入れる。ClamAV は GPLv2 で、定義は `freshclam` が更新する | `記憶`。一次資料は未読 |
| Windows の AMSI | `未確認` | AMSI は application が buffer を渡して、登録済みの antimalware provider（既定は Defender）に scan させる interface で、`AmsiScanBuffer` を持つ（`記憶`）。packetdeath から使えるかは `未確認` である。分からない点は3つ。(a) 実行 file の buffer を script と同じ精度で判定するか。(b) Rust から呼ぶ binding が在るか。(c) packet を扱う process からの呼び出しが許されるか。使えたとしても、渡す buffer は Suricata が組み立てた file になるので、AMSI は段階6 の engine の選択肢の1つに留まる | `未確認`。`docs/research/` に AMSI の資料は無い（`grep -in amsi docs/` が0件。2026-09-11） |

到着済みの file は止められない。
scan の結果が出るのは file が disk に書かれた後なので、落とせるのは同じ宛先への以後の接続だけである。
到着前に止めるには packet を溜めてから流す形（store-and-forward）が要り、それは段階1〜4 の packet 単位の verdict と別の機構になる。採らない。

平文 HTTP の download が守る対象でどれだけ在るかは、段階4 の tcp 80 rule を入れた状態で `grep -c '"dst_port":80' <log>` を `grep -c '"dst_port":443' <log>` と並べて測る。
Chrome は HTTPS の page からの HTTP download を警告か遮断する（`記憶`）ので、この割合は小さいと見込む（`推測`）。
割合が小さければ段階6 の優先度を下げる。

### 採らない手段（拡張）

| 採らない | 理由 |
|---|---|
| HTTPS の本文を見て file を scan する | **段階8 で採る**（利用者が入れた CA で復号する）。「段階8 MITM」節 |
| ウイルス定義と検知 engine の自作 | 署名 engine の自作は採らないと決めた（「採らない手段」の表）。定義の維持は個人では回らない |
| 常駐の file 監視（on-access scan） | packetdeath は packet を見る道具である。file system の常駐監視は、Windows では Defender が、Linux では ClamAV の `clamonacc` が既に担う（`記憶`）。packetdeath が持つと kernel driver（Windows の minifilter）が要り、追加 driver を入れない方針（「採る方式」）に反する。二重にしない |
| packetdeath の process 内で scanner を呼ぶ | 判定器の中で I/O をしない規則に反する。scan の時間が verdict の経路に乗り、queue が溢れて packet が落ちる（「fail-open」の hang と同じ形）。段階8 の proxy は接続ごとの thread から clamd の socket を呼ぶ。nfqueue の verdict 経路にも `Judge` の中にも載らないので、この行の対象外である |
| packet を溜めて scan 後に流す（store-and-forward） | 上の段落のとおり。段階8 の proxy が HTTP の本文を溜めて scan するのは L7 の話で、packet を溜める話ではないので別物である |

### 段階5 以降と受入 ID の予約

段階1〜4 の表（「段階」の節）は変えない。
段階5 以降はここに置く。
PK-41 から PK-49 は、「ECH と QUIC の扱い」が「別 ID」と書いた分のために空けておく。

| 段階 | 何ができたら次へ行くか | 着手条件 | 受入 ID |
|---|---|---|---|
| **5. 宛先 IP list** | `--iplist <path>`（1行1 IP か CIDR。`#` で始まる行は無視）に当たる宛先を、`sni_state` と proto を問わず落とす。SNI を持たない接続に届く唯一の材料である | 段階2（PK-13）が通ったら。段階3、4 を待たない。Suricata が無い環境（「前提」の表）でも進めるため | PK-50, PK-51, PK-52, PK-53 |
| **6. 外部 scanner の verdict 取り込み** | `--av <path>` を読み、`malicious` の宛先を drop 集合へ入れる。橋渡し program は packetdeath の外 | 段階4（PK-32）が通ったら。`fileinfo` と drop 集合を使うため | PK-60, PK-61, PK-62, PK-63 |
| **7. proxy** | packetdeath を非復号の CONNECT proxy として動かし、利用者が別端末（iPhone 等）の proxy 欄へ手で指せる（「段階7 proxy」節） | 段階2（PK-13）が通ったら。段階3〜6 を待たない | PK-70, PK-71, PK-72, PK-73, PK-74, PK-75, PK-76, PK-77, PK-78, PK-79, PK-80 |
| **8. MITM** | `--mitm-list` に当たる CONNECT を、利用者が端末へ入れた CA で復号し、応答の file を clamd で検査して `FOUND` を `403` に差し替える。scan で通信を遅くしない（「段階8 MITM」節） | 段階7（PK-78）と段階9（PK-94）が通ったら。段階9 は本番で通過済み。段階7 の proxy の上に載る | PK-100, PK-101, PK-102, PK-103, PK-104, PK-105, PK-106, PK-107, PK-108, PK-109, PK-111, PK-112, PK-113 |
| **9. malware feed（路線 A）** | 公開の malware feed を外部 script が取り込み、`--blocklist` と `--iplist`（どちらも複数指定可）で落とす（「段階9 malware feed」節） | 段階2（PK-13）と段階5（PK-51）が通ったら。段階7 の proxy でも同じ list が効く | PK-90, PK-91, PK-92, PK-93, PK-94 |
| **10. 能動防御** | 不信の証明書の list と鎖の probe と見張りの口を足し、確かさの高い source は最初から止め、読めない source だけを見張りから始める（「段階10 能動防御」節） | 段階8（PK-103）と段階9（PK-94）が通ったら。本番の proxy への反映（PK-142）までを1つの仕事とする | PK-130〜PK-144 |

`av.jsonl` の形式は1 verdict 1行で、field は `ts`、`proto`、`dst_ip`、`dst_port`、`sha256`（無ければ `null`）、`verdict`（`malicious` か `clean`）、`engine`（自由文字列）である。
`verdict` が `malicious` の行だけが効き、drop 集合へ入るのは `dst_ip` と `dst_port` の組である（`ids` は `dst_ip` も落とすが、`av` は落とさない。CDN の共有 IP を丸ごと落とすと、同じ IP の別の site が巻き込まれる）。
期限は行を読んだ時刻に `--ips-ttl` を足した値で、`ts` は記録するだけで使わない。
読めない行は捨てて stderr に出す。

| ID | 受入条件 | 打つ command | 通ったと判る出力 |
|---|---|---|---|
| **PK-50** | **陰性対照**。`--iplist` 無しでは IP で落ちない | `IP=$(dig +short example.com \| head -1); sudo packetdeath block &` の後に `curl -4 -sS -o /dev/null -w '%{http_code}\n' https://example.com/; grep -c '"reason":"iplist"' <log>` | `200`、`0` |
| **PK-51** | list に当たる宛先 IP を落とす | `printf '%s\n' "$IP" > ip.txt; sudo packetdeath block --iplist ip.txt &` の後に `curl -4 -sS --max-time 5 -o /dev/null -w '%{http_code}\n' https://example.com/; echo "exit=$?"; tail -1 <log>` | `000` と `exit=28`。log が `"decision":"block"` と `"reason":"iplist"` |
| **PK-52** | SNI を持たない flow も IP で落とす | 段階4 の tcp 80 rule を打ち、PK-51 の起動のまま `curl -4 -sS --max-time 5 -o /dev/null -w '%{http_code}\n' "http://$IP/"; echo "exit=$?"; tail -1 <log>` | `000` と `exit=28`。log が `"sni_state":"none"` と `"decision":"block"` と `"reason":"iplist"` |
| **PK-53** | 判定器を足しても段階2〜4 が壊れない（回帰） | PK-10 から PK-32 を打ち直す（段階3、4 が未着手なら PK-10 から PK-13） | 各 ID の「通ったと判る出力」と同じ |
| **PK-60** | **陰性対照**。`--av` 無しでは `malicious` が在っても落ちない | `printf '{"ts":"2026-01-01T00:00:00Z","proto":"tcp","dst_ip":"%s","dst_port":443,"sha256":null,"verdict":"malicious","engine":"manual"}\n' "$IP" > av.jsonl; sudo packetdeath block &` の後に `curl -4 -sS -o /dev/null -w '%{http_code}\n' https://example.com/; grep -c '"reason":"av"' <log>` | `200`、`0` |
| **PK-61** | `malicious` の宛先を、engine 無しでも落とす（取り込み口だけを測る） | `sudo packetdeath block --av av.jsonl &` の後に PK-51 の curl と `tail -1 <log>` | `000` と `exit=28`。log が `"reason":"av"` |
| **PK-62** | 平文 HTTP の EICAR を Suricata が抽出し、ClamAV が `malicious` と判定し、以後の同じ宛先が落ちる | local の HTTP server に EICAR test file を置き（EICAR の文字列は repo に入れない。on-access scanner が repo を隔離する。`記憶`）、Suricata を `file-store` 有効で起動し、橋渡し program を起動し、`sudo packetdeath block --eve <eve.json> --av av.jsonl &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:<port>/eicar.com; sleep 5; curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:<port>/eicar.com; echo "exit=$?"` | 1回目 `200`。2回目 `000` と `exit=28`。落ちるのは `127.0.0.1:<port>` の組だけで、他の loopback 通信は落ちない。Suricata の `file-store` がこの環境で動かなければ `skipped` と記録し、段階6 は PK-61 で閉じる |
| **PK-63** | AMSI が実行 file の buffer を判定するかを測る。**gate にしない** | packetdeath とは別の小さな Windows の probe で、EICAR の byte 列を `AmsiScanBuffer` に渡し、返った `AMSI_RESULT` を記録する。probe の作り方は段階6 の着手時に決める | 値を記録する。detected 相当なら AMSI を段階6 の engine の候補に入れ、そうでなければ候補から外す |

PK-62 の loopback を Suricata（AF_PACKET）と nfqueue の OUTPUT rule が見るかは `未確認`。
段階6 の最初に、`lo` 宛の `curl` で `flows.jsonl` が増えるかを測ってから PK-62 を打つ。

### 段階9 malware feed（路線 A）

antivirus 機能の場面は「(A) 悪い接続先を落とす」「(C) 端末に落ちた file を検査する」「(B) HTTPS の中身まで検査する」の3つで、この節は (A) だけを扱う。
(A) の手段は「malware の C2、配布 site、phishing の domain と IP を feed から取り込み、既存の遮断で落とす」であり、それ以上でも以下でもない。
復号はしない。packetdeath に新しい常駐物も足さない。

作る物は3つである。

1. `--blocklist <path>` と `--iplist <path>` を**複数回** 渡せる（`block` と `proxy`）。読み込みは union で、1本が読めなくても他は効く（fail-open）。
2. 走行中の読み直しに `--iplist` を加える。`WatchInputs`（`src/block_loop.rs`）は blocklist と allowlist に加えて iplist を読み直す。読み直しに失敗した file は前の内容を使い続ける。`IpList` に `len()` を足し、読み直しの log が件数の差を出せるようにする。`block`（nfqueue）、`proxy`、`--pcapng` は同じ `WatchInputs` を使うので、3経路とも読み直しが効く。
3. `scripts/pd-malware-feed.sh` が公開 feed を `curl` で取り、`<outdir>/malware-domains.txt`（1行1 domain）と `<outdir>/malware-ips.txt`（1行1 IP）を作る。packetdeath の外の script であり、1日1回 systemd timer（`scripts/systemd/pd-malware-feed.timer`）が起動する。timer の install は人が打つ。packetdeath は timer も `curl` も起動しない。

feed の URL と license の名前は script 冒頭の comment が正本である。license の本文は repo に入れず、利用者が取る。

| feed | URL | 取り出す物 | 行き先 |
|---|---|---|---|
| ThreatFox（CSV） | `https://threatfox.abuse.ch/export/csv/recent/` | `ioc_type` が `domain` の値と、`ip:port` の IP | domain と IP |
| URLhaus（hostfile） | `https://urlhaus.abuse.ch/downloads/hostfile/` | 2列目の host | domain（IP の形なら IP） |
| Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | 1行1 IP | IP |

ThreatFox の `url` の行は取り込まない。URL の host は無料の file 置き場や正規の site であることがあり、host ごと落とすと誤遮断になるからである。
IP は private、loopback、link-local、multicast、`0.0.0.0` を捨てる。feed が汚染されても、LAN と proxy 自身へ届かなくなる事故を起こさないためである。
3つの URL の形は、実際に取って確かめてある（`実測`、2026-10-03）。ThreatFox は `ip:port` が 3357 行、`domain` が 2126 行で、Feodo は 5 行しか無い。IP の本体は ThreatFox が担う。

各 file は、取得と変換の後に行数（`#` の行を除く）を数える。
下限（domain は 1000、IP は 100。`--min-domains` と `--min-ips` で変える）を下回ったら、**書き換えずに前の file を残して** rc=1 で終わる。
下限を満たしたら tmp に書いて `mv` する（atomic write）。先頭には `#` の source と取得時刻の comment を付ける。
取得できなかった feed が1つでもあれば、書き換えが成立しても rc=1 にする。timer の失敗として見えるようにするためである。
取得した raw は `<outdir>/raw/` に残す。`--from <dir>` は取得を飛ばして `<dir>` の raw を読む。network の無い環境でも検査できる。

採らない手段は5つである。

- **packetdeath 本体が feed を HTTP で取りに行く**：crate が増え、packetdeath が外部 network に依存する常駐物になる。「packetdeath は pktmon も iptables も scanner も起動しない。落ちたとき残る物を作らない」に反する。
- **feed を1本の blocklist file へ追記（merge）する**：利用者の list と feed の list が混ざり、feed の失敗で利用者の list が壊れる。file を分け、`--blocklist` を複数回 渡して union にする。
- **IP を domain の blocklist に混ぜる**：`--blocklist` は SNI 判定、`--iplist` は宛先 IP 判定で、判定器が違う（「判定を差し込む口」）。C2 は IP 直打ちが多いので `--iplist` 側に入れる。
- **VirusTotal 等のクラウド lookup**：`docs/research/av-latest-2026.md` の「採らない手段」にある。
- **MITM と CA**：(B) の範囲なので、ここでは触らない。

波及先は3つある。
`WatchInputs::new` の引数が変わる（blocklist と iplist は中身を持つ値で受け、file は `with_blocklist_files` と `with_iplist_files` で足す）。
`BlockConfig` は `iplist` を持たなくなる。読み直す値を `WatchInputs` と `BlockConfig` の2か所に持つと、古い方を読む事故になるからである。
`service-run`（Windows）の `--blocklist` は1本のまま変えない。

| ID | 受入条件 | 打つ command | 通ったと判る出力 |
|---|---|---|---|
| **PK-90** | **陰性対照**。`--blocklist` 1本のとき従来どおり（PK-71 と同じ出力） | PK-71 の command をそのまま打つ | PK-71 と同じ（`1`、log が `"reason":"sni"`） |
| **PK-91** | `--blocklist a.txt --blocklist b.txt` で、b.txt だけに在る domain が block される | `printf 'a.example\n' > a.txt; printf 'b.example\n' > b.txt; packetdeath proxy --listen 127.0.0.1:8899 --blocklist a.txt --blocklist b.txt --deny 403 &` の後に `curl -sS -x http://127.0.0.1:8899 https://b.example/ 2>&1 \| grep -c 'CONNECT tunnel failed'; grep -c '"reason":"sni"' <log>` | `1`、`1` |
| **PK-92** | `--iplist x.txt --iplist y.txt` で、y.txt だけに在る IP 宛てが block される（reason は `iplist`） | `printf '192.0.2.1\n' > x.txt; printf '127.0.0.1\n' > y.txt; packetdeath proxy --listen 127.0.0.1:8899 --iplist x.txt --iplist y.txt --deny 403 &` の後に、`127.0.0.1` で待つ上流へ `curl -sS -x http://127.0.0.1:8899 http://127.0.0.1:<port>/ -o /dev/null -w '%{http_code}\n'; grep -c '"reason":"iplist"' <log>` | `403`、`1` |
| **PK-93** | 走行中に iplist を書き換えると 300 ms 後の判定が変わる（PK-74 の iplist 版） | `: > y.txt; packetdeath proxy --listen 127.0.0.1:8899 --iplist y.txt --deny 403 &` の後に PK-92 の curl（`200`）、続けて `printf '127.0.0.1\n' >> y.txt; sleep 0.4;` の後に同じ curl | 書き換え前 `200`、書き換え後 `403` |
| **PK-94** | feed script が2 file を作り、行数が下限以上になる。network が無ければ `--from` で同じ検査が通る。取得に失敗したら前の file が残る（陰性対照）。key の file が無い間は ThreatFox と URLhaus を取らずに `[warn]` を出し、前の list を残す | `scripts/pd-malware-feed.sh --out <dir> --from <fixture> --min-domains 1 --min-ips 1; echo "rc=$?"; wc -l <dir>/malware-domains.txt <dir>/malware-ips.txt`。陰性対照は、壊れた raw を置いた `--from` で同じ command を打ち、`cksum <dir>/malware-*.txt` を前後で比べる。key の file が無い場合は、`--from` を付けずに記録用の偽の `curl` を先頭に置いた PATH で打ち、ThreatFox と URLhaus への request を数える（PK-143） | `--from`：`rc=0` で、2 file の `wc -l` が下限以上。陰性対照は `rc=1` で cksum が同じ。key 無し：ThreatFox と URLhaus への request が 0 件、`[warn]` が出る、2 file の cksum が前後で同じ |

実機の完了条件は、本番の proxy 経由で feed に載った domain へ繋ぐと、`flows.jsonl` に `"decision":"block"` が出ることである。
この段階の実装では本番（`~/pd/`）を触らず、release binary を別の port で起動して同じ形を測る。
運用の手順（取る、行数を見る、proxy の引数に足す、再起動する、測る、誤遮断は allowlist で救う）は、`blocklists/README.md` の運用チェックリストが正本である。

## 段階7 proxy

段階7 は、packetdeath を CONNECT proxy として動かし、iPhone などの別端末の proxy 欄から指せるようにして、広告を同じように落とす。
落とす対象は広告と監視系の両方である。
「禁じ手」の2番目（proxy 設定）は、packetdeath が自分の端末の設定を書き換えることを指す。
利用者が別端末の proxy 欄へ packetdeath を手で指すのはこの禁じ手に当たらない。

**CLI**：`packetdeath proxy --listen <addr:port> [--blocklist <path>]... [--allowlist <path>] [--iplist <path>]... [--av <path>] [--log-dir <path>] [--allow-from <CIDR>]... [--deny blackhole|403]`。
option の意味は `block` と同じ。`--listen` に既定は置かない（必須。指定しなければ起動しない。`0.0.0.0` を黙って開かない）。

**判定**：`CONNECT host:port HTTP/1.1` の `host` を SNI と同じ扱い（`SniState::Ok(host)`）で `judge::run_judges_with_allowlist`（`src/judge.rs`）へ渡す。
当たったときの返し方は「拒否の形（`--deny`）」節のとおり。
当たらなければ上流へ TCP を張り `200 Connection Established` を返して双方向に中継する（復号しない）。
平文 HTTP の絶対 URL（`GET http://host/path HTTP/1.1`）も同じく `host` を取り出して判定する。
EasyList の path ルールは段階7 に入れない。
path 判定器を足す口は段階8（MITM）の後に空け、ここでは名前だけ予約する（段階8 は復号した host の file を scan するだけで、URL path を判定しない）（「判定を差し込む口」節と同じ形）。

**拒否の形（`--deny`）**：これは CONNECT を受けた後の TCP 層で byte を読み捨てる形であり、「採らない手段」表の「DNS 応答だけで落とす（sinkhole 型）」とは別物である。DNS には触らない。
CONNECT の1行で判定して 403 を返すと、相手に広告が見られていないことが伝わるので、既定を `blackhole` にする。
`--deny blackhole`（既定）は、判定が当たった CONNECT に `HTTP/1.1 200 Connection Established` を返し（繋がったふりをする）、以後 client から届く byte を読んで捨て、何も送り返さない。
上流へは1 byte も出さない（TCP を張らない）。偽の広告応答は返さない（段階7 は TLS を割らないので、client が信じる応答を作れもしない）。
広告サーバは接続が落ちたことを一切 知らず、page 側の JS には「読み込めなかった」（timeout / 応答なし）としてしか見えない。
page の `onload` が hold の分だけ遅れ得る副作用がある。
hold（既定 60秒。`ProxyLimits::blackhole_hold`。`--deny` の CLI には露出しない）の経過か client の EOF のどちらか早い方で閉じる ── 時間無制限には黙らない。同時に hold する接続数にも上限を置く（既定 256）。
`--deny 403` は従来どおり `HTTP/1.1 403 Forbidden` を返して閉じ、上流へ1 byte も出さない。動作確認や、気づかれてもよい用途はこちらを明示する。

**log**：`flows.jsonl` に1 flow 1行で書く（field は増やさない。「名前と置き場」の `flow log` 節）。
`proto` は `tcp`、`dst_ip` は上流 `host` を名前解決した結果。`src_ip` と `src_port` は proxy へ繋いだ client の peer（端末の LAN IP と一時 port）であり、上流へ出るときの proxy 自身の port ではない。
解決できなければ判定は `host` で行い、`dst_ip` は `0.0.0.0` を書く（名前解決失敗を表す既存の値が無いため、この値を割り当てる）。
`decision` は `pass` / `block`、`reason` は既存の値のまま。

**reload**：`block_loop::WatchInputs`（`src/block_loop.rs:177-244`）をそのまま使い、300 ms ごとに `poll_reloads` を呼ぶ（「走行中の読み直し」節と同じ）。

**依存**：std の `TcpListener` と、接続ごとの thread で作る。同時接続数に上限を設ける。
tokio は足さない。`block` / `observe` は全部 同期で書かれており、proxy だけ非同期ランタイムを足すと依存が2系統に割れる。
unsafe は使わない。crate は足さない。

**PAC（ローカル宛ては proxy を通さない）**：ローカル宛て（LAN 内の IP と `.local` 等の名前）の通信を、packetdeath の proxy を経由させない。それ以上でも以下でもない。
広告の判定や blocklist には触れない。

採らない手段は次の5つである。
- **Windows の除外欄だけで済ませる**：Windows PC は既に `ProxyOverride` に `<local>` と LAN の IP を持つ（2026-10-03 実測）。しかし iPhone の手動 proxy 設定には除外欄が無く、iPhone 側に手が無い。片方だけでは両端末に届かない。
- **PAC を別の web server で配る**：もう 1 つ動かし続ける物が増える。proxy は既に両端末から届く port を開いているので、同じ port で配るのが最少である。
- **proxy がローカル宛ての CONNECT を自分で中継する（今の形のまま）**：`.local`（mDNS）の名前は proxy の居る機械では解決できず、UDP や multicast は HTTP proxy へそもそも届かない。中継できても接続元が proxy の機械になり、端末間の直接通信にならない。「proxy を通さない」を満たさない。
- **PAC で `dnsResolve` を使って宛先 IP を判定する**：すべての接続で名前解決が走り、iOS で遅くなる。名前は接尾辞で、IP は literal の範囲で判定する。
- **MITM や CA 導入**：PAC の話ではないので、この節では扱わない（MITM は段階8）。

`GET /proxy.pac HTTP/1.x`（相対 path）を受けたら、`200 OK`、`Content-Type: application/x-ns-proxy-autoconfig`、`Connection: close`、`Content-Length` 付きで PAC を返して閉じる。
相対 path のうち PAC の応答にするのはこの path だけで、それ以外の相対 path は `400` である。
判定も log（`flows.jsonl`）も通さない（flow ではない）。stderr に `[info]` を 1 行だけ出す。
`--allow-from` の検査は PAC にも掛かる。accept の直後に、request を読む前に弾くからである。

PAC の中身は固定の `FindProxyForURL(url, host)` で、次の順に判定する。
1. `isPlainHostName(host)`、`localhost`、`*.local`、`*.lan`、`*.home` は `DIRECT`。IPv6 literal は `.` を含まないので、この行で `DIRECT` になる。
2. `host` が IPv4 literal（正規表現で判定）で `127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16` に入るなら `DIRECT`。
3. それ以外は `PROXY <addr>; DIRECT`。

`<addr>` は client が繋いできた側の socket の `local_addr`（`TcpStream::local_addr()`）である。`--listen 0.0.0.0:8081` でも、client が実際に届いた IP になる。
末尾の `; DIRECT` は、proxy が死んだとき通信を止めない fail-open である（「制約」の「遮断できないときは素通しに倒す」）。

利用者の手順は、iPhone なら「Wi-Fi、プロキシ構成、自動」に `http://<proxy IP>:<port>/proxy.pac` を入れる。Windows なら「セットアップ スクリプトを使う」に同じ URL を入れる。

**fail-open の形**：上流へ繋げない・名前解決できないときは `502 Bad Gateway` を返す。
`CONNECT` / `GET` の1行目が parse できないときは `400 Bad Request` を返して閉じる。
proxy は透過ではないので、Linux の nfqueue や Windows の pktmon と同じ「通す」は定義できない。
proxy process が死ぬと、`--listen` へ向けた client は繋がらなくなる。利用者が別端末の proxy 欄を外せば通信は戻る。

**i18n**：log と CLI の文言は `src/i18n.rs` の関数経由で出す（「i18n」節と同じ）。

**安全（open proxy 対策）**：`--listen` は LAN へ開くので、接続元を制限する。
`--allow-from <CIDR>` を複数回 渡せる任意 option とし、未指定なら loopback と RFC1918（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）だけを既定で受け付ける。
`--listen` を家庭内 LAN へ向けても、既定のまま公開 network へ露出させると誰でも使える open proxy になる。
既定を絞ることで、利用者が明示的に外部からの利用を選んだときだけ `--allow-from` で広げる形にする。

**着手条件**：段階2（PK-13）が通ったら。段階3〜6 を待たない。

### accept の失敗と初回応答の write

accept loop は `accept()` の `Err`（fd が尽きた `EMFILE` を含む）を `[warn]` に出し、100 ms 待ってから次の accept に戻る。待たずに `continue` すると、fd が戻るまで loop が CPU を食って回り続けるので、待ちを置く。fd が戻るまで新規の接続を受けられないことは変わらない（「残る穴」。上限は unit の `LimitNOFILE=65536` で、1 本の中継が fd を 4 本 使う）。`[warn]` は失敗のたびに 1 行で、まとめない（100 ms に 1 行が上限になる）。

client への初回応答（`200 Connection Established`、`403`、`502`、`400`、PAC、CA）の write は、request 行を待つ `request_read_timeout`（既定 30 秒）と同じ値の write timeout の下で行う。request を読む前に read と write の両方の timeout を 1 箇所で武装し、中継へ入るときに `pipe_idle_timeout` へ切り替える。書く量は数十 byte から数 KiB で、受信 buffer を読まない client が居ても thread と枠を無期限に握らない。

### 受入 ID（PK-70〜PK-80）

command は Linux（WSL）を前提に書く。`--log-dir` は「受入 ID」節冒頭の約束（`LOGDIR`）をそのまま使い、表では省く。
`<log>` は `$LOGDIR/flows.jsonl`。`packetdeath proxy` は root を要らないので `sudo` を付けない。
PK-71〜PK-75 は `--deny 403` を明示し、従来どおりの `403` 前提で測る（既定は PK-76〜77 の `blackhole`）。

| ID | 受入条件 | 打つ command | 通ったと判る出力 |
|---|---|---|---|
| **PK-70** | **陰性対照**。`--blocklist` 無しで CONNECT が `200` で通る | `packetdeath proxy --listen 127.0.0.1:8899 &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.com/; grep -c '"decision":"block"' <log>` | `200`、`0` |
| **PK-71** | blocklist に当たる CONNECT が `403` で、上流へ1 byte も出ない | `printf 'example.org\n' > bl.txt; packetdeath proxy --listen 127.0.0.1:8899 --blocklist bl.txt --deny 403 &` の後に `curl -sS -x http://127.0.0.1:8899 https://example.org/ 2>&1 \| grep -c 'CONNECT tunnel failed'; tail -1 <log>` | `1`（curl が `CONNECT tunnel failed, response 403` を出し、TLS handshake まで進まなかった印）。log が `"sni":"example.org"` と `"decision":"block"` と `"reason":"sni"` |
| **PK-72** | 当たらない CONNECT が通る | PK-71 の起動のまま `curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.com/` | `200` |
| **PK-73** | allowlist が blocklist に勝つ | `printf 'example.org\n' > al.txt; packetdeath proxy --listen 127.0.0.1:8899 --blocklist bl.txt --allowlist al.txt --deny 403 &`（`bl.txt` は PK-71 と同じ `example.org` を含む）の後に `curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.org/; tail -1 <log>` | `200`。log が `"decision":"pass"` と `"reason":null` |
| **PK-74** | 走行中に blocklist を書き換えると 300 ms 後の CONNECT が変わる | `: > bl.txt; packetdeath proxy --listen 127.0.0.1:8899 --blocklist bl.txt --deny 403 &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.org/`（`200`）、続けて `printf 'example.org\n' >> bl.txt; sleep 0.4; curl -sS -x http://127.0.0.1:8899 https://example.org/ 2>&1 \| grep -c 'CONNECT tunnel failed'` | 書き換え前 `200`、書き換え後 `1` |
| **PK-75** | 平文 HTTP の絶対 URL（`curl -x` の `http://`）が `host` で判定される | `printf 'example.org\n' > bl.txt; packetdeath proxy --listen 127.0.0.1:8899 --blocklist bl.txt --deny 403 &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 http://example.org/; tail -1 <log>` | `403`。log が `"sni":"example.org"` と `"decision":"block"` と `"reason":"sni"` |
| **PK-76** | 既定（`--deny` 未指定＝ `blackhole`）で blocklist に当たる CONNECT が繋がったふりをして黙る | `printf 'example.org\n' > bl.txt; packetdeath proxy --listen 127.0.0.1:8899 --blocklist bl.txt &` の後に `curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.org/; echo "exit=$?"; tail -1 <log>` | `000` と `exit=28`（curl が `200` を受け取った後、以後 byte が届かず `--max-time` で timeout する）。上流（偽の upstream）への接続は0件。log は `"decision":"block"` と `"reason":"sni"` |
| **PK-77** | `blackhole_hold` 経過後に接続が閉じられ、blackhole 枠が解放される | `tests/independent_proxy.rs::blackhole_hold_expires_and_releases_the_blackhole_slot`（`cargo test --test independent_proxy`） | `max_blackhole_connections: 1` の下で、1本目の hold 経過後に2本目の block CONNECT が `403`（枠満杯）でなく `200`（blackhole 入り）になる |
| **PK-79** | accept の失敗が `[warn]` に出て、loop が空回りしない（失敗の後に 100 ms 待つ） | unit は `cargo test --release --lib -- accept_failure_backoff_is_short_and_nonzero accept_failed_message_names_the_error`。本番：配備の後の journal を `sudo journalctl -u packetdeath-proxy --since -10min \| grep -c 'accept'`、対照に `\| grep -c 'packetdeath'` | unit 2 本 `ok`。本番は `accept` が `0`（fd は尽きていない）、対照が 1 以上 |
| **PK-80** | client への初回応答の write に timeout が在る（request 行の timeout と同じ 30 秒）。読まない client が thread と枠を無期限に握らない | unit は `cargo test --release --lib -- client_timeouts_are_armed_before_the_first_response`（listener と client の対を作り、武装の関数を呼んだ後の `write_timeout()` と `read_timeout()` が `request_read_timeout`）。本番：配備の後に `curl -sS -o /dev/null -w '%{http_code}\n' -x http://192.0.2.20:8081 https://example.com/` が `200` | unit `ok`。本番 `200` |
| **PK-78** | PAC が `/proxy.pac` で配られ、flow log に残らない。**陰性対照**として他の相対 path は `400` のまま | `packetdeath proxy --listen 127.0.0.1:8899 &` の後に `curl -sS -D - -o /dev/null http://127.0.0.1:8899/proxy.pac \| grep -c 'application/x-ns-proxy-autoconfig'`、`curl -sS http://127.0.0.1:8899/proxy.pac \| grep -c 'PROXY 127.0.0.1:8899; DIRECT'`、`grep -c proxy.pac <log>`、`curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8899/other` | `1`、`1`、`0`（flow log に残らない）、`400` |

PK-71・PK-74 の `CONNECT tunnel failed, response 403` は curl の error 文言である（`記憶`。実機で初めて打つときに手元の curl 版で文言を確かめ、違えばこの表を直す）。

## 段階8 MITM（復号して file を検査する）

段階8 は antivirus 機能の「(B) HTTPS の中身まで検査する」に当たる。
手段は「利用者が自分で CA を端末に入れ、packetdeath の proxy が HTTPS を復号して中身（file）を検査する」であり、それ以上でも以下でもない。これは禁じ手1を段階8 の範囲で外す（「禁じ手」節）。
復号は検査のためである。広告の判定を復号側へ移す話ではなく、広告は段階7 のまま SNI と宛先で判定する。

「(C) 端末に落ちた file を検査する」の Windows 側は、(B) の proxy で file を scan する形に寄せる。
(C) は段階8 の scan で満たす。Windows に AMSI provider も driver も入れず、Linux の `clamonacc` も作らない（file が落ちるのは端末であり、proxy を動かす機械ではない）。
寄せた結果、検査できるのは proxy を通った HTTPS の download だけになる。USB で入った file、proxy を通らない通信で入った file、平文 HTTP の download は検査しない。

scan で通信を遅くしないことは、「scan」の小節の「遅くしない形」が受ける。

### 結論と流れ

`--mitm-list` と `--ca-dir` と `--clamd` が3つ揃ったときだけ有効になる。
有効でも、復号するのは次の流れで「復号する」へ進んだ CONNECT だけである。

```
client --CONNECT--> 判定（段階7 のまま）
   block ------------------------------> deny（blackhole か 403）。復号しない
   pass --> 復号の条件を満たすか
              いいえ ------------------> 段階7 の非復号の中継
              はい --> 上流へ TCP と TLS
                        失敗 ----------> 段階7 の非復号の中継（上流へ張り直す）
                        成功 --> client へ 200 を返し、packetdeath の CA の leaf 証明書で TLS
                                  client が handshake に失敗 --> 切断し、bypass 表へ入れる
                                  成功 --> request を上流へ、応答の head を読む
                                            download ではない --> そのまま流す
                                            download で 8191 MiB 以下 --> 全部受けて clamd へ
                                                     FOUND --> 403 に差し替え
                                                     OK、ERROR、timeout --> 本文を流す
                                            8191 MiB 超 --> scan せずそのまま流す
```

図の結論は、「復号は条件を満たした CONNECT だけで、どこで失敗しても段階7 の通信か、scan 無しの通信に倒れる」である。

### CLI

`packetdeath proxy` に3つの option を足す。既定はすべて無効で、渡さなければ段階7 と同じ挙動になる（PK-100）。

| option | 意味 | 読み込み |
|---|---|---|
| `--mitm-list <path>` | 復号する domain。1行1 domain、`#` で始まる行は無視、サフィックス一致（`example.org` は `example.org` と `*.example.org` に当たる。blocklist と同じ）。大文字小文字は区別せず、末尾の `.` は捨てる | 起動時と走行中の読み直し（`WatchInputs`。300 ms ごと）。読めなくなったら前の内容を使う |
| `--ca-dir <path>` | CA の鍵と証明書の置き場。無ければ作る（権限 `0700`）。`ca.crt` と `ca.key` が無ければ生成する | 起動時に1回 |
| `--clamd <unix socket の path か addr:port>` | scan 先の clamd。`:` を含み socket address として読めれば TCP、それ以外は path | 起動時に1回 |

3つのうち1つか2つだけ渡されたときは、復号を無効にして起動し、足りない option 名を `[warn]` に出す。
`--clamd` が無いときに「復号はするが scan しない」形にはしない。scan 先が無いのに復号する理由が無い。
起動を止める案も採らない。設定の間違い1つで、proxy を使う全端末が繋がらなくなるからである。
`--clamd` に loopback 以外の TCP address を渡したときは `[warn]` を出す。file の本文が平文で network を渡るからである。
Windows では3つとも無視し、`[warn]` を出す（「TLS の部品」の判断）。

### 復号する範囲

次の6つを全部満たす CONNECT だけを復号する。1つでも外れれば段階7 の非復号の中継である。

1. 3つの option が揃い、CA を読めている。
2. 段階7 の判定を通った（blocklist、iplist、av のどれにも当たらなかった）。当たった CONNECT は deny のままで、復号しない。
3. host が allowlist に当たらない。allowlist は「何があっても通す」ための list であり、`allowlists/microsoft-required.txt` のように壊してはいけない宛先を並べている。復号は通信を壊しうる操作なので、allowlist に当たる host は触らず通す。この重なりは無言にしない。`--mitm-list` の項目が allowlist に当たるときは、起動時と読み直し時に、その host 名を `[warn]` で出す（本番の allowlist には `github.com` と `dl.dropbox.com` が在り、`allowlists/pihole-common.txt` にも同じ行が在る。allowlist は suffix 一致なので `codeload.github.com` も復号されない。いちばん先に `--mitm-list` へ書かれそうな download host が、黙って scan されないことになる）。
4. host が `--mitm-list` に当たる。
5. port が 443 で、host が IP literal でない。mail や push 通知の port、IP 直打ちの接続は復号しない。
6. (client の IP, host) の組が bypass 表に無い（「復号した通信の扱い」）。

allowlist が blocklist に勝つ既存の順は変えない。段階8 は判定の列の外側に1つ条件を足すだけで、判定器を足さない。
平文 HTTP の絶対 URL（`GET http://host/path`）は復号と関係が無く、本文を scan しない。

### TLS の部品

候補を表にする。版と license は 2026-10-03 に crates.io の API で読んだ（`実読`）。unsafe の欄は、各 crate の `src/lib.rs` の先頭を読んだ結果（`実読`）である。

| 候補 | 版 | license | 自分の unsafe | 備考 |
|---|---|---|---|---|
| rustls | 0.23.45 | Apache-2.0 OR ISC OR MIT | `#![forbid(unsafe_code, unused_must_use)]` | TLS の本体。暗号は provider に任せる。同期の API（`StreamOwned`）を持つ |
| rcgen | 0.14.10 | MIT OR Apache-2.0 | `#![forbid(unsafe_code)]` | CA と leaf の生成と署名。暗号は provider（`aws_lc_rs` か `ring`）に任せる |
| tokio-rustls | 0.26.6 | MIT OR Apache-2.0 | `lib.rs` に forbid の行が無い（`未確認`） | tokio が前提 |
| hudsucker | 0.25.0 | MIT OR Apache-2.0 | `未確認` | tokio、hyper、rcgen を束ねた MITM 部品。採らない（下の表） |
| aws-lc-rs（provider） | 1.18.1 | ISC AND (Apache-2.0 OR ISC) | C の aws-lc への FFI を含む | rustls の既定の provider。2026-09-01 に更新。build に cmake と C compiler が要り、この機械に在る（`実測`） |
| ring（provider） | 0.17.14 | Apache-2.0 AND ISC | Rust と C と asm | 2025-03-11 から更新が無い。RUSTSEC-2025-0007 で一度 unmaintained とされ、rustls の組織が security 修正を引き受けた（`検索`） |
| rustls-graviola（provider） | 0.4.0 | Apache-2.0 OR ISC OR MIT-0 | Rust と検証済みの asm。低層に unsafe | C compiler が要らない。README が「very new」と書く。rcgen の backend に選べない（rcgen の feature は `aws_lc_rs` と `ring` だけ。`実読`） |
| rustls-rustcrypto（provider） | 0.0.2-alpha | MIT OR Apache-2.0 | pure Rust | alpha のまま 2024-04 から更新が無く、監査が無い |
| webpki-roots | 1.0.9 | CDLA-Permissive-2.0 | データ crate | 上流の証明書を検証する根。GPL 系でない |

**採るもの：rustls と rcgen と webpki-roots。provider は aws-lc-rs の1つだけ**（rustls は `default-features = false` で `aws_lc_rs` `std` `tls12`、rcgen は `crypto` `pem` `aws_lc_rs` と、既存 CA の読み込みに要る `x509-parser`）。
provider を1つに揃える理由は、rustls と rcgen がそれぞれ別の provider を引いて依存木に2つの暗号実装が入るのを避けるためである。aws-lc-rs を選ぶ理由は、候補のうち更新が続いていて監査の厚い実装がこれだけだからである。sha256 の計算も同じ crate の digest を使い、crate を足さない。
build に使う依存は `nfq` と同じ形で Linux target に限る（`[target.'cfg(target_os = "linux")'.dependencies]`）。aws-lc-sys が `x86_64-pc-windows-gnu` で通るかは `未確認` で、試さない。本番の proxy は Linux で動き、Windows と iPhone は client として CA を入れるだけである。

**解釈を1つ置く。**要件の「pure Rust で unsafe 0 件」を、「packetdeath の code に unsafe を書かず（`forbid` のまま）、openssl を依存木に入れない」と読む。
読む根拠は2つある。制約④が「Rust の code に unsafe を書かない」であり、その検査（`grep -o -E '\bunsafe\s*\{' src/*.rs`）が自分の code だけを数えること。`Cargo.toml` の `windows-service` の comment が「`forbid` は依存 crate 内部の unsafe には及ばない」と既に決めていること。
依存木ごと unsafe が 0 件の TLS は、表のとおり存在しない。provider は C か asm か unsafe のどれかを含み、unsafe が無いのは alpha で未監査の rustls-rustcrypto だけである。
この読みが違えば、段階8 は止まる。

**tokio は足さない。**段階7 は接続ごとの thread で書かれ、`block` と `observe` も同期である。非同期の runtime を足すと依存が2系統に割れる。
復号した通信の処理は、1接続で1 request を順に処理する形（後述）なので、同期の thread で足りる。rustls の `StreamOwned` が std の `TcpStream` の上でそのまま動く。
この選択は WebSocket と HTTP/2 を捨てる代償を払う。捨てた物を見つけたときの扱いは「復号した通信の扱い」に書く。
将来 `--mitm-list` を広い範囲へ広げる日が来たら、hyper へ移す。移すときに HTTP の層だけを替えられるよう、CA と leaf の生成、clamd の client、scan の条件、bypass 表、`av.jsonl` の書き込みは HTTP の層に依存させない。

### 採らない手段

| 採らない手段 | 理由 |
|---|---|
| すべての domain を復号する | 証明書 pinning の app（銀行、Apple の service、Google Play、Microsoft 365 など）が壊れる。復号する domain を `--mitm-list` で明示し、list に無い domain は段階7 の非復号のまま通す |
| 復号した本文で広告を判定する（EasyList の path rule） | 要件は antivirus である。広告は段階7 のまま。範囲を広げない |
| 検体をクラウド（VirusTotal など）へ送る | `docs/research/av-latest-2026.md` の「採らない手段」。検体を外へ出さない |
| packetdeath が CA を端末へ入れる、proxy 設定を書き換える | 禁じ手2のまま。packetdeath がするのは CA の生成と `ca.crt` の出力までで、端末へ入れるのは利用者の手である |
| CA に name constraints を付けて `--mitm-list` の domain に縛る | 縛ると list に domain を足すたびに CA を作り直し、端末へ入れ直すことになる。運用中に人が書き換える物は再起動なしで反映するというこのプロジェクトの規範と両立しない。代わりに CA の有効期間を2年に絞り、鍵を `0600` で repo の外に置き、漏れたときの手順を決める |
| 平文 HTTP の本文も scan する | 名指しされた手段は HTTPS の復号である。同じ scan の部品を絶対 URL に当てるだけで足りるので、必要になったら別に足す |
| `hudsucker` と tokio を使う（`attic/mitm-proxy`） | 依存が `Cargo.lock` で 224 package になる（現行は 27。いずれも `grep -c '^name = '` で `実測`）。同期の proxy と非同期の島に割れる。さらに、上流の TLS が失敗したときに非復号へ倒す、client の handshake が失敗した host を覚える、という段階8 の fail-open が hudsucker の handler からは取れない |
| `attic/mitm-proxy` の `src/ca.rs`（208行）をそのまま持ち込む | 考え方だけ再利用する（CA の生成、鍵を `0600`、既存の CA を再利用）。code は持ち込まない。CN が `packetdeath-ca` に固定で世代を区別できない、`BasicConstraints::Unconstrained` で pathlen が無い、鍵を書いてから chmod するので書いた直後に読める隙間がある、片方の file が無いと残りを上書きする、有効期限を検査しない、という5点が段階8 の要求と合わない |
| `attic/mitm-proxy` の `src/request_log.rs`（295行）を持ち込む | 復号した URL の path と query を `requests.jsonl` に書く。段階8 は復号した URL、header、本文を log に書かない |
| `attic/mitm-proxy` の `src/cli.rs`、`src/main.rs`、`src/paths.rs`（計538行）を持ち込む | 現行の CLI（`--log-dir`、i18n、`WatchInputs`）と規約が別である |
| `clamav-client` crate（2.3.0、MIT） | INSTREAM は「`zINSTREAM\0`、長さ付きの塊、長さ0で終わり」の3段で、自前で数十行で書ける。crate を足す理由が無い |

attic の `src` と `tests` は7 file で1140行、`Cargo.lock` は2221行で、合わせて 3402 行になる（`git show attic/mitm-proxy:<path> | wc -l`。`実測`）。

### CA

**生成の形。**

| 項目 | 決め |
|---|---|
| 鍵 | ECDSA P-256（iOS と Windows の両方が読む） |
| CN | `packetdeath CA <生成日 YYYY-MM-DD>`。世代の違う CA を端末の一覧で区別できる |
| 有効期間 | 730 日。notBefore は生成の1日前（端末の時計のずれに備える）。鍵が漏れたときの被害の期間と、端末へ入れ直す手間の釣り合いで置いた（`推測`。実機で見て変える） |
| basicConstraints | CA、pathlen 0（leaf しか署名しない） |
| keyUsage | keyCertSign と cRLSign |
| 書き込み | 鍵は作成時に権限 `0600` で開く（書いてから chmod しない）。既存の file は上書きしない。`ca.crt` の書き込みに失敗したら、自分が作った `ca.key` を消して戻す |
| 起動時の検査 | 片方の file だけが在る、鍵の権限が `0600` より緩い、parse できない、期限が切れている、のどれかなら復号を無効にして `[error]` を出す。作り直さない（鍵を黙って上書きすると戻せない） |
| 起動 log | `ca.crt` の SHA-256 と SHA-1 の fingerprint と期限を `[info]` に出す。期限まで30日を切ったら `[warn]` |
| leaf | その host の SAN、serverAuth、ECDSA P-256、有効7日。host ごとに作って memory にだけ置く（1日で作り直す。上限256 host。disk に書かない） |

**`ca.crt` の配り方。**proxy が PAC と同じ口で `ca.crt` を配る。`GET /ca.crt HTTP/1.x`（相対 path。query 無し）を受けたら、`200 OK`、`Content-Type: application/x-x509-ca-cert`、`Content-Length`、`Connection: close` 付きで `--ca-dir` の `ca.crt` の PEM をそのまま返して閉じる。MITM が無効（`--mitm-list` / `--ca-dir` / `--clamd` の 3 つが揃っていない）なら従来どおり `400`。`ca.key` は配らない（`GET /ca.key` は `400`。path は固定の 1 つだけで、`--ca-dir` の他の file にも届かない）。PAC と同じく flow ではなく、判定も `flows.jsonl` も通さず、stderr に `[info]` を 1 行 出す。`--allow-from` の検査は同じく掛かる。端末からは `http://<proxy IP>:<port>/ca.crt`（例：`http://192.0.2.20:8081/ca.crt`。192.0.2.20 は文書用の例で、実際の address に読み替える）で取れる。受入は PK-111 である。
採らない手段：別の静的 file server を立てる（部品が 1 つ増え、落ちたときに残る物が増える）。`Content-Disposition: attachment` を付ける（iPhone の Safari は `application/x-x509-ca-cert` の応答を profile として受けるが、attachment を付けると Files へ落ちて profile にならない。`記憶`）。

**端末へ入れる手順。**1段階1操作で書く。画面の文言は `記憶` で、実機で初めて打つときに確かめて直す。

iPhone：
1. proxy を起動し、起動 log の fingerprint（SHA-256）を控える。
2. iPhone の **Safari**（Chrome ではない。profile のダウンロードを受けるのは Safari だけ。`記憶`）で `http://192.0.2.20:8081/ca.crt` を開く。
3. 「このWebサイトは構成プロファイルをダウンロードしようとしています」に「許可」を押す。
4. 設定を開き、上部の「プロファイルがダウンロード済み」を押して「インストール」する。
5. 設定、一般、情報、証明書信頼設定を開き、packetdeath CA のスイッチを入れる。
6. 証明書の詳細に fingerprint が出る画面があれば、手順1の値と照合する（出る画面は `未確認`）。

Windows（現在のユーザーの store にだけ入れる。LocalMachine には入れない。管理者権限が要り、全ユーザーに及ぶため）：
1. PC のブラウザで `http://192.0.2.20:8081/ca.crt` を開き、`ca.crt` を保存する（保存先の path を控える）。
2. PowerShell を開く（管理者でなくてよい）。
3. `certutil -user -addstore Root "<path>\ca.crt"` を打つ。
4. 出るセキュリティ警告に「はい」を押す。
5. `(Get-ChildItem Cert:\CurrentUser\Root | Where-Object Subject -like '*packetdeath CA*' | Measure-Object).Count` が `1` になることを確かめる。

Firefox は独自の信頼 store を持ち、段階8 の対象外である。

**消し方。**

iPhone：
1. 設定、一般、VPN とデバイス管理を開く。
2. packetdeath CA のプロファイルを開き、「プロファイルを削除」を押す。
3. 設定、一般、情報、証明書信頼設定の一覧から packetdeath CA が消えていることを確かめる。

Windows：
1. Win+R で `certmgr.msc` を開く。
2. 「信頼されたルート証明機関」、「証明書」を開く。
3. `packetdeath CA <日付>` を右クリックして「削除」する。
4. 手順5と同じ command が `0` を返すことを確かめる。

**鍵が漏れたとき。**端末が旧 CA を信じている間は、鍵を持つ者がその端末に任意の site を名乗れる。だから端末から旧 CA を消すことを最初に置く。
1. 全端末から旧 CA を消す（上の「消し方」）。
2. proxy を止める。
3. `--ca-dir` の中身を消す。
4. proxy を起動する（新しい CA が生成され、log に新しい fingerprint が出る）。
5. 新しい `ca.crt` を全端末へ入れる（上の「端末へ入れる手順」）。

手順1から5の間、復号した通信は handshake に失敗して bypass 表へ入り、scan 無しの通信に倒れる。通信は止まらない。

### 復号した通信の扱い

復号した通信は、1つの TLS 接続で1 request だけを処理する。応答に `Connection: close` を付けて閉じる。
上流への request は `Connection: close` を付け、`Accept-Encoding` を `identity` に替え、`Expect` と `Proxy-Connection` と `Keep-Alive` を落とす。`identity` にする理由は、client が保存する file の bytes をそのまま scan するためである。
client 側と上流側のどちらにも ALPN は `http/1.1` だけを申し出る。HTTP/2 は使わない。

扱える物は、HTTP/1.1、`Content-Length` の body、chunked の body（request と応答）、接続が閉じるまでの応答である。request の body は streaming で上流へ写し、溜めない。
扱えない物は、`Upgrade`（WebSocket を含む）、`Content-Length` が2つで値が違う request や応答、`Transfer-Encoding` と `Content-Length` の同居、head が段階7 の上限（1行8 KiB、100行）を超える物である。見つけたら応答の head を送る前なら `501`（応答側の矛盾は `502`）を返して閉じ、その (client の IP, host) を bypass 表へ入れる。次の接続から非復号になる。

**bypass 表。**(client の IP, host) の組を memory にだけ持つ。寿命1時間、上限4096組（超えたら古い組から捨てる）。再起動で消える。
入れる契機は3つある。client が TLS alert を送ってきたとき（handshake の途中でも後でも）。client が handshake の後に request を 1 byte も送らず無通告（close_notify 無しの EOF か reset）で切ったとき。復号したままでは扱えない request を見たとき。次の3つは契機にしない。close_notify 付きの切断。TLS の byte を 1 つも送らずに閉じた、または止まった接続（leaf を見ていないので拒否の根拠が無い。`[debug]` 1 行）。handshake の途中（ClientHello の後、Finished の前）の alert 無しの切断（Chrome は起動直後に証明書検証の設定を読み直し、待ち中の接続を `ERR_ABORTED` で捨てる。2026-10-03 に net log で `実測`：`CERT_VERIFY_PROC_CREATED` 3 回、`SSL_ALERT_SENT` 0 件。証明書を拒んではいない）。handshake の途中で拒否とみなすのは alert、timeout（byte を 1 つでも読んだ後）、TLS の error だけである。線引きは「alert は明示の拒否、alert 無しの途中切断は曖昧」で、曖昧な切断を免除に入れると scan が黙って止まり、入れ損ねたときは `[warn]` と app の不通で失敗が見える、という非対称による。
無通告の切断だけは、**成功の記憶**で打ち消す。(client の IP, host) ごとに「最後に request の最初の 1 byte を読めた時刻」を memory に持ち（上限は bypass 表と同じ 4096 組で古い組から捨てる。寿命は 60 秒の窓そのもの）、無通告の切断を見てもその組が直近 60 秒（`MitmLimits` の `recent_request_window`）以内に request を始めていれば bypass に入れない。理由は、Chrome（BoringSSL）が page を読んだ直後に、使わなかった兄弟 socket を close_notify 無しに切るからである（2026-10-03 に headless Chrome で `実測`：page を 1 回 読むだけで `bypass 表へ入れた` が出て、以後 1 時間 scan が止まった）。pinning の client は request を 1 byte も送らないので、取り違えは起きない。CA を信じていない Chrome は全 socket が失敗して request が 0 のままなので、正しく bypass に入る。alert を成功の記憶で打ち消さないのは、同じ端末の browser と pinning の app が同じ host を使うとき、browser が動いている限り app が bypass に入れなくなるからである。
curl 8.18 + OpenSSL 3.5 は handshake を Finished まで済ませてから証明書を確かめ、alert 無しに切る（2026-10-03 `実測`）。request が無いので無通告の切断として bypass に入り、PK-107 が成り立つ。
組で持つ理由は、CA を入れていない端末の失敗が、CA を入れた端末の scan を止めないようにするためである。寿命1時間は、CA を入れた直後に scan が始まるまでの待ちと、pinning の app が失敗する頻度の釣り合いで置いた（`推測`。実機で見て変える）。

**最初の1回は失敗する。**pinning を事前に知る手段が無いので、client が packetdeath の CA を信じない host への最初の接続は handshake に失敗する。2回目から非復号で通る。
Microsoft の認証系は、一度失敗すると通信を戻しても繋がらず、再起動まで直らない（`転記`。Microsoft 側のネガティブキャッシュと見ている）。この種の host は「最初の1回の失敗」が許されないので、`--mitm-list` に入れない。

**pinning 相当の失敗の倒し先（PK-107 の決め）。**502 には倒さず、段階7 の非復号へ倒す。
client の handshake が失敗した時点で `200` は返し済みで、TLS の外側へ HTTP の `502` を返す経路が無い。だから「次の接続から非復号」である。
上流側の失敗（TCP は張れたが TLS が失敗した）は `200` を返す前なので、その場で段階7 の非復号へ倒す。倒すと client が上流の証明書を自分で検証するので、段階7 より悪くならない。上流へ TCP を張れない、名前解決できない場合は段階7 と同じ `502` である。

### scan

**scan に流す条件。**次の全部を満たす応答だけを clamd へ流す。

| 条件 | 決め |
|---|---|
| request | method が `GET` |
| 応答の status | `200` だけ（`206` の部分応答、`304`、`4xx` は流さない） |
| 本文の種類 | `Content-Disposition: attachment` なら種類を問わず流す。attachment でない応答は、`Content-Type` の media type が次の「流さない物」のどれにも当たらないときに流す。流さない物：`text/html`、`text/css`、`text/xml`、`text/event-stream`、`text/javascript`、`application/javascript`、`application/x-javascript`、`application/ecmascript`、`application/json`、`application/*+json`、`application/xml`、`application/xhtml+xml`、`image/*`、`video/*`、`audio/*`、`font/*`（page の部品、media、API の応答、SSE）。`Content-Type` が無い応答と `text/plain` は流す。条件を「流す物」ではなく「流さない物」の列挙にしたのは、流す物を列挙すると header を省いた応答が素通りするからである。SSE を流すと、`Content-Length` が無いので 20 MiB まで溜めて head を出さず、SSE が止まる |
| `Content-Encoding` | 無い、または `identity`（それ以外は流さず `[info]`） |
| 大きさ | `Content-Length` が1以上 8191 MiB（8588886016 byte）以下。`Content-Length` が無い応答は、8191 MiB を超えるまで溜めて、超えたら scan を諦める |

8588886016 byte ちょうどは scan し、+1 byte は scan しない。上限は clamd の `StreamMaxLength`＝`MaxFileSize`（8191M）と同じ定数から出す（PK-118）。配布の libclamav は `MaxFileSize` を設定の値にかかわらず 2 GiB−1（`INT_MAX - 2`）に丸めるので、2 GiB を超える値は丸めを外して自前で build した clamd（「clamd の自前 build」の小節、PK-114）でだけ効く。関係は `proxy の上限 ≤ StreamMaxLength ＝ MaxFileSize`、`MaxScanSize ≥ 2 × MaxFileSize`、`clamd の MaxScanTime < proxy の timeout`、`proxy の上限 ≤ scan の予算 < MemoryMax`（上限 8191 MiB と予算 8 GiB は同じ大きさなので、上限いっぱいの download は 1 本ずつ通る）。
公式の EICAR 配布 host は、`eicar.com.txt` が `text/plain`、`eicar.com` が `Content-Type` 無し、`eicar_com.zip` が `application/zip` を返す（`curl -I` で `実測`、2026-10-03）。3つとも流れる。
この反転が塞ぐのは、正直だが無印の応答（`eicar.com`、`text/plain` の script）だけである。`image/png` のような流さない物を名乗る server は抜ける（「残る穴」）。

**遅くしない形。**scan で通信を遅くしない。

| | 決め | 理由 |
|---|---|---|
| a | scan に流すのは download だけ（上の表）。page の部品、media、API の応答、SSE は流さない | 通信の大半は page の部品と media で、これを溜めて待つと page が遅くなる。API の JSON を流すと、request ごとに `av.jsonl` の `clean` と `[info]` が 1 行ずつ増え、溜めている間は scan の予算を握る |
| b | scan は復号した通信を扱う接続ごとの thread の中で行う。段階7 の接続ごとの thread のまま、他の接続を待たせない | thread を共有する worker や queue を足さない |
| c | clamd への接続と、送信と応答の待ちに timeout を置く（scan は既定 1260 秒、起動時の PING は別の定数で 10 秒）。超えたら `[warn]` を出して本文を流す（fail-open） | clamd が詰まっても、待たされるのは scan 対象の1接続だけで、上限 1260 秒で終わる。1260 秒の根拠（PK-118）：上限 8191 MiB を、本番の生の INSTREAM の最も遅い実測 10.3 MB/s で割った 834 秒の 1.5 倍を 60 秒単位で切り上げた物（`実測`：2 GiB の丸めだけ外した clamd で乱数 2.5 GiB が 259.63 秒、上限ちょうどの 4293918720 byte が 233.35 秒、64-bit 化の clamd64 で 4.5 GiB の印付きが 205.42 秒、印なしが 237.95 秒＝23.5 / 20.3 MB/s。速い方で決めると 660 秒になり、10 MB/s の回は 8 GiB 級が毎回 `MaxScanTime` で未了になる）。archive は展開した中身も数えるので `MaxScanSize`（16382M）の分まで走りうるが、clamd の `MaxScanTime` は 1134 秒（timeout の 0.9 倍）で proxy より短くし、時間切れは clamd が先に `Heuristics.Limits.Exceeded` で返す（下の fail-open の表の「検査未了」）。定数 1 つの代償は、clamd が固まると小さい download も最長 21 分 止まること（固まった実績は 0 件）。timeout を 10 秒にしない根拠：利用者が新しく落とす file は clamd の cache（archive の中身の file ごとの hash）に無い「中身まで cold」で、2 MB の zip（16 file）が 4.6 秒、679 file の zip が 9〜10 秒（`実測`）。費用は大きさでなく file 数と中身の種類で決まり、1 file あたり約 10 ms（`推測`）。10 秒では cold な zip の download が無検査で通る。起動時の PING を 10 秒に留めるのは、`Mitm::start` が bind の後 serve の前に走り、詰まった clamd に待たされる間 PAC も CONNECT も backlog で止まるため |
| d | 本文は clamd へ流しながら client へ流す（tee）のではなく、上限（8191 MiB。「scan」の小節の「大きさ」）以下の分を全部受けてから scan し、結果を見て返す | tee は FOUND が出る前に本文の先頭を client へ送ってしまい、後から 403 に差し替えられない。全部受けてから返す形なら、差し替えが1回の応答で済む。代償は、scan 対象の file が scan の終わりまで1 byte も届かないこと。上限は 8191 MiB で、memory は接続あたり最大 8191 MiB、溜めている本文の合計は scan の予算 8 GiB まで（proxy の unit に `MemoryMax=12G` を当て、超えたら proxy だけが落ちて systemd が 2 秒で戻す。機械の OOM より安い）。待ちは scan の終わりまで（最長 1260 秒） |
| e | clamd と freshclam は proxy より低い優先度で動かす | 署名の更新や scan が、proxy の通信に使う CPU を奪わないため。値は「運用」の小節に書く |

同時に溜める本文の合計にも上限を置く（scan の予算、既定 8 GiB）。scan に流す前に `Content-Length` の分（無い応答は上限の 8191 MiB）を予算から取り、足りなければ scan せず流して `[warn]`（`slot_full`）を出す。取った分は応答を返し終えたときに戻す。本数でなく bytes で数えるのは、上限が 8191 MiB だと本数の上限（4 本）では最大 32 GiB になり `MemoryMax=12G` を超えるからで、bytes なら 8191 MiB は 1 本、4 GiB は 2 本、1 GiB は 8 本と、memory に合わせて本数が決まる。`Content-Length` が無い応答は上限の分を予算から取り、`reserve_exact` で同じ分を先に確保する（予算から取った分と buffer の容量を一致させる。確保は仮想で、届いた分だけが RSS になる）。予約は仮想で、RSS は届いた分だけである（`vm.overcommit_memory` は `0`、1073228327 byte の本文で `MemoryPeak` は 1101180928。`実測`）。本文を溜めている間も予算を握るので、大きい download が重なると、その間の他の scan 対象は `slot_full` で素通しになる（「残る穴」）。
本文は memory にだけ置き、disk に書かない。

**clamd との会話。**1回の scan ごとに clamd へ1本繋ぐ。`zINSTREAM\0` を送り、64 KiB 以下の塊を「4 byte の big endian の長さ、その長さの bytes」で送り、長さ0の塊で終える。応答は NUL までを読み、次の3つに分ける。

| 応答の形（`実測`。下の「clamd の応答の実測」） | 扱い |
|---|---|
| `stream: OK` | clean |
| `stream: <signature> FOUND` | 検知。`<signature>` は空白を含みうる |
| 上のどちらでもない（`INSTREAM size limit exceeded. ERROR` を含む） | error。通す |

起動時に `zPING\0` を送り、`PONG` が返らなければ `[warn]` を出す。起動は止めない（clamd が後から上がることがある）。

**verdict ごとの動き。**

| verdict | client へ返す物 | flows.jsonl | av.jsonl | stderr |
|---|---|---|---|---|
| FOUND | `403 Forbidden`、`Content-Type: text/plain; charset=utf-8`、短い本文（locale に従う。signature 名は出さない） | `"decision":"block"` と `"reason":"av"` の1行を足す | `malicious` の1行 | `[info]` に host、signature、sha256 |
| OK | 溜めた本文をそのまま返す | 足さない | `clean` の1行 | `[info]` に host、sha256 |
| ERROR、timeout、clamd 不通、枠満杯 | 溜めた本文をそのまま返す | 足さない | 足さない | `[warn]` |
| 検査未了（clamd が `AlertExceedsMax yes` で `Heuristics.Limits.Exceeded.` で始まる名を FOUND として返す。`MaxScanSize`、中身の `MaxFileSize`、`MaxFiles`、`MaxRecursion`、`MaxScanTime` のどれかを超えた） | 溜めた本文をそのまま返す（`403` にしない。fail-open の原則） | 足さない | 足さない | `[warn]` に host と署名名 |
| scan に流さない | そのまま流す | 足さない | 足さない | 閾値超過と encoded は `[info]`（設計どおりの素通し）、枠満杯は上の行の `[warn]`（scan できなかった劣化）、対象外の種類は `[debug]` |

復号した通信でも `flows.jsonl` の field は増やさない。CONNECT で書く1行（`pass`）は段階7 のままで、FOUND のときだけ `block` の行がもう1行 増える。`Reason::Av` は段階6 で予約済みの値をそのまま使う（add-only）。
`sha256` は溜めた本文の SHA-256 である。log に URL、header、本文、cookie を書かない。書くのは host、sha256、verdict、engine までである。

**av.jsonl。**`<log dir>/av.jsonl` へ追記する。段階8 が有効なときだけ開く。形式は段階6 の1 verdict 1行（`ts`、`proto`、`dst_ip`、`dst_port`、`sha256`、`verdict`、`engine`）で、field は足さない。`dst_ip` は実際に繋いだ上流の IP、`dst_port` は 443、`engine` は clean が `clamav`、malicious が `clamav:<signature>` である。
この file は段階6 の reader（`AvList::parse`）がそのまま読める。error の行は書かない。reader は `malicious` 以外を clean と数えるので、error を書くと「scan した」と誤って数えられる。
この file を同じ proxy の `--av` へ渡すと、`malicious` の行の宛先 `IP:443` が `--ips-ttl` 秒 落ち、同じ IP の別 site も巻き込まれる。既定の運用では渡さない。`--av` は起動時にしか読まない。

### fail-open の形

| 事象 | いつ | 返す物 |
|---|---|---|
| CA が読めない、期限切れ、権限が緩い、片方の file だけ在る | 起動時 | 復号を無効にして段階7 のまま起動する。`[error]` |
| 3つの option の一部だけ、または Windows | 起動時 | 復号を無効にして起動する。`[warn]` |
| 上流へ TCP を張れない、名前解決できない | CONNECT の処理中 | `502`（段階7 と同じ） |
| 上流の TLS が失敗した（証明書の不正、古い TLS、client 証明書の要求） | `200` の前 | 段階7 の非復号へ倒す（上流へ張り直す）。`[warn]` |
| leaf 証明書を作れない | `200` の前 | 段階7 の非復号へ倒す。`[error]` |
| client が復号を拒んだ（alert、または request 無しの無通告の切断で直近 60 秒に成功の記憶が無い） | `200` の後 | 切断し、bypass 表へ入れる。次の接続から非復号。`[warn]`（理由：alert / 無通告 / handshake 未完） |
| client が request 無しに無通告で切ったが、同じ (client の IP, host) に直近 60 秒の成功の記憶が在る | `200` の後 | 閉じるだけ。bypass 表に入れない。`[debug]` |
| client が TLS の byte を 1 つも送らずに閉じた、または止まった | `200` の後 | 閉じるだけ。bypass 表に入れない。`[debug]` |
| client が handshake の途中に alert 無しで切った | `200` の後 | 閉じるだけ。bypass 表に入れない。`[debug]` |
| 扱えない request や応答 | `200` の後 | `501` か `502` を返して閉じ、bypass 表へ入れる。`[warn]` |
| 上流が応答の head を返す前に落ちた | `200` の後 | `502`（TLS の内側で返す） |
| scan 対象の本文の途中で上流が落ちた | head を送る前 | `502` |
| そのまま流している本文の途中で上流が落ちた | head を送った後 | 接続を閉じる |
| clamd に繋げない、timeout、ERROR | scan 中 | 溜めた本文を流す。`[warn]` |
| 8191 MiB 超、scan の予算が足りない | scan の前 | scan せず流す |

### 安全

`--mitm-list` に無い domain は復号しない。list は既定で空であり、迷ったら入れない。
`--allow-from` による open proxy 対策は段階7 のままである。

`--mitm-list` に入れてはいけない物を挙げる。根拠の無い物は `推測` と付ける。

| 入れない物 | 理由 | 出所 |
|---|---|---|
| Microsoft の認証と OneDrive（`login.microsoftonline.com`、`login.live.com`、`*.login.microsoftonline.com`） | 一度失敗すると通信を戻しても繋がらず、再起動まで直らなかった。同梱の `allowlists/microsoft-required.txt` に当たる host は、allowlist が復号を止める | `転記`（観測）、`実読`（allowlist の中身） |
| Windows Update と Defender（`*.update.microsoft.com`、`*.delivery.mp.microsoft.com`、`wdcp.microsoft.com`） | 更新と保護が止まる。Defender を妨げるのは本末転倒である | `blocklists/README.md` の「絶対に入れないもの」と同じ判断。pinning の有無は `推測` |
| Apple の service（`*.apple.com`、`*.icloud.com`、`*.mzstatic.com`） | app が証明書を固定している可能性がある | `推測` |
| 銀行と決済の app が繋ぐ host | app が証明書を固定している可能性がある | `推測` |
| Google Play と Google の app API（`*.googleapis.com`） | app が証明書を固定している可能性がある。Chrome の同期の不調と切り分けられなくなるので、段階8 では入れない | `推測` |
| password manager、メッセージ app（Signal など）の host | 証明書の固定、または独自の信頼 store を使う可能性がある | `推測` |
| client 証明書を要求する host | client の証明書を持たない leaf では handshake の先へ進めない | 一般論（`推測`） |

復号した通信の URL、header、本文、cookie は log に書かない。本文は memory にだけ置く。
`ca.key` を読める者は、端末が CA を信じている間、その端末に任意の site を名乗れる。権限は `0600`、置き場は repo の外（本番は deploy 先の directory）である。
復号して見えるのは利用者自身の通信である。他人の端末を proxy に通さない（`--allow-from` の既定のまま）。

### 運用

CA と `--mitm-list` と `--clamd` は、本番の proxy の systemd unit の起動引数に足す。足すのと再起動は人が打つ。packetdeath は unit も timer も触らない。
`--mitm-list` は走行中に書き換えてよい（300 ms 後に効く。PK-106）。CA と `--clamd` を替えるときは proxy を再起動する。

本番の proxy が動く機械の clamd の実測値（2026-10-03）。

| 値 | 実測 |
|---|---|
| socket | `/var/run/clamav/clamd.ctl`（mode 666）。proxy の user がそのまま繋げる |
| 版 | clamav 1.5.4。binary は自前 build の `/opt/clamav-64/sbin/clamd64`（「clamd の自前 build」と「libclamav の 64-bit 化」の小節）で、2 GiB の丸めだけ外した `/opt/clamav-2g/sbin/clamd` と配布の package は戻し先として入れたまま |
| `TemporaryDirectory` | `/var/tmp/clamav`（tmpfs でない disk、`clamav` 所有の 0700。書庫の展開分を RAM に乗せない） |
| `StreamMaxLength` | `8191M`（`/etc/clamav/clamd.conf`。2 GiB を超える値は自前 build の libclamav でだけ効く。`MaxFileSize` と同値にする：同値を崩すと、`MaxFileSize` 超の stream 全体を clamd が検査せず OK と返す経路（libclamav/scanners.c の `CL_SUCCESS`）が開く） |
| `MaxFileSize` | `8191M`（同上） |
| `MaxScanSize` | `16382M`（archive の外側と中身の合計で数えるので `MaxFileSize` の 2 倍 以上） |
| `MaxScanTime` | `1134000`（1134 秒。proxy の timeout 1260 秒より短くし、時間切れは clamd が先に `Heuristics.Limits.Exceeded` で返す） |
| `AlertExceedsMax` | `yes`（limit 超を `Heuristics.Limits.Exceeded.*` の FOUND として返させ、proxy は「検査未了」として本文を流す。無いと時間切れと limit 超が OK に畳まれる） |
| `PCREMaxFileSize` | `25M`（据え置き。25M 超の file には PCRE の部分署名が走らない。「残る穴」） |
| 設定の反映 | `clamd.conf` は restart でしか読み直されない（`reload`（USR2）は DB だけ）。退避 `clamd.conf.prev-<日付>`、restart の直前 1 分の journal に list の host の行が 0 であることを見る。約 11 秒の fail-open の窓、cache は消える。clamd の temp は tmpfs（`PrivateTmp=no`）で、4 GiB の scan は RAM を使う |
| 署名の反映 | `EnableReloadCommand false` かつ `SelfCheck 3600` なので、新しい署名の反映は最長1時間 遅れる。すぐ反映するには `sudo systemctl reload clamav-daemon`（USR2。2026-10-03 に 11 秒を確かめた（`実測`）。`clamdscan --reload` は通らない） |
| freshclam | `Checks 24`（1日24回） |
| 動作 | EICAR で `FOUND`、clean で `OK`。2026-10-03 11:28 に実測済み |

clamd と freshclam は proxy より低い優先度で動かす。systemd の drop-in で `clamav-daemon.service` と `clamav-freshclam.service` に `Nice=10` と `CPUWeight=50` を当てる。
2026-10-03 に `systemctl show <unit> -p Nice -p CPUWeight` で、2 unit とも `Nice=10` と `CPUWeight=50` を確かめた（`実測`）。proxy の unit は既定（`Nice=0`、`CPUWeight=100`）のままである。

運用の手順書（取る、足す、再起動する、測る、誤検知を救う）は `docs/mitm-runbook.md` に在る（`blocklists/README.md` と同じ形）。誤検知は ClamAV 側の sha256 の許可 list（`/var/lib/clamav/local.sfp`、`<sha256>:*:<名前>:73`。archive は外側の sha256 でよい）で file 1 本だけを救い、proxy に許可 list を持たせない（ClamAV と二重になるため）。403 の本文に署名名と sha256 を載せる案も採らない（journal の `[info]` に在り、Chrome は download の 403 の本文を見せない。`記憶`）。

clamd の unit には `MemorySwapMax=0` の drop-in（`noswap.conf`）も当てる。clamd の anon page（約 300 MB）が swap に出て scan が 10 秒を超える疑いを断つためである。疑いの根拠は、cold な zip の scan 10.90 秒と swap-in 2512 page（当時の値は遡れず `NOT VERIFIED`）。drop-in を当てた後の受入（restart から 40 分 以上 置いた後の cold な scan が 2 秒 未満、swap-in 0）は落ちた（2026-10-03 22:07 `実測`：16 file の zip 4.60 秒、679 file の zip 9.19 秒、swap-in 0）。遅さの正体は、clamd が archive の中身の file ごとに hash で cache しており、新しい file は常に「中身まで cold」で 4.6〜10 秒 掛かること（外側の hash だけ変えた 2 回目は 1.82 / 2.52 秒。`実測`）。swap が原因だったかは立証されていない（`NOT VERIFIED`）。drop-in は害が無い（RAM 約 300 MB）ので残し、timeout は 10 秒にしない（上の表の c、PK-112）。

### clamd の応答の実測

次の値は 2026-10-03 に測った。EICAR の文字列は repo に入れない（on-access scanner が repo を隔離する。段階6 と同じ規則）ので、EICAR を流した command は書かず、結果だけを書く。

| 値 | 測った command | 結果 |
|---|---|---|
| clamd の版と署名 DB | `clamd --version` | `ClamAV 1.5.4/28141/Fri Oct  2 15:26:12 2026` |
| clamd の設定の一部 | `grep -E '^(ReadTimeout\|ArchiveBlockEncrypted)' /etc/clamav/clamd.conf` | `ReadTimeout 180`、`ArchiveBlockEncrypted false` |
| PING | `printf 'zPING\0' \| nc -U -q1 /var/run/clamav/clamd.ctl` | `PONG` |
| INSTREAM の clean | `printf 'zINSTREAM\0\0\0\0\x05hello\0\0\0\0' \| nc -U -q2 /var/run/clamav/clamd.ctl` | `stream: OK` |
| INSTREAM の検知 | 上と同じ形で、68 byte の標準の EICAR を1塊で流す | `stream: Eicar-Test-Signature FOUND` |
| `StreamMaxLength` 超 | 上と同じ形で、`StreamMaxLength 25M` の設定のときに 26214401 byte の `/dev/zero` を1塊で流す | `INSTREAM size limit exceeded. ERROR` |
| 20 MiB の clean | 同じ形で 20971520 byte の `/dev/zero` を流す | `stream: OK`。全体で約5.3秒（`nc -q2` の2秒待ちを含む。clamd の処理だけの時間ではない） |
| EICAR 配布 host の header | `curl -sS -I https://secure.eicar.org/eicar.com.txt`（`eicar.com`、`eicar_com.zip` も同様） | `text/plain`、`Content-Type` 無し、`application/zip` |
| clamd と freshclam の優先度 | `systemctl show clamav-daemon -p Nice -p CPUWeight`（freshclam も同様） | `Nice=10`、`CPUWeight=50` |
| freshclam の頻度 | `grep -E '^Checks' /etc/clamav/freshclam.conf` | `Checks 24` |
| 依存の数 | `git show attic/mitm-proxy:Cargo.lock \| grep -c '^name = '`、現行は `grep -c '^name = ' Cargo.lock` | 224 と 27 |
| build の道具 | `command -v cmake gcc clang` | 3つとも在る |

実測していない物は、`x86_64-pc-windows-gnu` での aws-lc-sys の build、iPhone と Windows の画面の文言、Chrome と iPhone の app が packetdeath の CA でどこまで通るかである。段階8 を組み込んだ後の依存の数は 87 package（`grep -c '^name = ' Cargo.lock`。2026-10-03 `実測`。段階7 までは 27）。lock に `ring` 0.17.14 が 1 つ載るが build されない（`cargo tree -i ring --target all` が "nothing to print"）。lockfile を見る `cargo audit` は RUSTSEC-2025-0007 を拾いうる。

### clamd の自前 build

配布の clamd は 2 GiB 以上の file を検査しない。
libclamav が `MaxFileSize` を設定の値にかかわらず 2 GiB−1（`INT_MAX - 2`）に丸めるからで（`libclamav/others.c` の `cl_engine_set_num`、`CL_ENGINE_MAX_FILESIZE` の分岐）、設定でも proxy でも動かせない。
この丸めを外した clamd を配布と同じ版の source から build し、配布の binary の隣に置いて unit で切り替える（PK-114）。

| 決め | 内容 | 理由 |
|---|---|---|
| source | 配布と同じ版（1.5.4、tag `clamav-1.5.4`）を `~/pd/src/clamav` に clone する。patch は repo の `scripts/clamav-2g.patch`（1 hunk） | 版を揃えると署名 DB の機能 level（`CL_FLEVEL` 234）と `clamd.conf` の語彙が配布と同じで、freshclam と設定をそのまま使える |
| patch | `CL_ENGINE_MAX_FILESIZE` の分岐の丸めと警告を消し、`engine->maxfilesize = num` だけにする。他は触らない | `maxfilesize` は `uint64_t`、設定の `MaxFileSize` と `StreamMaxLength` は `long long` に読まれ、clamd の INSTREAM の残量（`quota`）は `long`、file の大きさの比較は `uint64_t` と `size_t` で行われる（`cli_checklimits`、`cl_scandesc_callback`、`fmap`）。丸めの 1 箇所だけが 32-bit で、x86_64 ではそこを外せば 4 GiB の file が clamd を通る |
| build | cmake（Ninja、Release）に `-DCMAKE_INSTALL_PREFIX=/opt/clamav-2g -DCMAKE_INSTALL_RPATH=/opt/clamav-2g/lib -DAPP_CONFIG_DIRECTORY=/etc/clamav -DDATABASE_DIRECTORY=/var/lib/clamav -DSYSTEMD_UNIT_DIR=/opt/clamav-2g/lib/systemd/system -DENABLE_SYSTEMD=ON -DENABLE_UNRAR=OFF -DENABLE_CLAMONACC=OFF -DENABLE_MILTER=OFF -DENABLE_TESTS=OFF` | 配布の binary と並べて置き、戻すときは unit の drop-in を消すだけにする。RPATH で `/opt/clamav-2g/lib` の libclamav を使い、配布の `libclamav.so.12` と混ざらない。`clamav-daemon.socket` が `/var/run/clamav/clamd.ctl` を握って渡す形（socket activation）を同じに受けるために `ENABLE_SYSTEMD`（libsystemd が無いと socket activation 無しで黙って build されるので、`ldd` で `libsystemd` を見る）。`SYSTEMD_UNIT_DIR` を prefix の中に向けるのは、既定（pkg-config の `systemdsystemunitdir`＝`/usr/lib/systemd/system`）だと `cmake --install` が配布の unit file 5 本を上書きするため。install は `/etc/clamav` に `*.sample` と `clamav.crt` も置く（配布と同じ bytes。`clamd.conf` は触らない）。配布（dfsg）に無い unrar は入れない |
| 足す package | `libbz2-dev`、`libpcre2-dev`、`libjson-c-dev`、`libcurl4-openssl-dev`、`libsystemd-dev`、`systemd-dev` | build に要る。`systemd-dev` は `systemd.pc` を持ち、無いと `SYSTEMD_UNIT_DIR` を渡しても configure が止まる。`apt remove` で戻る |
| 配備 | unit の drop-in `/etc/systemd/system/clamav-daemon.service.d/binary.conf`：`ExecStart=` を空にしてから `/opt/clamav-2g/sbin/clamd --foreground=true --config-file=/etc/clamav/clamd.conf`、`Restart=on-failure`、`RestartSec=2`、`ExecStartPre=-`（配布の `/usr/sbin/clamd --version` と `/opt/clamav-2g/sbin/clamd --version` の版（`/` の前）を比べ、違えば journal に `clamav-2g: distribution <版> differs from /opt/clamav-2g <版>; rebuild` を出す。止めない）。`clamd.conf` の値は「運用」の表。restart 1 回 | `Restart=on-failure` は、大きな file で parser が落ちたときに clamd が止まったままになるのを防ぐ（配布の unit は `Restart=no`。止まったままだと、その後の scan が全部 fail-open で通る）。`ExecStartPre` の版比較は「apt の更新」の行の検知器で、配布の更新は clamd を restart するのでその瞬間に当たる。drop-in の先頭に戻し方を書く |
| 順 | clamd（build、install、`clamd.conf`、drop-in、restart）が先、proxy の binary が後 | 逆だと、2047 MiB 超 4095 MiB 以下の本文が配布の clamd に `INSTREAM size limit exceeded. ERROR` で `[warn]` 素通しになる。clamd が先なら、proxy の上限が 2047 MiB のままの間は何も変わらない |
| 戻し方 | proxy を前の binary（`packetdeath-prev-<hash>`）に `mv` して restart するのが先。次に drop-in を消して `daemon-reload`、`clamd.conf` を `clamd.conf.prev-<日付>` に戻し、clamd を restart 1 回 | 配布の package は入れたままなので、apt の binary がそのまま戻り先になる。順を逆にすると、新しい proxy が 2047 MiB 超 4095 MiB 以下の本文を配布の clamd へ送り、`INSTREAM size limit exceeded. ERROR` で `[warn]` 素通しになる |
| apt の更新 | 配布の `clamav-daemon` は unattended-upgrades（`-security`）で自動で上がり、動いている自前 build は上がらない。検知は配備の行の `ExecStartPre` の版比較（journal の `clamav-2g: … rebuild`）と、手順書の「測る」の手順の同じ比較。出たら、`git restore` で patch を戻してから同じ版の tag を checkout し、patch を当てて build し直す | security fix が自前 build に届く経路はこれだけである。`apt list --upgradable` は自動更新の後では空なので、trigger にならない |
| 採らない手段 | `MaxFileSize` だけ上げて配布の binary のまま動かす | 丸めで 2 GiB−1 のままになり、設定の値に意味が無い |
| 採らない手段 | parser の 32-bit の大きさを 64-bit に書き換える（libclamav の 54 file 315 箇所） | 丸めを外すだけで 4 GiB まで通る。書き換えは、2 GiB 超の file で parser が誤動作した実測が出てから、その parser に限って行う |
| 採らない手段 | 配布の package を dpkg で置き換える | apt の更新で上書きされ、戻し方が package の再 install になる。隣に置いて unit で切り替える方が戻しが 1 手で済む |
| 採らない手段 | 丸めを外すだけで上限を 4095 MiB より大きくする | 丸めの次の天井は 4 GiB で、`libclamav/matcher.c` の `cli_scan_fmap` が走査の位置を `uint32_t offset` で持ち、4 GiB 以上で回る。その天井を外すのが次の小節で、上限は 8191 MiB になる。上限そのものは撤廃できない（本文を memory に溜めて答えを待つ形なので、予算 8 GiB と `MemoryMax=12G` が線になる） |

2 GiB を超える file を扱う parser は、開発元が試していない（`others.c` の丸めの comment）。4 GiB 以上は `cli_scan_fmap` の `uint32_t offset` で回るので、丸めを外しただけの libclamav の天井は 4095 MiB である。
AppArmor はこの機械で無効（`/sys/module/apparmor/parameters/enabled` が `N`）なので、`/usr/sbin/clamd` の profile が自前の binary に当たらないことによる差は無い。
4 GiB の天井を外すのが次の小節である。

### libclamav の 64-bit 化

丸めを外した libclamav の次の天井は 4 GiB で、file 全体を走査する loop と署名の位置が 32-bit だからである。
広げるのは位置（offset）だけで、長さは 32-bit のままにする（1 回に走査する塊は `SCANBUFF` の 131072 byte 以下で、32-bit で足りる）。
この小節は、その天井を外す改造を 4 つの段に分け、段ごとに受入 ID を置く。
改造は自前 build の patch の列（repo の `scripts/clamav-64/` に番号付きの patch。`scripts/clamav-2g.patch` の後に順に当てる）として持ち、配布の版が上がるたびに当て直す。

| 決め | 内容 | 理由 |
|---|---|---|
| source と build | `~/pd/src/clamav` の branch `packetdeath`（tag `clamav-1.5.4` に 2g の patch と 64 の patch の列を順に当てた branch `clamav64` を `--no-ff` で merge した物）。build dir `~/pd/src/clamav-64-build` の `CMakeCache.txt` は source を `~/pd/src/clamav/.claude/worktrees/clamav-64` で覚えているので、build し直す前に同じ path へ `git worktree add --detach ~/pd/src/clamav/.claude/worktrees/clamav-64 <branch clamav64 の tip>` で worktree を出し直し、済んだら `scripts/tidy-branches.sh --remove-worktree <その path>` で外す（worktree は repo の中の `.claude/worktrees/` にだけ作り、外すのはその script だけ）、「clamd の自前 build」と同じ cmake の option で prefix だけ `/opt/clamav-64`（RPATH と `SYSTEMD_UNIT_DIR` も prefix の中） | 2g の source と build を分けると、F が壊れていたときに 2g を build し直さずに戻れる |
| 名前 | prefix に入る program は全部 名前の末尾に `64` を付ける（`clamd64`、`clamscan64`、`clamdscan64`、`clamdtop64`、`freshclam64`、`sigtool64`、`clambc64`、`clamconf64`、`clamsubmit64` の 9 本）。patch の列の最後の 1 本で、各 program の `CMakeLists.txt` の target に `OUTPUT_NAME` を置く。lib（`libclamav.so.12`）と `man` と、library の利用者向けの shell script `clamav-config` は変えない | 配布の `/usr/sbin/clamd` と 2g の `/opt/clamav-2g/sbin/clamd` と並べたとき、どれが 64-bit 化の物かが path でなく名前で判る。install の後に `mv` で付け替える形は、build し直しの `cmake --install` が `clamd` を置き直して古い `clamd64` が残る。prefix の中の unit file は `clamd` を指すが使わない（drop-in が `clamd64` を指す） |
| 配備 | drop-in `binary.conf` の `ExecStart` を `/opt/clamav-64/sbin/clamd64` に向け、`daemon-reload`、restart 1 回。F-0 から F-2 は 1 回で配備し、F-3 の値はその後の別の restart で入れる | binary の切り替えと値の変更を分けると、落ちたときにどちらが原因かが journal で判る |
| 戻し方 | `binary.conf` の `ExecStart` を `/opt/clamav-2g/sbin/clamd` に戻して `daemon-reload`、restart 1 回。F-3 の後なら proxy を前の binary に戻すのが先、`clamd.conf` を `clamd.conf.prev-<日付>` に戻すのが次、binary の切り替えが最後 | 2g の prefix は消さないので、戻り先がそのまま残る |
| 完了の印 | patch を当てた tree を `-DCMAKE_C_FLAGS=-Wconversion` で build し、`matcher.c`、`matcher-ac.c`、`matcher-bm.c`、`matcher-pcre.c`、`scanners.c` の warning のうち、位置を狭める変換が、format が 32-bit の parser の入口（`scanners.c` が見つけた位置 `fpt->offset` を zip、arj、PE の parser の 32-bit の引数へ渡す 3 箇所）を除いて 0 件（patch の前の同じ build との差分で見る。残る warning はその 3 箇所と長さの物） | 「位置を全部 広げた」を人の読みでなく compiler に数えさせる。3 箇所は F-2 の「触らない」の側で、「残る穴」に書く |

| 段 | 変える物 | 変えない物と理由 | 受入 |
|---|---|---|---|
| F-0 bytecode | `cli_bytecode_runhook` と `cli_bytecode_runlsig` の 2 つの入口で、fmap の大きさが 4 GiB 以上なら bytecode を走らせず `cli_warnmsg` を 1 行 出す（`cli_bytecode_context_setfile` が fmap の大きさを `uint32_t` の `file_size` に写す手前で止める。`--debug` 無しで見える） | bytecode の API（`bytecode_api.h`）は大きさと位置を `int32_t` / `uint32_t` で受け渡し、その ABI は署名 DB（`bytecode.cvd`）と共有するので変えられない。4 GiB 超の file を 32-bit で渡すと位置が回る | PK-116 |
| F-1 走査の中核 | 位置を持つ物を `size_t` に揃える。`libclamav/matcher.c` の `cli_scan_fmap` の `offset`、`matcher_run` と `cli_scan_buff` の `offset` の引数、`cli_caloff` の `offdata` / `offset_min` / `offset_max`（`matcher-ac.h`、`matcher-bm.h`、`matcher-pcre.h` の同名 field、`cli_bm_off.offset`、`cli_pcre_off.offset` / `shift`）、`cli_ac_data` の `offset` / `lsigsuboff_first` / `lsigsuboff_last` / `offmatrix` と `matcher-ac.c` の `cli_ac_scanbuff` の局所の位置、`offmatrix` の空きの印 `(uint32_t)-1`（`SIZE_MAX` に）、`lsig_sub_matched` の `realoff`、`cli_subsig_matches.offsets`、`CLI_OFF_ANY` / `CLI_OFF_NONE`（`size_t` の印にする。container metadata（cdb）が同じ印を 32-bit で持つ所は `CLI_CDB_ANY`（`0xffffffff`）に分ける：`readdb.c`、`matcher.c`）。位置と比べる `matcher-byte-comp.c` と `yara_exec.c` の型も揃え、bytecode の `nooffsets` の表は 32-bit の値を明示する。`cli_bytecode_runlsig` へ渡す `lsigsuboff_first` は bytecode の ABI（`uint32_t` の列）なので、呼ぶ所で 1 つずつ狭めて写す（F-0 で 4 GiB 以上は来ない） | 長さ（`cli_scan_fmap` の `bytes`、`cli_scan_buff` と `cli_ac_scanbuff` の `length`）は 1 塊が `SCANBUFF` 以下なので 32-bit のまま。署名の文法（絶対位置 `n`、`EOF-n`、`EP+n`）と読み方（`cli_caloff` の `atoi`）は変えず、絶対位置の計算（`fsize − n` など）だけを 64-bit で行う。`cli_ac_result.offset` は既に `off_t`。`cli_pcre_scanbuf` は位置の引数を持たない。parser が渡す 32-bit の位置はそのまま（暗黙に広がる）。安全網は開発元の `unit_tests/check_matchers.c`（`ctest`） | PK-116 |
| F-2 書庫の parser | 4 GiB を超える位置を 32-bit で計算している parser を 2 つ揃える。tar（`untar.c`）：member の大きさを読む `octal()` が `unsigned int` に書き、呼ぶ側の `size_int` と `nskip` も同じ幅なので、`uint64_t` に揃える（tar の octal は 11 桁＝8 GiB まで表せる）。ISO9660（`iso9660.c`）：`needblock` が block 番号 × sector の大きさを `unsigned int` で掛けるので、`size_t` に cast してから掛ける（block 番号は 32-bit のままで、4 GiB 以上の位置に在る file が読める） | zip：`unzip.c` は zip64 を読まず、圧縮前後の大きさを `uint32_t`（`struct zip_record`、inflate の `avail_in`）で持つ。zip64 を足すのは parser の新規の code で、位置の幅を揃えるこの小節の範囲を超える（採らない手段）。format 自体が 32-bit の parser（PE、OLE2、Mach-O の 32-bit、CAB、ARJ、cpio の newc）は触らない。4 GiB 超の中身を表せない format なので、型を広げても読める物が増えない。dmg、xar、7z（SDK は `UInt64`）、gpt、hfsplus、egg、udf は大きさを 64-bit で持つ宣言だが、4 GiB 超の実測は無い | PK-117 |
| F-3 proxy と clamd の値 | proxy の上限を 8191 MiB（8588886016 byte）に。予算 8 GiB と `MemoryMax=12G` は据え置き（8 GiB 級なら 1 本、4 GiB 級なら 2 本）。clamd は `StreamMaxLength 8191M`＝`MaxFileSize 8191M`、`MaxScanSize 16382M`、`TemporaryDirectory /var/tmp/clamav`（tmpfs でない disk。`clamav` 所有の 0700、`findmnt -T /var/tmp` で tmpfs でないことを見る）。proxy の timeout は 1260 秒、`MaxScanTime 1134000`（表 c。本番の生の INSTREAM の最も遅い実測 10.3 MB/s で 8191 MiB を割った 834 秒の 1.5 倍を 60 秒単位で切り上げ、`MaxScanTime` はその 0.9 倍で `MaxScanTime < timeout` を保つ）。順は、`clamd.conf` の大きさの 3 行と `TemporaryDirectory` を入れて restart、4.5 GiB の stream を測る、timeout を表 c に書く、proxy の code、`MaxScanTime` を入れて restart、proxy の binary | 上限 × 2 ≤ 予算 の関係は、上限 ＝ 予算 で崩れる（8191 MiB の download は 1 本ずつで、その間 他の scan 対象は `slot_full`）。timeout 600 秒は据え置けない：生の INSTREAM は 10.3〜18.4 MB/s（表 c の実測）で、8191 MiB は 467〜834 秒。clamscan（PK-116）は file を直接 読むので INSTREAM の 3〜6 倍 速く、timeout の根拠にならない。`MaxScanTime` を先に上げると proxy の timeout より長くなって関係式が崩れるので、proxy の binary と同じ回に入れる。temp を disk へ移すのは、tmpfs のままだと書庫の展開分が RAM に乗り、proxy の 8 GiB と合わせて最悪 24 GiB になるため | PK-118 | 上限 × 2 ≤ 予算 の関係は、上限 ＝ 予算 で崩れる（8191 MiB の download は 1 本ずつで、その間 他の scan 対象は `slot_full`）。timeout 600 秒は据え置けない：生の INSTREAM は 10.3〜18.4 MB/s（表 c の実測）で、8191 MiB は 467〜834 秒。temp を disk へ移すのは、tmpfs のままだと書庫の展開分が RAM に乗り、proxy の 8 GiB と合わせて最悪 24 GiB になるため | PK-118 |

この小節の順は F-0、F-1、F-2、F-3 で、F-3 は F-1 と F-2 が通ってから入れる（先に上げると 4 GiB 超の本文が回る loop に入り、tar と ISO9660 は狭めた位置のまま読む）。

| 採らない手段 | 理由 |
|---|---|
| `uint32_t` の大きさと位置を機械的に全部 `size_t` にする（`uint32_t` で size / len / offset を持つ宣言は 82 file 386 箇所） | format が 32-bit の parser は型を広げても読める物が増えず、format の field と変数の幅が食い違って検査が増えるだけである。段 F-2 の表のとおり、位置が 4 GiB を超える所だけ揃える |
| 長さ（`bytes`、`length`）も `size_t` に広げる | 塊は `SCANBUFF` 以下で 32-bit で足りる。広げると `-Wconversion` の差分に長さの変換が混ざり、位置の取りこぼしが見えなくなる |
| zip64 を `unzip.c` に足す | 攻撃者が選べる入力を読む parser に新規の code を fuzz 無しで足すことになる。位置の幅を揃える改造とは別の仕事で、要件が出てから別の設計で |
| bytecode の ABI を 64-bit にする | 署名 DB（`bytecode.cvd`）の側と組で変える物で、こちらだけでは変えられない。4 GiB 超を渡さない（F-0）で止める |
| 開発元へ issue / PR として出す | 利用者の名前で外へ出る操作で、別の明示の GO が要る。patch は出せる形（`git format-patch`）で持つ |
| proxy の上限を 8191 MiB より大きくする、本文を disk に溜める | 上限は memory で決まる。disk に溜めるのは別の設計で、要件が出てから |
| 署名の文法に 64-bit の位置を足す | 署名 DB は開発元が配る物で、文法を足してもその署名は来ない |

受入に使う入力は手元で作る（開発元の test corpus に 4 GiB 超は 0）。乱数 4.5 GiB（4831838208 byte）の 1 GiB 目に印 A、4200 MiB 目に印 B、末尾に PK-113 の印を置いた file（印は 28 byte ずつで 3 つは別の bytes。hex は受入の手順書に置く）と、印を置かない同じ大きさの乱数。試験署名は 3 種で、EOF に anchor した ndb（`PacketdeathTest.TailMarker:0:EOF-28:<末尾の印の hex>`）、2 つの部分を `*` で繋いだ ndb（`PacketdeathTest.TwoParts:0:*:<印 A の hex>*<印 B の hex>`。部分の位置の並びを `offmatrix` が 4 GiB を跨いで持てるかを見る）、部分署名 2 本の ldb（`PacketdeathTest.Logical;Engine:51-255,Target:0;0&1;<印 A の hex>;<印 B の hex>`。`lsigsuboff` の経路を見る）。署名の文法に 4 GiB 超の絶対位置は書けない（`cli_caloff` が `atoi` で読む）ので、絶対位置の署名は使わない。bytecode の入口（F-0）は PE などの型の file と bytecode の論理署名が当たったときにしか呼ばれないので、F-0 の対照は乱数ではなく、4.5 GiB の PE（`pe4g5.exe`。sparse で作る）を本番の `bytecode.cvd` を足した署名 dir で流す。書庫は、印付きの 4.5 GiB を `tar` で包んだ物、ISO9660 の 4 GiB 目より後ろに印付きの小さい file を置いた image（2.1 GiB の埋め草 2 本の後に印付きの file。`xorriso -as mkisofs -iso-level 3 -o <image> <dir>`。`xorriso` は package に無いので `apt install xorriso` で足し、受入の後に `apt remove` で戻す）、記録用に `zip -0` で包んだ物（4 GiB 超は zip64）。置き場は scratchpad か `~/pd/tmp/`、終わったら消す。clamscan には `--max-filesize=8191M --max-scansize=16382M --max-scantime=3600000 --alert-exceeds-max=yes --tempdir=<tmpfs でない dir>` を付ける（`MaxScanTime` の既定 120 秒では 4.5 GiB が切れ、`--alert-exceeds-max=yes` で切れた回が `Heuristics.Limits.Exceeded` と見える。temp が tmpfs だと tar の展開分が RAM に乗る）。
改造の安全網は開発元の unit test で、`ENABLE_TESTS=ON` の別の build dir（`~/pd/src/clamav-build-tests`、package `check` と `python3-pytest` を足す）で `ctest` を回し、通る数（`check_matchers` を含む）が patch の前と同じであることを見る。

### i18n

log と CLI の文言は `src/i18n.rs` の関数経由で出す（書くのは実装者）。level の tag は翻訳しない。ここでは文言の一覧だけを決める。

| 文言 | level |
|---|---|
| 復号が有効になった（list の件数、CA の期限、fingerprint） | `[info]` |
| 復号を無効にした（足りない option 名、または Windows） | `[warn]` |
| CA を生成した、読み込んだ | `[info]` |
| CA を読めない（片方だけ、権限が緩い、parse 失敗、期限切れ） | `[error]` |
| CA の期限が30日以内 | `[warn]` |
| clamd の PING に失敗した、loopback 以外の address | `[warn]` |
| leaf を作れない | `[error]` |
| 上流の TLS が失敗した（host、理由の種類） | `[warn]` |
| client が復号を拒んだ（client の IP、host、理由：alert / 無通告の切断 / handshake 未完） | `[warn]` |
| client が無通告で切ったが見送った（client の IP、host、理由：成功の記憶 / TLS の byte 0 / handshake の途中） | `[debug]` |
| 扱えない request や応答（host、理由の種類） | `[warn]` |
| bypass 表へ入れた（host、寿命） | `[info]` |
| 検知した（host、signature、sha256、scan の所要 `ms=`） | `[info]` |
| clean だった（host、sha256、scan の所要 `ms=`。計るのは clamd への scan の呼び出しだけで、本文を溜める時間は含めない。外部依存の呼び出しには所要時間を記録する。`av.jsonl` は変えない） | `[info]` |
| scan しなかった（host、理由。`too_large` `encoded` は `[info]`、`slot_full` は `[warn]`、`not_eligible` は `[debug]`。枠満杯は保護の劣化なので `[warn]`） | 左記 |
| scan に失敗した（host、`clamd_unreachable` `clamd_timeout` `clamd_error`） | `[warn]` |
| 検査未了だった（host、`Heuristics.Limits.Exceeded.` で始まる署名名。本文は流す。`av.jsonl` に書かない） | `[warn]` |
| `--mitm-list` を読み直した（path、件数、前の件数） | `[info]` |
| `--mitm-list` の項目が allowlist に当たり復号されない（host。起動時と読み直し時に当たる項目ごとに1行） | `[warn]` |
| 403 の本文 | 応答の本文 |
| 3つの option の使い方、誤りの文言 | CLI |

### 波及先

| 場所 | 変わること |
|---|---|
| `src/proxy.rs` の `handle_connection`（上流へ TCP を張った後、`forward` を呼ぶ前） | 復号の条件を満たしたとき、`reader` と上流の `TcpStream` を復号の処理へ渡す。上流の TLS が失敗したときだけ `reader` を返し、上流へ張り直して従来の `forward` へ進む。`forward`、`pipe_bidirectional`、deny の分岐は変えない |
| `src/proxy.rs` の `serve` | 復号の実行時の状態（CA、leaf の cache、bypass 表、clamd の address、上限）を受け取る引数を足す。呼び出し元（`src/main.rs` と `tests/independent_proxy.rs`）が変わる |
| `src/proxy.rs` の `log_flow` | 復号の module から FOUND の行を書くため、公開範囲を `pub(crate)` に広げる |
| `src/block_loop.rs` の `WatchInputs` | `--mitm-list` を読み直しの対象に足す（段階9 が iplist を足した形と同じ） |
| `src/main.rs` の `ProxyArgs` と `parse_proxy_args` | 3つの option |
| `src/i18n.rs`、`src/lib.rs`、`Cargo.toml` | 文言、module の宣言、依存（Linux target に限る） |
| `src/scan.rs` の `ScanBudget` と `MitmLimits.scan_budget_bytes` | 同時に溜める本文の合計を bytes の予算で数える。`SkipReason::SlotFull` と log の語 `slot_full` はそのまま |

新しい module は4つに分ける。`src/ca.rs`（CA と leaf の生成、読み込み、起動時の検査、fingerprint）、`src/clamd.rs`（clamd への INSTREAM と PING、応答の3分類、timeout）、`src/scan.rs`（scan に流す条件、同時 scan の枠、sha256、`av.jsonl` の行）、`src/mitm.rs`（復号した通信の処理、HTTP/1.1 の head と chunked、request の書き換え、bypass 表）。この4つ以外の `pub mod` は足さない。
段階7 の proxy の形は壊れない。復号は `forward` と同じ位置に載る別の処理であり、判定、log、枠、timeout の規則は段階7 のものをそのまま使う。

### 受入 ID（PK-100〜PK-122）

command は Linux を前提に書く。先に `LOGDIR`（「受入 ID」節冒頭の約束）に加えて次を置く。

```
CADIR=$LOGDIR/ca
CLAMD=/var/run/clamav/clamd.ctl
```

`CADIR` は `.gitignore` の `*.crt` と `*.key` に当たる。`CLAMD` はこの機械の実測値で、別の機械では替える。
`<log>` は `$LOGDIR/flows.jsonl`、`<av>` は `$LOGDIR/av.jsonl` である。proxy は `--listen 127.0.0.1:8899` で起動する。
PK-103 から PK-105 と PK-107 から PK-109 は、偽の上流と偽の clamd を test の中に立てる（外部 host の応答を gate にしない）。
EICAR の文字列は、test の中で2つ以上の断片から組み立てる。1つの literal として repo に置かない。

| ID | 受入条件 | 打つ command | 通ったと判る出力 |
|---|---|---|---|
| **PK-100** | **陰性対照**。`--mitm-list` が無いとき段階7 と同じで、CA を作らない | `packetdeath proxy --listen 127.0.0.1:8899 --ca-dir "$CADIR" &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.com/; grep -c '"decision":"block"' <log>; test -e "$CADIR"; echo "rc=$?"` | `200`、`0`、`rc=1`（PK-70 と同じ出力。起動 log に足りない option を言う `[warn]` が1行） |
| **PK-101** | `--ca-dir` が空のとき CA が生成され、`ca.crt` が出る。鍵の権限が `0600`。再起動で作り直さない | `printf 'example.com\n' > mitm.txt; packetdeath proxy --listen 127.0.0.1:8899 --mitm-list mitm.txt --ca-dir "$CADIR" --clamd "$CLAMD" &` の後に `ls "$CADIR"; stat -c '%a' "$CADIR/ca.key"; stat -c '%a' "$CADIR"; openssl x509 -in "$CADIR/ca.crt" -noout -subject \| grep -c 'packetdeath CA'; openssl x509 -in "$CADIR/ca.crt" -noout -ext basicConstraints \| grep -c 'pathlen:0'`。続けて `cksum "$CADIR/ca.crt"` を打ち、proxy を起動し直して同じ command を打つ | `ca.crt` と `ca.key`、`600`、`700`、`1`、`1`。再起動の前後で `cksum` が同じ |
| **PK-102** | `--mitm-list` に当たる domain の CONNECT が、packetdeath の CA で署名された leaf を返す。当たらない domain は上流の証明書のまま | PK-101 の起動のまま `curl -sS -o /dev/null -w '%{http_code}\n' --cacert "$CADIR/ca.crt" -x http://127.0.0.1:8899 https://example.com/; openssl s_client -proxy 127.0.0.1:8899 -connect example.com:443 -servername example.com </dev/null 2>/dev/null \| openssl x509 -noout -issuer \| grep -c 'packetdeath CA'; openssl s_client -proxy 127.0.0.1:8899 -connect example.org:443 -servername example.org </dev/null 2>/dev/null \| openssl x509 -noout -issuer \| grep -c 'packetdeath CA'` | `200`、`1`、`0` |
| **PK-103** | EICAR（平文の test string。実物の malware ではない）を返す偽の上流に、`--clamd` 有りで `403` と `"reason":"av"`。clean の file は通り、`av.jsonl` に残る | `cargo test --release --test independent_mitm -- eicar_is_replaced_with_403_and_logged_as_av clean_file_passes_and_is_recorded_in_av_jsonl`（test 名を 2 つ以上 並べるときは `--` の後に置く。前に置くと `cargo test` が `unexpected argument` で落ちる。2026-10-03 `実測`）。実機の記録として、`--mitm-list` に `secure.eicar.org` を足して `curl -sS -o /dev/null -w '%{http_code}\n' --cacert "$CADIR/ca.crt" -x http://127.0.0.1:8899 https://secure.eicar.org/eicar_com.zip; tail -2 <log>; tail -1 <av>` を1回だけ打つ（外部 host なので記録だけで、gate にしない） | 2本とも `ok`。test の中で、client の status が `403`、本文が上流の物でない、`<log>` の末尾が `"decision":"block"` と `"reason":"av"`、`<av>` の末尾が `"verdict":"malicious"` と64桁の sha256、clean の file は `200` で本文が byte 一致し `<av>` が `"verdict":"clean"`。実機の記録は `403` が期待で、値を残す |
| **PK-104** | clamd が居ないとき、同じ file が通る（fail-open） | `cargo test --release --test independent_mitm clamd_down_passes_the_same_file` | `ok`。status が `200`、本文が byte 一致、`[warn]` に scan の失敗が1行、`<log>` の `block` が0、`<av>` が増えない |
| **PK-105** | 閾値超え（上限 + 1 byte）が scan されず通る。上限ちょうどは scan される。test は `MitmLimits.max_scan_bytes` を小さく差して測る（既定の 8191 MiB を memory に積まない） | `cargo test --release --test independent_mitm -- oversize_body_is_streamed_without_scan exactly_the_limit_is_scanned` | 2本とも `ok`。上限 + 1 byte は byte 一致で届き、偽 clamd への接続が0。上限ちょうどは接続が1 |
| **PK-106** | `--mitm-list` の走行中の読み直し（PK-74 の MITM 版） | `: > mitm.txt; packetdeath proxy --listen 127.0.0.1:8899 --mitm-list mitm.txt --ca-dir "$CADIR" --clamd "$CLAMD" &` の後に `curl -sS -o /dev/null --cacert "$CADIR/ca.crt" --capath "$CADIR" -x http://127.0.0.1:8899 https://example.com/; echo "exit=$?"`、続けて `printf 'example.com\n' >> mitm.txt; sleep 0.4; curl -sS -o /dev/null -w '%{http_code}\n' --cacert "$CADIR/ca.crt" --capath "$CADIR" -x http://127.0.0.1:8899 https://example.com/` | 書き換え前は `exit=60`（list に無いので非復号で、上流の証明書は packetdeath の CA で検証できない）。書き換え後は `200`。`--capath "$CADIR"` が要るのは、curl が `--cacert` に加えて既定の CApath（`/etc/ssl/certs`）も見るからで、hash 済みでない `$CADIR` を渡すことで system の root を外している（2026-10-03 に curl 8.18.0 + OpenSSL 3.5.5 で `実測`：`--cacert` だけだと `exit=0`）。PK-107 には足さない（既定の CApath で上流の本物の証明書を検証する） |
| **PK-107** | pinning 相当の失敗（client が packetdeath の CA を信じない）が、`502` でなく **次の接続から段階7 の非復号**へ倒れる。寿命が過ぎると復号に戻る | PK-106 の書き換え後の list のまま proxy を起動し直し（PK-106 の `200` が同じ (127.0.0.1, example.com) の成功を記憶しているので、それを消す）、`--cacert` を渡さずに `curl -sS -o /dev/null -x http://127.0.0.1:8899 https://example.com/; echo "exit=$?"` を2回 続けて打つ。寿命と (client の IP, host) の組は `cargo test --release --test independent_mitm -- pinned_client_falls_back_to_tunnel_on_the_next_connection bypass_expires_after_its_ttl upstream_tls_failure_falls_back_to_tunnel` | 1回目 `exit=60`（`[warn]` に client が復号を拒んだこと、理由は無通告の切断）。2回目は `exit=0`（非復号で通り、上流の本物の証明書で検証できる）。`<log>` の2行とも `"decision":"pass"`。3本の test が `ok` |
| **PK-108** | scan が download を遅くしない。10 MiB の clean file を偽の上流から取るとき、scan 有りと無しの所要時間の差が2秒以内 | `cargo test --release --test independent_mitm -- --nocapture ten_mib_clean_download_overhead_is_within_two_seconds`。test は偽の上流に10 MiB の clean file を置き、curl を3回ずつ打って `%{time_total}` の中央値を比べる。偽の上流は request ごとに違う 10 MiB（乱数）を返す。clamd は同じ内容の 2 回目以降を結果 cache から返すので（2026-10-03 `実測`：10 MiB の乱数の cold が 0.549〜0.572 秒、同じ内容の 2 回目が 0.066〜0.069 秒）、同じ file を 3 回 測ると中央値が cache の値になり、cold を測れない。無しは `--mitm-list` を渡さない段階7 の非復号の中継、有りは3つの option を渡し、実際の clamd（`/var/run/clamav/clamd.ctl`）へ流す | `ok`。有りの中央値から無しの中央値を引いた値が `2.0` 以下。2つの中央値を標準出力へ出す。clamd の socket が無い機械ではこの test は落ちる（通ったことにしない） |
| **PK-109** | PK-108 の scan 中に、`--mitm-list` に無い domain への CONNECT が段階7 と同じ時間で通る | `cargo test --release --test independent_mitm -- --nocapture connect_to_unlisted_host_is_not_slowed_by_a_running_scan`。test は PK-108 の scan を裏で走らせ、その間に list に無い別の偽の上流（IP literal で CONNECT）へ curl を打って `%{time_total}` を測る。scan が走っていないときの同じ curl と比べる | `ok`。scan 中の `time_total` と scan が無いときの `time_total` の差が `0.5` 秒以内 |
| **PK-111** | proxy が `ca.crt` を `/ca.crt` で配る。**陰性対照**として `/ca.key` と、MITM 無効のときの `/ca.crt` は `400` | PK-101 の proxy（`--mitm-list mitm.txt --ca-dir "$CADIR" --clamd …`）の後に `curl -sS -D - -o "$LOG/got.crt" http://127.0.0.1:8899/ca.crt \| grep -c 'application/x-x509-ca-cert'`（`$LOG` は `--log-dir` に渡した dir。`/tmp` は guard が止める）、`cmp "$LOG/got.crt" "$CADIR/ca.crt"; echo rc=$?`、`curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8899/ca.key`、`grep -c 'ca.crt' <log>`。次に PK-100 の proxy（`--mitm-list` 無し）で `curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8899/ca.crt`。unit は `cargo test --release --test independent_mitm -- ca_certificate_is_served_and_the_key_never` | `1`、`rc=0`、`400`、`0`（flow log に残らない）、`400`。unit は `ok` |
| **PK-112** | scan の timeout が 10 秒より長く（既定は表 c の値）、`[info]` の `clean` / `検知した` に scan の所要 `ms=` が出る。**10 秒を超える本物の scan が無検査にならない**ことを、中身まで cold の archive で見る | 本番の clamd で測る（cache を消すために各回の前に `sudo systemctl reload clamav-daemon` を 1 回 打ち、`/var/log/clamav/clamav.log` の `Database correctly reloaded` が増えたことを見る。直前 1 分の journal に list の host の行が 0 であることも見る）。file 数が 679 の 2 倍 以上の zip（10 秒を超える物）を list の host に置けないので、`clamdscan --stream` で先に cold の所要を測って 10 秒 超を確かめ、proxy 経由は同じ zip を手元の test server から落とす（`tests/independent_mitm.rs` の形で、clamd は本番の socket）。timeout が 10 秒の binary では `[warn] scan に失敗した … 理由=clamd_timeout`（陽性対照）、現行の binary では `[info] 検査した。clean だった … ms=<10000 以上>`。unit は `cargo test --release --test independent_mitm -- clean_and_found_lines_carry_the_scan_time` | 10 秒の binary：`[warn]` 1 行。現行：`clean` と `ms=` が 10000 以上。unit は `ok` |
| **PK-113** | scan する file の大きさの上限を設定できる最大にする。proxy の上限と clamd の `StreamMaxLength`＝`MaxFileSize`、`MaxScanSize` は「大きさ」の行と「運用」の表の値（PK-115 で上げた）、timeout 600 秒、`MaxScanTime 540000`、`AlertExceedsMax yes`、limit 超は「検査未了」で流す。proxy の unit に `MemoryMax=12G`。**順は上限を上げる側（clamd）が先、proxy の binary が後**（逆だと proxy の上限と clamd の limit の間の大きさが ERROR で `[warn]` 素通し） | proxy：unit は `cargo test --release --test independent_mitm -- exactly_the_limit_is_scanned limits_exceeded_is_passed_through_as_unscanned` と `--lib -- default_limits_match_the_design`。本番：binary を cp→mv で入れ替え、drop-in に `MemoryMax=12G`、restart 1 回。clamd：`clamd.conf` を退避して書き換え、`clamconf -n \| grep -E 'StreamMaxLength\|MaxFileSize\|MaxScanSize\|MaxScanTime\|AlertExceedsMax'` が新しい値、直前 1 分の journal に list の host の行が 0 を見て restart。受入は生の INSTREAM（`nc -U`、64 KiB 塊）で 30 MiB を流し、変更の前は `INSTREAM size limit exceeded. ERROR`（陽性対照）、後は `stream: OK`。30 MiB の末尾まで検査されることは、EOF に anchor した試験用の署名（`local.ndb` の 1 行 `PacketdeathTest.TailMarker:0:EOF-28:<印の hex>`）を DB の dir に置いて reload し、末尾に印を置いた 30 MiB が `FOUND`、置かないと `OK` で見る（EICAR は file 全体の hash の署名なので、大きい本文の先頭や末尾に置いても当たらない）。試験の後は署名を消して reload する。`AlertExceedsMax` の陽性対照：`MaxFiles` を超える archive か `MaxScanTime` を超える本文で `Heuristics.Limits.Exceeded.` の FOUND が返り、proxy 経由では `200` と `[warn] 検査未了`。PC の Chrome（CA 入り）で list の host の 25 MB 超の asset を 1 本 落とし、av.jsonl に `clean`、`ms=` が大きさ ÷ 9 MB/s の桁。1 GB 級で先頭 byte まで 60 秒 超の 1 本も測り、Chrome が諦めたら上限を 512 MiB へ戻す | unit 3 本 `ok`。clamconf が新しい値。30 MiB：前 ERROR、後 OK、EICAR 付き FOUND。limit 超が `200` と `[warn]`。PC からの 25 MB 超が `clean` |
| **PK-114** | 2 GiB を超える file を clamd が末尾まで検査する。自前 build の clamd（「clamd の自前 build」の小節）が `clamav-daemon` として動き、`MaxFileSize 4095M` が丸められずに効く | build：`cmake -S ~/pd/src/clamav -B ~/pd/src/clamav-build -G Ninja -DCMAKE_BUILD_TYPE=Release <小節の option>`、`cmake --build ~/pd/src/clamav-build`、`sudo cmake --install ~/pd/src/clamav-build`。`/opt/clamav-2g/sbin/clamd --version` が `ClamAV 1.5.4/…`、`ldd /opt/clamav-2g/sbin/clamd` が `/opt/clamav-2g/lib/libclamav.so.12` と `libsystemd` を指す、`dpkg -V clamav-daemon clamav-freshclam clamav libclamav12 | grep -vc ' c /etc/'` が 0（install が配布の file を上書きしていない）。restart の前の対照（本番を触らない）：試験署名 `local.ndb` 1 本だけを `-d` に渡し、乱数 2.5 GiB（2684354560 byte）の末尾に PK-113 の印（28 byte）を付けた file を `/opt/clamav-2g/bin/clamscan --max-filesize=4095M --max-scansize=8190M -d <その ndb> <file>` で `PacketdeathTest.TailMarker FOUND`、同じ引数の `/usr/bin/clamscan` で `Heuristics.Limits.Exceeded.MaxFileSize FOUND`（陽性対照。配布の libclamav は 2147483645 に丸める）。配備の後に `/var/log/clamav/clamav.log` の起動の行 `Limits: File size limit set to 4293918720 bytes.`、`systemctl show clamav-daemon -p ExecStart -p Restart` が `/opt/clamav-2g/sbin/clamd` と `on-failure`。末尾まで（本番の clamd）：`local.ndb` の試験署名を DB の dir に置いて reload してから、印付きの 2.5 GiB を `clamdscan --stream --no-summary <file>` で流して `PacketdeathTest.TailMarker FOUND`、印を付けない同じ大きさの乱数は `OK`、上限ちょうど（`head -c 4293918692 /dev/urandom` に印 28 byte を続けて pipe で `clamdscan --stream -` に流す。file を作らない）は `FOUND`。所要の秒を記録する。試験の後は署名を消して reload する。大きい file は scratchpad か `~/pd/tmp/` に置き、`/tmp` に置かず、終わったら消す。記録だけ（gate にしない）：同じ 2.5 GiB を `zip -0` で 1 member に収めた archive の verdict と所要（2 GiB 超の member を parser がどう扱うかの最初の実測） | `--version` が 1.5.4、`ldd` が prefix の libclamav と libsystemd、`dpkg -V` が 0、restart 前の clamscan が FOUND と `Limits.Exceeded`、`File size limit` が 4293918720、ExecStart と Restart が新しい値、2.5 GiB と上限ちょうどの印付きが `FOUND`、印なしが `OK`、受入の間 `NRestarts=0` |
| **PK-115** | proxy の上限を 4095 MiB（4293918720 byte）にし、同時に溜める本文の合計を bytes の予算（8 GiB）で数える。`MemoryMax=12G` は据え置き | unit：`cargo test --release --test independent_mitm -- exactly_the_limit_is_scanned scan_slot_exhaustion_passes_unscanned scan_budget_counts_bytes_not_connections unknown_length_takes_the_whole_limit_from_the_budget` と `--lib -- default_limits_match_the_design`。本番：PK-114 の後に binary を cp→mv で入れ替え、restart 1 回。入力は書庫でない生の file（`application/octet-stream` の safetensors。`huggingface.co` の `resolve` が `hf.co` の CDN へ 302 で飛ぶので、list には `huggingface.co` と `hf.co` の 2 行）。2 つが allowlist に無いことを `rg` で見て（対照に `github`）、`~/pd/mitm-list.txt` に足し（300 ms で効く）、各回の前に `sudo systemctl reload clamav-daemon` で cache を消してから（2 回目は cache で `ms=` が小さく出る）、`curl -sS -o <file> -w 'http=%{http_code} size=%{size_download} ttfb=%{time_starttransfer}s\n' --cacert ~/pd/ca/ca.crt -x http://192.0.2.20:8081 <URL>`（受入の日に `curl -sIL` で `Content-Length` を採り直す。2047 MiB 超 4095 MiB 以下であること）。前の binary では journal に `too_large` の `[info]`（陽性対照。同じ大きさの帯の別の file でよい）、新しい binary では `av.jsonl` の末尾が `clean` で `sha256` が `sha256sum <file>` と一致、journal に `[info] 検査した。clean だった host=<CDN の host> … ms=`、`systemctl show packetdeath-proxy -p MemoryPeak -p NRestarts`。終わったら list の 2 行を外す。記録だけ（gate にしない）：2047 MiB 超の ISO（`releases.ubuntu.com` の live-server）を同じ形で落とした verdict と `ttfb`（ISO9660 は中身の合計が `MaxScanSize` に当たり、`検査未了` で通る） | unit 5 本 `ok`。本番：`http=200`、`size=` が `Content-Length` と一致、`clean`、sha256 一致、`ms=` が 大きさ ÷ 22 MB/s から 540000 の間、`NRestarts=0`、`MemoryPeak` が 大きさ + 200 MB 未満。生の file で `検査未了` なら設計へ戻る |
| **PK-116** | 4 GiB を超える file を libclamav が末尾まで走査し、4 GiB を跨ぐ部分署名と論理署名が当たる（F-0、F-1）。bytecode は 4 GiB 以上の file に走らない | patch の前後で同じ command を打つ（前は `/opt/clamav-2g/bin/clamscan` で陽性対照）。`/opt/clamav-64/bin/clamscan64 --no-summary --allmatch=yes --max-filesize=8191M --max-scansize=16382M --max-scantime=3600000 --alert-exceeds-max=yes --tempdir=<tmpfs でない dir> -d <試験署名 3 種の dir> <印付き 4.5 GiB>`（後：`PacketdeathTest.TailMarker.UNOFFICIAL`、`PacketdeathTest.TwoParts.UNOFFICIAL`、`PacketdeathTest.Logical.UNOFFICIAL` の 3 行が `FOUND`。1 つでも欠けたら署名を 1 種ずつ `-d` に渡して切り分ける。前：出力をそのまま記録）、印なしの 4.5 GiB（`OK`）、所要の秒と MB/s。4.5 GiB の PE（sparse）を `bytecode.cvd` を足した dir で流すと `OK` で、stderr に F-0 の warning の行（`skipping bytecode for a file of 4831838208 bytes`）が有る（対照：2.5 GiB の file では無い）。配備の後（本番の clamd64、上限 4095M のまま）：試験署名を DB の dir に置いて reload し、印付きの 2.5 GiB を `clamdscan --stream` で `FOUND`（2 GiB 超の退行の対照）、`clamav.log` の `File size limit set to 4293918720`、`systemctl show clamav-daemon -p ExecStart` が `clamd64`、`NRestarts=0`。試験の後は署名を消して reload する。開発元の unit test：`ctest --test-dir ~/pd/src/clamav-build-tests` の通る数が patch の前後で同じ（数を記録） | 3 種の署名が `FOUND`、印なしが `OK`、前の build は `FOUND` でない、F-0 の warning の有無が大きさで分かれる、ctest の通る数が同じ、本番の 2.5 GiB が `FOUND` で `ExecStart` が `clamd64` |
| **PK-117** | tar と ISO9660 の、4 GiB より後ろの位置に在る印を検査する（F-2） | PK-116 と同じ clamscan で、印付き 4.5 GiB を `tar` で包んだ物と、4 GiB 目より後ろに印付きの file を置いた ISO9660 を流す（後：`PacketdeathTest.TailMarker.UNOFFICIAL FOUND`。前：出力をそのまま記録）。所要の秒。記録だけ（gate にしない）：印付き 4.5 GiB を `zip -0` で包んだ zip64 の verdict と所要 | tar と ISO9660 の両方で `FOUND`、前の build は `FOUND` でない、clamscan が crash しない（rc が 0 か 1） |
| **PK-118** | proxy の上限を 8191 MiB（8588886016 byte）に、clamd を `8191M` / `8191M` / `16382M` と `TemporaryDirectory /var/tmp/clamav` に、proxy の timeout を 1260 秒、`MaxScanTime` を `1134000` に（F-3）。予算 8 GiB と `MemoryMax=12G` は据え置き | 最初の手：`clamd.conf` の大きさの 3 行と `TemporaryDirectory` を入れて restart し、試験署名を載せて 4.5 GiB の印付きを `clamdscan --stream` で `FOUND`、所要の秒（timeout の根拠）。unit：`cargo test --release --test independent_mitm -- exactly_the_limit_is_scanned clean_and_found_lines_carry_the_scan_time` と `--lib -- default_limits_match_the_design`（既定の上限 8588886016、予算 8589934592、timeout 1260 秒）。本番：PK-114 と同じ順（`clamd.conf` → restart → proxy の binary）で配備し、`clamconf -n` に `TemporaryDirectory` と新しい値、`findmnt -T /var/tmp` が tmpfs でない。PK-115 と同じ形で生の file（`application/octet-stream` の safetensors。4095 MiB 超 8191 MiB 以下。受入の日に `curl -sIL` で大きさを採る）を proxy 経由で落とす。前の binary では `too_large`（陽性対照）。記録だけ（gate にしない）：4095 MiB 超の ISO（`releases.ubuntu.com` の desktop）の verdict と `ttfb` | unit 2 本 `ok`。本番：`clamconf` と `findmnt` が期待の値、`http=200`、`size=` が `Content-Length` と一致、`clean`、sha256 一致、`ms=` が 大きさ ÷ 18.4 MB/s から `MaxScanTime` の間、`NRestarts=0`、`MemoryPeak` が 大きさ + 200 MB 未満。生の file で `検査未了` なら設計へ戻る |
| **PK-119** | `linux.rs` の `seen` と `blocked` の集合に idle の TTL（600 秒）を置く（「flow の集合の上限」） | unit：`cargo test --release --lib -- idle_flows_leave_the_set_after_the_ttl a_touched_flow_survives_the_sweep flow_set_swept_message_names_the_count`（`src/linux.rs` の 2 本と `src/i18n.rs` の 1 本）。配線：`rg -n 'HashSet<FlowKey>' src/linux.rs \| wc -l` が 0（対照 `rg -c 'FlowKey' src/linux.rs` が 1 以上）、`sed -n '1,/^#\[cfg(test)\]/p' src/linux.rs \| rg -c '(seen\|blocked)\.contains'`（本番の部分だけ。unit は同じ file の `#[cfg(test)]` の中に在る）が 出力なし・rc=1（対照 `sed -n '1,/^#\[cfg(test)\]/p' src/linux.rs \| rg -c '(seen\|blocked)\.touch\('` が 4）、`sed -n '1,/^#\[cfg(test)\]/p' src/linux.rs \| rg -c '(seen\|blocked)\.sweep\('` が 3（`run` の `seen`、`run_block` の `seen` と `blocked`） | unit 3 本 `ok`、`HashSet<FlowKey>` 0 件、本番の部分で `.contains` 0 件、`.touch(` 4、`.sweep(` 3。本番の proxy には関係しない（nfqueue の経路だけ）ので配備は無し |
| **PK-120** | Windows の `service-run` が `[info]` / `[warn]` / `[error]` の行を `<log dir>/service.log` に時刻つきで書き、`[debug]` は書かない（「Windows サービスの log」） | unit：`cargo test --release --lib -- service_log_writes_one_timestamped_line_per_call service_log_writes_the_given_offset service_log_reopen_appends_instead_of_truncating write_line_on_a_full_device_returns_err write_line_survives_a_poisoned_lock service_log_open_failed_message_names_the_path service_log_utc_fallback_message_names_utc`（`src/flow.rs` の 5 本と `src/i18n.rs` の 2 本）。main.rs の配線：`rg -c '\bservice_log\(' src/main.rs` が 2（dispatcher の失敗と UTC fallback。`\b` を付けて `redirect_service_log(` を外す。対照 `rg -c 'redirect_service_log\(' src/main.rs` が 1）、`rg -c 'service_log_utc_fallback' src/main.rs` が 1。integration（global の経路。別 process）：`cargo test --release --test independent_service_log`（`service_log_lines_reach_the_redirected_file`、`service_log_open_on_a_missing_dir_fails_without_panic`）。配線：`rg --files-with-matches 'eprintln!' src/ \| sort` の出力が `av.rs eval.rs filterlist.rs flow.rs i18n.rs ids.rs iplist.rs linux.rs main.rs mitm.rs proxy.rs` の 11 file だけ（stderr に残す file の列挙。「Windows サービスの log」の節に理由）、同じ 10 module で `rg -c 'service_log\('` が win_service 5、block_loop 9（PK-121 の後は温めの `[info]` と `[error]` が加わり 11）、ps_bridge 1、reload 2、reassemble 2、blocklist 2、allowlist 1、windows 1、judge 2、sni 1（合計 26）、`rg -c 'eprintln!' src/flow.rs` が 2（向け直す前の fallback と、書けなかったときの fallback）、`rg -n 'redirect_service_log\(\|run_service_dispatcher\(' src/main.rs` で `redirect_service_log(` の行番号が `run_service_dispatcher(` より小さい（向け直しが dispatcher の前。`\(` を付けて comment の語を外す。対照：`rg -c 'run_service_dispatcher\(' src/main.rs src/win_service.rs` が 1 と 1）。feature：`cargo tree -e features --target x86_64-pc-windows-gnu \| grep -c 'local-offset'` が 1 以上、`cargo tree -e features --target x86_64-unknown-linux-gnu \| grep -c 'local-offset'` が 0（Linux の binary に入れない）。cross build：`cargo build --release --target x86_64-pc-windows-gnu 2>&1 \| grep -c -E '^(warning\|error)'` が 0（対照 `… \| grep -c Finished` が 1）。Linux：`cargo test --release` が全 binary `0 failed`。実機（Windows、管理者の PowerShell）：新しい exe でサービスを起こし、`(Select-String -Path <log dir>\service.log -Encoding UTF8 -Pattern '読み直した\|reloaded').Count` を採り、blocklist の file に `# probe` の 1 行を足して 1 秒 待ち、同じ command が 1 増え、最後の一致行が RFC 3339 の時刻（`+09:00` の形。`Z` なら offset が取れていない）で始まり `path=` と `entries=` を含む（`-Tail` ではなく一致行の数で数える）。量（記録だけ。通過線は置かない）：`(Get-Item <log dir>\service.log).Length` と `(Get-Item <pcapng>).Length`、`(Get-Item <pcapng>).LastWriteTime`、`(Get-Content <log dir>\flows.jsonl).Count` を同じ 10 分の窓で 2 回ずつ採り、service.log の差を bytes/分 で、pcapng の差と大きさと `LastWriteTime` の変化と flows.jsonl の行の増加を陽性対照として記録する（pktmon の rotate で pcapng が作り直されると `Length` が偶然 同じになり得るので、`LastWriteTime` と flows.jsonl で動いていることを見る）。fail-open：`sc stop packetdeath` の後に既存の `service.log` を `Rename-Item` で退避し、`<log dir>\service.log` の名前で directory を作り、`(Get-Item <log dir>\service.log).PSIsContainer` が `True` であることを見てからサービスを起こし、`sc query packetdeath` が `RUNNING` のままで `flows.jsonl` が増える（開けないときに止まらない）。試した後は directory を消して file を戻し、サービスを再起動する。`LastWriteTime` も `flows.jsonl` も動かなかった窓は、pcapng が作られていない窓なので「bytes/分 は未測定」と記録する。`Select-String -Encoding UTF8 -Pattern '\[debug\]'` の一致が 0（対照：`'\[info\]'` が 1 以上）。`'\[warn\]'` の一致数も記録する（`pcapng_truncated`、`reassemble_*` の頻度） | unit 7 本と integration 2 本 `ok`、main.rs の `service_log(` 2、`eprintln!` を持つ file が列挙の 11 file だけ、10 module の `service_log(` 合計 26（PK-121 の後は 28）、`src/flow.rs` 2、向け直しが dispatcher の前、`local-offset` が Windows の木だけ、cross build の warning 0、Linux の test `0 failed`、実機で読み直しの一致行が +1。実機の受入は Windows 11 の host（WSL の interop で管理者の PowerShell を打つ機械）で通過：`service-install` → `Running`、読み直しの一致行 0 → 1、行は `+09:00` の RFC 3339、`[debug]` 0 / `[info]` 2、`service.log` を directory にしても `Running` のまま、`service-uninstall` で 0 件。利用者の PC（`C:\pd`、install.ps1 で入れ替え）でも通過：`RUNNING`、`service.log` に `[info]` 2 行（blocklist 47689 件、allowlist 363 件。日本語。`+09:00`）、読み直しの一致行 0 → 1、`[debug]` 0 / `[warn]` 0 / `[error]` 0。量は 4 分 52 秒 の窓で読み直しの 1 行（140 byte）だけ、それ以外は 0 bytes/分。同じ窓の pcapng は rotate ごとに 0.2 KB、`flows.jsonl` は +2 行（PC の通信は proxy の 8081 へ向くので、443 の capture にはほとんど入らない） |
| **PK-121** | 常駐 PowerShell を spawn の直後に温め、温まった bridge だけが行を送る。温めの上限は 5 秒、行の上限は 500 ms のまま。温めが失敗したら 60 秒は spawn しない | unit：`cargo test -- ps_bridge::tests::warm_up_accepts_a_slow_first_response_within_startup_timeout ps_bridge::tests::warm_up_times_out_when_no_response_within_startup_timeout ps_bridge::tests::a_warmed_bridge_keeps_the_row_timeout block_loop::tests::respawning_bridge_warms_a_slow_child_before_the_first_row block_loop::tests::respawning_bridge_waits_before_respawning_after_a_failed_warm_up i18n::tests::ps_bridge_warmed_message_names_ms i18n::tests::ps_bridge_warm_up_failed_message_names_timeout`。配線：`rg -c 'fn with_spawner' src/block_loop.rs` が 1、`rg -c 'fn prepare' src/block_loop.rs` が 1、`rg -c '\.prepare\(\)' src/win_service.rs src/main.rs` が 1 / 1、`rg -c 'STARTUP_TIMEOUT\|WARM_UP_BACKOFF' src/ps_bridge.rs src/block_loop.rs` が各 1 以上、`rg -c 'from_millis\(500\)' src/ps_bridge.rs` が 1（`RESPONSE_TIMEOUT` は触らない）。cross build：`cargo build --release --target x86_64-pc-windows-gnu 2>&1 \| grep -c '^warning'` が 0。実機（利用者の PC、`install.ps1` の後。非昇格の ssh から `powershell.exe -NoProfile -Command` で打つ）：`Select-String -Encoding UTF8 -Pattern '温めた\|warmed' C:\pd\log\service.log` の行とその `rc=`、`$c = New-Object Net.Sockets.TcpClient('<blocklist に当たる host>', 443); $s = New-Object Net.Security.SslStream($c.GetStream()); $s.AuthenticateAsClient('<host>'); $p = $c.Client.LocalEndPoint.Port; @(Get-NetTCPConnection -LocalPort $p -State Established).Count; Start-Sleep 12; @(Get-NetTCPConnection -LocalPort $p -State Established -ErrorAction SilentlyContinue).Count; try { $s.Write([byte[]]@(0)); $s.Flush(); 'write ok' } catch { 'write failed' }`、`flows.jsonl` のその host の末尾 1 行、`Select-String -Pattern '500ms' service.log` の数を install の前後で。陰性対照は blocklist に無い host で同じ形（`1` → `1`、`write ok`、`"decision":"pass"`） | unit 7 本 `ok`、配線の数が上の値、cross build の warning 0、実機で温めの `[info]` が 1 以上で `rc=317`（SYSTEM。違う値なら所見として記録）、保持した接続が `1` → `0` で `write failed`、`flows.jsonl` が `"decision":"block"` と `"reason":"sni"`、`500ms` の `[warn]` が install の後は増えない、陰性対照が `1` → `1` と `pass` |
| **PK-122** | `try_block` は `SetTcpEntry` の `rc=0` のときだけ `true` を返す。`rc≠0` は `false` と `[warn]`（`rc` と所要時間）。`judge_and_log` は `false` を `pass` に写す | unit：`cargo test --release -- block_loop::tests::a_nonzero_rc_is_not_a_cut block_loop::tests::a_zero_rc_is_a_cut i18n::tests::tcp_cut_rejected_message_names_rc` と既存の `judge_and_log` の test。integration：`cargo test --release --test independent_cut_result`。配線：`rg -c 'resp.rc == 0' src/block_loop.rs` が 1、`rg -c 'tcp_cut_rejected' src/block_loop.rs src/i18n.rs` が 1 / 2 以上、`sed -n '1,/^#\[cfg(test)\]/p' src/block_loop.rs \| rg -c '317'` が出力なし（対照 `rg -c '317' src/block_loop.rs` が 1 以上）。cross build の `^warning` が 0。実機：PW-7 の形で打つ前と後に `(Select-String -Encoding UTF8 -Pattern '切らなかった\|did not cut' C:\pd\log\service.log).Count` を採り、`flows.jsonl` の `decision` を読む | unit 3 本 `passed`、integration 1 本 `passed`、既存の test が `0 failed`、`rg -c` が左の数、実機は 接続が切れなければ「切らなかった」が +1 で `rc=<n>` が読め `pass`、切れれば +0 と `block`。実機 2026-10-04 17:48（利用者の PC、exe c60b4bf70faa5ad7）：0 → 1、`rc=87`、`flows.jsonl` は `pass`。通過 |

### test 項目

実装の前に決める。作った物に test を合わせないためである。

unit test（各 module の `#[cfg(test)]`）。

| 対象 | 確かめること |
|---|---|
| `--mitm-list` の一致 | 完全一致、サブドメイン、大文字小文字、末尾の `.`、`notexample.org` が `example.org` に当たらない、`#` の行と空行、IP literal は当たらない |
| `--mitm-list` と allowlist の重なり | allowlist に当たる項目ごとに、起動時と読み直し時に host 名つきの `[warn]` が1行 出る。陰性対照：重なりが無ければ 0 行 |
| scan の条件 | `Content-Length` が 4293918720 は scan、4293918721 は scan しない、0 は scan しない、無いときは溜めて超えたら諦める（境界は定数 `DEFAULT_MAX_SCAN_BYTES` から導く） |
| 本文の種類 | `application/zip` と `application/octet-stream` は scan、`application/json` と `application/javascript` と `application/vnd.api+json` と `text/xml` と `text/event-stream` は scan しない、`text/html` と `image/png` と `font/woff2` は scan しない、`image/png` に attachment が付けば scan、`text/plain` と種類無しは scan する、`Application/ZIP; x=y` のような大文字と parameter を正しく読む |
| status と method | `200` と `GET` だけ scan。`206`、`304`、`HEAD`、`POST` は scan しない |
| `Content-Encoding` | 無い、`identity` は scan。`gzip`、`br` は scan しない |
| clamd の応答 | `stream: OK`、`stream: Eicar-Test-Signature FOUND`、空白を含む signature、`INSTREAM size limit exceeded. ERROR`、空、NUL が無い、壊れた形 |
| INSTREAM の組み立て | 塊の長さが big endian、64 KiB で分割、最後が長さ0、空の本文 |
| `Reason::Av` | `as_log_str()` が `"av"`。FOUND の行が `"decision":"block"` と `"reason":"av"` を含む JSON になる |
| `av.jsonl` の行 | field と型が段階6 の形に一致し、`AvList::parse` で読み戻すと `malicious` と `clean` の件数が合う（既存の reader との往復） |
| CA | 生成して読み戻せる。CN が `packetdeath CA <日付>`。pathlen 0。有効期間730日。鍵が `0600`。片方だけ在るときと権限が `0644` のときと期限切れのときは読み込みを拒み、file を書き換えない |
| leaf | SAN が host、serverAuth、有効7日、CA で署名されている。1日以内は同じ設定を返す。上限256で古い物を捨てる |
| bypass 表 | 組ごとに入る、寿命で消える（時計を引数で渡す）、上限4096で古い組から捨てる、別の client の IP は影響されない |
| chunked | 正常、16進の大文字小文字、chunk extension、size 行が長すぎる、16進でない、size が `usize` を超える、終端の欠落、trailer。そのまま写した結果が入力と一致する |
| request と応答の書き換え | `Connection`、`Proxy-Connection`、`Keep-Alive`、`Expect` を落とす、`Accept-Encoding` を `identity` にする、`Content-Length` の重複で値が違うときと `Transfer-Encoding` の同居を拒む |
| CLI | 3つの option が読める、一部だけのときは無効で足りない名前を返す、`--clamd` が path と `addr:port` を見分ける |

integration test（`tests/independent_mitm.rs`。既存の `independent_*.rs` の並び）。偽の上流（rustls の server。test 用の CA が署名した `localhost` の証明書）と偽の clamd（`tests/tmp-independent-mitm/` の下の Unix socket。`.gitignore` の `tests/tmp-*/` に当たる）を test の中に立てる。proxy へ渡す上流の信頼 root は、test 用の CA に差し替える（本番は webpki-roots）。時間と上限は `ProxyLimits` と同じ形の struct にまとめ、test が短い値を渡す。

| test | 受ける ID | 確かめること |
|---|---|---|
| `eicar_is_replaced_with_403_and_logged_as_av` | PK-103 | status `403`、本文の差し替え、`flows.jsonl` の `block` と `av`、`av.jsonl` の `malicious` |
| `clean_file_passes_and_is_recorded_in_av_jsonl` | PK-103 | `200`、本文が byte 一致、`av.jsonl` に `clean` |
| `clamd_down_passes_the_same_file` | PK-104 | clamd を閉じた状態で `200`、本文が byte 一致、`[warn]` |
| `oversize_body_is_streamed_without_scan` | PK-105 | `MitmLimits.max_scan_bytes` を小さく差した proxy で、上限 + 1 byte が byte 一致で届き、偽 clamd への接続が0、`too_large` の `[info]` |
| `exactly_the_limit_is_scanned` | PK-105、PK-113 | `MitmLimits.max_scan_bytes` を小さく差した proxy で、上限ちょうどの本文は scan され（偽 clamd への接続が1）、+1 byte は 0。既定の `max_scan_bytes` は 4293918720 |
| `pinned_client_falls_back_to_tunnel_on_the_next_connection` | PK-107 | 1回目は client が復号を拒む（alert か無通告の切断）、2回目は非復号で通る |
| `bypass_expires_after_its_ttl` | PK-107 | 寿命を1秒にして、3回目は復号に戻る |
| `upstream_tls_failure_falls_back_to_tunnel` | PK-107 | 上流の証明書が proxy の root に無いとき、client が直接 検証できる非復号で通る |
| `ten_mib_clean_download_overhead_is_within_two_seconds` | PK-108 | 実際の clamd を使う。socket が無ければ失敗 |
| `connect_to_unlisted_host_is_not_slowed_by_a_running_scan` | PK-109 | scan 中の別の CONNECT の遅れが0.5秒以内 |
| `chunked_response_is_scanned_decoded` | PK-103 の補足 | 偽 clamd が受けた bytes が、chunk を外した本文と一致する |
| `head_range_and_page_parts_are_not_scanned` | PK-105 の補足 | `HEAD`、`206`、`text/html` で偽 clamd への接続が0 |
| `request_body_is_forwarded_exactly` | 復号した通信の扱い | `Content-Length` の body が上流へそのまま届く |
| `ca_certificate_is_served_and_the_key_never` | PK-111 | MITM 有効の proxy の `GET /ca.crt` が `200` と `application/x-x509-ca-cert` で `--ca-dir` の `ca.crt` と同じ bytes を返し、`GET /ca.key` は `400`。MITM 無効の proxy の `GET /ca.crt` は `400`。flow log に残らない |
| `clean_and_found_lines_carry_the_scan_time` | PK-112 | 擬似 clamd が `stream: OK` を返す download の `[info]` に `ms=` が在り、`FOUND` を返す download の `[info]` にも `ms=` が在る。`MitmLimits::default().clamd_timeout` は 1260 秒、起動時の PING の timeout は 10 秒の別の定数 |
| `a_silent_clamd_times_out`（`src/clamd.rs` の unit） | PK-112 | 何も返さない偽 clamd に 200 ms の timeout で `scan` すると `Failed(Timeout)`。偽 clamd は test が終わるまで stream を握り、時間で切らない。握りの上限 30 秒は `scan` が timeout を失う回帰で test が止まらないための物で、test が頼る窓ではない |
| `an_interrupted_read_is_retried`（`src/clamd.rs` の unit） | PK-112 | `read_reply` に、最初の `read` が `ErrorKind::Interrupted` を返し 2 回目に `stream: OK\0` を返す偽の reader を渡すと `Ok(b"stream: OK\0")`。`EINTR` は verdict ではない。socket の read に受信 timeout が付いていると、signal で起きた read は `EINTR` で戻って再開されない（Linux の `sock_intr_errno`）。同じ process の別 thread が子 process を spawn する間は signal を block するので、その窓に届いた `SIGCHLD` は捨てられずに queue に入り、kernel が read で眠る別の thread を起こす。unit test の ps_bridge の test が子 process を spawn・kill するので、lib の test 全体の走行では 10 回に 1 回ほど `scan` が `Failed(Error)` を返していた（ps_bridge を外すと 0） |
| `limits_exceeded_is_passed_through_as_unscanned` | PK-113 | 擬似 clamd が `stream: Heuristics.Limits.Exceeded.MaxFileSize FOUND` を返す download は `200` で本文がそのまま届き、`403` にならず、`av.jsonl` に行が増えず、`[warn]` に host と署名名が出る。本物の署名名（`Eicar-Test-Signature`）を返す download は従来どおり `403` と `malicious` |
| `upgrade_gets_501_and_is_bypassed_next_time` | 復号した通信の扱い | `501`、次の接続は非復号 |
| `scan_slot_exhaustion_passes_unscanned` | 安全、PK-115 | 予算が本文 1 本分のとき、2本目の大きい応答が scan されずに通る（`slot_full` の `[warn]`）|
| `scan_budget_counts_bytes_not_connections` | PK-115 | 予算が小さい本文 2 本分のとき、2 本は同時に scan され、3 本目は scan されずに通る。1 本が返り終えると予算が戻り、次は scan される |
| `unknown_length_takes_the_whole_limit_from_the_budget` | PK-115 | 予算が上限 1 本分のとき、`Content-Length` の無い（chunked の）応答が予算を全部 取り、同時の小さい応答は scan されずに通る |
| `default_limits_match_the_design`（`src/mitm.rs`） | PK-113、PK-115、PK-118 | 既定の上限が「大きさ」の行の値（PK-115 で 4293918720、PK-118 で 8588886016）、予算が 8589934592、timeout が表 c の値（PK-118 で 1260 秒） |
| `blocked_host_in_mitm_list_is_not_decrypted` | 復号する範囲の2 | blocklist に当たる host は deny のままで、上流への接続が0 |
| `allowlisted_host_in_mitm_list_is_tunneled` | 復号する範囲の3 | allowlist に当たる host は非復号 |
| `mitm_list_reload_takes_effect` | PK-106 | 走行中の書き換えが 300 ms 後の CONNECT に効く |
| `client_dropping_after_the_handshake_falls_back_to_tunnel` | PK-107 | request 0 のまま無通告で切る client は bypass に入る（curl 8.18 の形） |
| `clean_close_after_the_handshake_keeps_decrypting` | PK-107 の陰性対照 | close_notify 付きの切断は bypass に入らない |
| `silent_close_after_a_recent_request_is_not_bypassed` | 成功の記憶 | request を始めた後に同じ (client, host) の別接続が無通告で切れても bypass に入らず、次も復号される（Chrome の兄弟 socket の形） |
| `alert_is_bypassed_even_after_a_recent_request` | 成功の記憶の陰性対照 | 直近に成功があっても alert は bypass に入る |
| `close_before_tls_is_not_bypassed` | 契機にしない物 | TLS の byte 0 で閉じた接続は bypass に入らない |
| `silent_close_during_the_handshake_is_not_bypassed` | 契機にしない物 | handshake 途中の alert 無しの切断は、成功の記憶が無くても bypass に入らず、次は復号される（Chrome の起動直後の形） |
| `idle_flows_leave_the_set_after_the_ttl`（`src/linux.rs` の unit） | PK-119 | 時刻 t に入れた flow は、t + TTL − 1 秒の掃除では残り、t + TTL + 1 秒の掃除で落ちる。掃除は落とした数を返す |
| `a_touched_flow_survives_the_sweep`（`src/linux.rs` の unit） | PK-119 | 時刻 t に入れ t + TTL/2 に packet を見た flow は、t + TTL + 1 秒の掃除で残る（最後の packet から数える） |
| `flow_set_swept_message_names_the_count`（`src/i18n.rs` の unit） | PK-119 | 掃除の `[debug]` の文に落とした数が `removed=` で入る（ja と en の両方） |
| `service_log_writes_one_timestamped_line_per_call`（`src/flow.rs` の unit） | PK-120 | offset `None` で開いた file に 2 行 書くと 2 行 在り、各行は RFC 3339 の形の時刻（`YYYY-MM-DDThh:mm:ss` で始まり `Z` で終わる）、空白、渡した文の順で、末尾が改行 |
| `service_log_writes_the_given_offset`（`src/flow.rs` の unit） | PK-120 | offset `+09:00` で開いた file に 1 行 書くと、時刻が `+09:00` で終わり `Z` を含まない |
| `service_log_utc_fallback_message_names_utc`（`src/i18n.rs` の unit） | PK-120 | offset が取れないときの `[warn]` の文に `UTC` が入る（ja と en の両方） |
| `service_log_reopen_appends_instead_of_truncating`（`src/flow.rs` の unit） | PK-120 | 1 行 書いて閉じ、同じ path を開き直して 1 行 書くと 2 行 在る（append で開く） |
| `write_line_on_a_full_device_returns_err`（`src/flow.rs` の unit。Linux） | PK-120 | `/dev/full` で開いた sink の `write_line` が `Err` を返し、panic しない（書けない行を stderr へ落とす枝の入口） |
| `write_line_survives_a_poisoned_lock`（`src/flow.rs` の unit） | PK-120 | 別 thread が名前付きの guard で lock を握ったまま panic して mutex を poison した後（`is_poisoned()` が true を assert）も、`write_line` が `Ok` を返し file に 1 行 増える |
| `service_log_open_failed_message_names_the_path`（`src/i18n.rs` の unit） | PK-120 | `service.log` を開けなかったときの `[warn]` の文に path が `path=` で入る（ja と en の両方） |
| `service_log_lines_reach_the_redirected_file`（`tests/independent_service_log.rs`） | PK-120 | 別 process で `redirect_service_log` に開いた sink を渡し（戻りが true）、`service_log` を `[info]`、`[debug]`、`[warn]` の 3 回 呼ぶと、file に 2 行 在り（`[debug]` は無い）、本文が渡した文と一致し、2 回目の `redirect_service_log` は false |
| `service_log_open_on_a_missing_dir_fails_without_panic`（`tests/independent_service_log.rs`） | PK-120 | 無い dir の下の path で `ServiceLog::open` が `Err` を返し、panic しない（dir は作られない） |
| `warm_up_accepts_a_slow_first_response_within_startup_timeout`（`src/ps_bridge.rs` の unit。Linux。`sh -c` で、1 行 読んでから 700 ms 待って `rc=317 us=1.0` を返す偽の子） | PK-121 | `warm_up(Duration::from_secs(5))` が `Ok` を返し、その応答の `rc` が 317。700 ms は `RESPONSE_TIMEOUT`（500 ms）より長く、温めの上限より短い |
| `warm_up_times_out_when_no_response_within_startup_timeout`（`src/ps_bridge.rs` の unit。`HANGS_FOREVER` の子） | PK-121 | `warm_up(Duration::from_millis(300))` が `Err(BridgeError::Timeout)` を返し、かかった時間が 300 ms + 4 秒 未満、以後の `send_tcp_row` は `Err(BridgeError::Poisoned)` |
| `a_warmed_bridge_keeps_the_row_timeout`（`src/ps_bridge.rs` の unit。Linux。1 行目には即 `rc=317 us=1.0` を返し、2 行目以降は返さない偽の子） | PK-121 | `warm_up(Duration::from_secs(5))` が `Ok` の後、`send_tcp_row` が `Err(BridgeError::Timeout)` を `RESPONSE_TIMEOUT` + 4 秒 未満で返す（温めの後の行の上限は 500 ms のまま） |
| `respawning_bridge_warms_a_slow_child_before_the_first_row`（`src/block_loop.rs` の unit。Linux。`with_spawner` に、1 行目だけ 700 ms 待ってから返し、以後は即 返す `sh -c` の子を渡す） | PK-121 | `try_block(&row)` が `true`（温めが無いと 1 行目が 500 ms で timeout して `false` になる形を、`try_block` 越しに通す） |
| `respawning_bridge_waits_before_respawning_after_a_failed_warm_up`（`src/block_loop.rs` の unit。`with_spawner` に `HANGS_FOREVER` の子、`startup_timeout` 200 ms、`backoff` 2 秒を渡す） | PK-121 | 1 回目の `try_block` は `false` で約 200 ms かかり、直後の 2 回目は `false` で 50 ms 未満（spawn していない）、`backoff` の後の 3 回目は再び約 200 ms（spawn し直した） |
| `ps_bridge_warmed_message_names_ms`（`src/i18n.rs` の unit） | PK-121 | 温めの `[info]` の文に ms の数が入る（ja と en の両方） |
| `ps_bridge_warm_up_failed_message_names_timeout`（`src/i18n.rs` の unit） | PK-121 | 温めの失敗の `[error]` の文に timeout の長さが入る（ja と en の両方） |
| `a_nonzero_rc_is_not_a_cut`（`src/block_loop.rs` の unit。Linux。`sh -c` で、温めにも行にも `rc=317 us=1.0` を返す偽の子） | PK-122 | `with_spawner` 越しの `try_block` が `false` を返す（`rc=317` を成功側に書くと落ちる） |
| `a_zero_rc_is_a_cut`（`src/block_loop.rs` の unit。Linux。温めには `rc=317 us=1.0`、行には `rc=0 us=1.0` を返す偽の子） | PK-122 | `try_block` が `true` を返す |
| `cut_result_reaches_the_service_log`（`tests/independent_cut_result.rs` の integration。Linux。別 binary。`ServiceLog::open` の file へ `redirect_service_log` し、`with_spawner` の偽の子が温めに `rc=317`、1 行目に `rc=0`、2 行目に `rc=317` を返す） | PK-122 | 1 行目の `try_block` の後に「切らなかった」を含む行が 0、2 行目の後に 1 で、その行に `[warn]` と `rc=317` が入る。温めの `[info]` は数えない |
| `tcp_cut_rejected_message_names_rc`（`src/i18n.rs` の unit） | PK-122 | `[warn]` の文に `rc=` と `us=` が入る（ja と en の両方） |

CLI の段階で、3つの option の一部だけのときに段階7 と同じ挙動になること（PK-100）は、`src/main.rs` の既存の `parse_proxy_args` の test と同じ場所で受ける。

### 残る穴

保証できないこと、残る穴を書く。
- 常駐 PowerShell の温め（PK-121）は spawn ごとに最大 5 秒 待ち、その間に来た広告の接続は fail-open で通る。温めが毎回 失敗する機械（`powershell.exe` の起動が 5 秒を超える）では、60 秒ごとに 5 秒の待ちと、`[warn]`（5s 以内に来なかった）と `[error]`（温めの失敗）の 2 行が出て、遮断は 1 件も成立しない。`process_pcapng_snapshot` は 1 snapshot を同期で処理するので、その 5 秒の間はサービスの停止も待つ。`service.log` の `[error]` の数で見つける。
- 検知率は ClamAV の署名の質であり、packetdeath の性能ではない。「マルウェアを防げる」とは書けない。
- 8191 MiB を超える file、`Range` で再開する download（`206`）、パスワード付きの archive（この機械の clamd は `ArchiveBlockEncrypted false`）は検査されずに通る。上限は memory で決まる値で（「clamd の自前 build」の採らない手段）、上限超を選べる攻撃者に対しては無力である。
- 2 GiB を超える file を扱う libclamav の parser は開発元が試していない。誤動作が crash なら `Restart=on-failure` で clamd が戻り、その scan は fail-open で通る（`[warn]`）。誤動作が「検査したつもりで見逃す」形なら、機械では当たらない。実測は PK-114 の記録の行（2.5 GiB の zip）から積む。
- 自前 build の clamd には apt の security fix が届かない。届けるのは手順書の build し直しだけで、打たないと配布より古い clamd が動き続ける。64-bit 化の patch の列（`scripts/clamav-64/`）は配布の版が上がるたびに当て直しが要り、当たらなくなった patch は読み直して作り直す。
- 64-bit 化の後も、format が 32-bit の書庫（PE、OLE2、CAB、ARJ など）の中身は 4 GiB を超えられない。zip の 4 GiB 超の member は `unzip.c` が zip64 を読まないので member として展開されず、生の走査で当たる部分署名だけが当たり、EOF に anchor した署名は当たらない（PK-117 の記録の行）。4 GiB より後ろに埋め込まれた zip、arj、PE は、`scanners.c` がその parser へ渡す位置が 32-bit なので、回った位置を読む（crash なら `Restart=on-failure` で戻り、見逃しなら機械では当たらない）。同じ種類の狭まりが 3 箇所 残る：byte-compare 署名の `cli_bcomp_compare_check` の位置は `int`（2 GiB 以上で狭まるが、領域の検査は長さに対して行われる）、`matcher_run` が PCRE に渡す file 全体の長さは `uint32_t`（`PCREMaxFileSize` が 0 のときだけ 4 GiB 以上で先頭の下位 32 bit 分しか見ない。この機械は 25M）、tar の `cli_matchmeta` に渡す大きさは 32-bit（cdb の metadata の照合だけが 4 GiB で回る）。bytecode の署名は 4 GiB 以上の file に走らず（F-0）、大きさ付きの hash 署名（`.hdb` / `.hsb` の size の欄。`cli_hm_scan` が `uint32_t` で受ける）は 4 GiB 以上の file に当たらない（size が `*` の署名は当たる）。tar と ISO9660 の直しは手元の 2 本と開発元の unit test（`ctest`）だけが安全網で、fuzz は掛けていない。hfsplus、egg、udf の 4 GiB 超は実測が無い。
- `PCREMaxFileSize 25M` を据え置くので、25M 超の file には PCRE の部分署名が走らない。2 GiB まで同じ強さで検査しているわけではない。
- `MaxScanSize`、`MaxFiles 10000`、`MaxRecursion 16`、`MaxScanTime 1134 秒` を超えた file は「検査未了」で通る（`[warn]`）。10000 file 超の正規の archive は毎回 未了になる。2 GiB 級の ISO9660 は中身の合計が `MaxScanSize`（8190M のとき）に当たって未了になった実測が在り、16382M でも大きい ISO は同じ形で未了になりうる（端末はその間 本文を待つ）。
- 本文を溜めている間も scan の予算（8 GiB）を握るので、8191 MiB 級の download 1 本（4095 MiB 級なら 2 本）で予算が尽き、その間（最長 1260 秒）の他の scan 対象は `slot_full` で素通しになる。
- `Content-Length` の分（無ければ上限の分）を先に `reserve_exact` で予約する（`hold_exact`）。4 GiB と名乗って本文を送らない上流は、上流の read timeout で `502` になるまで予算を握る。予約は仮想で、RSS は届いた分だけである（`vm.overcommit_memory` が `0`。`実測`）。
- timeout（1260 秒）の間、端末の download は本文が来ないまま止まって見える。iPhone や Windows の app が最初の byte を数分 待つかは `未確認`（PK-113 で PC の Chrome を 1 回 測る）。
- clamd の temp は F-3 まで tmpfs なので、4 GiB の scan は展開分を含めて RAM を使う（予算いっぱいの 2 本 同時なら proxy の 8 GiB に加えて 8 GiB と展開分）。F-3 で `/var/tmp/clamav`（disk）へ移す。
- `Content-Encoding` を無視して br や gzip で返す server の本文は scan しない。
- 署名の反映は最長1時間 遅れる。
- 最初の1回は pinning の host で失敗する。
- `Content-Type` は server が名乗る物である。流さない物（`image/png` など）を名乗る server の本文は scan しない。「流さない物」の列挙が塞ぐのは、header を省いた応答と `text/plain` だけである。
- clamd の timeout（既定 1260 秒）は fail-open なので、timeout を起こす重い archive は無検査で通る（clamd の `MaxScanTime` は 1134 秒で先に切れ、「検査未了」として `[warn]` になる）。新しい file の scan は clamd の cache（archive の中身の file ごと）に当たらない「中身まで cold」で 4.6〜10 秒 掛かる（`実測` 2026-10-03 22:07：16 file の zip 4.60 秒、679 file の zip 9.19 秒、どちらも swap-in 0。同じ zip の外側の hash だけ変えた 2 回目は 1.82 / 2.52 秒）。swap に出ていたことも疑って unit に `MemorySwapMax=0` を当てたが、原因だったかは立証されていない（`NOT VERIFIED`。害が無いので残す）。timeout の間、端末の download は本文が来ないまま止まって見える。iPhone や Windows の app が最初の byte を待つ限界は `未確認`。10 秒を超える cold scan の実測は 0 件。
- 検査するのは `--mitm-list` の host から落ちる file だけである。list に無い host の file は復号も scan もしない。
- `ca.key` が漏れた場合、旧 CA を端末から消すまでの間、被害は端末が信じる全 domain に及ぶ（name constraints を採らない代償）。
- 復号した通信は HTTP/2、WebSocket、パイプラインを扱わない。扱えない物を見つけた host は1時間 非復号になる。
- (C) の元の意図（端末に落ちた file）のうち、proxy を通らない file は検査しない。
- 応答側の「扱えない」（`Content-Length` の不一致など）でも bypass 表に入る。悪意の host が最初の 1 回だけ矛盾した応答を返すと、その (client, host) は 1 時間 scan されない。穴は広がっていない（host が自分の file を上限超や `image/*` に偽装すれば今でも同じ結果になる）。
- handshake を終えた後に request 無しで無通告に切られ、成功の記憶も無い場合は bypass に入る（Chrome の起動直後の設定の読み直しが handshake 完了後に当たった回。2026-10-03 の headless Chrome 14 回中 1 回）。その host の scan が 1 時間 止まる。pinning の client が close_notify を付けて切る場合は、どの契機にも当たらず見えない。
- handshake の途中で alert を送らずに切る pinning の client は、bypass に入らず失敗し続ける（1 時間の免除が無い）。OpenSSL、BoringSSL、rustls は拒否のときに alert を送るが、Windows の Schannel と Apple の実装は `未確認`。CA を入れた普通の Chrome（`--ignore-certificate-errors` 無し）での再測も導入時に 1 回 取る。
- clamd への `connect` と `write` は `EINTR`（signal で起きた syscall）を再試行しない（`read` だけ再試行する。`write_all` は std が再試行する）。本番の proxy は Linux で子 process を持たず signal の handler も無いので、`EINTR` が起きる契機は無い。
- unit test の fixture（偽 clamd の socket、CA の dir）は repo の中の process ごとの dir（`tests/tmp-unit-<pid>/`。`.gitignore` の `tests/tmp-*/` に当たる。Unix socket の path は 108 byte までなので dir の名前は短くする）に置き、作るときに同じ親の `tmp-unit-*` のうち pid が生きていない物（`/proc/<pid>` が無い）を消す。同じ repo の test binary を 2 つ 同時に走らせると、固定の path では片方が相手の socket file を消して bind し、相手の `scan` が別の偽 clamd に繋がって `Failed(Error)` になり、CA の test も 12 本 落ちる。cargo を 1 本ずつ打つ決まりの外（別の担当が同時に打った回）でだけ起きる。
- `docs/` の md は `check-privacy.sh` の項目5 の対象外（項目4 が引用と出所の印だけを見る）。
- `linux.rs` の flow の集合は payload の在る packet が 600 秒 来ないと忘れる（PK-119）。再開した flow は log に 2 行 目が出て、`run_block` では `SniState::None` で判定が走り直すので、allowlist（SNI にしか効かない）で通した接続が IP・IDS・av で切れることが在る。ACK しか出さない長い download は idle と数えられる。block した flow は、client の data の再送間隔が 600 秒を超えると末尾の segment が通る（Linux の RTO の上限は 120 秒なので当たらない。他 OS の再送の上限は未確認）。集合の個数は到着率 × 600 秒まで育ち、flood で memory が尽きれば nfqueue は `--queue-bypass` で素通しに倒れる。`HashMap::retain` は容量を縮めないので、一度 育った map の容量は process が生きている間 残る。`cname_matched_qnames`（CNAME の行き先が blocklist に当たった応答の qname の集合）には TTL が無く、DNS 応答の qname の種類の数だけ育つ。
- `service.log`（PK-120）に rotation が無い。`pcapng_truncated` の `[warn]` は snapshot の読みごとに出るので、pcapng の長さが poll ごとに変わり続ける間は最大 300 ms に 1 行 育つ（長さが止まれば読み直されず 1 行で止まる。頻度は `未確認`。実機の受入で bytes/分 を測る）。`reassemble_buffer_overflow` と `reassemble_flow_limit_reached` の `[warn]` は `feed` の中で出るので、同じく読み直しのたびに履歴の flow の分だけ出る（数は pcapng の大きさで決まる）。`[debug]`（allowlist で通した flow、切った接続、SNI の判定）はサービスでは見えない（file に書かない）。file へ書けないこと（`write_line_on_a_full_device_returns_err`）と poison の後も書けること（`write_line_survives_a_poisoned_lock`）は unit で当たるが、`service_log` が `Err` の行を stderr へ落とす枝そのものは、global を使う process で stderr を読む手が無いので機械では当たらない。`write_all` が途中で `Err` になると、file に半端な行が残り、同じ行が stderr にも出る。
- 「anti-adblock script の回避」を対象外と書く行（「公開の検討」の 2 箇所と「技術的制限手段」の行）と、`--deny blackhole` の既定（拒否を相手に伝えない）、利用者が自分で入れる blocklist に anti-adblock 系の host が混じり得ること（packetdeath は list の中身を選ばない）の 3 つは、公開前（PK-40）に 1 つの文で整合を取る。`未確認`。anti-adblock の壁を出す第三者 host（Google の Funding Choices の配信 host）は blocklist に足さない（壁の除去は要件に無く、同じ host は多くの site が読む）。panic の文は stderr へ出るので失われる。offset は起動時の 1 回だけ取るので、夏時間の在る zone では切り替えの後の時刻の offset が古いまま（夏時間の無い zone では起きない）。`service-run` の引数の parse error、`locale=` の `[info]`、`service.log` を開けなかったときの `[warn]` は、向け直しの前なので stderr のまま消える。`--log-dir` が無いか権限が無いときは `service.log` と `flows.jsonl` が同じ原因で開けず、いちばん要る `flow_log_open_failed_wait_stop` の `[error]` も残らない。`service_main_entry` は `run_service` の `Err`（`register` や `set_service_status` の失敗）を捨てるので、その失敗は 0 行のまま。向け直しは process に 1 回なので、`--log-dir` を変えるには再起動が要る。
- clamd への Unix socket の connect に timeout が無い（std に API が無い。送受信の timeout は 1 手ごと）。backlog が満杯の clamd だと scan の thread と枠が戻らず、素通し（fail-open）に落ちて log は出ない。
- 本文を溜めている間も scan の予算を握る。遅い上流が少しずつ送ると、予算は最大 `pipe_idle_timeout` のあいだ埋まり、その間の download は素通しになる。
- `Expect: 100-continue` を落とすだけで `100 Continue` を返さないので、upload する client は本文を送る前に約 1 秒 待つ（curl の既定の待ち）。
- fd が尽きた間（上限は unit の `LimitNOFILE=65536`。1 本の中継が 4 本 使う）、accept は失敗し続け、proxy は `[warn]` を 100 ms ごとに出すだけで新規の接続を受けられない。端末からは proxy が応答しないように見える。fd が戻る契機は既存の接続の終わり（`pipe_idle_timeout` 300 秒か相手の切断）だけである。
- 対象外の種類の応答ごとに `[debug]` が 1 行 出る（page の部品ごと）。`av.jsonl` の権限は `flows.jsonl` と同じ `0644` で、download ごとの宛先 IP と sha256 を含む（「捨てるとき」）。

## 段階10 能動防御（PC を守る見張りと遮断）

### 結論

段階10 は、公開の告知と脅威の feed から得た「悪い証明書」と「悪い宛先」を、PC の通信へ当てる。
作る物は4つで、確かさの高い source（OneCRL、SSLBL の証明書の指紋）は最初から止める側で入れる。
誤爆の見込みが読めない source（広く使われる root の行、SSLBL の IP）だけを見張りから始める。
止める側の PC への害は、当たりの `[warn]` と `watch.jsonl`、allowlist の 1 行、`touch ~/pd/defense-off` の 1 操作、breaker の4つで抑える。

1. **不信の証明書の list**：`--distrust <path>`（止める）と `--watch-distrust <path>`（見張る）。中身は Mozilla の OneCRL と、手で足す行である。段階8 の上流の鎖と、次の probe が読んだ鎖に当てる。
2. **鎖の probe**：`--probe-chains`。PC が繋いだ host へ packetdeath が別に TLS を張って鎖を読み、不信の証明書を含む host を以後の flow で落とす（`Reason::Chain`、log の値は `chain`）。
3. **見張りの口**：`--watch-blocklist <path>` と `--watch-iplist <path>`（当てて `watch.jsonl` に書き、落とさない）と、当たりを数える `packetdeath defense-report`。
4. **止める側の安全装置**：不信の list と probe の source ごとの breaker と、その2つだけを 1 file で見張りへ戻す `--defense-off <path>`。

作らない物は、運用者の脆弱性監視の結果から脆弱な道具の通信を狭める機能、告知の文章を自動で list に変える機能、JA3 と JA4 を packetdeath が計算する機能、証明書を差し替える MITM を自動で広げる機能である（「段階10 の採らない手段」）。

守る範囲は2つの経路である。
PC（Windows）の通信のうち PAC で proxy を通る物は、本番の `packetdeath proxy`（`:8081`）が見る。
この host（WSL）の道具の通信は、本番の `packetdeath block`（NFQUEUE 1808）が見る。
PC の通信で proxy を通らない物（PAC を読まない道具）は、Windows サービスの経路だけが見ていて、段階10 は届かない（「段階10 の残る穴」）。

### 要件を疑った結果

頼まれた物は、PC に害を出さずに、新しい脅威の宛先と証明書を packetdeath が先に落とすことである。
頼まれていない物は、OS の信頼 store を書き換えること、packetdeath が CA を入れること、新しい常駐物を足すこと、画面である。

削った物と、足す物 1 つごとに消した物を並べる。

| 足す物 | 代わりに消した物 |
|---|---|
| 不信の証明書の list と照合 | packetdeath での JA3 と JA4 の計算（Suricata 8 が計算し、`eve.json` の `ja3` と `ja4` と、`tls.cert_fingerprint` の rule で同じ判定ができる）。証明書を読む crate の追加（`x509-parser` 0.18.1 が `Cargo.lock` に既に在る） |
| 鎖の probe | `--mitm-list` を広げて TLS 1.3 の鎖を見る案（pinning の app が壊れる。「段階8 MITM」の採らない手段と同じ理由） |
| `watch.jsonl` | `flows.jsonl` への field の追加（「名前と置き場」の field の契約を変えない） |
| `defense-report` | 見張りの結果を人が目で数える工程。`eval` の `flows.jsonl` の読み方を流用する |
| feed の新しい出力 | 新しい timer と unit（`pd-malware-feed.sh` と同じ timer で取る） |

### 数えた結果

数えた時刻は 2026-10-22 の午前である。
`target/` は数えない。

| 数えた物 | pattern と範囲 | 結果 | 対照 |
|---|---|---|---|
| 上流の鎖を検証する root | `rg -n 'webpki_roots\|RootCertStore' src` | `src/mitm.rs` の `production_roots`（webpki-roots 1.0.9）。`src/ca.rs` の 1 件は test | ─ |
| webpki-roots 1.0.9 の eMudhra の root | `rg -c -i 'emsign\|emudhra'`（crate の `src/lib.rs`） | 16 行。root は `emSign Root CA - C1`、`- G1`、`emSign ECC Root CA - G3`、`- C3` の 4 本 | ─ |
| この host の system store の eMudhra の root | `ls /etc/ssl/certs` | `emSign` の 3 本（C1、G1、ECC C3） | ─ |
| 段階8 の上流の TLS を張る所 | `rg -n 'fn connect_upstream' src/mitm.rs` | 1 箇所。handshake の後に鎖を読める | ─ |
| 本番の proxy の 1 日（`ts` が 2026-10-21） | `grep -a` で `~/pd/log/flows.jsonl` | 31195 flow、block 1353（reason は全部 `sni`）、pass 29842、pass の host の種類 1027 | block と pass の和が 31195 |
| 本番の process | `ps -o rss,pcpu` | proxy は RSS 23312 KiB、%CPU 0.1（起動から 3日23時間の平均）。block は RSS 10088 KiB | ─ |
| 本番の list の行数 | `grep -vcE '^\s*(#\|$)'` | blocklist 47691、malware-domains 2606、malware-ips 2556、allowlist 374、mitm-list 2 | ─ |
| feed の最後の取得 | `pd-malware-feed.log` の末尾と `malware-domains.txt` の先頭 | 2026-10-21T15:18:56Z に 3 feed とも取れた（認証の key を送っていない） | ─ |
| `Cargo.lock` の package | `grep -c '^name = ' Cargo.lock` | 88 | ─ |
| 受入 ID | `rg -o 'PK-[0-9]+'` | 最大は PK-122。PK-13x 以上は 0 件（rc=1） | PK-122 が 8 件 |
| Suricata の版 | `suricata -V` | 8.0.3。配布元の最新は 8.0.7 | ─ |

### 出所（取得 2026-10-22）

- Mozilla Security Blog の eMudhra の告知 https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/ ：取得できなかった（HTTP 403。2 回）。中間 CA 8 枚という数は `転記` で、この文書では読んでいない。
- Red Hat RHSB-2026-012 https://access.redhat.com/security/vulnerabilities/RHSB-2026-012 ：対象は `ca-certificates`。漏れた中間 CA は system store に在る eMudhra の root が署名した物。修正の package は未公開。保護の手として「Comodo AAA Services」と「emSign ECC Root CA - G3」の 2 本の root を blocklist に入れることを勧める。
- Mozilla OneCRL https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/changeset?_expected=0 ：record は `subject` と `pubKeyHash`（SPKI の SHA-256 の base64）の組か、`issuerName` と `serialNumber` の組のどちらかを持つ。eMudhra と emSign の record の数は取得の道具の目算で約 26（`転記`。全文は数えていない）。
- RFC 8446 §1.2 https://www.rfc-editor.org/rfc/rfc8446 ：TLS 1.3 では ServerHello より後の handshake の message が全部 暗号化される。だから server の証明書は経路の途中から見えない。
- Windows Filtering Platform https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page と https://learn.microsoft.com/en-us/windows/win32/fwp/object-management （どちらも更新 2025-03-11）：user mode の API と kernel mode の API が在る。`FWPM_SESSION_FLAG_DYNAMIC` で開いた session の object は session の終わりに消え、session は process の終わりで終わる。API は C/C++ 向けである。
- Suricata https://suricata.io/download/ ：stable は 8.0.7（2026-09-15）、7.0.17 は end-of-life。
- Suricata の eve の `tls` https://docs.suricata.io/en/latest/output/eve/eve-json-format.html と JA の keyword https://docs.suricata.io/en/latest/rules/ja-keywords.html ：`fingerprint`（証明書の SHA1）、`issuerdn`、`ja3`、`ja4`、`chain` を出せる。`ja3` と `ja4` は `app-layer.protocols.tls.ja{3,4}-fingerprints` で有効にする。
- abuse.ch の利用条件 https://abuse.ch/terms-of-use/ （施行 2025-11-04、更新 2026-10-21）：Feodo Tracker と SSL Blacklist は CC0 で、商用でも使える。URLhaus と ThreatFox の商用は有料の契約が要りうる。2.1 は access を認証した利用者（Authenticated Users）だけに与えると書き、3.4 の CC0 の例外は Feodo Tracker、SSL Blacklist、YARAify だけである。query の量に上限がある。誤検知の責任を負わない。data を AI の学習に使わない。
- SSLBL https://sslbl.abuse.ch/blacklist/ ：`sslblacklist.csv`（証明書の SHA1）、`sslblacklist_tls_cert.rules`（Suricata 4.1 以降）、`sslipblacklist.txt`、`ja3_fingerprints.csv` と `.rules`。JA3 の list は正常な通信で試していないので誤検知が多いと配布元が書く。
- JA4 の license https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md ：JA4（TLS client）は BSD 3-Clause。JA4S など他の JA4+ は FoxIO License 1.1 で、製品に入れて売ることを許さない。
- Li ほか「Reading the Tea Leaves: A Comparative Analysis of Threat Intelligence」USENIX Security 2019 https://www.usenix.org/conference/usenixsecurity19/presentation/li ：公開と商用の threat intelligence の網羅と正確さに大きな限界がある。この設計では「feed の当たりは誤爆を含みうる」の根拠として使い、見張りを先に置く。

### 方針と理由

#### 1. 不信の証明書の list

**list の形。**1行1件、`#` で始まる行と空行は無視する。行は3つの形のどれかである。

| 形 | 中身 | 出所 |
|---|---|---|
| `spki-sha256 <base64>` | 証明書の SubjectPublicKeyInfo の SHA-256 | OneCRL の `pubKeyHash`、手で足す root と中間 CA |
| `issuer-serial <base64 の issuer DER> <base64 の serial>` | 発行者の名前と serial の組 | OneCRL の `issuerName` と `serialNumber` |
| `cert-sha1 <hex>` | 証明書全体の SHA1 | SSLBL の `sslblacklist.csv` |

読めない行は捨てて数え、読み込みの `[warn]` に件数を出す。1 行の誤りで list 全体を捨てない。
走行中の読み直しは `WatchInputs` に足す（段階9 が iplist を足した形と同じ）。読み直しに失敗したら前の内容を使う。

**照合の範囲。**server が送った鎖の全部の証明書と、鎖の最上位の証明書の issuer に一致する webpki-roots の root の 1 本を照合する。
root を照合に入れるのは、root は server が送らない鎖が多く、送った鎖だけを見ると root の不信が当たらないからである。
root は、最上位の証明書の issuer の DER と root の subject の DER が一致する物を選ぶ。

**手で足す行。**告知が機械で読める list を出さないとき（RHSB-2026-012 の 2 本の root がこれに当たる）は、運用者が `distrust-manual.txt` に `spki-sha256` の行を足し、直前の `#` 行に告知の URL を書く。
この file も `--watch-distrust` から始める（「段階的な入れ方」）。

#### 2. 段階8 の上流の鎖への当て方

段階8 の proxy は `--mitm-list` の host の上流と自分で TLS を張り、client へは packetdeath の CA で署名した leaf を見せる。
上流の鎖が不信の中間 CA を経ていても、webpki-roots がその root を持つ限り検証は通る（webpki は OneCRL を持たない）。
そのとき client は packetdeath の leaf しか見ないので、client の側の不信の判定（ブラウザの OneCRL や CRLSet）が働かない。
この形では、packetdeath が不信の鎖を client から隠してしまう。段階10 で最初に塞ぐ所である。

`connect_upstream`（`src/mitm.rs`）の handshake の後に鎖を照合する。
当たったときの扱いは、上流の TLS の失敗（今の形は段階7 の非復号へ倒す）と分ける。
非復号へ倒すと client が上流の鎖を自分で検証し、OS の store が不信の root をまだ信じている道具（この host の `ca-certificates` は修正前）はそれを通すからである。
`--distrust` で当たったら deny（`--deny` の形）にして `flows.jsonl` に `"decision":"block"` と `"reason":"chain"` を書く。
`--watch-distrust` で当たったら今のとおり復号して進め、`watch.jsonl` に `kind:"distrust"` の行を書く。

#### 3. 鎖の probe

TLS 1.3 では server の証明書が暗号化される（RFC 8446 §1.2）。
nfqueue も pktmon も、復号しない CONNECT の中継も、経路の途中から鎖を見られない。
鎖を見る方法は、packetdeath が自分で同じ host へ TLS を張るか、復号するかの2つで、復号は `--mitm-list` の host に限る（段階8）。
だから鎖は、packetdeath が別に張る handshake（probe）で読む。

- **何を probe するか**：判定で `pass` になった flow の SNI のうち、cache に無い host だけ。allowlist に当たる host は probe しない（何があっても通す host の鎖を読んでも結果を使わないため）。IP literal と port 443 以外は probe しない。
- **接続先**：flow が持つ `dst_ip` に固定する。SNI を名前解決し直さない（名前解決し直すと、client が繋いだ相手と別の相手を probe し、DNS を操れる者が probe の行き先を選べる）。`dst_ip` が private、loopback、link-local、CGNAT、multicast、`0.0.0.0/8` なら probe しない（feed の IP の除外と同じ範囲。LAN の機器へ packetdeath から handshake を出さない）。proxy の flow で `dst_ip` が `0.0.0.0`（名前解決の失敗）なら probe しない。
- **どの process で動かすか**：最初は proxy の process だけで動かす（unit は root 以外の専用 user で動かし、`NoNewPrivileges=yes`）。root で動く block の process に載せるのは、block の unit に hardening の drop-in（root 以外の user で動かせない部分を除き、`NoNewPrivileges=yes`、`ProtectSystem=strict`、`ProtectHome=read-only` と書き込み先の `ReadWritePaths`、`CapabilityBoundingSet` を nfqueue に要る `CAP_NET_ADMIN` だけ）を入れた後にする。probe は外から来た鎖を parse する code で、root の process に載せると parse の欠陥の影響が host 全体に及ぶからである。
- **ECH で隠れた名前が出ること**：proxy は CONNECT の行の host を知っているので、client が ECH で SNI を隠した host でも、probe は平文の SNI でその名前を送る。経路の途中の観測者には、client が隠した名前が probe の ClientHello で見える。Chrome が proxy 越しの接続で ECH を使うかは `NOT VERIFIED`。対処は probe が平文 SNI を出すことを記録して残す（「段階10 の残る穴」）。
- **いつ**：verdict を返した後に、別の thread が queue から取り出して張る。verdict の経路と `Judge` の中では I/O をしない（「判定を差し込む口」の規則のまま）。最初の flow は probe の結果を待たずに通る（反応型。IDS と同じ）。
- **何をするか**：TCP を張り、同じ SNI で ClientHello を送り、server の Certificate を受けたら鎖を照合し、`close_notify` を送って閉じる。HTTP の request は 1 byte も送らない。鎖の検証は webpki-roots で行い、検証の成否は記録するだけで判定に使わない（照合するのは不信の list だけ）。
- **結果の置き場**：host ごとに、probe が読んだ鎖の指紋（各証明書の SPKI の SHA-256、発行者と serial、SHA1）を memory の表（`ChainVerdicts`）に置く。不信の list との照合は判定のたびに表と今の list で行うので、list を書き換えると probe し直さずに効く。寿命 24 時間、上限 4096 host で古い物から捨てる。判定器 `ChainJudge` はこの表を引くだけで、当たれば `Reason::Chain` を返す。表は `IdsDropSet` と同じく別 thread が書き、判定器は読むだけである。宛先 IP でなく host で持つのは、CDN の共有 IP を丸ごと落とさないためである（段階6 の `av` が `dst_ip` 単独で落とさないのと同じ理由）。
- **上限**：実効の上限は 1 秒に 1 回の rate である（1 日なら最大 86400 回）。実際の数は pass の host の種類で決まり、`flows.jsonl` の 42 の日付（2026-10-22 は途中）で最大は 2026-10-08 の 1389 だった。proxy と block の両方に `--probe-chains` を付けると、同じ host へ probe が 2 本 出る（process ごとに cache を持つため）。probe の thread は 1 本、1 秒に 1 回まで、1 回の上限は 5 秒（TCP と handshake の合計）、queue は 256 件で溢れたら古い物を捨てる。捨てた数と、probe の数、当たりの数、timeout の数を 1 時間に 1 行の `[info]` に出す。
- **失敗**：TCP が張れない、timeout、TLS の失敗は「判定なし」で、表に何も書かない（fail-open）。
- **自分の probe**：block の process の probe も OUTPUT の 443 を通り、自分の nfqueue で判定される。probe 自身の flow も他の flow と同じに扱う。同じ host は cache で 2 回目を張らないので、probe が probe を呼ぶ循環は起きない。probe の flow は `flows.jsonl` に 1 行ずつ残る。

#### 4. 見張りの口と defense-report

`--watch-blocklist` と `--watch-iplist` は、`--blocklist` と `--iplist` と同じ形の file を読み、当たった flow を `watch.jsonl` に書いて、判定は変えない（`flows.jsonl` の `decision` は当たらなかったときと同じ）。
見張りの判定は、allowlist の短絡（`judge::run_judges_with_allowlist` は allowlist に当たると判定器を1つも評価しない）の外で、全部の flow に走らせる。allowlist に当たった flow も見張りの list に当て、`watch.jsonl` に `"allowlisted":true` で書く。
こうしないと、allowlist の host に当たる誤った list の行が見張りに 1 件も出ず、昇格の基準の「allowlist の当たり 0」が自分で満たされてしまう。
止める側が当てた flow は見張りに書かない（同じ flow を 2 回 数えない）。
走行中の読み直しは `WatchInputs` に足す。

`packetdeath defense-report` は read-only の subcommand で、network に出ず、file だけを読む。

```
packetdeath defense-report --flows <flows.jsonl> [--blocklist <path>]... [--iplist <path>]... [--allowlist <path>]... [--days <N>]
packetdeath defense-report --watch <watch.jsonl> [--allowlist <path>]... [--days <N>]
```

`--flows` は、過去の `flows.jsonl` の `sni` と `dst_ip` に候補の list を当て直す（本番の process に何も足さずに誤爆を見積もる）。
`--watch` は `watch.jsonl` を source ごとに数える。
出力は source ごとに 1 行で、`source=<名前> hits=<件数> hosts=<host の種類> allowlisted=<allowlist に当たる host の種類> days=<日数> promote=<yes|no>` の形である。
`days` は引数ではなく、読んだ log に実際に在る日付の数で数える（`ts` の日付の種類。`--days <N>` は必要な日数の下限で、数えた日数の代わりにならない）。
`allowlisted` は、`--watch` では `watch.jsonl` の `"allowlisted":true` の host の種類、`--flows` では当てた list と `--allowlist` の両方に当たる host の種類である。
`promote=yes` は、数えた `days` が 7 以上、`allowlisted` が 0、1 日の `hosts` の最大が breaker の閾値より小さい、の3つを満たすときだけ出す。

source の系ごとに、昇格の根拠を足す。

- **blocklist と iplist の系**：見張りの 7 日に加えて、`defense-report --flows` を本番の `flows.jsonl` の全部（2026-10-22 の計数で 972468 行、42 の日付）に当てた結果も `promote=yes` であること。見張りの 7 日だけでは、その 7 日に通らなかった host の誤爆が見えないからである。
- **不信の証明書の系**：広く使われる root の行（RHSB-2026-012 の勧める「Comodo AAA Services」のように、多くの site の鎖が経る root）は、見張りの `hosts=` を見るまで止める側へ移さない。root の 1 行は、その root を経る全部の host を止めるからである。`defense-report` は `spki-sha256` の行のうち webpki-roots の root に一致する行を `root=yes` と出し、`root=yes` の行は `hosts=` の値を人が読むまで `promote=no` にする。

#### 5. feed の新しい出力

`scripts/pd-malware-feed.sh` に3つの出力を足す。既存の2 file（`malware-domains.txt`、`malware-ips.txt`）と下限と atomic な置き換えは変えない（PK-94 が回帰を見る）。

| 出力 | 取る物 | 取り出し方 | 下限 |
|---|---|---|---|
| `distrust-onecrl.txt` | OneCRL の changeset（JSON） | `enabled` が true の record から `spki-sha256` か `issuer-serial` の行を作る | `--min-distrust`、既定 100（`ASSUMPTION`。初回の件数を記録して直す） |
| `sslbl-certs.txt` | SSLBL の `sslblacklist.csv` | SHA1 の列から `cert-sha1` の行を作る | `--min-sslbl-certs`、既定 100（`ASSUMPTION`） |
| `sslbl-ips.txt` | SSLBL の `sslipblacklist.txt` | 1行1 IP。既存と同じ private 等の除外 | `--min-sslbl-ips`、既定 0（配布元はこの list の公開を廃止予定として空にしているため、下限を置けない。空の間は `--watch-iplist` に当たる物が無い） |

取得は既存の timer の1日1回のまま増やさない。
SSLBL と Feodo は CC0 で、出力の扱いに制限が無い。URLhaus と ThreatFox の条件は「段階10 の残る穴」に書く。

**認証の key。**abuse.ch は data の利用を認証した利用者に限る。script は `--auth <file>` を受け、file が在れば curl に `-K <file>` で渡す（file は curl の設定の形で key の header を持ち、権限は `0600`。key を argv にも log にも載せない）。
file が無いとき、または権限が `0600` より緩いときは、ThreatFox と URLhaus へ request を 1 件も出さず、`[warn]` を出して前の list を残す（abuse.ch の条件 2.1 は認証した利用者だけに access を与える。list が古くなる方を採る）。
Feodo Tracker、SSL Blacklist、OneCRL は key 無しで取り、key を送らない。`--from` は network に出ないので、key の検査の対象外である。
本番の置き場は `~/pd/abuse-ch.curl` で、key の発行は利用者自身の認証の手続き（auth.abuse.ch）が要る。
出力は既存の2 file と同じ `~/pd/` に置く。script は OneCRL の record のうち subject か issuer に `eMudhra` か `emSign` を含む物の数を `onecrl emudhra=<n>` の 1 行で log に出す（告知の中間 CA 8 枚が OneCRL に載ったかを数で見るため）。

#### 6. 止める側の安全装置

**breaker。**`--distrust` の file ごとと probe ごとに、新しく止めた host の種類を直近 10 分で数える。
`--breaker-hosts <N>`（既定 5。`ASSUMPTION`。見張りの期間の `defense-report` の値で決め直す）を超えたら、その source を見張りへ落とし、`[error]` を 1 行 出し、以後の当たりは `watch.jsonl` に `mode:"breaker"` で書く。
落とした source は、その file の指紋（`mtime` と `len`）が変わるか process が再起動すると、止める側へ戻る。
breaker を段階10 の source に限るのは、広告の blocklist（47691 行）は 1 page で多くの host を止めるのが正常で、同じ閾値で数えると誤って外れるからである。

**`--defense-off <path>`。**この file が在る間は、`--distrust` と probe の当たりを止めずに `watch.jsonl` へ `mode:"off"` で書く。
在るかは `WatchInputs` の poll（300 ms）で見る。消せば戻る。
広告の blocklist、allowlist、段階4〜9 の判定は変えない。
本番の置き場は `~/pd/defense-off`（作るのは `touch ~/pd/defense-off`、戻すのは `rm ~/pd/defense-off`）。

### 構造

```
pd-malware-feed.sh（1日1回）
   OneCRL, SSLBL, ThreatFox, URLhaus, Feodo
        |
        v
~/pd/*.txt
   |                                   |
   | 確かさの高い list                  | 読めない list
   v                                   v
--distrust（止める）                  --watch-distrust / --watch-iplist（見張り）
   |                                   |
   +-----------------+-----------------+
                     v
proxy の判定（allowlist → 止める側の判定器 → allowlist の外で見張り）
   |                  \
   |                   probe の thread（verdict の後。1本、1秒に1回、5秒で諦める）
   v                    |
flows.jsonl（reason chain）と watch.jsonl  <---+
   |
   +--> breaker / touch ~/pd/defense-off で止める側を見張りへ戻す
   +--> defense-report --watch（promote=yes の見張りの source だけ、人が止める側へ移す）
```

図の結論は、「確かさの高い list は最初から止める側に入り、読めない list だけが見張りを通り、止める側はどれも breaker と 1 file の切り替えで見張りへ戻せる」である。

### 告知から list までの流れ

```
公式の告知（ブラウザの CA の告知、distro の advisory、project の security release）
   |
   +-- 機械で読める list が在る（OneCRL、abuse.ch、SSLBL）
   |      -> pd-malware-feed.sh が毎日取る -> ~/pd/ -> 300 ms で読み直し（止める側か見張りかは「段階的な入れ方」の表）
   |
   +-- 文章だけ（例：RHSB-2026-012 の 2 本の root）
          -> 運用者が告知を読む
          -> 運用者が distrust-manual.txt に 1 行足し、直前の # 行に告知の URL を書く
          -> --watch-distrust で見張る -> defense-report -> 止める側
```

告知の文章を機械が読んで list へ入れる工程は作らない（「段階10 の採らない手段」）。
機械で読める list だけが自動で入り、文章の告知は運用者の 1 行を通る。
`distrust-manual.txt` に足す役は運用者である。運用者は毎日、使っている OS、ブラウザ、distro の公式の告知を読み、手元に当たる証明書の告知が在れば、その日のうちに `--watch-distrust` 側の file へ 1 行 足す。
運用者にするのは、読む者と足す者が分かれると行が落ちるからである。

### PC に影響がないことの決まり

#### 逃げ道

| 誤って止めたときの範囲 | 戻す手 | 効くまで |
|---|---|---|
| 1 つの host | `~/pd/allowlist.txt` に 1 行 足す。allowlist は段階10 の判定より先に効き、probe もしない | 300 ms |
| 段階10 の止める側の全部 | `touch ~/pd/defense-off` | 300 ms |
| 1 つの source が誤って大量に当たる | breaker が自動で見張りへ落とす | 当たりの次の判定 |
| packetdeath の全部 | `sudo systemctl stop packetdeath-proxy packetdeath-block`。block は `--queue-bypass` で素通しになり（PK-1、PK-4）、PAC は `PROXY …; DIRECT` で直結へ倒れる（「段階7 proxy」） | 即時 |
| 止める側へ移した source を戻す | unit の drop-in を前の版へ戻して restart 1 回 | restart |

`allowlist` は不信の証明書にも勝つ。allowlist は「何があっても通す」契約で、段階10 だけ例外にすると契約が 2 通りになるからである。
allowlist の host が不信の鎖を出したときは、通した上で `[warn]` を出す。
allowlist に当たると判定器を1つも評価しない（`judge::run_judges_with_allowlist`）ので、`[warn]` は allowlist の分岐の中で `ChainVerdicts` を読み取り専用で引いて出す。印が在れば 1 host につき 1 時間に 1 行だけ出す（分岐の中で I/O をしない。表を引くだけである）。

#### 速さの上限

| 測る物 | 上限 | 測り方 |
|---|---|---|
| CONNECT の遅れ | 段階10 の option 有りと無しの p95 の差が 5 ms 以下 | `tests/independent_active_defense.rs` の偽の上流へ CONNECT を 50 回ずつ打つ（PK-140） |
| probe が判定を待たせない | probe が 5 秒 止まっている間の別の CONNECT の遅れが 0.5 秒以下 | 同じ test で、応答しない偽の上流を probe させながら測る（PK-140） |
| block の process の memory | RSS が 64 MiB 以下（今は 10088 KiB） | `ps -o rss= -p $(systemctl show -p MainPID --value packetdeath-block)` |
| proxy の CPU | 10 分の窓で CPU 時間が 12 秒以下（1 core の 2%。今の平均は 0.1%） | `/proc/<pid>/stat` の 14 列目と 15 列目の和を 600 秒 空けて 2 回 読み、差を `getconf CLK_TCK` で割る |
| probe の数 | 1 秒に 1 回以下（実効の上限）。1 日の数は pass の host の種類を超えない（42 の日付の最大 1389） | 1 時間ごとの `[info]` の行の `probes=` を足す |
| feed の取得 | 1 日 1 回 | timer の実行の数 |

proxy の memory は段階8 の本文の溜めで大きく動く（`MemoryMax=12G`）ので、上限を置かずに記録だけする。

#### 段階的な入れ方

source ごとに、入れる側を決める。

| source | 入れる側 | 理由 |
|---|---|---|
| `~/pd/distrust-onecrl.txt`（OneCRL。eMudhra の中間 CA を含む） | `--distrust` | 配布元が鍵の漏れや規則違反で個別に不信とした証明書で、正規の site の鎖に残るのは誤りの方である |
| `~/pd/sslbl-certs.txt`（SSLBL の証明書の SHA1） | `--distrust` | C2 の leaf 証明書の指紋で、1 行が 1 枚の証明書にしか当たらない |
| `~/pd/distrust-canary.txt`（受入の確かめ用。普段は空） | `--distrust` | 本番の受入（PK-142）で 1 host だけを止めて戻すため |
| `~/pd/distrust-manual.txt`（文章の告知から足す行。広く使われる root を含む） | `--watch-distrust` | root の 1 行は、その root を経る全部の host を止める |
| `~/pd/sslbl-ips.txt` | `--watch-iplist` | IP は共有されうる |

見張りから始めた source は、`defense-report` が `promote=yes` を出したときだけ人が止める側へ移す（方針 4 の基準。allowlist の短絡の外で評価し、日数は log の実際の日付で数え、blocklist と iplist の系は `flows.jsonl` の全部への当て直しを足し、root の行は `hosts=` を読むまで移さない）。
止める側に入れた後は、`watch.jsonl` と breaker の `[error]` を毎日 数える。

### 段階10 の採らない手段

| 採らない手段 | 理由 |
|---|---|
| 証明書を差し替える MITM を自動で入れる、`--mitm-list` を自動で広げる | 段階8 の採らない手段（全部の domain の復号は pinning の app を壊す）。CA を端末へ入れるのは利用者の手で、packetdeath は入れない（禁じ手） |
| packetdeath が OS の信頼 store を書き換える | 禁じ手の1と同じ。OS の store は distro の更新が直す |
| 脆弱性監視の結果から脆弱な道具の通信を狭める、見張る | packetdeath が見るのは 5 つ組と SNI と client の IP で、通信がどの process の物かを持たない（nfqueue も pcapng も CONNECT も process を運ばない）。脆弱性監視の finding も process と flow を持たない。修正の無い listener の露出を狭めるのは firewall の仕事で、packetdeath は iptables も firewall も打たない |
| 告知の文章を機械が読んで list へ入れる | 文章から宛先や証明書を抜く工程は決定的でなく、誤って入れた 1 行が PC の通信を止める。機械で読める list だけを自動にする |
| JA3 と JA4 を packetdeath が計算する | Suricata 8 が計算し、`eve.json` と rule で使える（出所）。JA4 以外の JA4+ は FoxIO License で、公開する道具に入れると条件が付く。SSLBL の JA3 は配布元が誤検知の多さを書く |
| Windows で WFP の filter を足す | user mode の API は C の API で、Rust から呼ぶと unsafe が要る（`unsafe_code = "forbid"`）。PowerShell の firewall の規則は永続で、packetdeath が落ちても残る（「落ちたとき残る物を作らない」）。dynamic session なら process の終わりで消えるが、そこへ届く道が unsafe の FFI だけである |
| probe の結果を待ってから最初の flow を通す | verdict の経路で I/O を待つと nfqueue が溢れ、通信が止まる（「fail-open」の hang と同じ形） |
| 宛先 IP で probe の結果を持つ | CDN の共有 IP で、同じ IP の別の site を巻き込む |
| VirusTotal などの cloud の照会 | 段階9 の採らない手段のまま |
| breaker を広告の blocklist にも掛ける | 1 page で多くの host を止めるのが正常で、閾値で数えると誤って外れる |

### 受入 ID（PK-130〜PK-144）

command は Linux を前提に書く。`LOGDIR` と `<log>` は「受入 ID」節冒頭の約束のまま、`<watch>` は `$LOGDIR/watch.jsonl` である。
偽の上流（test 用の CA で署名した鎖を返す rustls の server）と偽の不信の list は test の中で作る。外の host の応答を gate にしない。

| ID | 受入条件 | 打つ command | 期待値 | 陽性対照 | 陰性対照 |
|---|---|---|---|---|---|
| **PK-130** | **陰性対照**。段階10 の option を渡さない proxy と block は今と同じで、`watch.jsonl` を作らない。crate を足さない | `packetdeath proxy --listen 127.0.0.1:8899 &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.com/; test -e <watch>; echo "rc=$?"; grep -c '^name = ' Cargo.lock` | `200`、`rc=1`、`88` | PK-133 の起動では `rc=0` | ─ |
| **PK-131** | `defense-report --flows` が過去の `flows.jsonl` に候補の list を当て直し、source ごとの数を出す。本番の process に触らない | `P=$(systemctl show -p MainPID --value packetdeath-proxy); ps -o etimes= -p $P; packetdeath defense-report --flows ~/pd/log/flows.jsonl --blocklist <known.txt> --blocklist <none.txt> --allowlist ~/pd/allowlist.txt; ps -o etimes= -p $P` | source ごとに 1 行。`known.txt` が `hits=` 1 以上、`none.txt` が `hits=0`。前後の `etimes` が増え、pid が同じ | `known.txt` は `grep -a -m1 -o '"sni":"[^"]*"' ~/pd/log/flows.jsonl` で取った host の 1 行 | `none.txt` は `nonexistent.invalid` の 1 行で `hits=0` |
| **PK-132** | feed script が `distrust-onecrl.txt`、`sslbl-certs.txt`、`sslbl-ips.txt` を作り、既存の2 file は今のまま。network が無くても `--from` で同じ検査が通る。取れなければ前の file が残る | `scripts/pd-malware-feed.sh --out <dir> --from <fixture> --min-domains 1 --min-ips 1 --min-distrust 1 --min-sslbl-certs 1 --min-sslbl-ips 0; echo "rc=$?"; grep -cE '^(spki-sha256\|issuer-serial) ' <dir>/distrust-onecrl.txt; grep -c '^cert-sha1 ' <dir>/sslbl-certs.txt; grep -vc '^#' <dir>/sslbl-ips.txt` | `rc=0`、`distrust-onecrl.txt` と `sslbl-certs.txt` の数が 1 以上、`sslbl-ips.txt` は 0 以上（配布元が空で公開している間は 0）。PK-94 の command も同じ出力 | `--from` の fixture（OneCRL の 2 形の record を 1 件ずつ）で `distrust-onecrl.txt` が 2 行 | 壊れた raw を置いた `--from` で `rc=1`、`cksum <dir>/*.txt` が前後で同じ |
| **PK-133** | `--watch-blocklist` と `--watch-iplist` の当たりが `watch.jsonl` に出て、flow は通る | `printf 'example.org\n' > w.txt; packetdeath proxy --listen 127.0.0.1:8899 --watch-blocklist w.txt --deny 403 &` の後に `curl -sS -o /dev/null -w '%{http_code}\n' -x http://127.0.0.1:8899 https://example.org/; tail -1 <watch>; tail -1 <log>` | `200`。`<watch>` が `"sni":"example.org"`、`"source":"w.txt"`、`"kind":"blocklist"`、`"mode":"watch"`。`<log>` が `"decision":"pass"` と `"reason":null`。`--allowlist` に `example.org` を足して同じ command を打つと、`<watch>` の行が 1 増え `"allowlisted":true` | `<watch>` の行が 1 増える | 同じ file を `--blocklist` で渡すと `CONNECT tunnel failed` が 1 |
| **PK-134** | `--watch-distrust` のとき、段階8 の上流の鎖が不信の中間 CA を含むと `watch.jsonl` に出て、通信は今のとおり復号される | `cargo test --release --test independent_active_defense -- a_distrusted_upstream_chain_is_logged_in_watch_mode` | `ok`。client の status `200`、`<watch>` が `"kind":"distrust"`、`<log>` に `block` が 0 | test の中で不信の list に中間 CA の `spki-sha256` を置く | 同じ鎖で list を空にすると `<watch>` が増えない |
| **PK-135** | `--distrust` のとき、不信の中間 CA か不信の root を経る上流の鎖は deny になり、段階7 の非復号へ倒れない | `cargo test --release --test independent_active_defense -- a_distrusted_upstream_chain_is_denied_and_not_tunneled` | `ok`。`--deny 403` で status `403`、`<log>` が `"decision":"block"` と `"reason":"chain"`、偽の上流への接続が 1 本（鎖の照合の分だけ。張り直しが無い）。root の行でも同じ | 不信の list に root の `spki-sha256` だけを置いても deny | 不信の list に当たらない鎖は `200` で復号され、`av.jsonl` の扱いが段階8 のまま |
| **PK-136** | `--probe-chains --watch-distrust` のとき、probe が不信の鎖を読んで `watch.jsonl` に書き、flow は通る。probe の失敗は判定なし | `cargo test --release --test independent_active_defense -- the_prober_records_a_distrusted_chain_without_blocking_in_watch_mode` | `ok`。1 回目と 2 回目の CONNECT がどちらも `200`。`<watch>` に `"source":"probe"`、`"kind":"chain"` が 1 行 | 不信の中間 CA を持つ偽の上流 | 応答しない偽の上流では 5 秒の後に表へ何も書かず、`<watch>` が増えない |
| **PK-137** | `--probe-chains --distrust` のとき、probe が当てた host への次の CONNECT が `chain` で止まる。allowlist の host は止まらず、印の在る host につき 1 時間に 1 行の `[warn]` が出る | `cargo test --release --test independent_active_defense -- a_host_marked_by_the_prober_is_denied_on_the_next_connect` | `ok`。1 回目 `200`（反応型）、probe の後の 2 回目が deny で `<log>` が `"reason":"chain"`。続けて同じ host を allowlist へ足し（先に probe で印を付け、それから allowlist へ足す順。allowlist の host は probe しないため）、0.4 秒後の 3 回目と 4 回目が `200`、`[warn]` が 1 行だけ | 不信の鎖を返す偽の上流 | 鎖が当たらない偽の上流では 2 回目も `200` で `[warn]` が 0 |
| **PK-138** | breaker：1 つの不信の source が 10 分に `--breaker-hosts` を超える host を止めたら、その source だけが見張りへ落ち、`[error]` が 1 行 出る。file が変わると戻る | `cargo test --release --test independent_active_defense -- a_distrust_source_over_the_breaker_threshold_falls_back_to_watch` | `ok`。閾値を超えた次の当たりから `<watch>` に `"mode":"breaker"`、`[error]` が 1 行、別の source は止め続ける。file を書き換えた後は再び止める | 閾値 + 1 の host を当てる | 閾値ちょうどの host では落ちず、`[error]` が 0 |
| **PK-139** | `--defense-off` の file が在る間は、不信の list と probe の当たりを止めずに `"mode":"off"` で書く。広告の blocklist は止め続ける。file を消すと戻る | `cargo test --release --test independent_active_defense -- the_defense_off_file_turns_stage10_blocking_into_watch_within_one_poll` | `ok`。file を作った 0.4 秒後の CONNECT が `200` で `<watch>` に `"mode":"off"`、同じ時に `--blocklist` の host は deny。file を消した 0.4 秒後は再び `chain` で deny | file を作る | file が無いときは `chain` で deny |
| **PK-140** | 段階10 が CONNECT を遅くしない。probe が判定を待たせない。本番の process が上限の中に居る | `cargo test --release --test independent_active_defense -- --nocapture stage10_judging_adds_at_most_five_ms_to_connect_p95`。本番は見張りを入れた後に「速さの上限」の表の command | test は `ok` で、p95 の差（ms）と、probe が止まっている間の CONNECT の遅れ（秒）を標準出力に出す。差が 5 以下、遅れが 0.5 以下。本番は表の上限の中 | 段階10 の option を全部 渡した proxy | option 無しの proxy（差の基準） |
| **PK-141** | `defense-report --watch` が、log の実際の日付が 7 に届かない source（`--days` の値では満たせない）、`"allowlisted":true` の当たりを持つ source、1 日の host の数が閾値以上の source、`root=yes` の行に `promote=no` を出し、残りに `promote=yes` を出す | `cargo test --release --lib -- promotion_is_refused_when_an_allowlisted_host_was_hit`。本番は `packetdeath defense-report --watch ~/pd/log/watch.jsonl --allowlist ~/pd/allowlist.txt --days 7` | test は `ok`。本番は source ごとに 1 行 | fixture で 3 条件を満たす source が `promote=yes` | allowlist の host が 1 件 混じると `promote=no` |
| **PK-142** | 本番の proxy に段階10 を反映した後、(a) PC と この host の通信が今と同じ、(b) 不信の当たりが本番の `flows.jsonl` に `"reason":"chain"` で出る、(c) `defense-off` の 1 操作で戻る | (a) proxy の drop-in に「実装の順番」の引数を足して restart する前と後で `curl -sS -o /dev/null -m 8 -w '%{http_code}\n' https://api.anthropic.com/; curl -sS -o /dev/null -m 8 -w '%{http_code}\n' http://example.com/; getent hosts github.com \| wc -l; curl -sS -o /dev/null -w '%{http_code}\n' -x http://192.0.2.20:8081 https://example.com/`。(b) `H=example.org; FP=$(openssl s_client -connect $H:443 -servername $H </dev/null 2>/dev/null \| openssl x509 -noout -fingerprint -sha1 \| cut -d= -f2 \| tr -d : \| tr A-F a-f); printf 'cert-sha1 %s\n' "$FP" > ~/pd/distrust-canary.txt; sleep 1; curl -sS -o /dev/null -w '%{http_code}\n' -x http://192.0.2.20:8081 https://$H/; sleep 7; curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' -x http://192.0.2.20:8081 https://$H/; echo "exit=$?"; grep -a "\"sni\":\"$H\"" ~/pd/log/flows.jsonl \| tail -1`。(c) `touch ~/pd/defense-off; sleep 1;` 同じ curl と `tail -1 ~/pd/log/watch.jsonl`、続けて `rm ~/pd/defense-off; : > ~/pd/distrust-canary.txt`。最後に `journalctl -u packetdeath-proxy --since -10min \| grep -c 'onecrl\|distrust'` と `grep -c 'onecrl emudhra=' ~/pd/log/pd-malware-feed.log` | (a) 前後で同じ値（`404`、`200`、1 以上、`200`）。(b) 1 回目 `200`（反応型）、2 回目 `000` と `exit=28`（既定の `blackhole`）、`flows.jsonl` の末尾が `"decision":"block"` と `"reason":"chain"`。proxy は鎖を 24 時間 host ごとに表へ持つので、これは `$H` の鎖が表に無いときの形である（proxy の restart の直後、または 24 時間 その host へ繋いでいないとき）。表に在る host は、canary を書いた直後の 1 回目から `000` になり、`flows.jsonl` の末尾が `"reason":"chain"` になる。どちらの形かは `grep -a "\"sni\":\"$H\"" ~/pd/log/flows.jsonl` で、24 時間 以内の `pass` の行が在るかで分かる。(c) `200`、`watch.jsonl` の末尾が `"mode":"off"`。読み込みの `[info]` が 1 以上、`onecrl emudhra=` の行が 1 以上（数を記録し、告知の 8 枚と比べる） | canary に example.org の leaf の SHA1 を書く | canary が空のときは example.org が `200` のまま |

| **PK-143** | feed script が `--auth <file>` を受け、`0600` の file が在れば ThreatFox と URLhaus の request にだけ curl の `-K` で渡し、key を argv にも log にも載せない。file が無い、または権限が緩ければ、ThreatFox と URLhaus へ request を 1 件も出さず `[warn]` を出す | `curl` を同じ名前の記録用の偽の command に替えた PATH で、`scripts/pd-malware-feed.sh --out <dir> --auth <dir>/auth.curl` を、`auth.curl` が 0600 で在るとき、0644 のとき、無いときの 3 回 打つ。各回で偽の command が記録した request の宛先と引数の file、`rc`、stderr の `[warn]` を見る | 0600：ThreatFox と URLhaus への request が各 1 件で `-K <file>` つき、引数と log に key の文字列が 0。0644：その 2 宛先への request が 0 件、file の mode を名指す `[warn]` が 1。無い：その 2 宛先への request が 0 件、`not requested` の `[warn]` が 2。3 回とも Feodo、SSL Blacklist、OneCRL へは key なしで request する | 0600 の file | 無いときの ThreatFox と URLhaus への request が 0 件 |
| **PK-144** | probe の接続先は flow の `dst_ip` に固定し、名前解決し直さない。private、loopback、link-local、CGNAT、multicast、`0.0.0.0/8` の `dst_ip` は probe しない | `cargo test --release --lib -- the_prober_dials_the_flows_destination_and_skips_private_addresses` | `ok`。偽の resolver が別の IP を返しても、偽の上流が受けた接続の相手は flow の `dst_ip`。`10.0.0.1`、`127.0.0.1`、`169.254.1.1`、`100.64.0.1`、`224.0.0.1`、`0.0.0.0` の flow は probe の queue に入らない | 公開の範囲の `dst_ip`（test では `198.51.100.1` を偽の上流へ向けた経路） | private の `dst_ip` で probe の数が 0 |

PK-131 と PK-132 は本番の process に触らない。PK-142 だけが本番の unit を変え、restart は人が打つ。

### 段階10 の test の名前

ケースの行（`T-PK-13x-nnn`）はテスト設計の担当がこの節の下に書く。名前はここで固定し、ケースの名前はこの名前を延ばす。

| ID | 受入 test の名前 | 置き場 | 陰性のケース |
|---|---|---|---|
| PK-130 | `without_stage10_options_no_watch_log_is_written` | `tests/independent_active_defense.rs` | `--watch-blocklist` を渡すと file が出来る |
| PK-131 | `defense_report_counts_hits_per_source_and_allowlisted_hosts` | `src/defense.rs` の unit | 当たらない list は `hits=0` |
| PK-132 | `distrust_list_reads_spki_issuer_serial_and_cert_sha1_lines` | `src/distrust.rs` の unit（script の側は PK-132 の command） | 読めない行は捨てて数え、list 全体は捨てない |
| PK-133 | `a_watch_list_hit_is_logged_and_the_flow_passes` | `tests/independent_active_defense.rs` | 同じ file を `--blocklist` で渡すと deny |
| PK-134 | `a_distrusted_upstream_chain_is_logged_in_watch_mode` | 同上 | list が空なら書かない |
| PK-135 | `a_distrusted_upstream_chain_is_denied_and_not_tunneled` | 同上 | 当たらない鎖は復号される |
| PK-136 | `the_prober_records_a_distrusted_chain_without_blocking_in_watch_mode` | 同上 | 応答しない上流は判定なし |
| PK-137 | `a_host_marked_by_the_prober_is_denied_on_the_next_connect` | 同上 | allowlist の host は通る |
| PK-138 | `a_distrust_source_over_the_breaker_threshold_falls_back_to_watch` | 同上 | 閾値ちょうどでは落ちない |
| PK-139 | `the_defense_off_file_turns_stage10_blocking_into_watch_within_one_poll` | 同上 | file が無いときは deny |
| PK-140 | `stage10_judging_adds_at_most_five_ms_to_connect_p95` | 同上 | option 無しの proxy が基準 |
| PK-141 | `promotion_is_refused_when_an_allowlisted_host_was_hit` | `src/defense.rs` の unit | 3 条件を満たす source は `promote=yes` |
| PK-142 | ─（本番の受入。command だけで測る） | ─ | restart の前は `watch.jsonl` が無い |
| PK-143 | `tests/independent_feed.rs` の 5 本（script の受入。PK-94 と同じく command でも測る） | `tests/independent_feed.rs` | file が無ければ ThreatFox と URLhaus への request が 0 |
| PK-144 | `the_prober_dials_the_flows_destination_and_skips_private_addresses` | `src/prober.rs` の unit | private の `dst_ip` は probe しない |

新しい module は `src/distrust.rs`（list の読み込みと鎖の照合）、`src/prober.rs`（probe の thread と `ChainVerdicts`）、`src/defense.rs`（見張りの判定、`watch.jsonl`、breaker、`--defense-off`、`defense-report`）の3つで、`src/lib.rs` に `mod` を足す。
log と CLI の文言は `src/i18n.rs` の関数経由で出す。

### 実装の順番

本番の proxy で止める側まで、同じ日のうちに入れる。
順 1〜4 は 1 本の branch で作り、順 5 の配備は 1 回の restart で入れる。

| 順 | 何をするか | 受入 |
|---|---|---|
| 1 | `src/distrust.rs`（list と鎖の照合）。段階8 の上流の照合（止める側と見張り） | PK-132 の unit、PK-134、PK-135 |
| 2 | `src/defense.rs`（見張り、`watch.jsonl`、breaker、`--defense-off`、`defense-report`） | PK-130、PK-131、PK-133、PK-138、PK-139、PK-141 |
| 3 | `src/prober.rs`（probe と `ChainVerdicts`、`ChainJudge`、allowlist の分岐の `[warn]`） | PK-136、PK-137、PK-140、PK-144 |
| 4 | `scripts/pd-malware-feed.sh` の新しい出力と `--auth` | PK-132、PK-143、回帰の PK-94 |
| 5 | 回帰と配備。`cargo test --release` の全部、PK-6（Windows の cross build）。feed を人が 1 回 打って `~/pd/` に新しい file を作り、`touch ~/pd/distrust-manual.txt ~/pd/distrust-canary.txt`。binary を cp→mv で入れ替え（前の binary を `packetdeath-prev-<hash>` で残す）、proxy の drop-in に `--distrust ~/pd/distrust-onecrl.txt --distrust ~/pd/sslbl-certs.txt --distrust ~/pd/distrust-canary.txt --watch-distrust ~/pd/distrust-manual.txt --watch-iplist ~/pd/sslbl-ips.txt --probe-chains --defense-off ~/pd/defense-off` を足し、restart 1 回 | PK-142 |

block の unit は今日は変えない（probe を root の process に載せる前に hardening の drop-in が要る。「段階10 の残る穴」）。

配備の壊れ方は次のとおりである。
初めての実行では、feed が OneCRL の changeset（取得の道具が返した本文で約 83 万字の JSON）と SSLBL の 2 file を取る。下限は `ASSUMPTION` なので、初回は `--min-*` を 1 にして件数を記録する。proxy は起動時に list を読み、probe の thread が pass の host を 1 秒に 1 回まで張り始める。
取り合う資源は proxy の process（restart の約 2 秒は PAC の `DIRECT` へ倒れる）、cargo の build の枠（`-j 2`）、`~/pd/` の file である。block と Suricata と clamd は触らない。
始めてよい条件は、`git status --porcelain` が空で、`systemctl is-active packetdeath-proxy` が `active`、`~/pd/log/av.jsonl` の末尾の時刻が 1 分より前である（段階8 の scan の最中に restart しない）ことである。
承認を待つ command は `sudo systemctl restart packetdeath-proxy` と drop-in の書き込みで、`sudo -n` が通らなければ止めて運用者へ返す。
戻し方は、前の binary へ `mv` して drop-in を前の版へ戻し、restart 1 回である。止める側だけを切るなら `touch ~/pd/defense-off`（restart 不要）。

Suricata の側（SSLBL の `sslblacklist_tls_cert.rules` と `ja3_fingerprints.rules`、`ja3-fingerprints` と `ja4-fingerprints` の有効化）は packetdeath の code を変えない設定で、配備の後に人が入れる。
入れても `--ips-sids` に足さない間は alert が出るだけで止めない。alert の数は「測って記録するだけの値」と同じ扱いで記録する。

### 段階10 の残る穴

- 最初の flow は通る。probe と IDS は反応型で、不信の鎖の host への最初の接続は probe の結果を待たない。
- probe が見る鎖は、packetdeath の居る host から見た鎖である。PC だけを狙って経路の途中で差し替える攻撃者は、probe と同じ経路に居なければ当たらない（`ASSUMPTION`。家庭内では PC と WSL の host は同じ出口を通る）。
- proxy を通らない PC の通信（PAC を読まない道具）には段階10 が届かない。Windows サービスの経路は SNI だけを見て鎖を見ず、rustls は Windows の target に載せていない（段階8 の「TLS の部品」）。
- この host の system store は emSign の root を 3 本 持ち、`ca-certificates` の修正は配布されていない。WSL の道具の TLS 1.3 は block の probe だけが見張り、最初の接続は通る。
- 不信の list は OneCRL と手で足す行だけで、Chrome の CRLSet、Microsoft の不信の list、distro の判断は入らない。OneCRL の eMudhra の record の数は `転記`（約 26）で、全件は数えていない。Mozilla の告知の本文はこの文書で読めていない（HTTP 403）。
- allowlist は不信の鎖にも勝つ。allowlist に入れた host が不信の鎖を出しても止まらず、`[warn]`（1 host 1 時間に 1 行）だけが出る。allowlist の host は probe しないので、`[warn]` が出るのは allowlist へ足す前に probe の印が付いていた host だけである。
- probe は pass の host ごとに 1 回 外へ handshake を増やし、`flows.jsonl` もその分 増える。実効の上限は 1 秒に 1 回の rate で、42 の日付の最大は 1 日 1389 host だった。proxy と block の両方に付けると同じ host へ 2 本 出る。相手の server からは同じ出口の IP から 2 本 繋がって見える。
- proxy 越しに ECH で名前を隠した host でも、probe は平文の SNI でその名前を送る。経路の途中から名前が見える。Chrome が proxy 越しに ECH を使うかは `NOT VERIFIED`。
- probe は最初 proxy の process だけで動く。WSL の道具の通信（block の経路）を probe が見るのは、block の unit に hardening の drop-in が入った後である。
- ThreatFox と URLhaus は、認証の key の file が置かれるまで取らない。abuse.ch の条件の 2.1 は data の利用を認証した利用者に限り、CC0 の例外（3.4）は Feodo、SSL Blacklist、YARAify だけである。key の発行には利用者自身の認証の手続き（auth.abuse.ch）が要る。それまでは `malware-domains.txt` と `malware-ips.txt` が前の内容のまま古くなり、feed の script は 1 日 1 回 `rc=1` で終わる（timer の失敗として見える）。Feodo Tracker、SSL Blacklist、OneCRL は取り続ける。
- breaker の閾値（既定 5）、feed の下限（100、100、10）は `ASSUMPTION` で、配備の後の `defense-report --watch` の値で決め直す。
- block の unit は変えないので、WSL の道具の通信（`ca-certificates` が eMudhra の root をまだ信じる経路）は段階10 の止める側が届かない。block に probe を載せるのは hardening の drop-in の後である。
- JA4 の悪性の list は、無料で使える物をこの文書では見つけていない。JA3 の list は配布元が誤検知の多さを書く。
- 修正の無い listener の露出は段階10 では狭めない。firewall の仕事である。
- Suricata は 8.0.3 で、配布元の最新 8.0.7 より古い。上げるのは Suricata の運用である。Suricata が proxy の上流へ出る tunnel の TLS（PC の ClientHello）を見ているかも `NOT VERIFIED`（Suricata の設定を入れる前に `eve.json` の `tls` の event の `sni` を数えて確かめる）。
- `watch.jsonl` に rotation が無い（`flows.jsonl` と同じ）。

### 決まった事と、外の手を待つ事

- allowlist を不信の list より先に効かせる。`[warn]` は allowlist の分岐の中で `ChainVerdicts` を読み取り専用で引いて出す。
- probe は上の上限で採る。接続先は `dst_ip` に固定し、最初は proxy の process だけで動かす。
- 昇格は、見張りを allowlist の短絡の外で評価し、log の実際の日付で数え、blocklist と iplist の系は `flows.jsonl` の全部への当て直しを足し、root の行は `hosts=` を読むまで移さない形で決める。
- 外の手を待つ事は1つで、abuse.ch の key の発行（利用者自身の認証の手続き）である。key の file が置かれるまで、ThreatFox と URLhaus は取らない。
- 見張りの行の `source` は list の file 名で、probe が読んだ鎖の行は `source:"probe"`、`kind:"chain"` である。probe の行は、鎖が表に入った後の flow の判定で書く。
- breaker は、閾値を 1 つ超えた新しい host の当たり自身も止めない（その当たりから `mode:"breaker"` で書く）。閾値ちょうどの数の host は止める。
- 段階8 の上流の鎖で deny したとき、`flows.jsonl` には先に書いた `pass` の行の後に、`block` と `chain` の行がもう 1 行 増える（`av` の `block` の行と同じ）。
- 段階10 は `proxy` だけに配線する。`block` の option は今日は足さない（block の unit に hardening の drop-in を入れる前に probe を root の process に載せないため）。
- `defense-report --watch` は、`root=yes` を出すために `--distrust <path>` を任意で受ける（見張りの file の中身を読んで、public な root に一致する行を探す）。

### 実装後の状態と次の手

実装は `src/distrust.rs`、`src/prober.rs`、`src/defense.rs` と、`proxy.rs`、`mitm.rs`、`block_loop.rs`、`main.rs` の配線である。
受入は PK-130 と PK-133〜PK-140 が `tests/independent_active_defense.rs`、PK-131 と PK-141 と PK-144 が `src/defense.rs` と `src/prober.rs` の unit、PK-132 と PK-143 が `tests/independent_feed.rs` に在る。

本番の proxy には drop-in `stage10.conf`（`lists.conf` の ExecStart に段階10 の引数を足した物）で反映してあり、止める側の切り替えは `touch ~/pd/defense-off` の 1 操作である。
`--watch-iplist` に渡す `sslbl-ips.txt` は、配布元が空で公開している間は当たる物が無い。

次の手は 3 つで、動かす者はどれも運用者である。

1. 毎朝 `~/pd/log/watch.jsonl` の行数と、proxy の journal の `breaker` の行を数える。
2. 見張りの source が 7 日たったら `defense-report --watch` を打ち、`promote=yes` の source を止める側へ移すかを決める。
3. 利用者が abuse.ch の key の file を置いたら、feed を 1 回 打ち、ThreatFox と URLhaus の取得が戻ることを確かめる。
