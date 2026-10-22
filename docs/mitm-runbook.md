# 段階8 MITM の運用手順書

proxy が復号した download を clamd で検査する仕組み（段階8）を、日々 動かすための手順である。
設計は `docs/design.md` の「段階8 MITM」節が正本で、この文書はその「運用」の小節が指す運用の手順書として「取る、足す、再起動する、測る、誤検知を救う」の 5 つを書く。

検査されるのは `~/pd/mitm-list.txt` に書いた host から落ちる file だけである。
list に無い host は復号も検査もされない。
検知率は ClamAV の署名の質で決まり、「マルウェアを防げる」とは書けない（設計の「残る穴」）。

## 手順

1. CA を端末へ取る：端末のブラウザで `http://192.0.2.20:8081/ca.crt`（192.0.2.20 は文書用の例。proxy の実際の address に読み替える）を開き、設計の「端末へ入れる手順」のとおりに信頼させる。CA が無い端末は、list の host で証明書の警告になる。
2. 復号する host を足す：`~/pd/mitm-list.txt` に 1 行 1 domain（サフィックス一致）。300 ms で効き、再起動は要らない。足した直後に `sudo journalctl -u packetdeath-proxy --since -1min` を読み、読み直しの `[info]`（件数つき）が 1 行 出て、allowlist に当たった `[warn]` が 0 行であることを見る。allowlist に当たる host は復号されない。設計の「入れてはいけない物」の表に当たる host は入れない。
3. 再起動する：proxy の再起動が要るのは、引数（`--mitm-list`、`--ca-dir`、`--clamd`）を変えたときだけである。binary は `cp … .new && mv -f` で入れ替え、drop-in は binary の後に変え、restart は 1 回にする（drop-in を先に変えると、旧 binary が新しい引数で起動して再起動 loop に入りうる）。clamd の再起動が要るのは unit の drop-in を変えたときだけで、`clamav-daemon.socket` が生きているので restart 中の scan は `clamd_timeout` の fail-open になる。直前 1 分の journal に list の host の行が無いことを見てから打つ。clamd の restart と DB の読み直しは、archive の中身の file ごとの cache を消す。新しい file の scan は cache に当たらず、16 file の zip で 4.6 秒、679 file の zip で 9〜10 秒 掛かる（2026-10-03 実測）。proxy の timeout は 1260 秒である（10 秒では restart 直後の cold な 1 回が無検査になる。10.34 秒の実測が在る。1260 秒は 8191 MiB を本番の最も遅い INSTREAM 10.3 MB/s で割った 834 秒の 1.5 倍）。clamd の `clamd.conf` を変えたときも restart が要る（`reload` は DB だけ）。退避 `clamd.conf.prev-<日付>` を取り、`clamconf -n` で新しい値を見てから restart する。動いている clamd の binary は自前 build の `/opt/clamav-64/sbin/clamd64`（drop-in `binary.conf`。64-bit 化の patch 入り）で、2 GiB の丸めだけを外した `/opt/clamav-2g/sbin/clamd` へ戻すときは同じ dir の `binary.conf.prev-2g` を `binary.conf` に `mv` して `daemon-reload` と restart、配布の `/usr/sbin/clamd` へ戻すときは drop-in を消して `daemon-reload` と restart する（どちらも drop-in の先頭の comment に在る）。
4. 測る：proxy の機械から list の host の file を 1 本 落とす。`curl -sS -o <file> -w '%{http_code}\n' --cacert ~/pd/ca/ca.crt -x http://192.0.2.20:8081 <URL>`。`~/pd/log/av.jsonl` の最後の行に `"verdict":"clean"` が出て、`sha256` が `sha256sum <file>` と一致する。journal に `[info] 検査した。clean だった host=… sha256=… ms=…` が出る（`ms=` は clamd の scan の所要）。あわせて `/usr/sbin/clamd --version` と `/opt/clamav-64/sbin/clamd64 --version` の版（`/` の前）が同じことを見る（違えば「知っておくこと」の build し直し）。受入 ID は PK-100 から PK-109 と PK-111 から PK-118 である（PK-110 は段階1 の flow log の ID）。
5. 誤検知を救う：次の節。

## 誤検知を救う

正規の file が `403` で止まったときの手順である。
手掛かりは journal の `[info] 検知した。403 に差し替えた host=… signature=… sha256=…` と、`~/pd/log/av.jsonl` の `sha256` と `engine`（`clamav:<署名名>`）に残る。
ブラウザに出る 403 の本文には署名名も sha256 も載らない（設計の「流さない物」の段、「signature 名は出さない」）。

1. すぐ取りたいときは、その host を `~/pd/mitm-list.txt` で `#` で伏せる。300 ms で効き、sudo も要らない。伏せている間はその host の全 file が無検査で通るので、取り終えたら戻す。
2. file 1 本だけを許すときは、sha256 を journal か av.jsonl から取る。archive（zip など）は外側の sha256 でよく、中身の検知も消える（2026-10-03 に EICAR の zip で実測）。size は要らない。
3. scratchpad に 1 行の file を Write する。形は `<sha256>:*:<好きな名前>:73`。
4. 置く前に parse を測る。`clamscan --no-summary -d /var/lib/clamav -d <その file> <何か 1 file>` が `OK` か `FOUND` で終わり、error が出ないことを見る（壊れた行は `Malformed hash string` の `ERROR` で止まる。2026-10-03 実測。壊れた file を置いたときに clamd の読み直しがどうなるかは未測なので、置く前に測る）。
5. 置いて読み直す。`sudo install -o clamav -g clamav -m 0644 <その file> /var/lib/clamav/local.sfp` の後に `sudo systemctl reload clamav-daemon`（USR2 を送る。`EnableReloadCommand false` なので `clamdscan --reload` は通らない）。`/var/log/clamav/clamav.log` に `Database correctly reloaded` が 1 行 増える（2026-10-03 の実測で 11 秒。読み直しの間に来た scan が答えを返すか fail-open になるかは未測）。
6. 同じ URL をもう 1 度 落とし、av.jsonl に `clean` が出ることを見る。
7. 戻す：`sudo rm /var/lib/clamav/local.sfp && sudo systemctl reload clamav-daemon`。公式 DB の誤検知は配布元が daily の更新で取り下げるのが通例で、freshclam は 1 時間ごとに更新を見に行く。取り下げが届いたら行を外す。

2026-10-03 21:18 に本番で通した受入：`local.sfp` に EICAR の 1 行を置いて reload（11.3 秒）→ proxy 経由の `eicar.com` が `http=200`、av.jsonl に `clean` → 行を消して reload → 同じ download が `http=403`、av.jsonl に `malicious`（`clamav:Eicar-Test-Signature`）。

## 知っておくこと

- 署名ごと無視する file（`/var/lib/clamav/local.ign2`、署名名 1 行）も在るが、同じ署名が当たる全 file を素通しにするので、原則 使わない。1 つの file に複数の署名が当たることがある（EICAR は `Eicar-Test-Signature` と `Eicar-Signature` の 2 つ。片方だけ無視しても `FOUND` のまま）。
- `clamscan -d` で試すときは、無視 list を DB の後ろに置くと効かない。clamd と同じ読み方（DB の dir に並べる）で測る。
- 誤検知を増やす設定は入れない。`DetectPUA false`、署名 DB は公式の 3 本（main、daily、bytecode）だけ。非公式 DB を足さない。`local.sfp` が読まれるのは `OfficialDatabaseOnly false` のときだけで、この機械はその設定である。
- freshclam が `local.*` を消さないことは未測（NOT VERIFIED）。消えていたら、この手順書の 3〜5 を打ち直す。
- clamd の unit には drop-in が 4 本 在る。`extend.conf`（socket の dir）、`lowprio.conf`（`Nice=10`、`CPUWeight=50`。clamd の scan が proxy の CPU を奪わないため）、`noswap.conf`（`MemorySwapMax=0`。clamd が swap に出て scan が遅くなる疑いを断つ。swap が遅さの原因だったかは `NOT VERIFIED`）、`binary.conf`（自前 build の `/opt/clamav-64/sbin/clamd64` を `ExecStart` にし、`Restart=on-failure`。同じ dir の `binary.conf.prev-2g` は `/opt/clamav-2g/sbin/clamd` を指す前の版で、systemd は `.conf` 以外を読まない）。`lowprio.conf`、`noswap.conf`、`binary.conf` の戻し方は各 file の先頭の comment に在る（`extend.conf` は package 由来の 3 行で、触らない）。
- scan する file の上限は 8191 MiB（8588886016 byte。設計の「大きさ」の行）で、clamd の `StreamMaxLength`＝`MaxFileSize`（8191M）と同じ定数である。片方だけ変えない（`MaxFileSize` 超の stream を clamd が検査せず OK と返す経路が開く）。2 GiB を超える値は自前 build の clamd でだけ効き、配布の `/usr/sbin/clamd` は 2 GiB−1 に丸める。4 GiB を超える値は 64-bit 化の patch が入った `/opt/clamav-64` でだけ効く（`/opt/clamav-2g` は 4 GiB で位置が回る）。`MaxScanSize 16382M`、`MaxScanTime 1134000`、`TemporaryDirectory /var/tmp/clamav`（disk。tmpfs の `/tmp` に展開分を乗せない）、`AlertExceedsMax yes`。limit 超（`Heuristics.Limits.Exceeded.*`）は「検査未了」として `[warn]` で流れ、`av.jsonl` に行は増えない（2 GiB 級の ISO は中身の合計が `MaxScanSize` に当たるので毎回 未了になり、端末は約 10 分 本文を待つ）。同時に溜める本文の合計は 8 GiB までで、超える分は `slot_full` の `[warn]` で無検査で流れる。proxy の unit は `MemoryMax=12G`。
- 配布の `clamav-daemon` は unattended-upgrades で自動で上がる。上がったことは `/usr/sbin/clamd --version` と `/opt/clamav-64/sbin/clamd64 --version` の版（`/` の前）が違うことで判り、drop-in `binary.conf` の `ExecStartPre` が restart のたびに比べて journal に `clamav-2g: … rebuild` を出す（`sudo journalctl -u clamav-daemon | grep -c 'clamav-2g:'`、対照に `grep -c clamd`）。出たら自前 build を同じ版で作り直す。`cd ~/pd/src/clamav && git fetch --tags && git worktree add .claude/worktrees/clamav-64-<版> clamav-<版>`、その worktree で `git apply <repo>/scripts/clamav-2g.patch` と `git -c user.name=packetdeath -c user.email=packetdeath@localhost commit -am 'Remove the 2 GiB clamp on MaxFileSize'`、`git -c user.name=packetdeath -c user.email=packetdeath@localhost am <repo>/scripts/clamav-64/*.patch`（4 本）、設計の「libclamav の 64-bit 化」の決めの表の cmake（prefix `/opt/clamav-64`。configure、build、`sudo cmake --install`）、`sudo systemctl restart clamav-daemon`、`/opt/clamav-64/sbin/clamd64 --version` と `/var/log/clamav/clamav.log` の `File size limit set to`。当たらない patch は、その hunk の source を読み直してから作り直す（2g は `libclamav/others.c` の `CL_ENGINE_MAX_FILESIZE` の分岐、64 は `scripts/clamav-64/` の 4 本）。作り直すまでの間は、配布より古い clamd が動いている。
- clamd の timeout（1260 秒）を超えた scan は `[warn]` を出して file をそのまま通す（fail-open）。`[warn] scan に失敗した … 理由=clamd_timeout` が続くときは、journal の `[info] 検査した。clean だった … ms=` の分布を見て、cold な file の scan 時間を `clamdscan --stream` で測る。timeout の間、端末の download は本文が来ないまま止まって見える。
