# AV / マルウェア対策 — 最新研究サーベイ（2026）

調査 2026-09-11。調べた問いは、マルウェア配布元と C2 の遮断、ダウンロードした file の中身の scan、Defender の代わりをどこまで担えるか、今の IPS/IDS 機能への追加か新規開発か、パターンファイルだけを ClamAV にして packet で捉えられるか、最新研究である。**これは調査のみ。source code と `docs/design.md` は変えていない。段階は1つも進めていない。**

出所ラベル：`確実` = 一次情報（公式 doc / 論文 / vendor doc）に URL 付きで当たった。`未確認` = 検索要約止まり、または一次情報に届かなかった。`推測` = 資料の合成。

## 確実 / 未確認 の総覧

**確実**：JA4/JA4+ の仕組みとライセンス、JA4 の Suricata 実装、YARA-X の成熟度とライセンス、ClamAV の clamd INSTREAM・clamonacc/fanotify・GPLv2、c-icap+SquidClamav の構成、Tetragon/Falco の eBPF 概要、Windows Tamper Protection と third-party AV の passive mode 挙動、AMSI provider（IAntimalwareProvider）の実装要件、abuse.ch ThreatFox/Feodo Tracker の更新頻度とライセンス、OpenPhish 無料枠の更新頻度、2025-2026 の暗号化トラフィック検知論文の存在（複数）。

**未確認**：ClamAV 公式シグネチャの実際の検知率の一次データ（SecuriteInfo という一利害関係者の主張のみ）、Suricata の file-store → clamd 連携の具体的な公式レシピ（doc に file extraction 機構はあるが clamd 連携の一次記述には届かなかった）、eBPF+ML のネットワーク malware 検知（USENIX/NDSS）の的確な一次論文（ransomware 検知の kernel ML はあるが暗号化トラフィックへの eBPF+ML 適用は未確認）、Trident（LLM+behavioral malware detection, arXiv:2605.00297）の査読状況。

---

## 1. JA4/JA4+ と暗号化トラフィックのマルウェア検知

JA4 は FoxIO が JA3 の後継として出した TLS/TCP/HTTP/SSH/QUIC の fingerprint 群。復号せずに ClientHello 等の特徴からハッシュを作る（[FoxIO blog](https://blog.foxio.io/ja4+-network-fingerprinting)、[GitHub FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)）。C2/malware infra の識別に使われている実績が [Team Cymru の解説](https://www.team-cymru.com/post/a-primer-on-ja4-empowering-threat-analysts-with-better-traffic-analysis) と [hunt.io](https://hunt.io/features/ja4) にある。2024-2026 の ML ベース暗号化トラフィック分類は SoK 論文（[arXiv:2503.20093](https://arxiv.org/pdf/2503.20093)、IEEE S&P 2025）が手法を整理、個別に低誤検知を狙う BFDet などの手法名が挙がったが本文は未読（検索要約止まり）。誤検知率の具体的な数値（%）には一次情報で届かなかった＝**未確認**。

Suricata は 7.x 系から `ja3.hash` / JA4 keyword をネイティブでサポートし、`app-layer.protocols.tls.ja{3,4}-fingerprints` を有効にすれば rule で使える（[Suricata docs](https://docs.suricata.io/en/suricata-7.0.8/rules/ja-keywords.html)）。既存の Suricata 併走（`docs/design.md` の EVE JSON 読み込み）に素直に乗る。

- packetdeath の前提に効くか：段階4（IDS）の Suricata rule に JA4 keyword を足すだけで、非復号のまま C2 fingerprint 判定が増える。新規開発は proxy 側でも可能（後述）
- 復号が要るか：不要（ClientHello の平文部分だけで足りる）
- Rust で書けるか：可。`FoxIO-LLC/ja4` 本体が Rust 実装を持ち、`huginn-net`（[crates.io](https://crates.io/keywords/ja4)）や `rama::net::fingerprint`（[docs](https://ramaproxy.org/docs/rama/net/fingerprint/struct.Ja4.html)）で crate 化済み。unsafe 不要な範囲で使える見込み（各 crate の unsafe 使用は個別確認が要る）
- license：**JA4（TLS Client Fingerprinting）自体は BSD 3-Clause**。だが **JA4+ 一式（JA4S/L/H/X/SSH 等）は FoxIO License で商用の product 組込みは OEM ライセンスが要る**（自社内利用は可）。packetdeath を配布・販売するなら JA4+ の範囲を確認する必要（[LICENSE FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md)、[LICENSE](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE)）

## 2. inline file scan（proxy/ICAP → ClamAV）

Squid + c-icap + SquidClamav が定番構成。c-icap が ICAP daemon、SquidClamav が Squid と clamd の橋渡し（[Squid wiki](https://wiki.squid-cache.org/ConfigExamples/ContentAdaptation/C-ICAP)、[SquidClamav doc](https://squidclamav.darold.net/documentation.html)）。packetdeath は自前 proxy（段階7、非復号 CONNECT）なので Squid は要らず、**clamd の INSTREAM プロトコルを直接 Rust から叩く**方が筋が良い。

- packetdeath の前提に効くか：段階7（proxy）と段階6（`--av av.jsonl`）の間を埋める。proxy 経由の file だけは中身が見えるので、CONNECT ではなく平文 HTTP でダウンロードされた file、または将来 利用者が明示的に許可した復号経路の file をここで scan できる
- 復号が要るか：TLS 越しの file は復号しないと中身に届かない（CONNECT トンネルの中身は見えない）。**平文 HTTP ダウンロードだけは復号なしで scan 可能**
- Rust で書けるか：可。`clamav-client`（sync/async 両対応、[crates.io](https://crates.io/crates/clamav-client)）、`clamd-client`（tokio、[crates.io](https://crates.io/crates/clamd-client)）など複数 crate が INSTREAM を実装済み
- license：ClamAV 本体は **GPLv2**（[Wikipedia](https://en.wikipedia.org/wiki/ClamAV) 経由確認、公式配布も GPLv2 表記）。GPLv2 の daemon を別 process（clamd）として起動し socket 越しに呼ぶ分には packetdeath 本体の license に波及しない（動的リンクしない）

## 3. YARA / YARA-X

YARA-X は VirusTotal による Rust 完全書き直し。2025-06 に 1.0.0 安定版、YARA 4.x は保守モードへ移行し新機能は YARA-X のみに入る（[VirusTotal blog](https://blog.virustotal.com/2025/06/yara-x-100-stable-release-and-its.html)）。VirusTotal 本番で数十億 file・数万 rule 規模の実運用実績あり（[YARA-X blog](https://virustotal.github.io/yara-x/blog/yara-is-dead-long-live-yara-x/)）。**ネットワークストリームへの適用の一次記述には届かず**（未確認）。ファイル/バイト列への適用が主眼で、network stream は抽出した file に対して掛ける前提になるとみられる（推測）。

- packetdeath の前提に効くか：段階6（`--av`）で clamd に加えて YARA-X ルールを file に掛ける第二の検知エンジンにできる。C2 通信パターンそのものへの適用は未確認
- 復号が要るか：抽出済み file への適用なら不要（file 自体は proxy/Suricata file-store 経由で既に平文）
- Rust で書けるか：可。`yara-x` crate が公式（[crates.io/lib.rs](https://lib.rs/crates/yara-x)）。unsafe の有無は要個別確認だが、VirusTotal が「Rust core が通常のメモリバグを避ける」と述べている（[blog](https://blog.virustotal.com/2025/06/yara-x-100-stable-release-and-its.html)）
- license：**BSD 3-Clause**（原 YARA が switch 済み。YARA-X も VirusTotal/OSS で同系統。個別の LICENSE file 確認は未読 = 半確実）

## 4. Suricata の file 抽出 + scan

Suricata は `eve.files`（fileinfo メタデータのみ）と `file-store`（実体を SHA256 名で `filestore/xx/` へ保存）の2つの出力を持つ（[Suricata 6.0.14 docs](https://docs.suricata.io/en/suricata-6.0.14/file-extraction/file-extraction.html)）。**clamd との連携を謳う Suricata 公式ドキュメントには届かなかった**（未確認）。実務上は `file-store` が書いた file を外部スクリプトが監視し clamd へ INSTREAM で流す、という自作橋渡しが一般的とみられる（推測、`docs/design.md` の「橋渡し program は packetdeath の外」という段階6の設計方針とも整合する）。

- packetdeath の前提に効くか：**既存の Suricata 併走に無理なく足せる**。`file-store` の出力を監視する外部 program（Rust 製）が clamd へ scan させ、結果を `--av av.jsonl` 形式で書き出せば、段階6の口にそのまま載る。新規開発は小さい
- 復号が要るか：Suricata が復号なしで抽出できるのは平文 HTTP/SMB 等の file のみ。TLS 越しの file は Suricata 単体では見えない
- Rust で書けるか：可（file watch + clamd client の自作。上記 crate 群で足りる）
- license：Suricata 本体 GPLv2（既存前提と同じ）

## 5. eBPF ベース検知（Cilium/Tetragon、Falco）

Tetragon は eBPF で kernel 内のプロセス実行・ネットワーク・file access を観測し、real-time で policy enforcement も可能（オーバーヘッド1%未満、[infoworld](https://www.infoworld.com/article/3810607/tetragon-extending-ebpf-and-cilium-to-runtime-security.html)、[Cilium 公式](https://tetragon.io/)）。Falco は CNCF 卒業プロジェクトで syscall を eBPF で見て rule engine に掛ける（1万 events/sec、CPU 5%未満、[MangoHost 2025 blog](https://mangohost.net/blog/falco-in-2025-real-time-security-monitoring-with-ebpf/)）。**両方とも Falco は検知のみで既定では遮断しない**（[decryptiondigest](https://www.decryptiondigest.com/blog/ebpf-runtime-security-tools-falco-tetragon)）。どちらも主に Kubernetes/コンテナ向けの実績が厚く、汎用 Linux ホスト単体での実績記述は薄い。

- packetdeath の前提に効くか：段階4/6 とは別軸。**host 側（ネットワーク層の外）の実行監視**であり、路線(C)（host 側で Defender 相当）に直結する。ネットワーク遮断そのものには効かない
- 復号が要るか：不要（file/process/syscall レベルの観測。ネットワーク特徴を見る場合も暗号化の有無は無関係）
- Rust で書けるか：eBPF プログラム自体は C（または Rust の `aya` crate 経由でも書けるが実績が薄い）。Tetragon/Falco 本体を「使う」だけなら Rust で書き直す必要はなく、外部 daemon として動かして log を packetdeath が読む形が現実的
- license：Tetragon は **Apache 2.0**、Falco は **Apache 2.0**（両方 CNCF、一次 LICENSE file までは未読＝準確実。プロジェクトの CNCF 加盟条件として Apache 2.0 が一般的）

## 6. 「Defender を置き換える」の現実

Windows は **Tamper Protection が有効だと registry/GPO/PowerShell からの Defender 無効化を一切拒否する**。無効化は Windows Security アプリの GUI 操作、または互換な third-party AV を「登録」することでのみ起きる（[techcommunity 2025-2026](https://techcommunity.microsoft.com/discussions/microsoftdefenderatp/how-to-disable-defender-on-windows-server-with-tamper-protection-enabled/4449402)）。third-party AV を入れても **Defender は「完全停止」ではなく Passive Mode**（network protection・AMSI・behavior monitoring の一部は動き続ける）に落ちるだけ（検索要約、複数ソース一致）。**Defender 自体のアンインストールは Windows 10/11 で通常不可能**（built-in component。[itechguides](https://www.itechguides.com/how-to-uninstall-microsoft-windows-defender-what-you-can-do-instead/)、[Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/5623360/how-to-uninstall-defender-security-completely)）。

「third-party AV として Windows に登録される」には Windows Security Center API 経由の登録（WSC）が要り、これは Microsoft の Security Provider 認定の実務（一次資料未確認、Microsoft の互換要件文書に当たれなかった）。

自作 AV/EDR に最低限 要る層（一次情報＋推測の合成）：
1. **on-access file scan**：ファイルシステムのフック。Windows は minifilter driver（カーネルドライバ＝ Rust の unsafe か C が前提、「①アセンブラ②Rust③それ以外」の路線と衝突しやすい）。Linux は `fanotify`（後述、非 driver で済む）
2. **AMSI provider**：`IAntimalwareProvider` COM interface を実装した in-process DLL を `HKLM\SOFTWARE\Microsoft\AMSI\Providers` へ登録すれば、PowerShell/JScript/VBScript の実行前スクリプトを **カーネルドライバなしで** 受け取れる（[Microsoft Learn IAntimalwareProvider](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider)、[サンプル](https://learn.microsoft.com/en-us/samples/microsoft/windows-classic-samples/iantimalwareprovider-sample/)）。**これは driver 不要で packetdeath の「中国 driver 禁止」「Npcap を採らない」路線と衝突しない**
3. **behavioral（実行時挙動）**：ETW（Event Tracing for Windows）購読、または Sysmon 相当。driver 不要で実装できる範囲がある（一次情報未確認、Microsoft ETW doc への到達なし＝推測寄り）

Linux 側 ClamAV 常駐は `clamonacc`（ClamAV 付属）が `fanotify` API で file access を監視し、prevention mode では kernel 空間でブロックできる（driver 不要、kernel >= 3.8）（[ClamAV 公式 On-Access docs](https://docs.clamav.net/manual/OnAccess.html)、[man page](https://www.mankier.com/8/clamonacc)）。

- packetdeath の前提に効くか：**路線(C)**。Windows は AMSI provider（driver 不要）が唯一の低コストな入口。file system 全面の on-access は minifilter driver が要り、「driver 順序①アセンブラ②Rust③それ以外」との整合を要検討（Rust で minifilter を書く実績は薄い＝未確認）。Linux は `clamonacc`/fanotify がそのまま使える（driver 不要）
- 復号が要らない：この層はネットワークではなく file/process が対象なので復号の概念自体が無い
- Rust で書けるか：AMSI provider の DLL 自体は COM in-process server として Rust で書ける可能性が高い（`windows-rs` crate 経由。個別実績は未確認）。Linux 側は `clamonacc` を外部 daemon として使うだけで Rust 実装は不要
- license：AMSI は Windows API（Microsoft の利用規約下、無償で使える）。ClamAV は GPLv2（前述と同じ）

## 7. 公開の malware domain/IP feed

ThreatFox（IOC 共有）と Feodo Tracker（C2 botnet infra）は **5分ごとに更新**、少なくとも30分ごとの取得を推奨（[Spamhaus doc 経由 abuse.ch](https://docs.spamhaus.com/real-time-feeds/docs/source/50-abuse-ch-real-time-feeds/600-feeds-ach.html)）。URLhaus は malware 配布 URL。ThreatFox Community API は **fair use の下 無償**だが、商用/営利での利用は commercial API（有償）が必要な場合がある（[ThreatFox API](https://threatfox.abuse.ch/api/)）。**2025-05-01 以降、6ヶ月超過の IOC は expire する運用**（検索要約、一次 policy page 未読）。

OpenPhish の無料 feed は **1日2回更新**、有償 Light/Extended プランは15分更新（[vmray 2026 記事](https://www.vmray.com/best-threat-intelligence-feeds/)、[OpenPhish 公式](https://openphish.com/phishing_feeds.html)）。

いずれも domain/IP/URL のリストで、**1行1domain（または1行1IP）への変換は素直**（既存の `--iplist`／blocklist の形式にそのまま載る）。license は abuse.ch 系は基本 **CC0 相当**（YARAify の rule 共有では明示、feed 本体の license 文言は個別未読＝準確実）、商用利用条件は fair use ポリシー次第で要個別確認。

- packetdeath の前提に効くか：**路線(A)の中核**。既存の blocklist/allowlist（走行中 読み直し対応済み、`src/reload.rs`）へ、ThreatFox/Feodo Tracker/URLhaus を定期 pull → 1行1domain/IP へ変換 → 既存 blocklist file を書き換える、という外部 program 1本で足りる。新規開発は小さい
- 復号が要るか：不要（domain/IP マッチのみ、既存の SNI/IP 判定と同じ層）
- Rust で書けるか：可（HTTP GET + パース。追加 crate は最小限）
- license：CC0 相当（無償利用は可、商用/営利は fair use の範囲を要確認）

## 8. 最新研究の目玉（2024-2026）

| 論文 | 掲載 | 要旨 | URL |
|---|---|---|---|
| SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers | IEEE S&P 2025 | 暗号化トラフィック分類の手法を統一的に整理・比較する体系化論文 | [arXiv:2503.20093](https://arxiv.org/pdf/2503.20093) |
| Adaptive Detection of Encrypted Malware Traffic via Fully Convolutional Masked Autoencoders（Malcom） | Frontiers of Computer Science 2026 | Header-Payload Matrix という新しい表現で暗号化 malware トラフィックを検知 | [Springer](https://link.springer.com/article/10.1007/s11704-025-41273-9) |
| Integrating Explainable AI for Effective Malware Detection in Encrypted Network Traffic | arXiv 2025-01 | 暗号化トラフィックの malware 検知に説明可能性を統合 | [arXiv:2501.05387](https://arxiv.org/pdf/2501.05387) |
| MalMoE: Mixture-of-Experts Enhanced Encrypted Malicious Traffic Detection Under Graph Drift | arXiv 2026（検索要約止まり、URL 未確認） | graph drift 下での MoE ベース検知 | 未確認 |
| Trident: Improving Malware Detection with LLMs and Behavioral Features | arXiv 2026-04 | LLM が sandbox の挙動レポートを解釈し、静的 ML 分類器・behavioral rule・LLM 判定の多数決でconcept drift に強い検知を実現 | [arXiv:2605.00297](https://arxiv.org/pdf/2605.00297) |
| ML-Based Behavioral Malware Detection Is Far From a Solved Problem | arXiv 2024 | 挙動ベース ML 検知の限界を指摘する批判的論文（過大評価への警鐘） | [arXiv:2405.06124](https://arxiv.org/pdf/2405.06124) |
| Ransomware Detection Using Machine Learning in the Linux Kernel | arXiv 2024 | kernel 内（eBPF 系）で ML により ransomware を検知する試み | [arXiv:2409.06452](https://arxiv.org/pdf/2409.06452) |

**eBPF + ML でネットワーク（暗号化トラフィック）を検知する USENIX/NDSS 級の一次論文には届かなかった**（未確認。eBPF+ML は上記の通り host 内 ransomware/kernel compartmentalization の文脈が中心で、ネットワーク malware 検知への直接適用は今回の検索では見つからず）。

- packetdeath の前提に効くか：直接の実装対象ではなく、路線(A)(C) の判定精度を将来 上げる候補。Trident 型（LLM + behavioral の多数決）は段階4以降の「ML 判定（AdVersa 系）」の枠と同じ位置づけになりうる（`docs/design.md` 「ML 判定（AdVersa 系）は段階4の後に別設計とする」と整合）
- 復号が要るか：手法により異なる（SoK・Malcom は非復号前提、LLM/behavioral 系は file/実行痕跡が前提で file scan 経路が要る）
- Rust で書けるか：研究実装は Python/PyTorch が主流。推論のみを Rust に持ち込む（ONNX Runtime 等）のは可能だが個別実績は未確認
- license：論文自体は学術公開。実装コードの license は個別（AdVersa は MIT、`docs/research/prior-art.md` 既存記載）

---

## 3路線の比較表

| 路線 | 効果 | 実装コスト | 誤検知 | 依存 | license |
|---|---|---|---|---|---|
| **(A) 復号なしで届く範囲**（malware feed + JA4 + 平文/proxy 経由 file の clamd scan） | C2/malware infra の domain・IP 遮断は既存 blocklist 路線の延長で高い効果。file 中身の scan は **TLS 越しは不可**、平文 HTTP と proxy が明示的に復号した範囲に限定 | 中。feed 取り込み・JA4 rule・clamd 橋渡しはいずれも既存路線への追加で、新規基盤は不要 | feed 由来は基本 低い（既知悪性のみ）。JA4 の ML 併用は SoK 論文水準では未検証（packetdeath 用の実測が要る） | Suricata（既存）、clamd（新規 daemon 依存、GPLv2 だが別 process）、ThreatFox/Feodo/URLhaus/OpenPhish（外部ネットワーク依存、feed 停止時は fail-open で前回内容を使う設計と整合） | JA4+ は商用 OEM 要検討。他は GPLv2/CC0/BSD で組込み容易 |
| **(B) MITM 前提**（利用者が自分で CA を入れる選択のときだけ。全 file scan） | TLS 越しの file も含め全面 scan 可能。効果は最大だが**既定にしない**方針（要件で明示排除） | 高。CA 生成・配布・証明書ピンニング対応・失効管理が要る。proxy 側の再暗号化ロジックも要る | 中〜高。復号ミスで正規サイトを壊すリスク、証明書ピンニングで接続不能になるアプリが出る | mitmproxy 相当の自作、または既存 OSS の再利用検討が別途要る | 利用者の明示 opt-in が前提。技術選定は本調査の範囲外（既定にしない路線のため深掘りしていない） |
| **(C) host 側**（Windows/Linux の on-access scan で Defender 置き換え） | file 到達後の最終防波堤。Windows は AMSI provider（driver 不要）でスクリプト実行前を捕まえられるが、**file system 全面の on-access には minifilter driver が要り、Defender の完全代替には届かない**（Defender 自体のアンインストールは通常不可）。Linux は `clamonacc`/fanotify で driver なしに on-access 実現可能 | Windows: 中（AMSI provider 単体なら DLL 1本）〜高（minifilter まで含めると driver 開発）。Linux: 低（`clamonacc` は ClamAV 付属、設定のみ） | AMSI provider は誤検知がそのままユーザー体験を壊す（PowerShell 起動遅延の実測既知）。要 clamd 側 signature 品質に依存 | Windows: AMSI API（COM）。Linux: ClamAV（GPLv2）+ fanotify（kernel API） | AMSI は Microsoft API 利用規約下。ClamAV は GPLv2 |

### 各路線の最小の次の一歩

- **(A)**：ThreatFox + Feodo Tracker を pull して既存 blocklist file（`--blocklist` が読み直す形式）へ1行1domain/IPで追記する外部 program を1本作る。Suricata rule への JA4 keyword 追加は設定変更のみで着手できる
- **(B)**：着手しない。利用者が自分で CA を入れる選択をした時点で、その時の要件を別途 洗い直す
- **(C)**：Linux は `clamonacc` を `--av av.jsonl` 形式の verdict を吐く橋渡しとして試験導入（driver 不要、最短）。Windows は AMSI provider の DLL 実装可否（Rust + `windows-rs` での in-process COM server の実現性）を小さな PoC で確認する

---

## 採らない手段

- **CA 証明書を信頼ストアへ入れる MITM を既定にする**（CA を入れずに packet へ直接 作用させる、が要件。路線(B)は opt-in 専用）
- **ブラウザ拡張**（利用者が既に排除。uBlock 等で検出される経路）
- **中国の組織が署名した driver**（WinDivert 等。禁じ手3）
- **Rust の unsafe**（minifilter driver 等、driver 実装が unsafe/C 前提になりやすい箇所は要 個別検討）
- **検体や通信内容を外部 SaaS / クラウド sandbox へ送る検知**（プライバシー上 採らない。VirusTotal 系のクラウド lookup、商用 EDR のクラウド行動解析も同分類）
- （調査で新たに見えた危険な手段）**third-party AV の Windows 登録詐称（WSC API への虚偽登録）で Defender を Passive Mode へ落とす手口**は、Microsoft の互換性検証を経ない自己申告に近く、Tamper Protection 環境下での挙動保証がない（一次情報未確認のため実装対象にしない）
