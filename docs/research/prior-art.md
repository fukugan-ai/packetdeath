# パケットレベル広告遮断 — 先行研究の一覧

調査 2026-09-10。出所ラベルは3種。

- `実読` ── その file / page を自分で開いて、当該行を読んだ。行番号か節番号を添える
- `検索` ── 検索結果の記述のみ。一次資料は開いていない
- `推測` ── どちらでもない。資料の合成

## 0. 守る対象

**メインは Windows 上のブラウザ。WSL の Linux ではない。将来 Windows を捨てる可能性があるので、Linux でも動く形にする。**

この前提が、下の「どの層で切るか」の答えを決める。実行環境の制約は §7。

## 1. 最新（2026）

| 論文 | 会議 | 何を主張しているか | 出所 |
|---|---|---|---|
| **AdVersa: Adversarially-Robust and Practical Ad and Tracker Blocking in the Wild** — Chaejin Lim, Kiho Lee, Beomjin Jin, Heewon Baek, Hyoungshick Kim | ACM Web Conference 2026 (WWW 2026) | 既存の ML ブロッカーは敵対的摂動で **57〜92% 回避される**。code embedding と URL embedding の潜在特徴（摂動しにくい）を使い、2.74M request で **F1 98.23%**、未知ドメインで **91.47%**。擬似ラベルでフィルタリスト保守コストを **99.8% 以上 削減** | 実読（Zenodo record 17295030 の abstract） |
| **Privacy vs. Profit: The Impact of Google's Manifest Version 3 (MV3) Update on Ad Blocker Effectiveness** — Karlo Lukic, Lazaros Papadopoulos (Goethe University Frankfurt) | PoPETs 2026 Vol.1 / arXiv:2503.01000v2 | ad blocker 4種の MV2 版と MV3 版を比較。**遮断効果に統計的に有意な低下は無い**。一部は tracker 遮断でわずかに改善 | 実読（arXiv abstract page） |

- AdVersa DOI: `10.5281/zenodo.17295030`
- AdVersa 実装: https://github.com/SKKU-SecLab/AdVersa — **MIT License**。Python 3.8〜3.10 / Java / Node.js。**MITMProxy addon（`deployment/localproxy`）とブラウザ拡張（`deployment/extension`）の両方**、MOJO 形式 model（`adversa-java-server.jar`）、2.74M request の dataset（Zenodo）
- ACM DL の page は **HTTP 403 で開けなかった**。本文は未読。上の数値は abstract のみ

**AdVersa について、資料が言っていないこと（推測で埋めない）**

- CNAME cloaking と first-party proxy を解けるとは、abstract のどこにも書いていない。**URL embedding が domain 名にどれだけ依存するかは未確認**（本文 未読）
- EasyList との直接比較の数値は abstract に無い
- 「57〜92% の回避率」がどの攻撃モデル下の数字かは未確認（本文 未読）

## 2. Web 側の防衛が何をしたか

| 論文 | 掲載 | 数値 | 出所 |
|---|---|---|---|
| **SoK: Advances and Open Problems in Web Tracking** — Vekaria, Beugin, Munir, Acar, Bielova, Englehardt, Iqbal, Kapravelos, Laperdrix, Nikiforakis, Polakis, Roesner, Shafiq, Zimmeck（14名 / 14機関） | arXiv:2506.14057、2025-06-16 | **EasyList の rule の 90% は実質 発火しない**。tracker は「client から server 側へ tracking logic を移している」。server-side tracking の検出を **open problem** として明示 | 実読（HTML 版 §V-C1 と §X-B） |
| **Encrypted Client Hello (ECH) in Censorship Circumvention** — Niklas Niere, Felix Lange, Nico Heitmann, Juraj Somorovsky (Paderborn University) | FOCI 2025(2) | §4.1 ── Tranco Top 1M（2025-02-16 版）の TLS1.3 server のうち **328,541 台（51.28%）が ECH extension を parse**。そのうち **278,040 台（TLS1.3 server の 43%）が Cloudflare の ECH config で handshake 成立**。**非 Cloudflare の config で成立したのは 6 台のみ**。50,494 台はどの config でも成立せず。§5 ── Cloudflare は outer SNI に `cloudflare-ech.com` を**要求する**（非 Cloudflare 実装は outer SNI の省略・無効を受け入れる）。§8 ── **「ECH connections to Cloudflare are distinguishable from non-ECH connections」** | 実読（`foci-ech.txt:250-268`, `:340-352`, `:537-539`） |
| **CNAME Cloaking-Based Tracking on the Web: Characterization, Detection, and Protection** | IEEE（Access 系） | Tranco Top 10K の **9.98%** が CNAME tracker を使用（2020-10 時点）。2018→2020 で 22% 増 | 検索 |
| **The CNAME of the Game: Large-scale Analysis of DNS-based Tracking Evasion** — Dimova, Acar, Olejnik, Van Goethem ほか | PETS 2021 | Alexa Top 300K のうち **1,762 site**（2020-01） | 検索 |

**ECH の実読で、当初の見立てが1つ ひっくり返った。**

`ECH が普及すると SNI が消えるので、SNI ベースの手は死ぬ` ── **これは現時点では成り立たない。**

- ECH の handshake が成立するのは **ほぼ Cloudflare だけ**（非 Cloudflare は 6 台）
- Cloudflare の ECH フローは outer SNI が `cloudflare-ech.com` で固定なので、**「ECH を使っている」ことは丸見え**
- 隠れるのは「どの domain か」だけ

つまり ECH は **domain 単位フィルタを無効化するが、フローの識別自体は妨げない。** 当面の脅威度は、当初の見積もりより低い。

## 3. パケットレベル遮断の原典

| 論文 | 掲載 | 数値 | 出所 |
|---|---|---|---|
| **NoMoAds: Effective and Efficient Cross-App Mobile Ad-Blocking** — Anastasia Shuba, Athina Markopoulou (UC Irvine), Zubair Shafiq (Univ. of Iowa) | PoPETs 2018 Issue 4（Andreas Pfitzmann Best Student Paper Award） | **network interface を universal vantage point として使う**。packet header と payload から特徴を抽出し ML 分類器を学習。**F-score 最大 97.8%**。**EasyList が取り逃す広告を検出（dataset の 1/3 超）**。packet 単位で real-time 分類 | 実読（PoPETs の論文 page の abstract） |
| **NoMoATS: Towards Automatic Detection of Mobile Tracking** — Shuba, Markopoulou | PoPETs 2020 Issue 2 | 手作業の rule 作成を廃し、request の自動 label 付け。NoMoAds へ食わせて **平均 F-score 93%**、端末上で real-time | 検索 |
| **The TV is Smart and Full of Trackers: Measuring Smart TV Advertising and Tracking** | PoPETs 2020 Issue 1 | 41 世帯の residential gateway、7 platform / 57 台の smart TV、Roku と Fire TV の top-1000 app。**DNS ベース blocklist の (in)effectiveness を実測** ── 取り逃しと機能破壊の両方が出る | 検索 |

実装: https://github.com/nshuba/NoMoATS 、dataset は AthinaGroup が公開。

**NoMoAds は 2018年の測定であり、payload を読めることを前提としている。**いまの Web で同じ土俵に立つには、TLS を開く必要がある（§7）。

## 4. フィルタルール自動生成の系譜

| 論文 | 掲載 | 数値 | 出所 |
|---|---|---|---|
| **AutoFR: Automated Filter Rule Generation for Adblocking** | arXiv:2202.12872 / USENIX Security 2023 | multi-arm bandit の強化学習で site ごとに数分で rule 生成。**広告の 86% を遮断（EasyList は 87%）**、視覚的破壊は同等 | 検索 |
| **AdGraph: A Machine Learning Approach to Automatic and Effective Adblocking** | IEEE S&P 2020 / arXiv:1805.09155 | HTML / HTTP / JavaScript の多層グラフ。Alexa Top 10K で **精度 97.7%** | 検索 |
| **WebGraph: Capturing Advertising and Tracking Information Flows for Robust Blocking** | arXiv:2107.11309 / USENIX Security 2022 | 情報フローのグラフ表現で回避耐性を上げる | 検索 |
| **AdVersarial: Perceptual Ad Blocking meets Adversarial Machine Learning** | ACM CCS 2019 / arXiv:1811.03194 | 知覚ベース ad blocker が敵対的例で破れることを実世界の web security 文脈で初めて示した | 検索 |
| **Percival: Making In-Browser Perceptual Ad Blocking Practical With Deep Learning** | arXiv:1905.07444 | render pipeline に deep learning を入れる | 検索 |

## 5. パケット層の技術的制約

| 事実 | 何を意味するか | 出所 |
|---|---|---|
| TLS 1.3 + ECH で inner SNI が暗号化される。ただし成立はほぼ Cloudflare のみで、outer SNI は `cloudflare-ech.com` に固定 | **domain 単位フィルタは効かなくなるが、ECH フローの識別はできる。**広告だけを選り分ける役には立たない | 実読（FOCI 2025 §4.1, §5, §8） |
| SSAI（server-side ad insertion）は広告を video stream へ縫い込む | 別 request が発生しないので、**request 単位のどんな分類器も原理的に効かない**。HLS/DASH の manifest 上では `#EXT-X-DISCONTINUITY` と SCTE-35 の `#EXT-X-CUE-OUT` / `#EXT-X-CUE-IN` が境界を示す | 検索 |
| YouTube は同一 domain 配信 + anti-adblock script を 48〜72時間で rotate | 静的 rule の寿命が 2〜3 日 | 検索（AdGuard Research Labs の報告。一次資料 未確認） |
| server-side tagging（sGTM を `metrics.example.com` などの first-party subdomain に置く） | DNS でも SNI でも first-party と区別できない | 検索 |
| app が DoH を hard-code する | Pi-hole 系を素通りする | 検索 |
| eBPF / XDP は driver 層で drop できる（throughput 改善 最大 45% の報告） | **速いが、判定材料は L3/L4 まで。何が広告かを判定する材料を持っていない** | 検索 |
| 証明書ピンニングした app は、CA を信頼ストアへ入れても MITM proxy を拒否して接続を中断する | **proxy 路線は「ブラウザには効くが、ピンニングした native app には効かない」**。採用率の実測値は見つからなかった | 検索 |

## 6. まだ埋まっていない穴

- **暗号化フローの「広告らしさ」を packet size / 間隔 / 方向だけで判定する研究は、広告に特化したものが見当たらない。** 隣接領域（app fingerprinting、malicious traffic 検出）は多い。SoK も server-side tracking の検出を open problem に挙げている
- **SSAI を stream 内で切る研究**（ML による ad segment 検出）は、特許と業界資料はあるが査読論文が見つからなかった
- **証明書ピンニングの採用率**の実測が見つからない。proxy 路線の適用範囲を見積もる分母が無い

## 7. 実行環境の制約（Windows がメイン、Linux も準備）

| 事実 | 出所 |
|---|---|
| WSL2 の既定（NAT モード）では、Windows の `127.0.0.1` と WSL の `127.0.0.1` は**別物**。Windows のブラウザから WSL 内の proxy へは、`localhost` では届かない | 検索 |
| Windows 11 の **mirrored networking モード**なら localhost が共有される。`autoProxy=true` で Windows の HTTP proxy 設定を WSL が引き継ぐ | 検索 |
| **WinDivert** は user-mode から WFP を使って packet を横取り・注入できる（kernel driver を自分で書かなくてよい）。C API に **Rust binding がある** | 検索 |
| ただし **Windows は WinDivert の下位で TCP anti-spoofing を強制する**。透過 proxy は Wi-Fi で失敗し Ethernet で動いた、という報告がある | 検索 |
| **hudsucker** ── Rust の MITM HTTP/S proxy crate。HTTP/2 対応、`rustls` client、`rcgen` で CA 生成。request / response / WebSocket を書き換えられる | 検索 |
| 同系統に `third-wheel`、`slinger-mitm`（証明書 cache と生成最適化、HTTP proxy と SOCKS5 を同一 port で） | 検索 |
| `HttpFilteringEngine` ── WinDivert を使った透過 TLS filtering proxy。**C++、2017年に作者が放棄** | 検索 |

**この節の含意（この節は全行が `検索` 由来である。断定に見える行も、実測で覆りうる）**

- **透過（WinDivert / WFP）より、明示 proxy 設定を先に試す** ── `推測`。根拠は §7 の表の「Windows は WinDivert の下位で TCP anti-spoofing を強制する」「Wi-Fi で失敗し Ethernet で動いた報告」の2行だが、**どちらも `検索` であり、この環境で再現していない。****既存運用との接続については §8 を見ること。**
- **Rust で書けば Windows と Linux の両方に単一 binary で出せる** ── `推測`。`hudsucker` が両 OS で build できることは未確認。このプロジェクトの言語順序（アセンブラ、Rust、それ以外）の Rust と一致することだけが確定している
- **AdVersa の Python / Java 実装は本番へ載せない** ── これは判断であって事実ではない。根拠はこのプロジェクトの言語順序（アセンブラ、Rust、それ以外）。model が MOJO（Java）形式であることは repo の README に接地する（**実読**）が、Rust から使う経路（変換 or 再学習）は **未検証**

## 8. 自分で立てた反論と、その処理

| 反論 | 処理 |
|---|---|
| **ブラウザだけ守るなら、uBlock Origin で足りるのでは。** DOM と script 実行が見える拡張の方が、proxy より情報量が多い | **正しい。**しかも MV3 で効果は落ちていない（PoPETs 2026、実読）。**proxy 層の存在理由は「ブラウザ以外」に限る** ── Windows の native app、Electron、スマート家電、将来の Linux 機。両方 併用が筋。AdVersa 自身が拡張と MITMProxy addon の両方を出しているのは、おそらく同じ理由（**推測**） |
| **AdVersa が squid の直接の後継になる、と言えるか** | **言えない。**先行研究のどれも squid に言及していない。**利用者の squid 設定も、一度も述べられていない。**言えるのは「明示 proxy の位置に置ける実装が MIT で公開されている」までである。<br>⚠️ 前の版はここに `grep -i squid で prior-art 内 0件` と書いていた。**この式は自分自身の行に当たるので 0件にならない。**式が対象を掴んでいなかった（数えた式そのものを、必ず当たる語で先に確かめる） |
| **表の中で撤回した主張が、同じ file の別の場所に生き残っていないか** | **生き残っていた。**§8 で撤回した squid の主張が、§7 の含意にラベル無しの断定として残っていた（2026-09-10、レビューで捕まった）。**撤回したら、file 全体を照らし直す** |
| **F1 98.23% は自前 dataset 上の数字ではないか** | **そのとおり。**2.74M request の自前 dataset。EasyList との直接比較は abstract に無い。**自分の回線で測るまで、この数字を採用しない** |
| **ECH で SNI が消えるから案B は死ぬ、と言ったのは正しいか** | **間違いだった。**§2 の実読で訂正済み。案B の弱点は ECH ではなく「L3/L4 しか見えない」ことの方 |
| **MITM proxy は自分の TLS を割る。戻せるか** | CA 証明書を Windows の信頼ストアと Firefox の独自ストアへ入れる操作。**撤去手順を先に確定し、1件で戻せることを確かめてから入れる**（不可逆操作の規則） |
