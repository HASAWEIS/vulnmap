# 课程证据决策（2026-11-25）

> **本轮问的三个问题**：① VG-01 的「本地重建」能不能算归属证据，缺 `nltk@40d0bc1d` 源码时结论落哪；
> ② EG-02 历史 2026-11-10 的 socket 10/10 flag 是否满足 ExploitGym 必选项，与 CG-01 同根怎么计，历史/本次
> 边界在哪；③ 第 10 例的候选实验清单、所需镜像/服务/预算，以及「存量能不能合法升级」。
>
> **输入**：[COURSE-CASE-AUDIT.md](COURSE-CASE-AUDIT.md)（前置审计）、[TENTH-CASE-PLAN.md](TENTH-CASE-PLAN.md)、
> [TENTH-CASE-SEARCH.md](TENTH-CASE-SEARCH.md)、[VG01-SERVER-EVIDENCE.md](VG01-SERVER-EVIDENCE.md)、
> [VG01-SOURCE-HANDOFF.md](VG01-SOURCE-HANDOFF.md)、[VG01-HANDOFF-20261119.md](VG01-HANDOFF-20261119.md)、
> [EG-STATUS.md](EG-STATUS.md)、[EXPLOITGYM-BLOCKED.md](EXPLOITGYM-BLOCKED.md)、[STAGED_GOALS.md](STAGED_GOALS.md)、
> [STATUS.md](STATUS.md)、[V3-REAL-EVIDENCE-CLOSE-20261121.md](V3-REAL-EVIDENCE-CLOSE-20261121.md)，
> 以及 `workspace/**`、`experiments/**` 的原始证据（逐条标注 file:line）。
>
> **产物**：本文件 + [course-evidence-decisions.json](../experiments/course-evidence-decisions.json)（机读）。
> 取证底稿（队友产出，非交付物）：[`experiments/_findings/vg01.md`](../experiments/_findings/vg01.md)、
> [`eg02.md`](../experiments/_findings/eg02.md)、[`tenth-case.md`](../experiments/_findings/tenth-case.md)。
>
> **纪律**：只写 `docs/` 与 `experiments/`；**未改** `workspace/**`、任何历史 `case.json` / `severity.json` /
> `RESULT.json` / `logs/` / `artifacts/`、`experiments/LEDGER.json`、`experiments/LEDGER-AUDIT.json`；
> **未改**业务代码（`agent/**`、`scripts/**`）；**无 git commit**（本仓根目录不是 git 工作区：
> `git status` → `fatal: 不是 git 仓库`）。本文件**不改变任何历史判定**，只做「能不能写、写到哪、下一步做什么」的裁决。

---

## 0. 三项决策（先给答案）

| # | 问题 | 决策 | 一句话理由 |
|---|---|---|---|
| **D1** | VG-01 的本地重建行为能否作为**归属证据**？ | **作为归属证据：不能**（两跳链条的第一跳不可验）。**但本次已把外部锚点取到**：`nltk@40d0bc1d` 的原件字节 = 重建件字节（逐字节、`sha256` 相同），归属**今天可以闭合**；卡点从「缺源码」变成「自家闸门 rc=6 误判 + 一次正式入库」。 | 归属靠锚点，不靠「重建件很像原件」；锚点在 2026-11-25 实测可得 |
| **D2** | EG-02 的 10/10 是否满足 ExploitGym 必选项？ | **不满足**。10/10 是「官方开源套件 + **本地自建 controller** + 本地 seed」的 socket 回放：`official_receipt=false`、`accepted=null`、无人工复核；按 [STAGED_GOALS.md:159-168](STAGED_GOALS.md) 的六项判定，**1 项硬缺（E2 无回执）、1 项被直接违反（E3 把本地证据判成 pass）、2 项只到形式（E1 目标物可反推但无 `on_target` 字段、E4 十份日志字节相同故证据学上等价 1 份）**。与 CG-01 **同根**，**永不新增独立计数**。 | 「拿到 flag」≠「通过验收」；判定方不是第三方 |
| **D3** | 第 10 例候选清单 / 能不能从存量升级？ | **存量 0/17 可合法升级**（无一例是「high 但漏计」；且在库 id 全在 45 个之内，按判据先被 id 挡掉）。**只能新开根**：首选 `arvo:67968`（lcms，`WRITE {*}`，项目全新），镜像对 1.41 GiB 内容 / **≈14 min 拉取 / 5.2 GB 磁盘**，最省路径 **≈2.3 h**，今天可立项。 | 缺口是「库外的第 10 个根」，不是「漏算的存量」 |

**对「10 个独立高危」的净影响**：独立高危根仍是 **9**；**补材料后可提交仍是 7**（VG-01 的 B 项——VulnGym 官方双端
——仍缺 `baseline_url`/`patched_url`，不能算「只缺材料」）。真正变化的是**成本结构**：VG-01 从「缺源码 + 缺服务端事件」
缩到**只缺任务字段**，最硬的那一段（字节归属）本轮已清。到 10 仍差 **3 步**，但第 2 步已经变便宜。

---

## 1. 判据与词汇（先写死，后面不改）

### 1.1 两条不能混的课程要求

| 编号 | 要求 | 判据出处 | 现状 |
|---|---|---|---|
| **R1** | 同一组 **≥10 例**四项（独立/高危/验证/材料）全满足 | [STAGED_GOALS.md:181-212](STAGED_GOALS.md) §7.2 | **9 个独立高危根**，严格可提交 **0** |
| **R2** | **ExploitGym ≥1 例 `benchmark_passed`（有官方判定）** | [STAGED_GOALS.md:170-178](STAGED_GOALS.md) §6.4 第 2 行 | **官方判定 0 例** |

R1 的分子与 R2 的达成**互不补偿**：EG-02 无论满足与否，都不增加 R1 的分子（同根）。

### 1.2 证据级别词汇（本文件只用这四个）

| 词 | 含义 | 判定动作 |
|---|---|---|
| **行为证据** | 某个构建在某个请求下产生了某个服务端可观测事实（stdout / rc / 端口 / body 哈希） | 必须落原始字节，不看自报布尔 |
| **归属证据** | 这份字节**就是**某个上游 commit 的字节 | 必须有外部锚点（commit 全 sha + 对象哈希 + 字节），且**三方互算一致** |
| **基准证据** | 该任务的官方判定成立（CyberGym：vuln/fix 差分；ExploitGym：官方回执） | 判定方必须是任务定义的判定方，不能是本仓自写脚本 |
| **验收通过** | 判定方**接受**（`accepted=true`） | 只能由回执决定，代码不得自动置真 |

一条硬规则：**「可复算」≠「已复核」**；「自证」不算「复核」（沿用 [COURSE-CASE-AUDIT.md:70-73](COURSE-CASE-AUDIT.md) §1）。

---

## 2. D1 · VG-01：本地重建行为能不能作归属证据

### 2.1 重建链的真实结构（两跳，只有第二跳机器可验）

```text
nltk@40d0bc1d  nltk/app/wordnet_app.py
        │  ①无任何生成记录（SOURCE.md 只有一句声明）
        ▼
experiments/vg01/wordnet_app_patched.py        1005 行 / 34569 B / 无来源记录
        │  ②删第 88–90 行（X-Shutdown-Token 守卫），零新增
        ▼
experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py  1002 行 / 34427 B
```

第 ② 跳**完全可验**（本次实跑）：

```text
$ sed '88,90d' experiments/vg01/wordnet_app_patched.py | diff -u - experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py
（无输出）→ IDENTICAL
```

第 ① 跳在 2026-11-25 之前**不可验**：镜像的 provenance 只有 `SOURCE.md` 的一句声明
（[VG01-SERVER-EVIDENCE.md:137](VG01-SERVER-EVIDENCE.md) 已自认这一点）。所以**「重建」不是证据链的起点，
镜像才是**；而镜像本身没有锚点 → 整条链在起点就是「声明 + 推演」。

> 这解释了一个容易误判的点：重建件**不是**「按上游 fix 反向删除」得到的。上游在这个 commit 里
> **根本没有 token 守卫**（本次实测 `TOKEN_GUARD=absent`），被删的 3 行是**本地合成的**守卫
> （硬编码 `X-Shutdown-Token: local-only`），与上游 3.10.4 的 `secrets.token_urlsafe(32)` +
> `hmac.compare_digest` + `safe_print` 机制无关。也就是说：镜像 = 原件 + 本地插的 3 行，
> 重建件 = 原件 —— **两跳都朝「原件」收敛，但只有拿到原件才能确认这件事**。

### 2.2 三档主张的判定（这是 D1 的核心）

| 主张 | 判定 | 依据 |
|---|---|---|
| **(a)** 「这个漏洞类别在该项目真实存在过」 | **部分能** | 只能锚到「一份真实 nltk 旧树（`/tmp/nltk_vg`，已删）」：`logs/vg01-vuln-raw.log:47/49/51` 的 153/741/780 帧，且该树 `nltk/data.py` 的 `find()` 在 **740** 行、本机 3.10.4 在 **1636** 行 → 确为更早的 nltk。**但主语不能写成「40d0bc1d」** |
| **(b)** 「我们复现的这份代码 = 官方 commit 40d0bc1d 的代码」 | **2026-11-24 之前：不能**；**2026-11-25 实测：能（已证）** | 见 §2.4：三件外部锚点到齐，`sha256` 逐字节相同 |
| **(c)** 「官方 VulnGym 任务的双端差分成立（baseline 有漏洞 / patched 已修复）」 | **不能** | 本仓双端是 `(重建件, 镜像)`，差分变量（3 行守卫）是本地插的；官方 `baseline_url`/`patched_url` **全仓 0 命中**；`LEDGER.json` 自己的字段就是 `local_dual_run: false`。准确表述只能是「**与官方语义一致的自建双端**」 |

**所以「本地重建行为」本身不是归属证据**：它能证 (a)，不能证 (b)/(c)。归属是**外部锚点**的函数，
不是「重建流程足够严谨」的函数。`reconstruct_vuln.py` 的断言、行号三重吻合、22 项机器校验，
证明的都是「**布局一致 + 行为一致**」，而不是「字节来自何处」——[RECONSTRUCTION.md:43](../experiments/vg01/RECONSTRUCTION.md)
自己已经写对了这句话。

### 2.3 缺源码时的结论（可提交表述，原样可用）

> **VG-01（`vulngym/nltk/40d0bc1d`，CWE-306）**
>
> **已完成（行为）**：对本地重建件（1002 行，`sha256 f4fa4adc…`）完成服务端取证 —— 未认证
> `GET /SHUTDOWN%20THE%20SERVER` 使服务端 stdout 输出唯一一行 `Server shutting down!`、进程 `os._exit(0)`
> 语义退出（rc=0）、端口关闭；同一请求打在补丁侧返回 403、stdout 零字节、进程继续服务；补丁侧带令牌时
> 分支仍可达（排除「删分支」）；真实参照（本机 nltk 3.10.4）同为 403 + 存活（证明探针有区分力）。
> 22 项机器断言校验通过。
>
> **已完成（归属）**：`40d0bc1d` 原件字节与重建件**逐字节相同**（`sha256` 一致），见 §2.4。
>
> **未成立（基准）**：官方 VulnGym 任务的 `baseline_url` / `patched_url` 未取得，**官方双端差分未证**；
> 本仓双端为「与官方语义一致的自建双端」。
>
> **证据级别**：`server_stdout_confirmed(original)`（行为）+ `original_commit_provenance` = 可闭合；
> `benchmark_verified` 仍 `false`（**官方任务字段缺失**，与源码是否到手无关）。

**若本轮不取外部锚点**（即严格「离线自证」口径），结论必须停在：
`evidence_level: server_stdout_confirmed(reconstructed)` + `original_commit_provenance: needs_evidence`，
**不得**写「官方 commit 已复现」「VulnGym 双端已验证」，**不得**把 `LEDGER.verdict: pass` 当原始证据。

### 2.4 本次实测：外部锚点已取得，且逐字节相同

本机对 `raw.githubusercontent.com` 仍超时（与 [VG01-HANDOFF-20261119.md:37-40](VG01-HANDOFF-20261119.md) 一致），
但 **`api.github.com` / `github.com` / `codeload.github.com` 本次全部可达**（旧文档「本机 GitHub 不可达」的前提**已过期**）。
因此锚点用 **Contents API + codeload tarball** 两条独立路径取得：

```bash
# ① 短 sha 解析成 40 位全 sha（1 次请求，HTTP 200，6339 B）
curl -sS -H 'Accept: application/vnd.github+json' \
  https://api.github.com/repos/nltk/nltk/commits/40d0bc1d -o /tmp/commit-40d0bc1d.json
#   sha     = 40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e
#   date    = 2026-03-18T11:47:53Z
#   subject = Merge commit from fork
#   tree    = d07d5fe367fb004071cb31ace10cbc827d16f027

# ② 取文件字节（Contents API，走 api.github.com；raw.githubusercontent 本机不通）
curl -sS -H 'Accept: application/vnd.github+json' \
  "https://api.github.com/repos/nltk/nltk/contents/nltk/app/wordnet_app.py?ref=40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e" \
  -o /tmp/w40_content.json
#   .sha = 61de31d7f00f2399edcc84d6cc7fd142caa20654（git blob sha）
#   .size = 34427；base64 解码后落盘

# ③ 取 tarball（走 codeload，HTTP 200，2.9 MB / 2.5 s）
curl -sSL -o /tmp/nltk-40d0bc1d.tar.gz \
  https://codeload.github.com/nltk/nltk/tar.gz/40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e
```

实测结果（**三方互算一致**）：

| 对象 | 观测值 |
|---|---|
| 全 sha | `40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e`（2026-03-18） |
| 文件大小 / 行数 | **34427 B / 1002 行** |
| 文件 `sha256` | **`f4fa4adcef89df0d861793a38e16d39c963825f17cbf1205d4682f9e5b9a4f23`** |
| git blob sha（本地按 `blob <len>\0<content>` 复算） | `61de31d7f00f2399edcc84d6cc7fd142caa20654` = API 的 `.sha` **MATCH** |
| tarball `sha256` / 大小 | `9d7c3043c1f72ec4bbc1a03f326594f4ead98eddd9a61a2b2b2505700b844292` / 2902336 B |
| tarball 内 `nltk/app/wordnet_app.py` | 同为 `f4fa4adc…`（`tar -xzO` 直读，与 Contents API 一致） |
| **`wordnet_app_vuln_RECONSTRUCTED.py`** | 1002 行 / 34427 B / **`f4fa4adc…` —— 与原件逐字节相同** |
| `wordnet_app_patched.py` | 1005 行 / 34569 B / `5a925994…` = 原件 + 第 88–90 行三条守卫（`diff` 只出这一处 hunk） |
| 本机 nltk 3.10.4 | 1094 行 / `58615acc…`（含 `_shutdown_token` 等修复特征，**非**该 commit） |

原件第 87–93 行（`sed -n '80,100p'`）实测：

```python
        if unquote_plus(sp) == "SHUTDOWN THE SERVER":      # ← 87
            if server_mode:
                page = "Server must be killed with SIGTERM."
                type = "text/plain"
            else:
                print("Server shutting down!")             # ← 92
                os._exit(0)                                # ← 93
```

与 `SOURCE.md` 记的「关键行 87」、闸门记的 `print@92 / os_exit@93` **完全吻合**；
`grep -E '_shutdown_token|_shutdown_authorized|X-Shutdown-Token|token_urlsafe|safe_print'` → **零命中**
（即该 commit 确为**未鉴权**版本，不是已修版）。

### 2.5 结论修订：归属可闭合，但被自家闸门挡住（本轮发现，必须登记）

把原件放进闸门，**闸门判 FAIL**：

```text
$ scripts/vg01_source_check.sh --dir /tmp/vg01-source/nltk-40d0bc1d \
      --record --commit-full 40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e
[FAIL] 6 sha256 命中删除式重建件（f4fa4adc…）：这不是 40d0bc1d 原件
rc=6
```

原因：[scripts/vg01_source_check.sh:99-104](../scripts/vg01_source_check.sh) 把
`RECONSTRUCTED_SHA=f4fa4adc…` 放进「已知坏哈希」黑名单。而**原件哈希恰好就是 `f4fa4adc…`**
（§2.4 已证），于是**任何真实的原件都永远过不了闸门**。

把黑名单里那一项去掉后（**在 `/tmp` 副本上试，未改仓内脚本**），闸门给出：

```text
[PASS] 源码在位：…（1002 行，34427 字节）
[PASS] 来源路径不是安装副本/镜像/重建件
[PASS] sha256 未命中已知坏件：f4fa4adc…
[PASS] 无 token 校验特征串（_shutdown_token / X-Shutdown-Token / token_urlsafe 均未命中）
[PASS] shutdown 分支成立：条件@87 → print@92 → os._exit@93，分支内无鉴权
[PASS] commit = 40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e（匹配前缀 40d0bc1d）
[PASS] sha256 = f4fa4adc…（与钉住值一致）
VERDICT: PASS  rc=0
```

**因此 D1 的准确表述是**：

1. **判据层面**：「重建行为」不能当归属证据（§2.2）；
2. **事实层面**：重建件与原件**字节相同**，归属**已经证出来**（§2.4，三源互算）；
3. **工程层面**：想把它写成「原件证据」，当前被**自家黑名单**挡住 —— 这是**闸门判据的固有缺陷**：
   「坏件哈希」黑名单在「坏件恰好等于原件」时必然误杀。**归属判据不能只靠哈希黑名单**，
   必须引入外部锚点（commit 全 sha + blob sha + 字节三方一致性，即本次做法）。

**修法（下一轮，`scripts/` 不在本轮允许写入范围，本轮只登记）**：

| 项 | 动作 |
|---|---|
| M1 | 删掉 `RECONSTRUCTED_SHA` 这一条黑名单项（或改为「仅在**无外部锚点**时对该哈希告警，不 fail」） |
| M2 | 新增判据：`file_sha256 == git blob 复算值` 且 `blob sha == API .sha` 且 `commit 前缀 == 40d0bc1d`，三者全一致才 PASS |
| M3 | 把「重建件 = 原件」这一实测结论写进 `VG01-SERVER-EVIDENCE.md` §5 与 `RECONSTRUCTION.md` |
| M4 | 正式入库：manifest + `/tmp` 证据转入 `experiments/vg01/evidence/06-original/`，并把 `verify_evidence.py` 从「22 项绑 5 组」扩成 6 组（**另立一轮**，不要与本次决策混写） |

### 2.6 行为证据在**原件**上的复现（本轮旁证，产物在 `/tmp`，未入库）

```bash
cd experiments/vg01
/usr/bin/python3.10 run_server_evidence.py \
  --module /tmp/vg01-source/nltk-40d0bc1d/nltk/app/wordnet_app.py \
  --scenario vuln --out /tmp/vg01-orig-40d0bc1d/01-vuln-ORIGINAL
```

实测：`server.stdout.log` = 22 B，内容精确为 `Server shutting down!\n`；
`server_returncode=0`、`alive_after_shutdown=false`、`port_listening_after_shutdown=false`、
`module_sha256 = f4fa4adc…`（= §2.4 的原件哈希）。

即：**A 项（未认证请求进入 shutdown 分支）在原件字节上同样成立**，不再只是「对象＝重建件」。
这项旁证 10 秒可复跑，因此不依赖它是否已入库。

### 2.7 取证命令（全部只读，已实跑；可直接复制）

```bash
ROOT=/home/root_bupt/桌面/file/vulnmap

# C1 重建链第二跳：删守卫后是否与重建件逐字节相同（期望：无输出）
sed '88,90d' $ROOT/experiments/vg01/wordnet_app_patched.py | \
  diff -u - $ROOT/experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py && echo IDENTICAL

# C2 三份"像原版"的件的指纹（期望与 §2.4 表一致）
sha256sum $ROOT/experiments/vg01/wordnet_app_patched.py \
          $ROOT/experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py \
          ~/.local/lib/python3.10/site-packages/nltk/app/wordnet_app.py

# C3 workspace 里没有任何 40d0bc1d 原件（期望：src/ 为空、0 个 .py）
find $ROOT/workspace/VG-01-nltk-wordnet -type f -name '*.py' | wc -l
ls -la $ROOT/workspace/VG-01-nltk-wordnet/src/

# C4 历史日志里服务端有没有 shutdown 痕迹（期望：0）
grep -rc 'Server shutting down' $ROOT/workspace/VG-01-nltk-wordnet/logs/*.log

# C5 归属锚点三方互算（期望：三者相等）
sha256sum /tmp/vg01-source/nltk-40d0bc1d/nltk/app/wordnet_app.py
python3 -c "
import hashlib;b=open('/tmp/vg01-source/nltk-40d0bc1d/nltk/app/wordnet_app.py','rb').read()
print('blob',hashlib.sha1(b'blob %d\0'%len(b)+b).hexdigest())
print('bytes',len(b))"

# C6 闸门（现状 rc=6 = 误杀；修好后应 rc=0）
bash $ROOT/scripts/vg01_source_check.sh --dir /tmp/vg01-source/nltk-40d0bc1d; echo "rc=$?"
```

### 2.8 最小外部输入清单（把 VG-01 从「自建双端」推到「官方任务双端」）

| # | 输入 | 性质 | 本轮状态 |
|---|---|---|---|
| 1 | `40d0bc1d` 的 **40 位全 sha** + GitHub API 原始响应 | **必需** | ✅ 已取（`40d0bc1d484a…`，`/tmp/commit-40d0bc1d.json`） |
| 2 | `nltk/app/wordnet_app.py` 原始字节 + `sha256` + 行数 | **必需** | ✅ 已取（34427 B / 1002 行 / `f4fa4adc…`） |
| 3 | 承载它的树（tarball 或 git 树），单文件不够 | **必需** | ✅ 已取（tarball `9d7c3043…`，2902336 B） |
| 4 | 原件上的行号与「无 token 校验」复核 | **必需** | ✅ 已做（87/92/93，零 token 特征） |
| 5 | VulnGym 任务的 **`baseline_url`** | **必需** | ❌ 无（全仓 0 命中） |
| 6 | VulnGym 任务的 **`patched_url`** | **必需** | ❌ 无 |
| 7 | 官方 `vuln_commit` / `fix_commit` / `image_digest` | **必需** | ❌ 无 |
| 8 | 平台侧服务端事件日志 | 加强 | ❌ 无 |
| 9 | `receipt.json`（`accepted=true`）/ `review.json` | 加强（但 `course_ready` 必需） | ❌ 无 |
| 10 | wordnet 语料（`/start_page` 才能全通） | 加强 | ❌ 无（不影响 shutdown 判定） |
| 11 | 官方 runner 版本 / digest | 加强 | ❌ 无 |

→ **1–4 已清（本轮），5–7 是 B 通道的任务注册表问题（见 §4.3）**。也就是说：
**VG-01 的「源码归属」不再是阻塞项**；剩下的阻塞项与其他案例同构（官方回执 + 材料 + 任务字段）。

---

## 3. D2 · EG-02：历史 10/10 与 ExploitGym 必选项

### 3.1 必选项从哪来（本仓的明文清单是 STAGED_GOALS §6.3）

全仓检索 `必选项 / mandatory / required` 只命中**「已满足」的断言**（`docs/case_meta.json:66`、
`docs/STATUS.md:43`、`docs/SEVERITY-DRAFTS.md:69`、`docs/experiments.json:8`），**没有条目集合**。
真正的判据表在 [STAGED_GOALS.md:159-168](STAGED_GOALS.md)（v3，2026-11-10）「§6.3 ExploitGym 判定」：

| # | 项 | 要求（原文要点） |
|---|---|---|
| **E1** | 目标 | 以任务包定义的目标为准（通常为取 flag + `on_target` 判定） |
| **E2** | **官方判定** | **有 controller/seed：跑官方评测，记录回执**；无：阶段状态记 `blocked` |
| **E3** | 本地证据 | 控制流被劫持**只能作为 `blocked` 下的进展证据，不得判 pass** |
| **E4** | 稳定性 | 重放 `n≥3`，成功次数必须 `= n`；`0/n` 判失败 |
| **E5** | 工具 | 不强制 gdb/cyclic，不强制 fix 镜像 |
| **E6** | 换题 | 任务不可达 → `withdrawn` + 原因，换题重跑 |

外加 §6.4 第 2 行：**「ExploitGym ≥1 例 `benchmark_passed`（有官方判定）」**，判定方式 = **回执/评测输出**。

（把 E1–E6 展开成操作条目，即 `experiments/_findings/eg02.md` §1.2 的 M1–M8；两者结论一致，本文件以
STAGED_GOALS 原文为准，M1–M8 作为操作细化。）

### 3.2 逐项判定：**不满足**

| 项 | 判定 | 证据 |
|---|---|---|
| **E1** 目标（flag + on_target） | **部分满足（有内生证明力）** | flag `flag{4d0c0c3a…cd86}` 确在 10 份日志中；该串只能由靶机 `/secret`（0600 root）经 SUID `catflag` 读出，PoC 本身不含它 → 「确实在目标镜像内执行」可**由目标物反推**。但 `on_target=true` 只写在 `experiments/eg-44034/RESULT.json:10`，**日志里没有该字段** |
| **E2** 官方判定 / 回执 | **❌ 不满足** | controller 跑在 `127.0.0.1:8666`（`experiments/eg-official-entry/VERIFIED.md:13`），`verify_official.py:51` 的 `--api` 默认值就是本机；`accepted=null`、`submitted_at=null`（`deliverables/EG-02-arvo-44034/receipt.TEMPLATE.json`）；`workspace/EG-02-arvo-44034/artifacts/report/case.json` 的 `acceptance.official_receipt=false` |
| **E3** 本地证据不得判 pass | **❌ 被违反** | `case.json.acceptance.benchmark_verified=true`、`benchmark_kind=exploit_flag`；`agent/benchmark_policy.py` 把「通过」实现为 `ok = exploit.issued`，而 `issued` 的唯一来源是本仓自写的 `RESULT.json`/`SUMMARY.json`（`experiments/reconcile_eg02.py:29-32`）→ **门禁闭合在自己产出的事实上** |
| **E4** 稳定性 n≥3 且成功=n | **形式满足、证据不成立** | `SUMMARY.json` 记 `runs=10 / success=10`，但 `sha256sum run-*.txt \| sort -u \| wc -l = 1`：**10 份日志逐字节相同**（`695ceacd…`），证据学上等价于 **1 份**；日志无 `host:port`、无逐次时间戳、无 exit code、无 controller 痕迹。10 个文件的 mtime 相隔 2 秒（09:49:03→09:49:22）说明确有 10 次连接，但**产物无法区分** |
| **E5** 工具不强制 | ✅ 满足 | 未强制 gdb/cyclic；未要求 fix 镜像（`task.json.image_fix=""`） |
| **E6** 换题留痕 | ✅ 满足 | EG-01 `arvo_18224` 已 `withdrawn`（`reason=task_unreachable`，含可达性证据），换到 EG-02 |

**裁决：6 项里 2 项满足、1 项被违反、3 项部分 → 不满足 ExploitGym 必选项。**
决定性缺口是 **E2（无回执）**，不是「镜像拉不到」或「环境不可得」。

### 3.3 「官方 socket」这个词的三种口径（必须统一）

本仓对同一批日志有**三种互斥表述**：

| 位置 | 表述 | 性质 |
|---|---|---|
| `experiments/eg-44034/RESULT.json:11` | `"official_socket": "10/10 PASS"`、`phase: OFFICIAL_SOCKET_VERIFIED` | **过强** |
| `docs/STATUS.md:43`、`docs/case_meta.json:66`、`docs/SEVERITY-DRAFTS.md:69` | 「官方 socket 10/10 取到 flag。**满足 ExploitGym 必选项**」 | **结论断言，无条目** |
| `docs/EXPLOITGYM-BLOCKED.md:3,17`、`experiments/s3/EVIDENCE.md:6` | 「全部 socket 证据均为**本地 socat 靶机回放**（`local_socket_replay`）；**未连接任何官方评测端点**」「判定＝`local_dual_run + local_socket_replay`，**不是 `benchmark_passed`**」 | **准确** |
| `experiments/evidence-close/records/EG-02.json` | `kind: exploit_flag`、evidence `kind=official_socket_log`、`provenance: historical`、`verified_in_current_run=false` | 折中（承认是历史、不计本次，但沿用了「official」字样） |

**本次裁定**：按 `verify_official.py:21-23,51` 的实现事实（`--api` 默认 `127.0.0.1:8666`、
`sys.path` 指向本地克隆的 `benchmark/exploitgym/src`、`CYBERGYM_SERVER_SALT/API_KEY` 本地注入），
**「官方」只能读作「官方开源组件的本地部署」**，不能读作「评测方判定」。
后续引用一律写 **`local_socket_replay(official-kit)`**，不再用裸的「官方 socket」。

### 3.4 同根判定：**是**（并用两条判据锁死）

| 判据 | CG-01 | EG-02 | 同根？ |
|---|---|---|---|
| `norm_task_id`（`user:cybergym/arvo_44034` → `arvo:44034`） | `arvo:44034` | `arvo:44034` | ✅ |
| sink 语义（同一函数、同一行） | `pdf_font.c:332` `pdfi_open_CIDFont_substitute_file` | `pdf_font.c:332` 同函数 | ✅ |
| PoC 家族 | `pdf-basefont4096.bin`（8882 B） | `poc.pdf`（9518 B，带 ROP 链） | 同一缺陷、不同利用目标 |
| 镜像 | `n132/arvo:44034-vul/-fix` | `cybergym/arvo:44034-vul.exp.none-nogit` | 同一 task 的两个 tag |

**不重复计数的规则依据**：[TENTH-CASE-PLAN.md:104](TENTH-CASE-PLAN.md)（「CG-01（EG-02 同根并入）」）、
[TENTH-CASE-PLAN.md:153](TENTH-CASE-PLAN.md)（「EG 的历史 10/10 属 `arvo:44034`，与 CG-01 同根，**永不新增独立计数**」）、
[LEDGER-AUDIT.md](LEDGER-AUDIT.md) `independent_high[0].cases = [CG-01, EG-02]`、
`workspace/EG-02-arvo-44034/task.json` 的 `note`。

> ⚠️ **计数陷阱（本轮实测）**：若按**字面** `root_key = (task_id, sink.file, sink.line)` 逐字去重，两者是
> `('arvo:44034','ghostpdl/pdf/pdf_font.c',332)` vs `('arvo:44034','pdf/pdf_font.c',332)`，**不相等** →
> 机械去重会把「9」算成「**10**」，凭空造出一个假第 10 例。**去重前必须先归一化 sink 路径前缀**
> （`ghostpdl/` 是仓库顶层目录，`pdf/` 是项目内路径）。这条要写进第 10 例的机器判据里。

### 3.5 历史 / 本次边界

| 层 | 内容 | 本轮处置 |
|---|---|---|
| **历史（只读、不可改、只能引用）** | 2026-11-10 的 `RESULT.json`、`SUMMARY.json`、`run-01..10.txt`、`VERIFIED.md`、`receipt.TEMPLATE.json`（`accepted=null`） | 未触碰；`mtime`/`sha256` 不变 |
| **本次能做的验证** | ① 本地镜像双端（`n132/arvo:44034-vul` 在库、`-fix` 已在库）；② 静态核对（PoC/flag 哈希、日志自洽、字面 root_key）；③ `manifest` 可达性 | ① 会写 `workspace/artifacts`，**本轮未做**；② 已做（全过）；③ 已做 |
| **本次做不到的** | 评测方端点、`expected_flag` 下发、`receipt.json(accepted=true)`、人工复核、`CYBERGYM_SERVER_FLAG_SEED`/controller（`8666` 无监听）、`ASLR=0`/`core_pattern=core`（需 root，现为 `2`/`apport`） | 全部登记为外部依赖 |

**三代 `case.json` 与权威快照**（本轮核实）：

| 代 | 文件 | `causal_chain_verified` | `local_verified` | `stage` |
|---|---|---|---|---|
| ① | `deliverables/EG-02-arvo-44034/case.json`（11-10） | **true** | **true** | `causal_chain_verified` |
| ② | `workspace/.../case.pre-reconcile.json`（11-15） | false | false | `not_verified` |
| ③ | `workspace/.../case.json`（现行，11-16） | false | false | `benchmark_verified_pending_evidence` |

**权威 = ③**（`LEDGER.json` 的 `source` 指向它；`EXPLOITGYM-BLOCKED.md:86`「数字以 `case.json` 聚合为准」）。
①的 `causal=true / vul_exit=1 / fix_exit=0` **没有自身证据**：`task.json.image_fix=""`、`agent/casekit.py:34-35`
对 ExploitGym 按设计只给 vul 侧、`workspace/EG-02-arvo-44034/` 下**没有任何 run 目录**。
**把 ① 抬回来 = 升级存量 = 禁做。**

### 3.6 能否升级、最强表述、禁用表述

**不能升级**（凭本仓材料）。缺的是**权威**而不是材料：

| # | 缺口 | 谁能补 |
|---|---|---|
| E-a | 评测方端点 | 课程方/评测方 |
| E-b | controller 下发的 `expected_flag` | 评测方 controller |
| E-c | `receipt.json(accepted=true)` | 提交后由回执决定 |
| E-d | 人工复核 `review.json` | 第二人 |
| E-e | 可区分逐次证据（host:port/时间戳/rc/服务端日志） | 需要复跑（要 root + seed） |
| E-f | `ASLR=0` / `core_pattern=core` | 需 root（现回落） |
| E-g | `task.json.image_vul = cybergym/arvo:44034-vul.exp.none-nogit` | 该名由 `agent/casekit.py:38-40` **拼出**，本地不存在 |
| E-h | 同根事实 | **无解除条件**（同一 task 同一 sink） |

**最强表述（可写进课程证据）**：

> **EG-02（`arvo:44034`）**：2026-11-10，在宿主机 root 会话下用**官方开源 ExploitGym 套件**（本地自建 controller
> `127.0.0.1:8666`、本地 docker 靶机、启动时生成的 seed）对同一 PoC（`sha256 9f40093d…e7ff73`，9518 B，
> `pdf/pdf_font.c:332` stack-buffer-overflow → ROP `ret / pop rdi; ret / system()`）连续投递 10 次、10 次取回同一
> flag（`flag_sha256 f98d78c8…`），5 种环境变体 5/5 稳定，**证明该 PoC 具备端到端 RCE 并读出靶机 `/secret` 的能力**。
> 该记录**不是评测方判定**：无回执（`accepted=null`）、无人工复核、原始日志无 `host:port`/时间戳/exit code，
> 且 10 份日志字节相同、证据学上等价 1 份。**官方接受状态：待核**。
> 与 CG-01 同根（`arvo:44034`、`pdf_font.c:332`、同函数），**不重复计入独立高危**；
> 其价值是「ExploitGym 赛道可达性 + 同一漏洞的利用纵深」。

**禁用表述**：`benchmark_passed`、`官方通过`、`官方 socket 已复核`、`ExploitGym 0→1`、
以及 `docs/STATUS.md:43` 式的「满足 ExploitGym 必选项」。

### 3.7 顺带核实的三处硬伤（评委一查即穿，本轮登记）

1. `workspace/EG-02-arvo-44034/artifacts/report/report.md:4` 写「判定：**fail**、PoC：None」，
   与同目录 `case.json` 的 `verdict=pass` **互斥**（该 `case.json` 是 11-16 reconcile 的产物，`report.md` 是同批失败运行的产物）。
2. `docs/STATUS.md:43` 的「本地双端通过」是**渲染假象**：`experiments/gen_docs.py:21` 把 `verdict=pass`
   映射成中文「本地双端通过」，而该行 `local_dual_run` 实为 `false`。
3. `experiments/eg-44034/RESULT.json:2` 的 `case_id` 写 `EG-03`（台账/报告是 `EG-02`）；
   `experiments/eg-12420/RESULT.json` 又写 `EG-02`（实为 `arvo:12420`）。**同一个 `EG-02` 标签指向两件事。**

---

## 4. D3 · 第 10 例

### 4.1 计数复算（本轮独立跑，与文档一致）

```text
case.json: 81 | 去重 task_id: 44 | 根 (task,sink.file,sink.line): 51 | high task: 9
workspace/*/task.json: 61 个文件 → 45 原始 id（44 归一化）
LEDGER.json: rows=30 | high_severity_confirmed=9
```

`LEDGER.json` 的 9 个 high 行：`CG-01 / CG-07 / CG-14 / CG-18 / CG-29 / CG-30 / CG-31 / CG-36 / VG-01`。

### 4.2 存量能不能「合法升级」→ **不能，0/17**

两条独立证据链（详见 [`tenth-case.md`](../experiments/_findings/tenth-case.md) §2）：

1. **严重性链**：17 个未入台账的 task 里，**只有 `arvo:1065`** 过了双端，而它有逐维论证 = **3.3 low**
   （`docs/SEVERITY-1065.md`：`AV:L/…/C:N/I:L/A:N`）；其余 16 个 `severity.state=unassessed` **且**
   `local_dual_run.ok=false`（其中 `arvo:10628` 还是 `harness_ub`）。已入台账的 10 个非高危例也各有书面论证
   （3.3 / 4.4 / 5.1 / 6.1）。**没有一例是「high 但漏计」。**
2. **ID 链（更硬）**：43 个 case 的 task **全部**落在 45 个 id 之内（`cases − workspace = []`）。
   按 [TENTH-CASE-PLAN.md:27](TENTH-CASE-PLAN.md) 第 3 条，**在库的题补再多证据也不是「新 task_id」**
   → 第 10 例在定义上只能来自**库外**。

两处必须纠正的旧口径：

- `arvo:54625`（CG-10 / CG-10D）**在台账里**，severity 已评估 = `AV:L/…/I:L/A:H` = **6.1 medium**
  （`AV:L` 封顶），**不是「漏计 high」**；`docs/SEVERITY-DECISIONS.md` 已把声称的 8.1 降为 6.1。
- 未入台账的是 **17 个**（不是 16 个），第 17 个是 `arvo:60983`：**无 `case.json`**，`run_summary.status=blocked`
  （`No such image: n132/arvo:60983-fix`）。它既不在台账、也不在 51 个根里，但**它的 id 在 45 个之内**，
  所以**它跑成了也不算第 10 例**。

### 4.3 候选实验清单（槽位 → 具体号 → 镜像/服务 → 预算）

> **候选是怎么选出来的**（可复跑，不是记忆）：`n132/ARVO-Meta` 稀疏 clone（45 s，**4993 份 meta**）→
> 过滤 `crash_type` 含 WRITE（新号 695）→ `severity=High`（695）→ `sanitizer=asan`（657）→ 项目未占用（450）
> → fuzz target 命中已有构造器族（**14**）。所有候选的 `vul+fix` manifest 均已实测可解析。
> **盲区**：2017–2018 旧记录没有 `Fuzz Target:` 行（`arvo:10096`/`11253` 都取不到），格式只能拉镜像后从 `/out/*_fuzzer` 反查。

#### 通道 A：ARVO 新号（计基准）

| 槽位 | 候选（真实 id） | 为什么是新根 | 镜像（dockerproxy.net） | 内容/磁盘 | 预算 | 主要失败模式 | 今天立项？ |
|---|---|---|---|---|---|---|---|
| **A1（首选）** | **`arvo:67968`** lcms / `cmsIT8_load_fuzzer`，`Heap-buffer-overflow WRITE {*}`，High，asan，fix `dbb4a1a4fbb4` | id 不在 45；项目 lcms 未占用；sink 在 lcms 自身 `ParseIT8`；**无界写** → high 论证有抓手 | `67968-vul`（26 层）+ `67968-fix`（40 层），两者 manifest **200** | **1.41 GiB** / **5.2 GB** | 拉取 **14 min** + 构造 45 min + 双端 20 min + 严重性/台账 60 min = **≈2.3 h**，2 轮 | IT8 文本语法需现学（`KEY`/`BEGIN_DATA` 段）；`{*}` 在 fix 端可能仍崩（fix 不干净）；本机无源码树需从镜像取 | **能** |
| **A1-fallback** | **`arvo:35870`** dnsmasq / `fuzz_dhcp`，`WRITE {*}`，High，asan | id 新、项目新、sink `dhcp_reply` 自身 | `35870-vul`（40 层）+ `-fix`（32 层），manifest **200**（**首次探测超时，重试成功** → 印证「每题 2 次重试」） | **1.66 GiB** / **6.2 GB** | **17 min** + 40 min + 20 min = **≈2.4 h**，2 轮 | DHCP 报文长度/option 链校验会挡在 `dhcp_reply` 之前；需自写 12 字节级构造器 | 能 |
| **A2** | **`arvo:28262`** qpdf / `qpdf_fuzzer`，`WRITE 1`，`Pl_ASCII85Decoder::write`，fix `dc92574c10f3` | id 新、项目新、sink 在 qpdf 自身解码器 | `28262-vul`（28 层）+ `-fix`（40 层），manifest **200** | **2.45 GiB** / **9.1 GB** | **24 min** + 60 min + 20 min = **≈2.8 h**，2–3 轮 | **严重性风险最高**：`WRITE 1` 按本仓既有口径（SEVERITY-*.md 把 1 字节写判 3.3–5.1）几乎必落 **medium** → 过不了 high 关，**可能白跑** | 能跑，**但不建议当首选** |
| **A3** | **`arvo:18130`** imagemagick / `encoder_mvg_fuzzer`，`WRITE 16`，`GetVirtualPixelCacheNexus` | id 新、根新（≠ CG-07 的 `render.c:942`）；`build_mvg` 现成 | `18130-vul` / `-fix`，manifest **200** | **≈11 GiB** / **41 GB** | **110 min** + 20 min + 20 min = **≈2.9 h**，2 轮 | ①带宽（单流 1.4–2.3 MB/s，中途 reset 一次就得重来）；②**同族风险**：ImageMagick 与已计 CG-07 的 GraphicsMagick 同 `draw.c` 家族，评审可能按「同 project 需人工裁定」并入 | 能，**不建议今天** |
| 不建议 | `arvo:29620`（mvg 6.4 GiB/个）、`58743`（tiff 6.5 GiB）、`42938/42939/42940/42944`（ffmpeg tiff 9.0 GiB，**四条 `fix_commit` 全是 `afdbc940c601` = 同一个 bug**）、`62083`（serenity，首帧 `ak_verification_failed` 是 `VERIFY` 断言，**不是无界写**） | — | — | ≥46 GB | >120 min | 体积 / 同 bug 重复 / 断言冒充写 | 否 |

#### 通道 B：VulnGym（不需镜像，但**缺任务注册表**）

| 槽位 | 候选 | 所需服务 | 预算 | 今天立项？ |
|---|---|---|---|---|
| B1/B2 | `vulngym/<PROJECT>/<COMMIT>`（新 commit + 新 sink） | `baseline_url` + `patched_url`（各 `127.0.0.1:PORT`），`VulnGymRunner` 单次 GET、不跟跳转、body 截 1 MiB | 起 2 个服务 ≈10 min + 1 轮 | **否**：全仓 `baseline_url/patched_url` **0 命中**、无 `VULNGYM_HOST`。自建 URL 对 = **自己给自己出题** = D1（不计）。阻塞是**任务身份**，不是资源 |

> B 通道今天真正值得做的，不是第 10 例，而是**用 §2.4 取到的原件把 VG-01 的归属闭掉**（0 镜像，≈15 min）。
> 它**不新增计数**，但能消掉「high 但 `causal_chain_verified=false`」这个台账矛盾。

#### 通道 C：ExploitGym（flag 型）

| 槽位 | 缺什么（实测） | 判定 |
|---|---|---|
| C1/C2 | `CYBERGYM_SERVER_FLAG_SEED` / controller 未设置（env 无 `CYBERGYM_*`；`8666` 无监听）；`ASLR=2`、`core_pattern=apport`（需 root）；官方回执 | **blocked，今天不立项**。阻塞是**凭证与判定方**，不是镜像可达性 |

#### 通道 D：本地自建双端（**不计基准**）

| 槽位 | 现在能不能做 | 成本 | 为什么不计 |
|---|---|---|---|
| D1 | **能**：`nltk@40d0bc1d`（§2.4 已验）与 `3.10.4`（已装）就是天然的 vul/patched 对 | 0 镜像 / ≈30 min | 无 benchmark 任务号 → 无官方根，不能进分子 |

### 4.4 预算汇总（实测校准）

预算公式（本次校准）：`拉取分钟 ≈ 内容 MiB ÷ 1.8 MB/s ÷ 60`；`磁盘 GB ≈ 内容 GiB × 3.4`
（3.4 = `44034` 实测 4.52 GB / 1.339 GiB 内容）。带宽实测 **1.44 / 2.07 / 2.28 MB/s**（第三次中途 SSL reset）。

| 路径 | 组成 | 拉取 | 构造 | 双端+证据 | 严重性+台账 | 总时长 | 峰值磁盘 |
|---|---|---|---:|---:|---:|---:|---:|
| **最省（只做 A1）** | `67968` 一对 | 14 min | 45 min | 20 min | 60 min | **≈2.3 h** | **5.2 GB** |
| 最省 + 兜底 | `67968` + `35870` | 31 min | 85 min | 40 min | 60 min | **≈3.6 h** | 11.4 GB |
| 完整 | `67968` + `28262` + `35870` | 55 min | 145 min | 60 min | 90 min | **≈5.8 h** | 20.5 GB |
| 完整 + 构造器最省 | 再加 `18130` | 165 min | 165 min | 80 min | 90 min | **≈8.3 h** | 61.4 GB |
| 全量（不建议） | 再加 `29620/58743/42940` | >400 min | — | — | — | **>12 h** | >150 GB |

资源现状：磁盘 **485 GB 可用**（另 `docker system df` 显示 59.23 GB 可回收）、20 CPU、可用内存 **14 GB**、
docker 守护可用；`docker.io` / `registry-1.docker.io` **不可达**，`dockerproxy.net` **可达**（`/v2/` 200 / 679 ms）。
**瓶颈是单流带宽与镜像站 reset，不是磁盘或 CPU。**

### 4.5 结论

1. **存量没有可合法升级的第 10 例（0/17）**，两条证据链（严重性 + ID）都闭合；`arvo:60983`、`arvo:54625`、
   `arvo:1065` 三个「看起来像」的都不是。
2. **只能新开根**。按本次实测改序：**A1 `arvo:67968` > A1-fallback `35870` > A2 `28262` > B1/B2 > C1/C2 > D1**。
   （文档先验是 `B1 > B2 > A1`；实测后 B 掉到第 4，因为缺任务注册表，且 A 的最小镜像对只要 14 分钟。）
3. **今天不立项的诚实状态**：第 10 例 = **`planned`**，不是 `verified`。
   可写：「候选已机器定位到 450 个新号、其中 14 个命中现有构造器族；最便宜的镜像对已验 manifest 可拉
   （14 min / 5.2 GB）；本轮**未拉镜像、未跑双端**。」
   不可写：把 `60983` 算成第 10 例、把 `54625` 的 6.1 说成 high、把 `1065` 的低危双端说成高危、
   把自建 nltk 双端（D1）当 benchmark。

---

## 5. 三项决策的合成影响

| 项 | 前置审计口径 | 本轮决策后 | 变化原因 |
|---|---:|---:|---|
| 独立高危根 | 9 | **9** | EG-02 同根；第 10 例未立项 |
| 严格可提交 | 0 | **0** | 8 例仍缺回执/复核/轨迹导出；EG-02 同根不入分子 |
| 补材料后可提交 | 7 | **7（不变）** | VG-01 的 B 项（VulnGym 官方双端）仍缺 `baseline_url`/`patched_url`，不能算「只缺材料」；归其位：**只差任务字段** |
| 到 10 还差 | 3 | **3（内容变了）** | ①CG-14 换干净输入重跑；②**VG-01 补任务字段 + C 重记**（源码已到手，成本大幅下降）；③**新增 1 个根**（`arvo:67968`） |
| ExploitGym ≥1 例（R2） | 0（待核） | **0（待核）** | 无回执，且同根不加分 |

**推荐执行顺序（按性价比，不按文档先验）**：

| 序 | 动作 | 成本 | 收益 | 阻塞 |
|---|---|---|---|---|
| 1 | 修闸门黑名单（§2.5 M1/M2）→ VG-01 归属正式入库（M4） | ≈30 min | 把 VG-01 从「归属未证」变「只差任务字段」 | **`scripts/` 不在本轮写入范围**，需下一轮 |
| 2 | `arvo:67968` 立项 → 双端 → 严重性论证 → 台账增行 | ≈2.3 h | 拿到**第 10 个独立根** | 无（网络/磁盘已验） |
| 3 | CG-14 换干净输入重跑（不得用 `cg14_ofctl.bin`） | 2 轮 | 把 CG-14 从 `not_submittable` 救回 | 需独立生成器 |
| 4 | 8 例材料补齐（回执/复核/轨迹导出/参数） | 人 + 外部 | 把「可提交」变成「严格可提交」 | 需第二人 + 评测方 |
| 5 | EG-02：把「满足必选项」改为「historical_verified + 官方接受待核」（§3.6） | ≈10 min | 消掉 `STATUS.md:43` 与 `EXPLOITGYM-BLOCKED.md` 的口径冲突 | 无 |

---

## 6. 本轮交叉发现（不进任何历史文件，只登记）

| # | 发现 | 影响 |
|---|---|---|
| X1 | **旧前提过期**：「本机 GitHub 不可达」不再成立（`api.github.com` / `github.com` / `codeload` 全 200）；`raw.githubusercontent.com` 仍超时 → **取证一律走 Contents API 或 codeload** | 直接解锁 VG-01 归属；`TENTH-CASE-PLAN` §4 的前提要改 |
| X2 | **`arvo:44034-fix` 已在机上**（4.71 GB，`dockerproxy.net/n132/arvo:44034-fix`），文档「只有 vul 端」已过期 | CG-01 的 fix 端可现场补跑 |
| X3 | **闸门黑名单误杀原件**（`scripts/vg01_source_check.sh:99-104`） | VG-01 只能停在 `needs_evidence`，直到修 |
| X4 | **字面 `root_key` 去重会虚增到 10**（`ghostpdl/pdf/pdf_font.c` vs `pdf/pdf_font.c`） | 第 10 例判据必须先归一化路径 |
| X5 | **同 bug 多号**：`arvo:42938/42939/42940/42944` 的 `fix_commit` 全为 `afdbc940c601` | 当 4 个候选用会造出假计数 |
| X6 | **`VERIFY` 断言冒充写**：`arvo:62083` 首帧 `ak_verification_failed` | 不能当「无界写」论证 |
| X7 | **前置审计在本轮期间被并行会话重写**：`docs/COURSE-CASE-AUDIT.md`（17:48:24）、`experiments/course-case-audit.json`（`generated_at 17:52:00`） | 本文件只引用其**口径与结论**（totals 未变：8 / 0 / 7 / 1），**不引用其字节哈希**；两文件非本轮写入 |
| X8 | `experiments/_findings/**` 是本轮队友取证底稿 | **非交付物**，可随时删；引用以本文件与 JSON 为准 |

---

## 7. 边界声明

- 写入范围：`docs/COURSE-EVIDENCE-DECISIONS.md`、`experiments/course-evidence-decisions.json`、
  `experiments/_findings/{vg01,eg02,tenth-case}.md`（取证底稿）。
- **未改**：`workspace/**`（历史证据）、`experiments/LEDGER.json`、`LEDGER-AUDIT.json`、
  任何 `case.json` / `severity.json` / `RESULT.json` / `logs/` / `artifacts/`；**未改**业务代码
  （`agent/**`、`scripts/**`、`bin/**`）。
- **无 git commit**（本仓根目录不是 git 工作区）。
- 本轮实跑过的命令：`curl`（GitHub API / codeload / ARVO release，**只读外部**）、`sha256sum`、`diff`、
  `tar`、`docker images` / `docker manifest inspect`（只读）、`scripts/vg01_source_check.sh`（在 `/tmp` 目录上跑，
  另在 `/tmp` 副本上验证「去掉黑名单后 rc=0」）、`experiments/vg01/run_server_evidence.py`（产物落 `/tmp`）、
  Python 只读计数与 SQLite 只读查询。
- **未拉任何镜像**（只做 manifest 级探测）；**未写 `workspace/`**。
- 本文件不替任何案例签「人工复核」；`sha256 一致`、`可复算`、`行为可复现` 都只到「证据」为止，
  不等于「第三方已接受」。

---

## 附录 A：本轮实际观测值（供复核对照）

| 观测 | 值 |
|---|---|
| `40d0bc1d` 全 sha | `40d0bc1d484a3458d6a63ecb5ba4957ab16ba14e`（2026-03-18） |
| 原件 `wordnet_app.py` | 34427 B / 1002 行 / `sha256 f4fa4adc…a4f23` / blob `61de31d7…0654` |
| 重建件 | 同一哈希（逐字节相同） |
| 镜像 `wordnet_app_patched.py` | 34569 B / 1005 行 / `5a925994…ec31a`（= 原件 + 88–90 行） |
| 本机 nltk 3.10.4 | 1094 行 / `58615acc…4b1ee` |
| tarball | 2902336 B / `9d7c3043…44292` |
| 闸门现状 | `rc=6`（黑名单命中原件哈希）；去黑名单 + manifest 后 `rc=0`，`shutdown@87 / print@92 / os_exit@93` |
| 原件上行为复现 | stdout 22 B `Server shutting down!\n`，rc=0，端口已关，`module_sha256=f4fa4adc…` |
| EG 10 份日志 | `sha256 695ceacd…` ×10（distinct=1），mtime 09:49:03→09:49:22 |
| EG flag / PoC | `4d0c0c3a…cd86` / 9518 B `9f40093d…e7ff73` |
| 候选镜像内容量 | `67968` 1.41 GiB｜`35870` 1.66 GiB｜`28262` 2.45 GiB |
| 网络 | `docker.io` ✗｜`registry-1` ✗｜`dockerproxy.net` ✓ 679 ms｜`api.github.com` ✓｜`codeload` ✓｜`raw.githubusercontent` ✗ |
| 资源 | 485 GB 可用｜20 CPU｜14 GB 可用内存｜59.23 GB 可回收镜像 |

## 附录 B：本文件与既有文档的关系

- 不推翻 [COURSE-CASE-AUDIT.md](COURSE-CASE-AUDIT.md) 的 A/B/C/D 判定与 0/7/1 分布；
  不改 §5 的「补材料后可提交 = 7」；本轮把 VG-01 的位置从「不可提交（缺源码）」改为
  「A/C 可立、B 缺任务字段」，并说明其字节归属已闭合（§2.4）——这是**成本**变化，不是**计数**变化。
- 不推翻 [TENTH-CASE-SEARCH.md](TENTH-CASE-SEARCH.md) 的「存量 = none」；本轮复算一致（0/17）。
- 不推翻 [TENTH-CASE-PLAN.md](TENTH-CASE-PLAN.md) 的通道划分与计数口径；只**更新**其两条前提
  （GitHub 可达、镜像体积非恒定）与**推荐顺序**（A1 提前）。
- 不推翻 [EXPLOITGYM-BLOCKED.md](EXPLOITGYM-BLOCKED.md) 的「官方判定 0 例」；本文件 §3 与它一致，
  并把与之冲突的 `STATUS.md:43` 口径列为**已知缺陷**（§3.7 第 2 条）。
