# VG-01 服务端证据：`SHUTDOWN THE SERVER` 是否真的进入 shutdown 分支

| 项 | 值 |
|---|---|
| 任务 | VG-01 / vulngym/nltk/40d0bc1d / CWE-306 |
| 本轮日期 | 2026-11-18 |
| 约束 | 不联网、不伪造上游源码；允许本地重建但必须标注 `reconstructed` |
| 未改动 | `workspace/**`（历史证据）、`experiments/vg01/wordnet_app_patched.py`、`experiments/vg01/RESULT.json` |
| 未执行 | `git commit` |

---

## 0. 结论（先给判定，再给证据）

**能（对象＝本地重建件）。** 在完全离线的条件下，vuln / patched 两版都能启动，并且抓到了**服务端 stdout**：漏洞版对未认证请求打出唯一一行
`Server shutting down!`、进程以 `os._exit(0)`（rc=0）退出、端口关闭；同一请求打在补丁版是 `403`、stdout 一字节都没有、进程继续存活。

但"证明"的范围必须切开，否则就会把重建件当成上游原件：

| 断言 | 判定 | 依据 |
|---|---|---|
| A. 未认证请求确实进入 `shutdown` 分支（服务端行为） | **成立**（对象＝本地重建件） | `evidence/01-vuln-reconstructed/server.stdout.log` = `Server shutting down!\n`；rc=0；端口关闭；A/B 见 §4 |
| B. 客户端 `RemoteDisconnected` 可单独作为"进入 shutdown 分支"的证据 | **不成立** | §3：语料缺失导致的 handler 崩溃在**单次响应**上给出完全相同的客户端输出；不做 `-u` 时 stdout 也会丢 |
| C. 证据对象是 nltk@40d0bc1d 的原始字节 | **未成立 → needs_evidence** | 本机无该 commit 源码；证据链起点是仓库镜像 `wordnet_app_patched.py`，见 §2 |

因此 VG-01 的证据级别从"仅客户端 `RemoteDisconnected`（ambiguous）"升级为
**`server_stdout_confirmed`（对象＝reconstructed）**；而对 commit 40d0bc1d 的**原始证据**判定仍是
**`needs_evidence`**，所需外部资源见 §9。

> 一句话给评审：**行为已证，归属未证。** 行为证据是服务端 stdout，不是客户端状态；归属证据仍要等 40d0bc1d 的源码树。

---

## 1. 这一轮到底解决了什么

历史记录（`workspace/VG-01-nltk-wordnet/logs/`）只有客户端结果：

```
GET /SHUTDOWN%20THE%20SERVER -> status=None err=RemoteDisconnected
alive_after=False
```

这批日志里 `shutting down` 出现次数为 **0**（6 个 `*.log` 逐个 grep 全为 0；`report.error.json` 亦无），也没有任何 stderr 帧提到 shutdown 请求。
也就是说：**协议层看到"连接断了"，但没有任何服务端输出证明断在 shutdown 分支**。`RemoteDisconnected` 至少有三义：

1. 命中 `print("Server shutting down!")` + `os._exit(0)`（漏洞路径）；
2. handler 内异常（本环境缺 wordnet 语料 → `LookupError`）；
3. 进程正常退出/被杀（`-s` 模式、SIGTERM）。

本轮把这三者用服务端 stdout、返回码、端口状态区分开了。

---

## 2. 环境与"不联网"这条约束

| 项 | 实测 |
|---|---|
| 解释器 | `/usr/bin/python3.10`（3.12 是 DSH 自身的，不装 nltk） |
| nltk | 本地已装 **3.10.4**：`~/.local/lib/python3.10/site-packages/nltk`（无 wordnet 语料） |
| 网络使用 | **零外网**：所有 socket 都是 `127.0.0.1` |
| 需要披露 | 本沙箱实际**可**连通外网（`https://pypi.org/simple/nltk/` 返回 200）。本轮按任务约束**未使用**；这使 §7 的"所需外部资源"是"下一轮可得"，而不是"环境不可能" |

**为什么不能直接跑 40d0bc1d**：本机唯一的 nltk 是 3.10.4，它**已经修过** shutdown 鉴权
（`_shutdown_authorized()` + 每次进程随机的 `?token=`，属 CWE-352 修复）。拿它当"漏洞版"会直接得出错误结论。
本轮把它当**控制组**：真实上游发布文件对同一请求返回 403、不打印、继续存活（§4 第 4 行），这证明探针有区分力，不是"随便一个请求都能打死服务"。

---

## 3. 方法论核心：为什么必须抓 stdout

### 3.1 `RemoteDisconnected` 不可判（实测复现）

在漏洞版上先请求 `/start_page`：本机没有 wordnet 语料，handler 抛 `LookupError`，socketserver 记 traceback 后关连接。
客户端拿到的也是"0 字节 EOF"，与 shutdown 请求**一模一样**：

| 请求 | 客户端 | 服务端 stdout | 服务端 stderr | 进程 |
|---|---|---|---|---|
| `GET /start_page`（缺语料） | `RemoteDisconnected`（0 B） | 空 | `LookupError` traceback ×1 链 | **存活** |
| `GET /SHUTDOWN%20THE%20SERVER` | `RemoteDisconnected`（0 B） | `Server shutting down!` | 无该请求的 traceback | **退出 rc=0** |

同一份**单次响应**，两种服务端事实无法区分 → **单次响应到此为止**。

注意限定："之后还能不能连上、端口是否关闭"本身也是客户端可观测的，它足以排除 case 2（handler 崩溃但进程存活）；stdout 的增量价值是把"进程退出了"进一步锁定为"**shutdown 分支的 print + `os._exit(0)`**"，而不是"客户端什么都证明不了"。

### 3.2 缓冲陷阱：`os._exit(0)` 会吞掉 stdout

`os._exit` 不做 stdio flush。stdout 被重定向（块缓冲）时，`print("Server shutting down!")` 直接丢弃。
实测（`evidence/05-buffering-trap/`）：

| 启动方式 | 客户端 | stdout | rc |
|---|---|---|---|
| `python3.10 wordnet_app_...py -p PORT` | 0 B | **空**（行被丢） | 0 |
| `python3.10 -u wordnet_app_...py -p PORT` | 0 B | `Server shutting down!\n` | 0 |

这解释了历史 logs 为什么"有客户端结论、没有服务端证据"：**不是没打印，是打印被缓冲吞了**。
所以本套脚本一律 `-u` + `PYTHONUNBUFFERED=1`，并在 README 意义上把它写成硬约束（见 `run_server_evidence.py` 顶部注释）。

---

## 4. 判定差分（4 组实跑，全部同一探针）

| # | 构建 | 请求 | index | shutdown | 服务端 stdout | rc | 之后存活 |
|---|---|---|---|---|---|---|---|
| 1 | `wordnet_app_vuln_RECONSTRUCTED.py`（reconstructed） | `GET /SHUTDOWN%20THE%20SERVER`，**无任何凭据** | 200（725 B） | 0 B EOF（`RemoteDisconnected`） | **`Server shutting down!`**（唯一一行） | **0** | **否**（端口关闭） |
| 2 | `wordnet_app_patched.py` | 同上，无 token | 200（**响应体**与 #1 相同，725 B / body sha256 一致；`Date` 头不同） | **403**（645 B） | 空（0 B） | 仍运行 | **是**（随后 `/` 仍 200） |
| 3 | `wordnet_app_patched.py` | 同上 + `X-Shutdown-Token: local-only` | 200 | 0 B EOF | **`Server shutting down!`** | 0 | 否 |
| 4 | 真实上游 `nltk 3.10.4` 的 `wordnet_app.py`（控制组，非 40d0bc1d） | 同 #2 | 200（773 B） | **403**（210 B） | 空 | 仍运行 | 是 |

读法：

- #1 vs #2：同一份请求、同一个服务端框架、**index 响应体逐字节相同**（725 B，`body_sha256` 相同；HTTP 头 `Date` 不同，整响应并不逐字节相同） → 唯一变量就是那 3 行 token 校验；差异只能来自它。另注：index 只在"新进程的第一个请求"稳定，同一进程的第二次请求会因 `firstClient` 翻转为 `upper_2.html` 而变成 727 B，所以 A/B 只比对第一帧。
- #3 证明补丁后的分支**仍然可达**（不是把分支删了），只是需要 token；因此 #2 的"无 stdout"不是"请求没进来"。
- #4 证明探针在**真实上游字节**上同样克制：403、不打印、不死。

---

## 5. 重建（reconstructed）：做了什么、凭什么可审计、边界在哪

**变换**：`experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py` = 仓库镜像 `wordnet_app_patched.py` **删除 88–90 行**（三行 `X-Shutdown-Token` 守卫），**不新增任何一行**。

可审计性（`reconstruct_vuln.py` 每次运行都断言，失败即拒绝写文件）：

1. 断言镜像 87 行就是 `if unquote_plus(sp) == "SHUTDOWN THE SERVER":`，88–90 行逐字节等于被删的三行；
2. 删除后 `shutdown` 条件仍在 **87 行**，与 `SOURCE.md` 记的关键行一致；
3. **行号三重吻合**：重建件跑出的 traceback 帧为 `do_GET:153 / page_from_word:741 / page_from_reference:780`，
   与 2026-11-13 记录在 `logs/vg01-vuln-raw.log:47/49/51` 的历史帧**完全相同**；镜像自身是 156/744/783，正好 +3（即插入的 3 行）。
   该次运行用的是 `/tmp/nltk_vg/nltk/app/wordnet_app.py`，**树已被删除**，仓内没有它来自 40d0bc1d 的记录 ——
   所以这里只能说是"与一份历史日志吻合"，**不构成对上游的归属证据**（见 §9.5）。

为什么文件名带 `RECONSTRUCTED` 而不是在文件头写注释：**任何新增注释行都会让行号移位**，第 3 条校验就失效。
标注放在**文件名 + 本文件 + `experiments/vg01/RECONSTRUCTION.md` + `summary.json.label`** 四处。

**边界（必须一起引用）**：

- 它是**删除式重建**，不是 40d0bc1d 的原件；**不得**当作原始证据引用，**不得**用它给上游行号背书；
- 行号吻合只证明**布局**一致、且非守卫部分逐字继承自镜像；**不能**证明镜像本身与 40d0bc1d 逐字相同。
  镜像的 provenance 只有 `SOURCE.md` 的一句声明，本轮离线无法独立核对——这正是 C 项仍 `needs_evidence` 的原因。

---

## 6. 复现

```sh
cd experiments/vg01
sh run_suite.sh        # 重建 → 4 组实跑 → 缓冲对照 → 22 项机器校验
```

需要：`/usr/bin/python3.10` + 本地 nltk；**不需要**网络、不需要 wordnet 语料。
末行应为 `22/22 checks passed`。校验器直接读 `server.stdout.log` 本体并比对 sha256（不是只信 `summary.json` 的自报布尔值）：把该文件截成 0 字节后重跑，校验会降到 21/22 并 FAIL。逐条产物：

```
experiments/vg01/evidence/
├── 01-vuln-reconstructed/     server.stdout.log(22 B) stderr.log client.requests.jsonl summary.json
├── 02-patched-deny/           server.stdout.log(0 B)  ...
├── 03-patched-allow/          server.stdout.log(22 B) ...
├── 04-upstream-3.10.4-control/ server.stdout.log(0 B) ...
└── 05-buffering-trap/         A-buffered.stdout.log(0 B) B-unbuffered.stdout.log(22 B) summary.json
```

---

## 7. 证据清单（可直接引用）

| 材料 | 位置 | 关键内容 |
|---|---|---|
| **服务端 stdout（核心）** | `experiments/vg01/evidence/01-vuln-reconstructed/server.stdout.log` | `Server shutting down!`，sha256 `17e15001cc167e53…`，22 B |
| 该次运行摘要 | `.../01-vuln-reconstructed/summary.json` | `server_returncode=0`、`alive_after_shutdown=false`、`port_listening_after_shutdown=false`、`module_sha256=f4fa4adc…` |
| 补丁侧 stdout（空） | `.../02-patched-deny/server.stdout.log` | 0 B（sha256 `e3b0c442…`＝空文件），`shutdown=403`、`alive=true` |
| 控制组 stdout（空） | `.../04-upstream-3.10.4-control/server.stdout.log` | 0 B；模块为已装 nltk 3.10.4（sha256 `58615acc…`），label 明写 **NOT 40d0bc1d** |
| 缓冲陷阱 | `.../05-buffering-trap/summary.json` | 缓冲 stdout 为空、`-u` 有行、客户端两种情况都是 0 B |
| 重建脚本 | `experiments/vg01/reconstruct_vuln.py` | 断言 + 行号交叉校验 |
| 重建件 | `experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py` | 1002 行，sha256 `f4fa4adcef…`；镜像 1005 行，sha256 `5a925994fc…` |
| 驱动 / 校验 | `run_server_evidence.py` / `verify_evidence.py` / `run_suite.sh` | 22 项断言，任一不成立即 FAIL；`client.requests.jsonl` 记录 `body_sha256` |

---

## 8. 与历史 `RESULT.json` 的一致性

| 字段 | 历史值（2026-11-12/13） | 本轮重建件实测 | 一致 |
|---|---|---|---|
| `vuln.index_status` | 200 | 200（`/`；历史用 `/index.html`，同为静态分支、不需要语料） | ✅ |
| `vuln.shutdown_result` | `RemoteDisconnected` | 0 B EOF（客户端视角同名） | ✅ |
| `vuln.alive_after_shutdown` | false | false（rc=0，端口关闭） | ✅ |
| `patched.shutdown_result` | `HTTPError` / 403 | 403 | ✅ |
| `patched.alive_after_shutdown` | true | true | ✅ |
| 服务端 stdout | **缺失** | **`Server shutting down!`** | ⬆ 新增 |

历史 `index_status=200` 与历史 `*-raw.log` 里成片的 `LookupError` 并不矛盾：那些 traceback 来自浏览器第二帧 `start_page`，
不是 index 请求。本轮把这点也复现了（§3.1），并借它证明了客户端证据的不可判性。

---

## 9. 局限与仍缺的外部资源

1. **原始 commit**：缺 `nltk/nltk@40d0bc1d` 的源码树。取得方式（下一轮、联网）：
   ```sh
   git clone https://github.com/nltk/nltk.git /tmp/nltk_40d0bc1d
   git -C /tmp/nltk_40d0bc1d checkout 40d0bc1d
   sha256sum /tmp/nltk_40d0bc1d/nltk/app/wordnet_app.py    # 记录后，用它替换 --module 重跑 run_server_evidence.py
   ```
   或 `pip download nltk --no-deps --no-binary :all:` 取对应 sdist。拿到后应把 `RECONSTRUCTED` 件降级为夹具，
   并把本文件的 A 项从"对象＝重建件"改写为"对象＝40d0bc1d 原件"，C 项才可关闭。
2. **wordnet 语料**：缺。`/start_page` 在 handler 内抛 `LookupError`，客户端拿到的是 **0 字节 EOF（没有 HTTP 状态行，不是 500）**，服务端 stderr 一条 traceback 链，进程继续存活。**不影响** shutdown 分支（判定发生在语料访问之前），但 index/搜索路径无法完整验证。
3. **镜像 provenance**：只有 `SOURCE.md` 的声明；离线无法核对镜像与 40d0bc1d 的逐字一致。
4. **AV 口径**：实测仍是 `127.0.0.1`；`severity.json` 的 AV:N 属"浏览器内可达"的保守外推，本轮未改变该判定。
   需要注意的反方材料：已装 3.10.4 的源码注释（`nltk/app/wordnet_app.py:77`）直接写
   "The loopback bind already blocks remote access (CWE-306)"，且它的修复动机是 CWE-352（跨站请求）而非 CWE-306。
   答辩时若被追问 AV:N/CWE-306 口径，本轮证据**只支持**"本机回环可达 + 未认证即关机"，
   跨站可达性属未实测的外推，应与 `report.md` §5 的既有局限一起陈述。
5. **`/tmp/nltk_vg` 的来源记录缺失**（本轮审查发现的新缺口）：那份被用来产生 153/741/780 帧的源码树已被删除，
   也没留下"怎么装的、什么版本、sha256 多少"的记录。因此 §5 第 3 条目前只能锚到一份日志；
   补上这份来源记录，才能把"与日志吻合"升级为"与上游吻合"。
6. **该 commit 对应的 nltk 版本号 / tag 未知**：镜像 1005 行、已装 3.10.4 是 1094 行，
   说明 3.10.4 之后又加过硬化代码；但没有版本对照，"3.10.4 晚于 40d0bc1d"目前仍是推断。
7. **不改历史**：本轮**没有**改动 `workspace/VG-01-nltk-wordnet/artifacts/RESULT.json`。若要落库，建议只增字段
   （例如 `vuln.server_stdout="Server shutting down!"`、`evidence_level="server_stdout_confirmed(reconstructed)"`），
   并保留原 `shutdown_result` 不动。

---

## 10. 本轮变更清单

新增（仅 `experiments/vg01/` 与 `docs/`）：

```
experiments/vg01/reconstruct_vuln.py
experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py
experiments/vg01/run_server_evidence.py
experiments/vg01/verify_evidence.py
experiments/vg01/buffering_trap.py
experiments/vg01/run_suite.sh
experiments/vg01/RECONSTRUCTION.md
experiments/vg01/evidence/**                (5 组运行产物)
docs/VG01-SERVER-EVIDENCE.md                (本文件)
```

未改动（ctime 均可核对，非 `touch` 可伪造）：

- `workspace/VG-01-nltk-wordnet/**`：全部 ctime ≤ 2026-11-15 19:21，早于本轮（2026-11-18 22:10 起）。
- `experiments/vg01/wordnet_app_patched.py`：ctime 2026-11-12 20:37，sha256 `5a925994fc…`。
- `experiments/vg01/RESULT.json`：ctime 2026-11-12 20:37。

无 git commit。

### 并发写入声明（避免误读台账）

同一时间段（22:10–22:13）另有一些文件被**其他会话/其他轮次**改写，**不是本轮写入、也不是本轮证据推出的**：

- `experiments/LEDGER.json`（其中 VG-01 条目的 `verdict: "pass"`、`benchmark_verified: true` 早于/独立于本轮证据）；
- `experiments/LEDGER-AUDIT.json`、`experiments/COURSE-GAP-CLOSED.json`（后者仍记 vg01 `decision: needs_evidence_unchanged`）；
- `workspace/CG-04-arvo-10400/**`、`agent/regate.py`。

本轮**不修改台账**。若谁要把 VG-01 的台账结论更新为本轮结果，建议写成
`evidence_level: server_stdout_confirmed(reconstructed)` + `original_commit_provenance: needs_evidence`，
而不是直接把"pass"当成原始证据通过。

### 复跑前的环境提醒

`poc/request.sh` 默认端口是 **8000**，而本机 8000 已被一个**无关**进程占用
（`python3 -m http.server 8000 --directory /home/root_bupt/xray-deploy/clash`，pid 81517，20:59 启动）。
直接跑默认参数会打到那个静态服务器，得到的"200"与本漏洞无关。复跑时请显式换端口（本套脚本默认随机空闲端口，且只连 `127.0.0.1`）。
