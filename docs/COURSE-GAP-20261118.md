# 课程证据缺口盘点（2026-11-18）

> **后续（2026-11-18 22:05）**：本文件 §3/§6 的 E1（CG-31 判据）与 E2（四例要素接线）已执行完毕，
> 结论与复算见 [COURSE-GAP-CLOSED-20261118.md](COURSE-GAP-CLOSED-20261118.md) /
> [COURSE-GAP-CLOSED.json](../experiments/COURSE-GAP-CLOSED.json)。
> 本文件保持为**闭环前的基线盘点**：`cases[*].ledger/gate/classification` 不改写，
> 闭环事实另存 `COURSE-GAP.json:closure`；§9「没有往 workspace 里写 propagation.json」是当时的纪律，
> 现在那一步已由 `experiments/course_gap_wiring.py` 完成（`verified_by=evidence_refs`，未代签复核）。

> 输入：`docs/LEDGER-AUDIT.md`、`docs/COURSE-READINESS-AUDIT.md`（先读），再逐例核 `workspace/*/artifacts`、`workspace/*/logs`、`workspace/*/src`、`docs/CAUSAL-CG*.md`、`agent/stages/{report,locate,verify}.py`。
> 产物：本文件 + [COURSE-GAP.json](../experiments/COURSE-GAP.json)（机读）+ [COURSE-GAP-verify.py](../experiments/COURSE-GAP-verify.py)（复算脚本）。
> 纪律：**不改写历史判定**。`experiments/LEDGER.json`、6 例的 `case.json`/`severity.json`、`workspace` 内原始证据一律未动；本文件只记录「缺什么、能补到什么程度、补不了要跑什么」。
> **字段补齐 ≠ 人工复核**：把已有证据挂到 `propagation` 上只是让门禁能读到它；`verified_by=manual_review` 必须由第二人按 refs 逐条核过后自己写。

## 1. 结论

| # | 案例 | 缺的门禁项 | 证据现状 | 结论 |
|---|---|---|---|---|
| 1 | CG-18 | propagation 三要素 | 日志 + 源码 + PoC 全对上 | 可闭环，只差 wiring |
| 2 | CG-29 | propagation 三要素 | 同上（含上游 patch 反证） | 可闭环，只差 wiring |
| 3 | CG-30 | propagation 三要素 | 同上（fix 日志自带"超 4096"反证） | 可闭环，只差 wiring |
| 4 | CG-36 | propagation 三要素 + `dataflow_has_evidence` | 同上（含 256=128×2 恒等式） | 可闭环，只差 wiring |
| 5 | CG-31 | `kind=unknown`、`cwe_matches_crash`、`root_cause=weak` | 三要素其实齐 | 判据问题，需代码改动（E1） |
| 6 | VG-01 | 无 `stage_status`、无 propagation、无服务端事件 | 只有客户端侧证据 | **needs_evidence**：必须新跑（E3） |

- 6 例中 **5 例（CG-18/29/30/31/36）** 的因果要素在现有 workspace 里都有可逐行核对的证据（`COURSE-GAP.json` 共 15 条要素、80 条 ref，全部由复算脚本验过）。
- **VG-01 补不了**：不是因为懒，而是它连「请求确实进了 shutdown 分支」都没有服务端记录——raw 日志里只有 wordnet 语料缺失的 traceback。
- **第 10 个独立高危根因在现有 workspace 里不存在**可合法升级的案例（详见第 5 节）；要么走评审口径（CG-02，风险自负），要么跑新任务（E4）。

补完 E1+E2 后，「benchmark 验证 + 因果链都通过」的独立高危根因从 **3 → 7**（CG-01/07/14 + CG-18/29/30/36）；再加 E1 的 CG-31 则为 8。仍差第 10 例。

## 2. 口径

| 项 | 本文件的处理 |
|---|---|
| `causal_chain_verified` | 必须 `local_dual_run.ok` **且** `root_cause.confidence=="strong"` **且** `propagation.complete` **且** `checks` 无失败（[report.py:695-720](../agent/stages/report.py)） |
| propagation 必要要素 | `memory_corruption` 要 `input_bytes / reaches_sink / missing_check / observed_oob` 四项；`_defect_kind` 认不出类型时退化成 `{unspecified}`（[report.py:558-597](../agent/stages/report.py)） |
| 证据等级 | `evidence_available` = refs 能逐条复算；`partial` = 有证据但不完全；`needs_evidence` = 本仓无、必须新跑；`already_present`/`not_applicable` = case.json 已有或类型不适用 |
| 每个要素都带 `derivation` | `direct_observation`（日志/字节直读）/ `arithmetic_identity`（由分配大小反推）/ `source_plus_upstream_patch` / `source_reading`；反推不冒充直读 |

## 3. 逐例：缺什么、补到什么程度

三要素的具体值、refs、恒等式都在 `COURSE-GAP.json` 的 `cases[*].elements`。下面只给判定要点。

### 3.1 CG-18（arvo:12420，libidn2）

`propagation.missing = [input_bytes, reaches_sink, missing_check]`，`root_cause=strong`，`checks` 全绿。

| 要素 | 证据 | 等级 |
|---|---|---|
| input_bytes | PoC 260 B = 65 个小端 UCS-4 码点 = 32×`a` + `.` + 32×`b`；fuzzer 按 `size/4 = 65` 传入 | 直读（脚本解出 65/32/1/32） |
| reaches_sink | `u32_to_u8`(:602) → `idn2_lookup_u8`(:611，逐 label ≤63 全过) → `strcpy`(:621) 写进 `malloc(64)`(fuzz:67) | 直读（ASAN 帧 #1/#2 与分配帧对上） |
| missing_check | 无 `strlen(output_u8)+1 ≤ 64`；:616-618 只是注释声明契约，:620 仅判非空 | 源码直读 + 实测 66 vs 64 |

与 `docs/CAUSAL-CG18.md` 的 5 步链一致；其 I1（真实 deployment 调用点）仍为 inferred，不影响本实验室链。

### 3.2 CG-29（arvo:11011，libarchive rar5）

`missing` 同上。要点：`window_size=0` 不是猜的——本次运行 `calloc(1, window_size)` 得到 **1 字节区域**（log:34/:37），而源码中 `window_size` 取 0 的唯一分支是 `is_dir`（rar5.c:1363-1365）。`cmask=(int)(size_t)-1=-1` ⇒ `write_idx & -1 == write_idx`，掩码失效；写点落在 1 字节区域的 offset 1，正好印证索引没被折回。上游 `patch.diff:10-13` 给 `window_size==0` 时置 mask=0，是同一根因的旁证。

### 3.3 CG-30（arvo:29633，fio）

`filename=` 值 6000 字符 → `sprintf` 写 6001 字节进 `char file_name[PATH_MAX]`(4096)。`__sprintf_chk` 因目标是 `file_name+len` 动态偏移而没能静态拦住（log:21-22）。**fix 日志第 18 行 `value exceeds max length of 4096`** 是"缺的正是长度上限"的正面反证。

### 3.4 CG-36（arvo:54839，libredwg）

除三要素外还多一个 `checks.dataflow_has_evidence=false`：本工作区 `artifacts/locate/findings.json` 没有 claims。好消息是 locate 的 `propagation.json` 机制会在 elements 存在时合成 `claim.dataflow`（[locate.py:143-158](../agent/stages/locate.py)），所以这一项与三要素由**同一步**修复。

数字：区域 256 B = 128×2 ⇒ `num_sections=0`；写点 offset 260 = 2×128+4 = `section[2]` 的 `size` 字段（结构体 size 在偏移 4，dwg.h:8593-8594）。`num_sections` 的字节值未逐字节 dump（`CAUSAL-CG36` 的 I2），本文件标为**算术反推**而非直读。

### 3.5 CG-31（arvo:61675，exiv2）

三要素其实齐（PoC 98339 = 24 ftyp + 98315 brob，压缩长度 98303，2×98303 = 196606 = ASAN 区域；下溢在 :205，`total_out > 131072` 补丁在 patch.diff:30）。卡住的是三处**判据**，不是证据：

| 现象 | 原因 |
|---|---|
| `root_cause=weak / sink_line_in_raw_trace` | 栈里 #0 是 `__interceptor_memcpy`、#1/#2 是 libbrotlidec，sink 函数 `brotliUncompress` 在 #3；帧解析器把 DSO 帧排除后落到 raw 文本兜底（[verify.py:1811-1815](../agent/stages/verify.py)） |
| `propagation.kind=unknown`、要素退化为 `{unspecified}` | `_defect_kind` 只认 `buffer-overflow`/`use-after-free`，`container-overflow` 无映射（[report.py:558-597](../agent/stages/report.py)） |
| `cwe_matches_crash=false` | `_checks.cwe_ok` 按字面 `heap`/`stack` 匹配崩溃文本；`CRASH_TO_CWE` 也没有 `container-overflow` 项（[diagnostics.py:132-141](../agent/diagnostics.py)） |

所以 CG-31 不能靠"补字段"过关，必须改判据（E1）。顺带说明：本例外层写动作发生在第三方库，缺陷在本仓 caller 算错长度——这需要一条明确的判据（strong 或显式 policy 降级），否则任何同类案例都会永久停在 local_verified。

### 3.6 VG-01（vulngym/nltk/40d0bc1d）— needs_evidence

`case.json` 没有 `stage_status`，也没有 propagation 结构：该例走 VulnGym 通道，没有 `artifacts/verify/result.json`，也没有 docker 双端。

现有证据实际只有客户端侧：

- `poc/request.sh:47` 发 `GET /SHUTDOWN%20THE%20SERVER`；
- `logs/vg01-vuln-client.log:3` `status=None err=RemoteDisconnected`、`:4 alive_after=False`；
- `logs/vg01-patched-client.log:3` patched 侧 403、存活。

缺的三件事，都不是"再整理一下"能解决的：

1. **服务端事件**：`logs/vg01-*-raw.log` 只有 wordnet 语料缺失的 traceback（`wordnet_app.py:153, in do_GET`），全文 **0 次** `Server shutting down`；进程退出码也没记录。现结论"未认证远程 shutdown"只有客户端旁证。
2. **源码**：`workspace/VG-01-nltk-wordnet/src/` 是空目录，`SOURCE.md` 锚定的 `wordnet_app.py:87` 在本仓无法复算。
3. **判据模板**：`_defect_kind` 没有 CWE-306 类（鉴权缺失）的要素模板，即使补了数据也会退化成 `{unspecified}`；另外 `case.json.agent=null`，课程要求的 Agent 轨迹/提示词版本也缺。

## 4. 三个结构性缺口（比逐例更值得修）

1. **propagation 从未自动产出**：`_auto_elements` 只会填 `observed_oob`，`input_bytes / reaches_sink / missing_check` 全靠 `propagation.json` 人工档案；所以 6 例的 missing 是**同一处机制缺口**，不是 6 个独立问题。
2. **`_defect_kind` 覆盖太窄**：`container-overflow`、CWE-306 这类明确知道缺陷类型却拿不到要素模板的情况，会被判成"没完成"，把判据问题伪装成证据问题（CG-31、VG-01）。
3. **`verified_by=manual_review` 可以自证**：`propagation.json` 一写，locate 就打上 `manual_review`（[locate.py:153](../agent/stages/locate.py)）。这条与本次"字段补齐 ≠ 复核"的纪律直接冲突，建议改成 `verified_by=evidence_refs` + 独立的 `reviewed_by/reviewed_at` 两段。

## 5. 第 10 个独立高危：能不能从现有结果里补？

方法：扫 60 个 `workspace/*/artifacts/report/case.json`，取 `acceptance.high_severity_confirmed` 与 `causal_chain_verified`，再按 arvo 根因去重对齐 LEDGER 的 9 个独立高危。

**结果：workspace 里没有"已判高危但未计入独立根因"的案例**——9 个高危恰好对应 9 个不同 arvo 根因（EG-02 与 CG-01 同根）。所以第 10 例不可能"捡"到，只能升级或新跑。

升级候选逐个看过（明细在 `COURSE-GAP.json.new_root_cause_search`）：

| 案例 | 现状 | 能否升到 high | 依据 |
|---|---|---|---|
| CG-02 arvo:47101 | medium 5.5 | **条件性** | `severity.json` 自己写了"I:H ⇒ 7.1"；但 (a) 零填充算 I:H 是评审口径决定，不是新证据；(b) 该例 `root_cause=weak`，因果链仍 false |
| CG-15 arvo:3940 | medium 4.4 | 否 | 因果链已 true，但越界恒为 1 字节 NUL，I:L 由结构决定 |
| CG-04 arvo:10400 | low | 否 | CWE-125 越界读 1 字节，无写 |
| CG-27 arvo:12818 | medium | 否 | 零填充、真实越界仅 1 字节，后果不受控 |
| CG-25 arvo:14821 | medium | 否 | 1 字节栈写，被 `VerifyOrExit` 卡住，不随输入放大 |
| CG-23/10/12/32/37/39 | low~medium | 否 | 各自 severity.json 已按固定幅度或读操作定性 |

另外 `experiments/EVAL_SET.json`、`experiments/candidates/CANDIDATES.md`、`discovery/*` 里出现的 arvo 编号（26 个去重）**全部已有 workspace 目录**（workspace 共 43 个 arvo 目录），未跑候选集合为空。结论：**要第 10 例，必须新跑（E4）**。

## 6. 最低新实验（目标 / 命令 / 预算 / 预期证据）

完整机读版见 `COURSE-GAP.json.min_experiments`；每条都带 abort 判据。

### E1 — CG-31 判据修复 + report 重跑（不重新 fuzz）

- **目标**：`workspace/S16-CG31-arvo-61675`
- **命令**：
  1. `cp -a workspace/S16-CG31-arvo-61675 /tmp/cg31-dry`
  2. 改 `agent/diagnostics.py`（`CRASH_TO_CWE` 增 `container-overflow → (CWE-122, CWE-125)`）；改 `agent/stages/report.py`（`_defect_kind` 增 `container-overflow → memory_corruption`；`_checks.cwe_ok` 接受 container-overflow ↔ CWE-122）
  3. `python3 bin/vulnmap.py run /tmp/cg31-dry --stages report`
  4. 副本通过后再对正式目录执行（先用 `experiments/rerun.py` 的备份语义）
- **预算**：0 docker、0 新 PoC、0 模型请求，< 30 min，1 次代码评审
- **预期证据**：`checks.cwe_matches_crash=true`、`propagation.kind=memory_corruption` 且 `complete=true`、`acceptance.causal_chain_verified=true`，且 `logs/`、`artifacts/verify/` 逐字节不变
- **中止**：重跑后 verify 产物被改写或 verdict 变化 → 停，不动正式目录

### E2 — CG-18/29/30/36 写 propagation.json + 重跑 locate+report（证据已在本仓）

- **目标**：上述 4 个工作区
- **命令**：先在 `/tmp` 副本演练（`cp -a workspace/<case> /tmp/<case>-dry`），确认 `--stages locate,report` 不重写 `artifacts/verify` 与 `logs`，再动正式目录；把 `COURSE-GAP.json` 里 `cases[case].elements[*].value` 写成 `workspace/<case>/propagation.json` 的 elements（refs 原样带上，`source` 写"COURSE-GAP-20261118 逐行核对"）→ `python3 bin/vulnmap.py run workspace/<case> --stages locate,report` → 第二人按 refs 复核后才写 `reviewed_by`
- **预算**：0 docker、0 新 PoC、每例 1 次重跑（< 5 min），1 次独立复核
- **预期证据**：4 例 `propagation.complete=true`、`missing=[]`；CG-36 额外 `checks.dataflow_has_evidence=true`；4 例 `causal_chain_verified=true`
- **中止**：本地双端字段或 verify 产物有任何变化

### E3 — VG-01 服务端取证 + 源码树（唯一需要外部资源的）

- **目标**：nltk@40d0bc1d 的 wordnet_app
- **命令**：
  1. `git clone https://github.com/nltk/nltk && git -C nltk checkout 40d0bc1d`；把 `nltk/app/wordnet_app.py` 放进 `workspace/VG-01-nltk-wordnet/src/` 并记 sha256
  2. `python3 -m nltk.app.wordnet_app > logs/vg01-server-vuln.log 2>&1 &` → `curl -sS -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8000/SHUTDOWN%20THE%20SERVER'` → `sleep 1` → 探活 → `wait <pid>; echo exit=$?`
  3. 用 `experiments/vg01/wordnet_app_patched.py` 重复同一组请求
- **预算**：0 docker、4 次起停、外网 ≥100 MB（**当前环境无外网，需先开通**）、30–60 min
- **预期证据**：vuln 侧 server 日志出现 `Server shutting down!` 且进程退出码 0（`os._exit`）；patched 侧 403 且探活 200；`wordnet_app.py:87` 可在本仓复算
- **中止**：server 日志无 shutdown 行或进程被信号杀死 → 现论述须降级重写
- **前置**：还需给 report 加 CWE-306 类要素模板，否则补齐数据仍是 `{unspecified}`

### E4 — 第 10 个独立高危根因（二选一）

- **路线 A（零新实验，评审口径）**：先做 E1 的 strong 判据与 E2 的 wiring，再对 CG-02（arvo:47101）做 I:N→I:H 的评审决定（`severity.json` 已写明替代口径 7.1）。风险：答辩会被问"为何 137 GB 零写算 I:H"，且它本身要先把 weak 判据解决。
- **路线 B（新任务）**：按 `experiments/candidates/CANDIDATES.md` 的做法先登记再跑——选 1 个「描述点名函数 + 堆写」且未跑过的任务，拉 vul/fix 镜像，走 `recon,locate,verify,report`。
  - **预算**：2×5–10 GB 镜像拉取 + 双端各 ≤5 min + ≤40 turns，2–4 h/例（含失败重试）
  - **预期证据**：新任务 `vul exit≠0 / fix exit=0` + ASAN heap write + 三要素齐 + 独立 arvo 根因
  - **中止**：3 个候选都只拿到 read-only 或固定幅度缺陷 → 如实记负结果，不降标准凑数

## 7. 材料补齐清单

课程口径（PPT 第 4/9/10 页）：每例 Agent 日志、报告、CWE、危害说明；CG/EG 各至少一例。逐例明细见 `COURSE-GAP.json.materials.per_case`。

| 案例 | Agent 轨迹 | 报告 | CWE | 危害 | 官方回执 | 人工复核 | 逐例采样参数 |
|---|---|---|---|---|---|---|---|
| CG-18 | 缺（只有 report-v1/p1） | 齐 | 齐 CWE-122 | 齐 | 缺 | 缺 | 仅 model + llm.enabled |
| CG-29 | 缺 | 齐 | 齐 CWE-122 | 齐 | 缺 | 缺 | 同上 |
| CG-30 | 缺 | 齐 | 齐 CWE-121 | 齐 | 缺 | 缺 | 同上 |
| CG-31 | 缺 | 齐 | 齐（但 checks 判 false，见 E1） | 齐 | 缺 | 缺 | 同上；sink 无 symbol |
| CG-36 | 缺 | 齐 | 齐 CWE-122 | 齐 | 缺 | 缺 | 同上；description 与崩溃点不同源 |
| VG-01 | 缺（`agent=null`） | 齐 | 齐 CWE-306 | 齐（AV:N 为保守外推） | 缺 | 缺 | 仅 model 名 |
| VG-01 额外 | 源码树缺（`src/` 空）、服务端日志缺（raw 不含 shutdown 事件）、CWE-306 模板缺 | | | | | | |

### 需要订正的两处文档（本次未改，建议随 E3 一起改）

1. `docs/MATERIALS.md` 写 VG-01「日志齐（原始 stdout）」——raw 日志实为 server stderr，内容是语料缺失异常，不含 shutdown 事件（复算脚本已按字符串计数验证）。
2. `workspace/VG-01-nltk-wordnet/report.md` 第 5 节先说「无原始 stdout」，随后又说「是 2026-11-13 原始采集」，两句矛盾。

## 8. 复核方式

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 experiments/COURSE-GAP-verify.py -v     # 当前结果：OK refs=80 identities=5 negative=2 history=6
```

复算内容：

- 80 条 ref 的文件存在性 / 行号范围 / 该行是否含 `expect` 子串（含源码行、日志行、patch 行、`SOURCE.md`）；
- 5 组数值恒等式：`65=32+1+32`、`6001=6000+1`、`196606=2×98303`（且 `98339=24+98315`）、`260=2×128+4`、`256=128×2`，以及 dwg.h 字段顺序给出的 `size` 偏移 4；
- VG-01 的负向事实：两份 raw 日志都不含 `Server shutting down`，但确实含 `in do_GET` 栈（证明日志真实、只是不含该事件）；
- 6 例的 ledger 字段与 `experiments/LEDGER-AUDIT.json` 逐字段一致（证明历史未被改写）。

## 9. 明确没做的事

- 没有改任何 `case.json` / `severity.json` / `LEDGER.json`，也没有往 `workspace` 里写 `propagation.json`——那一步（E2）需要独立复核签字，不能由本次盘点代劳。
- 没有把"字段补齐"说成"因果链已闭合"：`COURSE-GAP.json` 只记录 `classification` 与 `how_to_close`，`causal_chain_verified` 仍是 false。
- 没有为了凑第 10 例去抬严重性；CG-02 只列为**条件性**候选并写明依赖的评审口径。
- 没有 `git commit`（仓库当前不是 git 工作区）。
