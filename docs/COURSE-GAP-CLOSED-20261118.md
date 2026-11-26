# 课程证据缺口闭环（E1 + E2，2026-11-18）

> 输入：本目录 [COURSE-GAP-20261118.md](COURSE-GAP-20261118.md)（盘点）、
> [COURSE-GAP.json](../experiments/COURSE-GAP.json)（机读盘点）、
> 5 个 workspace 的落盘证据。
> 产物：本文件 + [COURSE-GAP-CLOSED.json](../experiments/COURSE-GAP-CLOSED.json)（机读记账）+
> [course_gap_wiring.py](../experiments/course_gap_wiring.py)（写要素/复算 refs）+
> [course_gap_closed.py](../experiments/course_gap_closed.py)（生成机读记账）+
> [test_course_causal_wiring.py](../tests/test_course_causal_wiring.py)。
> 纪律：**不改写历史判定**。基线（11-18 的 `cases[*].ledger/gate/classification`）原样保留，
> 闭环事实另存 `COURSE-GAP.json:closure` 与本文件；`logs/`、`artifacts/verify/`、
> `artifacts/locate/` 逐字节未写。

## 1. 结论

| 项 | 闭环前 | 闭环后 |
|---|---|---|
| `causal_chain_verified` 行数（LEDGER） | 5 | **10** |
| 独立高危根因 × （benchmark 验证 + 因果链） | 3 | **8** |
| 6 例盘点里的闭环数 | 0 / 6 | **5 / 6**（CG-18/29/30/31/36） |
| `high_severity_confirmed` | 9 | 9（口径未变） |
| `course_ready` | 0 | 0（缺官方回执 + 人工复核，见 §4） |

- **E2**：CG-18/29/30/36 的三要素档案 `workspace/<case>/propagation.json` 写入并生效，
  4 例 `propagation.complete=true`、`missing=[]`、`acceptance.causal_chain_verified=true`；
  CG-36 的 `checks.dataflow_has_evidence` 由 false 转 true（同一处机制）。
- **E1**：CG-31 的三处判据缺口按代码修掉（不是改字段）：帧解析器丢帧 → `weak`；
  `container-overflow` 无 kind 映射 → `{unspecified}`；CWE 按字面 `heap/stack`
  匹配 → `cwe_matches_crash=false`。修完后 `root_cause=strong`、`kind=memory_corruption`、
  `cwe_matches_crash=true`，`causal_chain_verified=true`。
- **VG-01**：按要求**不补字段**，仍 `needs_evidence`（`classification=needs_new_experiment`，
  `reaches_sink`/`missing_check` 仍是 `needs_evidence`，未写 `propagation.json`）。
- 仍差第 10 例独立高危：现有仓库里没有可合法升级的根因（见盘点 §5），仍要新跑（E4）。

## 2. E1：CG-31 是判据问题，而且是**帧解析器的真 bug**

盘点把 CG-31 归为"判据问题"是对的，但根因比预想的更靠底层：

1. **`FRAME_RE` 丢弃了 C++ 签名帧**（真 bug）。旧正则
   `#(\d+)\s+0x… in\s+(\S+)\s+(\S+):(\d+):(\d+)` 要求函数名不含空格；而 ASAN 的
   sink 帧长这样：

   ```
   #3 0x532b0e in Exiv2::BmffImage::brotliUncompress(unsigned char const*, unsigned long, Exiv2::DataBuf&) /src/exiv2/src/bmffimage.cpp:208:9
   ```

   签名里的逗号/空格让整行匹配失败 → 帧丢失 → `user_frames` 里第一个用户帧变成
   `readMetadata()` → `sink_not_in_stack` → 只能落到"原始日志文本命中"兜底（`weak`）。
   现在函数名取"行尾最后一个 `path:line:col`"之前，帧被正确解析，
   `first_user_frame` 就是 `bmffimage.cpp:208`（delta 0）→ `strong`。
   **这不是放宽标准**：栈里 `#1/#2` 是 `libbrotlidec` 的 DSO 帧（没有 `path:line:col`，
   本来就解析不到），真正被丢掉的是**目标程序自己的** sink 帧。
2. **`container-overflow` 无 kind 映射**：`_defect_kind` 只认
   `buffer-overflow`/`use-after-free`，落到 `else` 分支返回 `unknown`，必要要素退化成
   `{unspecified}`——**填多少要素都不可能 complete**。现在 `MEMORY_KINDS` 含
   `container-overflow`（[report.py:633](../agent/stages/report.py)）。
3. **CWE 判据按字面词匹配**：`_checks.cwe_ok` 只认崩溃文本里的 `heap`/`stack`，
   而 `container-overflow` 两个词都没有；`CRASH_TO_CWE` 也没有这一项。
   现在按 `diagnostics.CRASH_TO_CWE` 做语义对应（崩溃类型 + 读写方向 → 允许的 CWE 集合），
   只有崩溃类型未识别时才退回旧的文本判据（[diagnostics.py](../agent/diagnostics.py)）。
4. **判据修好后旧快照不会自己变**：`root_cause` 是 verify 那一次运行写下的。
   镜像已不在本机（`docker manifest inspect n132/arvo:61675-vul` 连不上 registry），
   不能假装重跑 verify。新增 [agent/regate.py](../agent/regate.py)：
   **只读** `artifacts/verify/result.json` 与它指向的原始日志，用当前判据重算
   `root_cause`/`cwe_by_crash`，并写下 `log_sha256`、解析帧数、判据版本。
   - `vul_exit` / `fix_exit` / `verdict` / `poc` 一律不动（执行类观测值只能由真跑产生）；
   - 重算结果**比原判更弱时不采纳**（记 `conflict`，交人工），防止借改判据把已通过案例翻掉。

改动前后的判据留痕（写在 `case.json.regate`）：

```json
{"applied": true, "criteria": "diagnostics-frames-v2+container-overflow-v1",
 "previous": {"matched": true, "confidence": "weak", "reason": "sink_line_in_raw_trace"},
 "reason": "rejudged:weak->strong",
 "provenance": {"log": "logs/V4.bmff-brob-98339.61675-vul.log",
                "log_sha256": "863d06c1bc40037d7f282dbb01999b9e90d60d0e977f002242b401cfeef3f2f9",
                "frames_parsed": 16, "user_frames": 14,
                "sink_source": "verify.root_cause.evidence.text_hit",
                "subject": "BmffImage::brotliUncompress",
                "kind": "container-overflow", "write": true}}
```

> 关于盘点里提的"写动作发生在第三方库、长度由 caller 算错，需要一条明确判据"：
> 修完帧解析后这条**不需要额外 policy 降级**了——按"首个用户帧 = 缺陷函数且行号一致"
> 的既有判据直接判 strong，因为栈里 `#3`（目标程序）就是 sink，`#1/#2` 只是它调用的库。
> 反过来，若某案例**只有**库内帧、目标程序帧完全不在栈里，则仍然是 `none`，
> 那条政策问题留给 E4 的新案例去碰。

## 3. E2：要素档案接线（为什么不重跑 locate）

### 3.1 机制改动

盘点的结构性缺口 #1 是"propagation 从未自动产出，全靠人工档案"。原实现只有
`locate` 读 `workspace/propagation.json` 并挂到 claim 上——于是"补要素"必然连带重跑
`locate`，而 `locate` 会重新生成 `artifacts/locate/findings.json`（还会调模型），
历史判定会被动到。本次把读取入口统一到 [agent/evidence.py](../agent/evidence.py)，
`report` 直接读档案：

```
workspace/<case>/propagation.json  ──merge_into_claim──>  claim.propagation.elements
                                                          claim.dataflow（缺失时由三要素合成）
report._propagation  ──>  stage_status.propagation{complete, missing, elements,
                                                   source, verified_by, reviewed_by, evidence_refs}
checks.dataflow_has_evidence  ──>  bool(claim.dataflow)   # CG-36 由同一步修复
```

顺带修掉盘点的结构性缺口 #3（自证）：`verified_by` 不再被代码写成 `manual_review`，
改为文件自己声明的 `evidence_refs`，人工复核另记 `reviewed_by/reviewed_at`——
本次**没有**填 `reviewed_by`（见 §4）。

### 3.2 逐例：要素与 refs

档案由 [course_gap_wiring.py](../experiments/course_gap_wiring.py) `--write` 生成，
`value/refs/computed/derivation` **逐字段抄自** `COURSE-GAP.json`（脚本不加工，
测试 `test_propagation_values_come_from_course_gap` 逐字段比对）。

| 案例 | 要素 | refs | refs 复算 | 关键恒等式 | before → after |
|---|---|---|---|---|---|
| CG-18 arvo:12420 | 4 | 15 | 全通过 | 260 B = 65 码点 = 32+1+32；66 写 / 64 区 | `local_verified_pending_evidence` → `causal_chain_verified` |
| CG-29 arvo:11011 | 4 | 13 | 全通过 | `calloc(1, 0)` → 1 字节区；`cmask=-1` | 同上 |
| CG-30 arvo:29633 | 4 | 14 | 全通过 | 6001 = 6000+1 写进 `char[4096]` | 同上 |
| CG-36 arvo:54839 | 4 | 13 | 全通过 | 256 = 128×2；写偏移 260 = 2×128+4 | 同上 + `dataflow_has_evidence` false→true |
| CG-31 arvo:61675 | 4 | 15 | 全通过 | 196606 = 2×98303；98339 = 24+98315 | `weak`→`strong`，`unknown`→`memory_corruption` |
| **合计** | 20 | **70** | 0 失败 | — | 5 例 causal chain 闭合 |

`refs` 的复算口径与 `experiments/COURSE-GAP-verify.py` 一致：文件存在且非空 /
行号在范围内 / 该行含 `expect` 子串（`line=null` 表示二进制或整文件证据）。
实现见 `agent/evidence.py:check_ref`，两条独立路径都会跑：
`python3 experiments/course_gap_wiring.py --verify` 与
`python3 -m pytest tests/test_course_causal_wiring.py`。

### 3.3 重跑：`--stages report` 原来跑不到 report

`bin/vulnmap.py run --stages` 旧语义是"从 recon 起走，遇到第一个未授权阶段就 break"，
于是 `--stages report` / `--stages locate,report` **一次都不会执行**（
`experiments/remediation-s0/note.md` 记过这个坑，当时只能写一次性脚本绕）。
本次改为"未列出的阶段标记 skipped，只向前跳过"，并新增 `--regate`：

```bash
python3 bin/vulnmap.py run workspace/S7-CG18-arvo-12420 --stages report --regate
# status=done  stages={recon:skipped, locate:skipped, verify:skipped, exploit:skipped, report:completed}
```

**镜像是怎么回事**：5 个 `n132/arvo:*` 镜像已不在本机，registry 不可达
（`docker manifest inspect` 超时；本机 33 个镜像里没有 arvo）。所以：

- `report` 在 re-gate 模式下 `requires_images=False`：不写检查点、不假装 docker 对账；
- `image_recorded` 这一条**保留但换口径**，写进 `case.json.image_provenance`：
  - live 模式（镜像在）：逐条 `docker inspect` 对账，与原实现一致；
  - recorded 模式（re-gate + 镜像不在）：要求四阶段检查点绑定的 digest
    **全是具体 sha256** 且**与上一版 case.json 的 `images` 逐条相同**，否则判 false。
    本次 5 例均 `mode=recorded_bindings`、`verified_live=false`、
    `matches_prior_case_json=true`（`live_error` 里如实记下 `No such image`）。
    这不是"放宽"：三条都不满足时 `image_recorded=false`，verdict 会被打成 `fail_checks`
    （测试 `test_image_provenance_rejects_digest_drift_and_missing_prior` 覆盖）。

**证据字节**：每例跑前跑后对 `artifacts/verify`、`logs`、`artifacts/locate`、
`artifacts/recon`、`artifacts/exploit` 做全量 sha256 清单比对（清单留档在
`experiments/course-gap-closed/evidence-manifest/<case>.{before,after}.sha256`，
共 106 行、逐行相同），5 例全部一致；
`case.json.upstream` 里记的 4 个上游哈希也等于当前文件哈希
（测试 `test_case_json_refreshed_and_sources_untouched` 断言）。

## 4. 没补的项（明确列出，不拿字段补齐冒充闭环）

| 项 | 状态 | 说明 |
|---|---|---|
| 官方回执 | 仍缺 | `official_receipt_not_attached`：需竞赛方回执，不在本仓能力内；5 例 `course_ready=false` |
| 人工复核签字 | 仍缺 | `case.json.acceptance.human_reviewed=false`；`propagation.json.reviewed_by=null`，`verified_by=evidence_refs` 只表示"能按 refs 复算"，**不是**复核 |
| 逐例采样参数 | 仍缺 | 温度 / max_tokens / 提示词版本仍未逐例落盘 |
| 镜像 live 对账 | 退化为 recorded | 镜像已删且 registry 不可达；`image_provenance.verified_live=false`，要恢复只需在有镜像的机器上再跑一次非 re-gate 的 report |
| 其它案例的 `root_cause` | 未重算 | 帧解析器修好后，**已落盘的 30 个 case.json 的 root_cause 是旧判据的快照**；本次只对 5 例重算。要把修正铺到其余案例必须重跑 verify（要镜像）——记为 E5，不在本次范围（改写历史判定也不在授权内） |
| CG-36 的 I1 | 仍缺 | `description.txt` 讲 `decode_r11`，与崩溃点 `decode_preR13` 不同源（上游 CVE 口径问题） |
| CG-31 的 `sink.symbol` | 仍为空 | 来自"文本命中"路径，没有函数符号；`case.sink.function` 有值 |
| VG-01 | 保持 needs_evidence | 服务端 shutdown 事件、源码树、CWE-306 要素模板都缺（E3）；`case.json` 无 `stage_status`，未写 `propagation.json` |
| 第 10 例独立高危 | 仍缺 | 现有仓库无可合法升级根因；需 E4（新跑） |

## 5. 代码改动（每项都有测试）

| 文件 | 改什么 | 为什么 |
|---|---|---|
| `agent/diagnostics.py` | `FRAME_RE` 容错（含逗号签名的帧不再丢）；`CRASH_TO_CWE` 增 `container-overflow`；新增 `expected_cwes()/cwe_for_crash()` | CG-31 的 `weak` 与 `cwe_matches_crash=false` 的**真根因** |
| `agent/stages/verify.py` | `cwe_by_crash` 改用 `cwe_for_crash()`（逐分支等价重构） | 两处 CWE 推导合一，避免 report/verify 口径分叉 |
| `agent/stages/report.py` | `MEMORY_KINDS` 含 `container-overflow`；`_cwe_matches_crash` 改语义对应；报告层直接读 `propagation.json`；`stage_status.propagation` 增 `source/verified_by/reviewed_by/evidence_refs`；re-gate 模式（`requires_images=False` + recorded 镜像证据链 + `case.regate` 留痕）；`image_refs()` 只给名字不再解析 digest | E1 三处判据 + E2 接线 + 离线可重判 |
| `agent/regate.py`（新增） | `rejudge_root_cause()` / `apply_rejudge()` / `rejudge_summary()` | 判据修好后用落盘证据重算，带 `log_sha256`/判据版本；更保守不采纳 |
| `agent/evidence.py`（新增） | `load_propagation/merge_into_claim/check_ref/check_all_refs` | 统一读取入口；`verified_by` 不再自证；refs 可复算 |
| `agent/stages/locate.py` | 两处要素合并改用 `merge_into_claim` | 口径统一 |
| `agent/stages/base.py` | `_save_checkpoint` 里 `image_refs()` 抛错不再让阶段失败 | 静态/离线阶段收尾处 `ImageMissing` 未捕获 |
| `agent/runtime/orchestrator.py`、`bin/vulnmap.py` | `--stages` 只向前跳过未授权阶段；新增 `--regate` | 让文档里的 `--stages report` 真的能跑 |
| `experiments/COURSE-GAP-verify.py` | history 校验改对**基线快照**；新增 `check_closure()` | 闭环后 `LEDGER-AUDIT.json` 已更新，再拿它比 11-18 基线只会假阳性 |
| `experiments/COURSE-GAP.json` | 只改 CG-31/`unspecified` 的 3 条 refs（代码行号随判据修复移动）+ 新增顶层 `closure` | 基线结论不动；refs 必须仍可复算 |
| `experiments/course_gap_wiring.py`、`course_gap_closed.py`（新增） | 写要素 / 复算 refs / 生成机读记账 | 数字从磁盘重算，不手抄 |
| `tests/test_course_causal_wiring.py`（新增） | 26 个用例 | 覆盖写入 / 重跑 / 判据 / 反例 |

## 6. 复算与验收

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 要素档案：70 条 refs 逐条复算
python3 experiments/course_gap_wiring.py --verify -v

# 2) 重跑（每例幂等；第二次的 prior_causal_chain_verified 会是 true）
python3 bin/vulnmap.py run workspace/S7-CG18-arvo-12420  --stages report --regate
python3 bin/vulnmap.py run workspace/S14-CG29-arvo-11011 --stages report --regate
python3 bin/vulnmap.py run workspace/S15-CG30-arvo-29633 --stages report --regate
python3 bin/vulnmap.py run workspace/S16-CG31-arvo-61675 --stages report --regate
python3 bin/vulnmap.py run workspace/S19-CG36-arvo-54839 --stages report --regate

# 3) 台账 + 核账 + 文档
python3 experiments/ledger.py && python3 experiments/audit_ledger.py
python3 experiments/gen_docs.py

# 4) 机读记账 + 盘点复算（含闭环校验）
python3 experiments/course_gap_closed.py --write
python3 experiments/COURSE-GAP-verify.py -v
#   -> OK  refs=80 identities=5 negative=2 history=6 closure=5

# 5) 测试
python3 -m pytest tests -q
```

当前结果：

- `experiments/LEDGER.json`：`causal_chain_verified 5 → 10`（`of_which_target_defect 4 → 9`）；
- `experiments/LEDGER-AUDIT.json`：`independent_high_verified 3 → 8`；
  冲突项从 6 条降到 **1 条**（只剩 VG-01 的 `high_without_causal_chain`）；
- `docs/STATUS.md` / `案例跟踪表.csv` 随台账重生成（5 行由「本地验证待补证据」变「因果链闭合」）；
- `pytest`：1236 → 1262 passed（新增 26），8 skipped。

### 6.1 一处与本次改动无关的已知不一致

`python3 experiments/check_consistency.py` 现在报 3 处 mismatch，全部是**口径定义差异**，
与 E1/E2 无关，也没有被本次改动放大：

| check | expected | actual | 解释 |
|---|---|---|---|
| `ledger_totals_vs_case_json` | 23 | 21 | 前者数 `verdict=="pass"`，后者数 `stage_status.local_dual_run.ok`，两个量本来就不同 |
| `ledger_totals_vs_case_json` | 0 | None | `ledger.py` 的 `totals` 里没有 `course_ready` 这个键 |
| `status_md_vs_ledger_totals` | 23 | 21 | 同上第一条（STATUS.md 写的是台账值） |

判断依据：5 例重判前后的 `verdict` 都是 `pass`、`stage_status.local_dual_run` 都是 `ok=true`，
所以这三个计数在闭环前也是 23/21；`tests/test_consistency.py` 的注释也写明
"真实案例目前有已知不一致，测试不能拿真实数据当 0 mismatch 的前提"。
本次**没有**顺手改这两个口径（改台账定义属于另一件事，且会让历史计数变动）；
顺带说明：跑这条审计会重写 `experiments/CONSISTENCY.json`（生成物，`generated_at` 已更新）。


## 7. 回滚

每例 `artifacts/report/` 下保留了改动前的三件备份（时间戳 `20261118T220419`）：

```
case.json.bak-regate-20261118T220419
report.md.bak-regate-20261118T220419
run_summary.json.bak-regate-20261118T220419
```

`propagation.json` 是新增文件（原本不存在），删掉即回到 E2 之前；
若以后重写会留 `propagation.json.bak-<ts>`。
`logs/`、`artifacts/verify/`、`artifacts/locate/`、`artifacts/recon/`、`artifacts/exploit/`
**没有被写过**（`experiments/course-gap-closed/evidence-manifest/` 的 before/after
清单逐行相同，可与 `case.json.upstream` 交叉核对）。

## 8. 明确没做的事

- 没有为了凑数改任何 `verdict` / `severity.json` / `LEDGER.json` 的历史结论；
  `causal_chain_verified` 的变化全部来自 `case.json` 重算，台账是重新生成的。
- 没有把"能按 refs 复算"写成"人工已复核"：`reviewed_by` 留空，
  `human_reviewed` 仍是 false，`course_ready` 仍是 false。
- 没有假装重跑过 `verify`：`executed_again=false`，`vul/fix` 退出码、`poc` 哈希、
  原始日志全部沿用落盘产物。
- 没有给 VG-01 补任何字段（任务要求），也没有替它写 `propagation.json`。
- 没有 `git commit`（本仓不是 git 工作区）。
