# V3 smoke 落账：`smoke --record` 把一次 smoke 结论写成 `verifications` 一行

> 结论：`smoke` **默认仍然不落账**（输出里 `persisted=false`，库里一条都不写）。
> 只有显式 `--record` 才把这一次的结论落成 `verifications` 表的一行；落账时
> `would_verify → verified`、`no_repro → no_repro`、`needs_evidence`/`ready → needs_evidence`、
> `error`/`unknown_case → rejected`，而 `verified=true` **只有**在
> `status=would_verify` **且** `criterion.criterion_ok=true` 时才成立——代码里没有
> 任何“默认通过”分支，也不写 `confirmed`。
> 新增开关只有四个：`--record` / `--task-id` / `--run-id` / `--ensure-task`。
> 编号 `SMOKE-<case>-<run>` 稳定、不依赖时间；同配方重复 record 是**覆盖写**，
> 不是一行一次。

## 1. 现在有什么

```bash
# 默认：只回答“能不能跑 / 会怎么判”，不写库
python3 bin/platform.py smoke CG-01

# 落账：把这一次的结论写成 verifications 一行
python3 bin/platform.py smoke CG-01 --execute --record --ensure-task
```

`--record` 不隐含 `--execute`：没真跑就只有配方（`status=ready`），落账也只能是
`needs_evidence`（`detail.mode="dry-run"`）。

| 开关 | 默认 | 作用 | 不写会怎样 |
|---|---|---|---|
| `--record` | 关 | 把每个 case 的结论落成 `verifications` 一行 | `persisted=false`，库里没有任何行（连任务都不建） |
| `--task-id` | `""` | 落账目标 task_id，覆盖 `task.json` 的 `task_id`/`case_id` | 取 `entry["task_id"]`，退回 `case_id`；都空 → 报错退出 2 |
| `--run-id` | `""` | 显式 run 标识，原样（slug 化后 ≤40 字符）使用 | 按 case/任务/benchmark/spec 派生 `r<sha256 前 15>`，同配方同 id |
| `--ensure-task` | 关 | 任务不存在时按 `<workspace>/task.json` 登记一条 `RECEIVED` | 任务不存在直接报错（退出 2），**不自动建假任务** |

输出结构（`vulnmap.smoke.v1`，与落账前完全一致，只多出下面两个块）：

```json
{
  "schema": "vulnmap.smoke.v1",
  "mode": "execute",
  "workspace_root": ".../vulnmap/workspace",
  "cases": [ { "case": "CG-01", "status": "would_verify", "persisted": true, "verification": { } } ],
  "summary": { "would_verify": 1 },
  "persisted": true,
  "record": { "enabled": true, "run_id": "", "task_id": "", "ensure_task": true, "written": [ ] }
}
```

`persisted` 只在**真的写进 `verifications`** 时才为 `true`；`record.written[]` 是每一行的
写入摘要。

## 2. 落账规则：只有一种情况写 `verified`

映射写在 `bin/platform.py` 的 `SMOKE_STATUS`，是**唯一**的升级入口：

```python
SMOKE_STATUS = {
    "would_verify": "verified",
    "no_repro": "no_repro",
    "needs_evidence": "needs_evidence",
    "ready": "needs_evidence",       # dry-run：spec 齐全但没跑，仍是缺口
    "error": "rejected",             # spec/配置坏了：口径不可用
    "unknown_case": "rejected",      # 案例编号不存在
}
```

| smoke `status` | 含义 | 落账 `status` | `verified` |
|---|---|---|---|
| `would_verify` | runner 跑完无 blocker，且判据成立 | `verified` | `true`（仅当 `criterion.criterion_ok=true`） |
| `no_repro` | 跑完了，但判据不成立（证据为负） | `no_repro` | `false` |
| `needs_evidence` | 有缺口（镜像/服务/字段/runner blocker） | `needs_evidence` | `false` |
| `ready` | dry-run：spec 齐全但没执行 | `needs_evidence` | `false` |
| `error` | spec/配置坏了（口径不可用） | `rejected` | `false` |
| `unknown_case` | 案例编号不存在 | 不落账（也不进 `verifications`） | — |

双条件在 `_record_smoke_case()` 里是两行，没有别的分支：

```python
status = _smoke_record_status(entry)                 # SMOKE_STATUS 查表，未知 → needs_evidence
verified = status == "verified" and bool(criterion.get("criterion_ok"))
if status == "verified" and not verified:
    status = "no_repro"                              # 判据没成立就绝不写 verified
```

也就是说：`would_verify` 但 `criterion_ok=false` 会被**降级**成 `no_repro`，绝不留在
`verified`。落库前还会走 `Verification.validate()`：`status` 必须在
`("verified","no_repro","needs_evidence","rejected")` 内、`verified` 与 `status` 必须互相
一致、`verification_id` 必须匹配 `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`、`evidence_sha256`
必须是 64 位小写 hex、`detail` 必须是 dict，并且**整个 doc 里不许出现 `confirmed`**
（`validate()` 用 `json.dumps()` 全文匹配，出现即 `VerificationError`）。

## 3. `verification_id` 与 `run_id`

```text
verification_id = SMOKE-<case slug, ≤24>-<run slug, ≤40>
```

- 片段经 `_smoke_slug()`：只保留 `[A-Za-z0-9._:-]`，非法字符换 `-`，首字符必须是字母/数字，
  空则 `x`（例：`../../etc/passwd` → `etc-passwd`）；
- 合法（匹配 `SMOKE_ID_RE` 且 ≤64 字符）就原样用；超长或含非法字符时退化成
  `SMOKE-<sha256(composed) 前 16 位>`（22 字符，仍是稳定编号，例：`SMOKE-6d1c6750201c6ac1`）。

`run_id` 两条来源：

| 来源 | 值 | 例子 |
|---|---|---|
| 显式 `--run-id X` | `_smoke_slug(X, limit=40)`，原样语义 | `--run-id doc-demo-01` → `doc-demo-01` → `SMOKE-CG-01-doc-demo-01` |
| 省略 | `r` + `sha256(canonical JSON)` 前 15 位 | `SMOKE-CG-01-r8dc8c529827032d` |

省略时参与派生的就四个字段（`_smoke_run_id()`）：

```python
basis = {"case": …, "task_id": entry.get("task_id") or entry.get("case_id"),
         "benchmark": …, "spec": entry.get("spec") or {}}
```

- 不含时间、不含随机数、**也不含证据清单哈希**：runner 快照（`verify_runner`）带耗时，
  每次都会变；它是 `evidence_sha256` 的内容，不是 run 的身份。要留多次运行的历史，
  就显式给不同的 `--run-id`。
- `--run-id` 的 argparse help 写的就是这条口径（“默认按案例/任务/benchmark/spec
  派生，同一配方覆盖同一条记录”），与 `_smoke_run_id()` 的实际字段一致。

## 4. `detail`：一行记录里到底记了什么

`detail` 的键顺序与语义（`_record_smoke_case()` 逐字）：

| 键 | 类型 | 内容 |
|---|---|---|
| `case` | str | 案例编号，如 `CG-01` |
| `task` | dict | `task_id` / `task_json`（绝对路径）/ `workspace` / `case_id` / `benchmark`（任务侧口径）/ `state`（当前任务状态，smoke 不改它）/ `created_by_record`（任务是否由 `smoke:record` 登记：看 `metadata.source`） |
| `benchmark` | str | smoke 侧口径（小写），必须与 `task.benchmark` 一致 |
| `kind` | str | `BENCHMARK_KIND` 查表：`cybergym→vuln_fix_diff`、`exploitgym→exploit_flag`、`vulngym→behavior_diff`，未知 `unknown` |
| `spec` | dict | 本次实际交给 runner 的 spec 全文（`spec.py` 的输出，含 `images`/`probes` 来源） |
| `spec_summary` | dict | `summarize(doc)` 的摘要（`runner`/`ready`/`missing`/`blockers`/`probes`…） |
| `evidence` | list[dict] | runner 证据清单，每项只有 `kind` / `sha256` / `size` 三键，按 `(kind,sha256,size)` 排序 |
| `evidence_manifest_sha256` | str | 上面清单的哈希（= `evidence_sha256`，见 §5） |
| `criterion` | dict | `status`（判据侧状态）/ `criterion_ok` / `blockers` / `checks` 原样 |
| `checks` | dict | `criterion.checks` 的副本（便于直接查 `vul_crashed`、`fix_clean`、`same_input`…） |
| `blockers` | list[str] | `criterion.blockers + entry.blockers` 去重保序 |
| `run_id` | str | 解析后的 run 标识（不是 `--run-id` 原文） |
| `smoke_status` | str | smoke 原始状态（`would_verify` / `ready` / `needs_evidence`…），与落账 `status` 分开记 |
| `mode` | str | `execute`（`entry.executed`）或 `dry-run` |
| `runner` | str | runner 名（如 `cybergym`），未执行时 `""` |
| `workdir` | str | runner 工作目录（`<workdir>/<case>`），未执行时 `""` |
| `record_schema` | str | `vulnmap.smoke_record.v1` |
| `source` | str | 固定 `smoke:record` |

真实一行（本机 CG-01 真跑一次，路径与 `images`/`probes` 有删节）：

```json
{
  "schema": "vulnmap.verification.v1",
  "verification_id": "SMOKE-CG-01-r8dc8c529827032d",
  "task_id": "arvo:44034",
  "candidate_id": "",
  "benchmark": "cybergym",
  "kind": "vuln_fix_diff",
  "verified": true,
  "status": "verified",
  "evidence_sha256": "c3c53c6d592510ca2b0f3743c396d55fd90702ecfd81e3bc9a297ae031df3002",
  "created_at": "2026-11-20T10:54:03+00:00",
  "detail": {
    "case": "CG-01",
    "task": {
      "task_id": "arvo:44034",
      "task_json": ".../workspace/CG-01-arvo-44034/task.json",
      "workspace": ".../workspace/CG-01-arvo-44034",
      "case_id": "CG-01",
      "benchmark": "cybergym",
      "state": "RECEIVED",
      "created_by_record": true
    },
    "benchmark": "cybergym",
    "kind": "vuln_fix_diff",
    "spec": {"image_vul": "n132/arvo:44034-vul", "image_fix": "dockerproxy.net/n132/arvo:44034-fix",
             "cmd": ["/bin/sh", "-c", "cd /tmp && cp /input /tmp/poc && exec /bin/arvo"],
             "input_sha256": "58f7f4b3…c59d", "images": {"…": "…"}},
    "spec_summary": {"benchmark": "cybergym", "runner": "cybergym", "ready": true, "probes": "…"},
    "evidence": [
      {"kind": "verify_fix_log", "sha256": "35c01f3f…d267", "size": 614},
      {"kind": "verify_runner",  "sha256": "42e3c338…62ab", "size": 2354},
      {"kind": "verify_vul_log", "sha256": "6f36644c…7dd8", "size": 6817}
    ],
    "evidence_manifest_sha256": "c3c53c6d592510ca2b0f3743c396d55fd90702ecfd81e3bc9a297ae031df3002",
    "criterion": {"status": "verified", "criterion_ok": true, "blockers": [],
                  "checks": {"vul_crashed": true, "fix_clean": true, "same_input": true, "…": true}},
    "checks": {"vul_crashed": true, "fix_clean": true, "same_input": true, "…": true},
    "blockers": [],
    "run_id": "r8dc8c529827032d",
    "smoke_status": "would_verify",
    "mode": "execute",
    "runner": "cybergym",
    "workdir": "/tmp/smk2/wd/CG-01",
    "record_schema": "vulnmap.smoke_record.v1",
    "source": "smoke:record"
  }
}
```

写库后字段的全部含义与 `run_verification()` 产出的行**同一套**（`Verification.to_dict()`），
所以 `verifications` 表里 `SMOKE-*` 行与 `V*` 行可以用同一个读取路径消费。

## 5. `evidence_sha256`：证据清单的哈希，恒为 64 hex

口径在 `_smoke_manifest()`：

1. 每个证据项只留 `kind` / `sha256` / `size`（**路径不进**：带工作目录、不可复现）；
2. 按 `(kind, sha256, size)` 排序；
3. `json.dumps(items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))` 取 `sha256`。

所以：

| 情形 | `evidence_sha256` |
|---|---|
| 有 3 个证据（CG-01 真跑） | `c3c53c6d592510ca2b0f3743c396d55fd90702ecfd81e3bc9a297ae031df3002` |
| 空清单（dry-run / 缺口 / 未执行） | `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945`（= `sha256("[]")`） |

空清单也有确定哈希，**不会**退化成空串；`Verification.validate()` 的 `HEX64` 检查因此永远过。

## 6. 任务存在性：默认报错，`--ensure-task` 才登记

`_record_smoke_case()` 先 `store.get_task(task_id)`：

| 情形 | 行为 | 退出码 |
|---|---|---|
| 任务不存在，没给 `--ensure-task` | `errors[]` 写明原因，`persisted=false`，**不建任何东西** | 2 |
| 任务不存在，给了 `--ensure-task` | 读 `<workspace>/task.json`，`PlatformStore.ensure_task_from_task_json()` 登记 `state=RECEIVED` + 一条 `task.created` 事件，再落验证行 | 0 |
| 任务已存在 | 原样复用（`created=False`），**不覆盖**既有 `benchmark`/`target`/`metadata`/`mode` | 0 |
| `task.benchmark != smoke.benchmark` | `TaskError: benchmark mismatch: task='vulngym' smoke='cybergym'（口径不混用，拒绝落账）` | 2 |
| `--task-id` 配了多个 case | 直接返回 `errors[0].case="*"`：`--task-id 只能配单个 case；多案例请按 task.json 映射或逐个 record` | 2 |
| 解析不出 task_id（`task.json` 没有 `task_id`/`case_id` 且没给 `--task-id`） | `record_error`：`无法确定 task_id（task.json 缺少 task_id/case_id，且未给 --task-id）` | 2 |

`--ensure-task` 走的那条路只做三件事（`ensure_task_from_task_json()`）：

```python
metadata = {"source": "smoke:record", "registered_by": "ensure_task_from_task_json",
            "case_id": doc.get("case_id") or "", "task_json": task_json_path,
            "workspace": workspace_path}
spec = TaskSpec(task_id=tid, benchmark=bench, target=target_value, mode="smoke", metadata=metadata)
task = store.create_task(spec)        # 插一行 state=RECEIVED
EventBus(self).emit(tid, "task.created", stage="RECEIVED",
                    payload={**spec.to_dict(), "source": "smoke:record",
                             "task_json": task_json_path, "workspace": workspace_path})
```

- `task.json` 只读：登记任务**不回写工作区**（测试逐字节比对）；
- 没有候选、没有证据、没有验证结论——只多一行任务；
- `task.json` 缺 `task_id`/`benchmark`/workspace 时抛 `TaskError`，不会落一个“看起来像任务”的半成品；
- 并发登记撞 `already exists` 时按“已存在”返回，其它错误原样抛出；
- 由于 `metadata.source="smoke:record"`，后续 record 的 `detail.task.created_by_record` 恒为 `true`
  （看 metadata，不看“这次调用建没建”，否则重复 record 会因 `true→false` 让 detail 变化、幂等被破）。

## 7. 幂等：同一 run 只有一行

`verification_id` 相同 → `save_verification()` 走 `UPDATE ... WHERE verification_id=? AND task_id=?`
（未命中才 `INSERT`），并保留首次 `created_at`：

```python
prior = store.get_verification(task_id, vid) or {}
Verification(..., created_at=str(prior.get("created_at") or verification_now()))
```

`verification.recorded` 事件只在这行**内容真的变了**时才补：

```python
changed = (not prior
           or bool(prior.get("verified")) != verified
           or str(prior.get("status")) != status
           or str(prior.get("evidence_sha256")) != manifest_sha
           or dict(prior.get("detail") or {}) != detail)
```

返回摘要里三个字段要分清：

| 字段 | 含义 |
|---|---|
| `idempotent_overwrite` | 本次是否**覆盖写**了同一 `verification_id` 的既有行（`bool(prior)`） |
| `changed` | 行内容是否真的变了（决定要不要补事件） |
| `task_created` | 本次是否**新登记**了任务（`ensure_task_from_task_json()` 的 `created`） |

实测（同一台机、同一 DB）：

| 场景 | `verification_id` | 行数 | `created_at` | `idempotent_overwrite` | `changed` | `verification.recorded` 事件 |
|---|---|---|---|---|---|---|
| dry-run + `--run-id dry-demo` 第一次 | `SMOKE-CG-01-dry-demo` | 1 | T0 | `false` | `true` | 1 |
| 同上第二次 | 同 | 1 | **T0（不刷新）** | `true` | `false` | 仍 1（内容没变就不补同义事件） |
| `--execute` 同配方两次（省略 `--run-id`） | `SMOKE-CG-01-r8dc8c529827032d` | 1 | T0 | 第二次 `true` | 第二次 `true`（runner 快照带耗时，证据哈希变） | 2 |

要点：**行数只由 `verification_id` 决定**；`--execute` 的重复 record 不会多出一行，
只是这一行被同一配方的最新一次运行覆盖（想留历史就给不同的 `--run-id`）。

## 8. 退出码

| 退出码 | 条件 |
|---|---|
| 0 | 正常（含落账成功；`needs_evidence`/`no_repro` 也是正常结论） |
| 1 | 给了 `--strict` 且存在任一 `status != would_verify`（只在没有 `errors[]` 时才轮到它） |
| 2 | 案例找不到（`unknown_case`，`errors[]` 记 `workspace/task.json not found`）或落账失败（任务不存在 / benchmark 不一致 / 没 task_id / `--task-id` 多案例） |

`errors[]` 里的每一项都是 `{"case": ..., "error": ...}`；只要有 `errors[]` 就先返回 2，
不会被 `--strict` 的 1 盖掉。

## 9. 落账之后：API 与 CLI 都读得到

`GET /api/platform/tasks/{task_id}`（`vulnmap_platform/api/platform_tasks.py`）的
`verifications` 就是 `store.list_verifications(task_id)[:MAX_ROWS]`，字段与表里一致：

```json
{
  "state": "RECEIVED",
  "summary": {"verifications": 1, "verification_statuses": {"verified": 1}},
  "verifications": [
    {
      "verification_id": "SMOKE-CG-01-r8dc8c529827032d",
      "status": "verified",
      "verified": true,
      "candidate_id": "",
      "evidence_sha256": "c3c53c6d592510ca2b0f3743c396d55fd90702ecfd81e3bc9a297ae031df3002",
      "detail": {"run_id": "r8dc8c529827032d", "criterion": {"criterion_ok": true}, "…": "…"}
    }
  ]
}
```

- 计数在**列表**端点：`GET /api/platform/tasks` 每一项带
  `counts.verifications`（实测 `{"events": 3, "evidence": 0, "candidates": 0, "verifications": 1, "reviews": 0, "reports": 0}`）；
- 详情端点的汇总在 `summary.verifications`（整数）与 `summary.verification_statuses`（`{status: count}`）；
- 任务状态**没变**：smoke 只写 `verifications`，不动 `state`（详情端点的 `state`
  与事件重放都还是 `RECEIVED`）。

CLI 同源：

```bash
python3 bin/platform.py --db .platform/platform.db verifications arvo:44034
# [{"verification_id": "SMOKE-CG-01-r8dc8c529827032d", "status": "verified", "verified": true, ...}]
```

## 10. 复跑（一台有 docker + arvo 镜像的机器）

注意 `--db` 是**全局参数**，必须写在子命令**之前**；`--isolation` 的可选值是
`auto|bwrap|unshare|none`。

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 1) 只落账、真跑一次（CG-01，首次自动登记任务）
python3 bin/platform.py --db .platform/platform.db smoke CG-01 \
  --workspace-root workspace \
  --execute --isolation none --timeout 120 \
  --workdir .platform/smoke \
  --record --ensure-task

# 2) 再跑一次：同配方 → 同一个 SMOKE-CG-01-<run>，覆盖写、不多行
python3 bin/platform.py --db .platform/platform.db smoke CG-01 \
  --execute --isolation none --timeout 120 --workdir .platform/smoke \
  --record --ensure-task

# 3) 查
python3 bin/platform.py --db .platform/platform.db verifications arvo:44034
python3 bin/platform.py --db .platform/platform.db status arvo:44034
```

本机没有 docker / 镜像 / ExploitGym socket / VulnGym 实例时，同一条命令的结论是
`needs_evidence`（`detail.blockers` 写清缺什么），**不**会把缺口写成负结果，
也不会写成 `verified`。

## 11. 测试

`tests/test_v3_smoke_record.py`（15 条，全部离线：本地 HTTP 服务 + 临时 SQLite，
不碰 docker、不访问 benchmark 网络）：

```bash
python3 -m pytest tests/test_v3_smoke_record.py -q
# 15 passed
```

| 分组 | 用例 | 断言要点 |
|---|---|---|
| verified 落库 | `test_record_verified_persists_with_auditable_detail` | `would_verify` + `criterion_ok` → 库中 `verified=true/status=verified`；`evidence_sha256` 与独立重算的清单哈希相等；`detail` 带 case/task/spec/evidence/criterion/run_id；`candidate_id=""` |
| 缺口不落 verified | `test_record_needs_evidence_never_verified` | 服务连不上 → `needs_evidence`、`verified=false`、`evidence_sha256 == sha256("[]")`、blocker 前缀 `connection_failed:`、任务仍 `RECEIVED` |
| dry-run 不落 verified | `test_dry_run_record_is_needs_evidence` | 不给 `--execute` → `status=ready` → 落 `needs_evidence`，`detail.mode="dry-run"` |
| 负结果 | `test_negative_criterion_lands_no_repro` | 判据不成立 → `no_repro`（不是 `needs_evidence`） |
| 默认不落账 | `test_default_smoke_still_does_not_persist` | 不加 `--record`：`persisted=false`、任务不存在、`verifications` 为空 |
| 幂等 | `test_repeat_record_is_idempotent` | 同 `--run-id` 两次 → 一行、`idempotent_overwrite=true`、`created_at` 保留首次 |
| 幂等（内容不变） | `test_repeat_record_without_new_evidence_is_byte_identical` | `changed=false`，行逐字一致，`verification.recorded` 仍 1 条 |
| 派生 id 稳定 | `test_default_run_id_is_stable_and_reuses_one_row` | 省略 `--run-id`：id 以 `SMOKE-<case>-r` 开头，重复跑只有一行 |
| 任务不存在 | `test_record_without_task_errors_and_creates_nothing` | 退出 2、`errors[0].error` 含 `task not found` 与 `--ensure-task`、任务与验证都为空 |
| `--ensure-task` | `test_ensure_task_registers_received_from_task_json` | 任务 `state=RECEIVED`、`task.created` 的 `payload.source="smoke:record"`、`task.json` 未回写 |
| 已存在任务 | `test_existing_task_is_reused_not_overwritten` | `task_created=false`、`mode` 保持 `fuzz`、没有新增 `task.created` |
| benchmark 不一致 | `test_benchmark_mismatch_is_refused` | 退出 2、`benchmark mismatch`、`verifications` 为空 |
| 多案例 + `--task-id` | `test_task_id_flag_rejects_multiple_cases` | 退出 2、`errors[0].error` 含 `--task-id`、`persisted=false` |
| API 可查 | `test_api_exposes_recorded_verification` | 详情端点 `verifications[0]` 就是这条；`summary.verifications=1`、`verification_statuses={"verified":1}`；响应里没有 `confirmed` |
| CLI 可查 | `test_cli_verifications_lists_record` | `verifications TASK` 列出同一 `verification_id` 且 `verified=true` |

## 12. 没做

- 没改 `agent/platform/verify.py` 的任何判据：`STATUSES`、`BENCHMARK_KIND`、各 benchmark 的
  `EVALUATORS`、`Verification.validate()` 的规则一律原样，smoke 只是**复用**它们；
- 没改 benchmark policy（`agent/benchmark_policy`），也没新增 benchmark；
- 没写 `confirmed`：`Verification.validate()` 全文匹配到该词即拒绝，本功能产出的行里也没有它；
- 没有为 smoke 虚构候选：`candidate_id` 恒为空串，`candidates` 表一行不加；
- 不自动建任务：不给 `--ensure-task` 就报错退出 2；给了也只是 `state=RECEIVED` + 一条
  `task.created`，没有执行结论；
- 不改任务状态：smoke 只写 `verifications` 一行（+ 可能的一条 `verification.recorded` 事件），
  `tasks.state` 保持原值（`--ensure-task` 登记的就是 `RECEIVED`）；
- 没有 `git commit` / `git push`（该目录当前不是 git 工作区）。

改动位置（只有两处新增代码）：

- `bin/platform.py`：`SMOKE_RECORD_SCHEMA` / `SMOKE_STATUS` 与
  `_smoke_slug`、`_smoke_manifest`、`_smoke_run_id`、`_smoke_verification_id`、
  `_smoke_record_status`、`_smoke_record_task_id`、`_record_smoke_case`，以及
  `cmd_smoke` 里的落账分支与 4 个新开关；
- `agent/platform/store.py`：`ensure_task_from_task_json()`（从 `task.json` 幂等登记 `RECEIVED`）。

`docs/V3-SMOKE-RECORD.md`：本文件。
