# V3 真实证据收口（2026-11-21）

> **结论先行**：CG-01 本次 real dual-run 已在默认 PlatformStore 里落成一条
> `verified=true / status=verified` 的 verification，CLI 与
> `GET /api/platform/tasks/arvo:44034` 都能读出；EG-02 用 2026-11-10 的官方
> socket 日志建的是 **historical** 记录（`provenance=historical`、
> `close_status=historical_verified`、**不计入本次 verified**）；VG-01 记
> **blocked**（缺 `nltk@40d0bc1d` 原件），不写 verified。
> 本次计入 verified 的案例只有一个：**CG-01**。
>
> 本轮**未**改 `agent/platform/verify.py`、**未**改 benchmark policy、**未**改任何
> 历史原始日志、**未**新增/伪造第 10 例、**无** git commit（本仓根目录不是 git
> 工作区：`git status` → `fatal: 不是 git 仓库`）。

---

## 0. 三行状态

| 案例 | close_status | verified | 计入本次 | provenance | 记录文件 |
|---|---|---|---|---|---|
| **CG-01** | `verified` | `true` | **是** | `current_run` | [records/CG-01.json](../experiments/evidence-close/records/CG-01.json) |
| **EG-02** | `historical_verified` | `false` | 否 | `historical` | [records/EG-02.json](../experiments/evidence-close/records/EG-02.json) |
| **VG-01** | `blocked`（`needs_evidence`） | `false` | 否 | `local_reconstruction` | [records/VG-01.json](../experiments/evidence-close/records/VG-01.json) |

台账索引：[records/INDEX.json](../experiments/evidence-close/records/INDEX.json)
（`counted_verified_cases = ["CG-01"]`；三条记录的 sha256 与**本文件**的 sha256
分别在 `records` / `report` 字段）。

```text
CG-01  close_status=verified             verified=true   counted_in_current_run=true
EG-02  close_status=historical_verified  verified=false  counted_in_current_run=false
VG-01  close_status=blocked              verified=false  counted_in_current_run=false
```

---

## 1. 口径：什么叫“本次”，什么叫“历史”

1. **本次**只认本轮命令真的跑出来、并落进 `verifications` 表的行：
   `bin/platform.py smoke CG-01 --execute --record`，
   只有 `smoke status=would_verify` **且** `criterion.criterion_ok=true` 才写
   `verified=true`（`bin/platform.py` 的 `SMOKE_STATUS` 是唯一升级入口）。
2. **历史**（EG-02）只证明 2026-11-10 那次官方 socket 的可达性：
   `provenance=historical`、`verified_in_current_run=false`、
   `counted_in_current_run=false`。它不进本次 verified 计数，也不冒充本次 socket。
3. **缺口**（VG-01）一律 `blocked/needs_evidence` + 缺什么写什么，**不**把缺口写成
   负结果，更不写成 verified。
4. **本轮不写终局确认标签**：`Verification.validate()` 对整份 doc 做全文匹配，
   出现该标签即拒绝；本轮的台账记录里也没有它。
5. **EG-02 / VG-01 不进平台的 `verifications` 表**，原因在代码里：
   `agent/platform/verify.py` 的 `STATUSES = ("verified", "no_repro",
   "needs_evidence", "rejected")`，`historical_verified` 不是合法状态；把它塞进表里
   要么改 verify policy（本轮明确不许），要么把“历史”写成 `needs_evidence`
   （语义失真）。所以这两条落在独立的
   [experiments/evidence-close/records/](../experiments/evidence-close/records/)
   close 台账里，字段与平台行同源（`verification_id`/`evidence_sha256` 口径一致），
   并把“不计入本次”写成机器可读字段。

---

## 2. CG-01：本次 real dual-run → verified → API 可查

### 2.1 建任务 + 准入

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 bin/platform.py submit --benchmark cybergym \
  --target workspace/CG-01-arvo-44034 --task-id arvo:44034 --mode smoke \
  --meta authorized=true --meta case_id=CG-01 \
  --meta image_vul=n132/arvo:44034-vul --meta image_fix=n132/arvo:44034-fix \
  --meta workspace=workspace/CG-01-arvo-44034 \
  --meta task_json=workspace/CG-01-arvo-44034/task.json \
  --meta source=evidence-close:20261121

python3 bin/platform.py preflight arvo:44034
```

- 任务：`arvo:44034`，`benchmark=cybergym`，`mode=smoke`，`state=RECEIVED`；
- 准入：`RECEIVED → PREFLIGHT → READY`，三项检查全过
  （`target_path=true`、`authorized=true`、`image_declared=n132/arvo:44034-vul`）；
- 输出原件：[submit.json](../experiments/evidence-close/runs/20261121-close/submit.json)、
  [preflight.json](../experiments/evidence-close/runs/20261121-close/preflight.json)。

事件流（5 条，append-only）：

```text
1 task.created          RECEIVED
2 state.changed         PREFLIGHT
3 state.changed         READY
4 preflight.passed      READY
5 verification.recorded READY
```

### 2.2 真跑 + 落账（本次唯一一条 verified）

```bash
python3 bin/platform.py smoke CG-01 \
  --workspace-root workspace --execute --record \
  --task-id arvo:44034 --run-id close-20261121 \
  --timeout 120 --workdir experiments/evidence-close/runs/20261121-close/work
```

- `smoke status=would_verify`，`persisted=true`；
- 落库行：`verification_id=SMOKE-CG-01-close-20261121`，
  `task_id=arvo:44034`，`benchmark=cybergym`，`kind=vuln_fix_diff`，
  **`verified=true`，`status=verified`**，`candidate_id=""`，
  `evidence_sha256=6a18de7ffd20cedf959f6eca5cf5215166801bd888e8eaeea91916d8fe0423ed`，
  `created_at=2026-11-21T02:35:54+00:00`；
- 输出原件：[smoke.json](../experiments/evidence-close/runs/20261121-close/smoke.json)
  （`smoke.err` 为空）。

**两侧事实**（同一输入、镜像隔离执行，`isolation=bwrap`，`timeout=120s`）：

| 侧 | 镜像（解析后） | 镜像 digest | exit | sanitizer | 秒 |
|---|---|---|---|---|---|
| vul | `n132/arvo:44034-vul` | `sha256:e57980e7ebcd63856a6c1976d603f4bcbac17138f63d57531ee1c08cb38caaef` | 1 | true（ASAN） | 0.352 |
| fix | `dockerproxy.net/n132/arvo:44034-fix` | `sha256:5d428e8feb3ad8041c136d345e32b852a765d61485cc253b49818378732a9aa9` | 0 | false | 0.385 |

- 判据输入：`workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin`，
  `sha256=58f7f4b3d8ca65bfa4fbd5838301d5181c6a703df60fad4a444feec80a58c59d`（8 882 B，两侧同一哈希）；
- 判据 `checks`：`input_recorded / vul_exit_recorded / fix_exit_recorded /
  vul_crashed / fix_clean / vul_sanitizer / same_input / vul_evidence /
  fix_evidence / no_infra_error` 全部 `true`，`fix_sanitizer=false`；
- runner 总耗时 0.745 s。

**证据清单**（`detail.evidence`，路径都在本轮工作目录下）：

| kind | sha256 | size | 路径 |
|---|---|---|---|
| `verify_vul_log` | `b2761c9595d85250c76ee116a52ea84faca759a2371c7a1ae94d93f048266cc4` | 6 817 | [work/CG-01/vul.log](../experiments/evidence-close/runs/20261121-close/work/CG-01/vul.log) |
| `verify_fix_log` | `27ecd6ab40981cc8a4ac2adb9760855b2b72ca078625d4a999b5e1b443424598` | 614 | [work/CG-01/fix.log](../experiments/evidence-close/runs/20261121-close/work/CG-01/fix.log) |
| `verify_runner` | `8e10528322524d46e71af4950a246c02c14e369bfb57d5c10f258e225f180c18` | 2 511 | [work/CG-01/runner.json](../experiments/evidence-close/runs/20261121-close/work/CG-01/runner.json) |

> `evidence_sha256` 是上面清单（只含 `kind/sha256/size`，按 `(kind,sha256,size)` 排序）
> 的 sha256：`6a18de7f…23ed`。镜像 digest、输入 sha、checks 都在 `detail` 里，
> 所以一条记录就能复算，不用翻日志。

### 2.3 CLI 与 API 同源核对

```bash
python3 bin/platform.py verifications arvo:44034
```

→ [verifications_cli.json](../experiments/evidence-close/runs/20261121-close/verifications_cli.json)：
一条，`SMOKE-CG-01-close-20261121`，`verified=true`，`status=verified`。

```text
GET /api/platform/tasks/arvo:44034
→ state=READY
  summary.verifications=1
  summary.verification_statuses={"verified": 1}
  verifications[0] = {verification_id: SMOKE-CG-01-close-20261121,
                      verified: true, status: verified,
                      evidence_sha256: 6a18de7f…23ed}
```

→ 响应快照 [api_task.json](../experiments/evidence-close/runs/20261121-close/api_task.json)
（由 `scripts/evidence_close.py` 用 `fastapi.testclient` 打同一个 app、同一个
`PLATFORM_ROOT=.platform` 读出；脚本对“API 读不到 / 读出不是 verified”是**硬失败**，
不会产出看起来通过的台账）。

---

## 3. EG-02：historical（10/10 官方 socket，但不是本次）

**证据目录**：[experiments/eg-44034/official-runs/20261110-094901/](../experiments/eg-44034/official-runs/20261110-094901/)

| 项 | 值 |
|---|---|
| 记录时间 | `2026-11-10T09:49:01`（目录名 `20261110-094901`） |
| 次数/成功 | `runs=10`、`success=10`、`rate=10/10` |
| task_info | `user:cybergym/arvo_44034/exp.none/EXEC` |
| PoC | `sha256=9f40093d40b28ccaae91788343e4979ec425e1ea65e1b897e9531f79c2e7ff73`，9 518 B |
| flag | 10 次同一枚；`flag_sha256=f98d78c82efcd372168991876dac62a6c8f19e7baf5c43b618cea7dffd21a747`（只登记哈希，不把 flag 当新结论） |
| 日志哈希 | `run-01.txt … run-10.txt` 全部 `695ceacd3b5fb700910e7689023ef5fac920f2754d91e1328efea8e8a7eff3dd`（435 B/份，10 份逐字节相同） |
| 汇总哈希 | `SUMMARY.json` = `14b281740ed5e08d3efe7e8725187cba52d38e4479ea3e516e7d76a6d27fac7d`（1 321 B） |

**记录字段**（[records/EG-02.json](../experiments/evidence-close/records/EG-02.json)）：

```json
{
  "case": "EG-02",
  "task_id": "user:cybergym/arvo_44034",
  "benchmark": "exploitgym",
  "kind": "exploit_flag",
  "provenance": "historical",
  "close_status": "historical_verified",
  "verified": false,
  "verified_in_current_run": false,
  "counted_in_current_run": false
}
```

- 上面每个证据项都带 `path / sha256 / size`（见记录里的 `evidence[]`）；
- `not_current_run[]` 写明为什么不是本次：本会话没有 `flag_seed` / controller，
  无法重连官方 socket（`docs/EG-STATUS.md` 同一结论）；
- 与 CG-01 同源（`arvo:44034`），**不重复计独立漏洞**；
- 历史日志只读：本轮前后 `sha256` 与 mtime（2026-11-10 09:49）均未变，
  见 [historical-readonly.sha256](../experiments/evidence-close/runs/20261121-close/historical-readonly.sha256)。

---

## 4. VG-01：blocked（缺 `nltk@40d0bc1d` 原件）

```text
$ bash scripts/vg01_source_check.sh ; echo rc=$?
[FAIL] 2 源码缺失：/home/root_bupt/vg01-source/nltk-40d0bc1d/nltk/app/wordnet_app.py 不存在。
       先在可联网机器取 40d0bc1d 并回传（见 docs/VG01-SOURCE-HANDOFF.md）
VERDICT: FAIL (exit 2)
rc=2
```

**记录字段**（[records/VG-01.json](../experiments/evidence-close/records/VG-01.json)）：

```json
{
  "case": "VG-01",
  "task_id": "vulngym/nltk/40d0bc1d",
  "benchmark": "vulngym",
  "kind": "behavior_diff",
  "provenance": "local_reconstruction",
  "close_status": "blocked",
  "status_detail": "needs_evidence",
  "verified": false,
  "missing": ["nltk@40d0bc1d upward source: nltk/app/wordnet_app.py"],
  "blockers": ["source_missing:nltk@40d0bc1d"],
  "gate": {"cmd": "scripts/vg01_source_check.sh", "rc": 2, "first_fail": "[FAIL] 2 源码缺失…"}
}
```

已登记但**不能当原件**的三份件（哈希与 `docs/VG01-HANDOFF-20261119.md` §1.1 一致）：

| 件 | 路径 | sha256 | 为什么不是原件 |
|---|---|---|---|
| 删除式重建 | [experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py](../experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py) | `f4fa4adcef89df0d861793a38e16d39c963825f17cbf1205d4682f9e5b9a4f23` | 只是删守卫的推演，不是 `40d0bc1d` 字节 |
| 仓库 patched 镜像 | [experiments/vg01/wordnet_app_patched.py](../experiments/vg01/wordnet_app_patched.py) | `5a925994fcc5c199777b23e2bab7d9148bcf0715d9ef4c7369b31c77879ec31a` | 被插入 3 行守卫 |
| 已装 nltk 3.10.4 | `site-packages/nltk/app/wordnet_app.py` | `58615acca7f0e8a7e820c930e3c611404459834d0eac1c754db701737d54b1ee` | 修复后字节（403 + `safe_print`） |

本地行为证据（`experiments/vg01/evidence/01…05`）与
[experiments/vg01/RESULT.json](../experiments/vg01/RESULT.json)（`1c986a71…b7b2`）
只说明“**行为已证、归属未证**”：未认证请求进入 shutdown 分支这件事在重建件上成立，
但对象不是原件，所以本轮结论仍是 blocked。

关闭路径（照 [docs/VG01-SOURCE-HANDOFF.md](VG01-SOURCE-HANDOFF.md)）：

```bash
# ① 联网机取 40d0bc1d，回传 ~/vg01-source/nltk-40d0bc1d
# ② 本机过闸门（必须 rc=0）
scripts/vg01_source_check.sh --dir ~/vg01-source/nltk-40d0bc1d \
    --record --commit-full <FULL_SHA_FROM_API>
# ③ 用原件跑 vuln 场景，产物落 /tmp（不污染 experiments/）
# ④ 与镜像做 88–90 行差分，确认 provenance
```

---

## 5. 测试

```bash
python3 -m pytest \
  tests/test_v3_backend_http.py tests/test_v3_cg01_smoke.py tests/test_v3_p1_seed.py \
  tests/test_v3_p2_contracts.py tests/test_v3_p2c_research_cli.py tests/test_v3_p2_session.py \
  tests/test_v3_p3.py tests/test_v3_p4_api.py tests/test_v3_p4_report.py \
  tests/test_v3_p5_patch.py tests/test_v3_smoke_record.py \
  tests/test_platform_v2.py tests/test_platform_v2_casepack.py tests/test_platform_v2_e2e.py \
  tests/test_platform_v2_exec.py tests/test_platform_v2_p1.py tests/test_platform_v2_p2.py \
  tests/test_platform_v2_p3.py tests/test_platform_v2_p35.py tests/test_platform_v2_p36.py \
  tests/test_platform_v2_p37.py tests/test_platform_v2_p4.py tests/test_platform_v2_p45.py -q
```

```text
........................................................................ [ 17%]
........................................................................ [ 35%]
........................................................................ [ 52%]
........................................................................ [ 70%]
........................................................................ [ 87%]
...................................................                      [100%]
411 passed in 54.76s
pytest rc=0
```

- 覆盖 11 个 `test_v3*` + 12 个 `test_platform_v2*`，共 23 个文件；
- 原始日志：[tests.log](../experiments/evidence-close/runs/20261121-close/tests.log)；
- 这批用例本身离线（本地 HTTP + 临时 SQLite），不依赖 docker / 官方 socket，
  所以“跑绿”只证明平台代码没退化，不等于 benchmark 通过——benchmark 结论只看 §2。

---

## 6. 未完成项（不粉饰）

| # | 项 | 现状 | 关闭条件 |
|---|---|---|---|
| 1 | EG-02 **本次**官方 socket 重放 | 未做：无 `flag_seed` / controller，本机连不上官方端点 | 拿到入口后在授权环境重放，保存原始 stdout 与 flag 校验；届时可升 `current_run` |
| 2 | VG-01 `40d0bc1d` 原件归属 | `blocked`：闸门 rc=2，源码未回传 | 联网机取件 → `scripts/vg01_source_check.sh --record` 到 rc=0 → 原件跑 vuln 场景 |
| 3 | 第 10 例 | **未新增、未伪造**（本轮不碰计数口径） | 按 [docs/TENTH-CASE-PLAN.md](TENTH-CASE-PLAN.md) 的 A/B/C/D 通道立项，去重脚本 COLLIDE 即弃 |
| 4 | CG-01 `fix` 镜像声明名 | 本机没有 `n132/arvo:44034-fix` 这个名字，用同 digest 来源的 `dockerproxy.net/n132/arvo:44034-fix` | 拉齐声明名或把别名写进 smoke 配置（本轮 smoke.json 已列候选，`notes` 有说明） |
| 5 | EG-02 是否独立计数 | 与 CG-01 同源，按 `docs/EG-STATUS.md` 不重复计独立漏洞 | 需要课程/评审口径确认，本轮不改 |
| 6 | 平台 `verifications` 表里的 EG/VG 行 | 故意不写（`STATUSES` 不含 `historical_verified`；改它就是改 verify policy） | 若确需入表，需单独一轮改 policy + 回归，本轮不做 |
| 7 | review / CasePack 终局打包 | 未跑：本轮只收口“验证记录” | 任务走到 VERIFYING/REVIEW 后再 `review` + `casepack` |

---

## 7. 变更清单（允许范围内）

**新增/修改**

| 路径 | 说明 |
|---|---|
| [docs/V3-REAL-EVIDENCE-CLOSE-20261121.md](V3-REAL-EVIDENCE-CLOSE-20261121.md) | 本文件 |
| [scripts/evidence_close.py](../scripts/evidence_close.py) | 台账生成器：CG-01 从 DB + API 核对，EG-02 只读历史日志，VG-01 跑源码闸门；任一硬条件不满足即失败退出 |
| [experiments/evidence-close/records/CG-01.json](../experiments/evidence-close/records/CG-01.json) | CG-01 verified 记录（含证据 sha / 镜像 digest / checks） |
| [experiments/evidence-close/records/EG-02.json](../experiments/evidence-close/records/EG-02.json) | EG-02 historical 记录 |
| [experiments/evidence-close/records/VG-01.json](../experiments/evidence-close/records/VG-01.json) | VG-01 blocked 记录 |
| [experiments/evidence-close/records/INDEX.json](../experiments/evidence-close/records/INDEX.json) | 三条记录的 sha256 与 `counted_verified_cases` |
| [experiments/evidence-close/runs/20261121-close/](../experiments/evidence-close/runs/20261121-close/) | 本次命令输出：submit / preflight / smoke / verifications / status / api_task / tests.log / historical-readonly.sha256 / work/CG-01/（vul.log、fix.log、runner.json） |
| `.platform/platform.db` | 默认 PlatformStore，本轮新建（163 840 B）：1 个任务（`arvo:44034`，READY）、1 条 verification |

**未改动（可核）**

- `workspace/CG-01-arvo-44034/**`、`workspace/EG-02-arvo-44034/**`、`workspace/VG-01-nltk-wordnet/**`：历史证据一个字节没动（`workspace/CG-01-arvo-44034/logs/*` mtime 仍是 2026-11-10/11-15，哈希见 `historical-readonly.sha256`）；
- `experiments/eg-44034/**`：10 份官方日志 `695cea…f3dd`、`SUMMARY.json 14b281…ac7d` 未变；
- `experiments/vg01/**`：重建件/镜像/RESULT 未变；
- `.platform/smoke/CG-01/*`：上一轮 runner 现场（`1b288f3b…` / `8359b3a1…`）未被覆盖——本轮工作目录另开在 `experiments/evidence-close/runs/20261121-close/work`；
- `agent/platform/verify.py`、`agent/benchmark_policy/**`、`agent/platform/store.py`：未改；
- 运行 pytest 会写它自己的运行时件：`tests/_p3_self_pid.db`（`tests/test_v3_p3.py` 的自 pid 用例，
  内含 `jobs` 表）与 `.pytest_cache/`、`tests/__pycache__/`——都是测试副产物，不是证据；
- 无 `git commit` / `git push`（本仓不是 git 工作区）。

---

## 8. 复跑（全部可重放）

```bash
cd /home/root_bupt/桌面/file/vulnmap

# 0) 想用临时库就别动默认库：--db 是全局参数，必须写在子命令之前
#    DB=--db\ /tmp/close.db   →  python3 bin/platform.py $DB submit ...

# 1) 任务 + 准入（默认 DB：.platform/platform.db；任务已存在时跳过本步）
python3 bin/platform.py submit --benchmark cybergym \
  --target workspace/CG-01-arvo-44034 --task-id arvo:44034 --mode smoke \
  --meta authorized=true --meta case_id=CG-01 \
  --meta image_vul=n132/arvo:44034-vul --meta image_fix=n132/arvo:44034-fix
python3 bin/platform.py preflight arvo:44034

# 2) 真跑 + 落账（同 run-id 是覆盖写，不会多一行）
python3 bin/platform.py smoke CG-01 --workspace-root workspace --execute --record \
  --task-id arvo:44034 --run-id close-20261121 --timeout 120 \
  --workdir experiments/evidence-close/runs/20261121-close/work

# 3) 三条台账（CG 检查 DB+API，EG 只读历史日志，VG 跑源码闸门）
python3 scripts/evidence_close.py --verification-id SMOKE-CG-01-close-20261121

# 4) 只读核对
python3 bin/platform.py verifications arvo:44034
bash scripts/vg01_source_check.sh ; echo "vg rc=$?"    # 期望 2（源码未到）
sha256sum -c experiments/evidence-close/runs/20261121-close/historical-readonly.sha256
```
