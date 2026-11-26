# V3 P0 基线（V3-001 / V3-002）

> **本文只写实测到的东西。** 每个数字都能在 `experiments/v3-baseline/raw/` 找到出处；
> 机器可读汇总见 [`experiments/v3-baseline/manifest.json`](../experiments/v3-baseline/manifest.json)，
> 由 [`build_manifest.py`](../experiments/v3-baseline/build_manifest.py) 从 raw 证据生成（不手填）。
>
> 生成时间：2026-11-19 21:2x–21:4x（Asia/Shanghai）｜生成者：lead + 4 条并行执行线
> （`svc-8102` / `code-baseline` / `db-schema` / `smoke-runner`）

---

## 0. 一句话结论

| 项 | 状态 | 锚点 |
|---|---|---|
| 代码基线 | **frozen（绑定 T0 时点）** | `tree_hash=sha256:15cb6d7b0d99…`（246 文件，逐字节复核无漂移）；快照后并行执行线仍在改树，见 §2.1 |
| DB schema 基线 | **frozen** | 11 表 / `user_version=4` / `schema_sha256=600eff82…`，空库重放 0 差异 |
| 测试 | **green** | 收集 1278，**1270 passed / 0 failed / 0 error / 8 skipped**，两条独立运行一致 |
| 8102 服务 | **up** | `127.0.0.1:8102` pid 63025，health/root/index/tasks/openapi **全 200** |
| 平台 smoke（`--execute`） | **needs_evidence 3/3** | 一个 runner 都没启动（`would_execute=false`），`persisted=false` |
| CG-01 | **pass（real-runner 双端）／smoke 层 needs_evidence** | vul exit=1 + ASAN `pdf_font.c:332`；fix exit=0 零 sanitizer |
| EG-02 | **needs_evidence** | 缺 `mode` / `exploit_target` |
| VG-01 | **needs_evidence** | 缺 `baseline_url` / `patched_url` |

**没有伪造任何通过。** 3 个 blocker 仍然挂着（见 §7），平台链路一个案例都没跑起来。

---

## 1. 两个判定轴，不要合并

这次最容易出错的地方是把"CG-01 双端真跑通过"和"平台 smoke 通过"混成一个数。它们是两条路：

| 判定轴 | 入口 | CG-01 | EG-02 | VG-01 |
|---|---|---|---|---|
| **平台 smoke 层** | `bin/platform.py smoke … --execute` | `needs_evidence` | `needs_evidence` | `needs_evidence` |
| **real-runner 层** | 手工 `docker run` 两端 + 同输入 | **pass** | 未跑（spec 无 target） | 未跑（spec 无端点） |

- smoke 层 `exit=0` **不代表通过**，它只代表「探测跑完了」。`--execute` 对三个案例全部
  `would_execute=false`，`.platform/smoke/` 目录压根没被创建，`persisted=false`（不写验证记录）。
- CG-01 的 `pass` 只来自 real-runner 层（§6.1），**平台层依然是 needs_evidence**。
  把它写成"平台链路跑通 CG-01"就是造假。

---

## 2. 代码基线（V3-001）

| 项 | 值 |
|---|---|
| 仓库 | `/home/root_bupt/桌面/file/vulnmap` |
| 版本控制 | **无 `.git`**（不是 git 仓库）→ 基线以文件哈希锚定，不以 commit sha 锚定 |
| Python | 3.12.14 @ `/usr/local/bin/python3` |
| `.py` 文件 / 行数 | **232 / 53 537** |
| 逐目录 | `agent` 103 文件/28 985 行；`tests` 115/20 647；`vulnmap_platform` 8/2 603；`bin` 5/1 166；`scripts` 1/136；`web`、`schema` 无 `.py` |
| **`tree_hash`** | **`sha256:15cb6d7b0d994950675ecb88b221af5233de1c6eb277fec9a9fffb79286ce15d`** |
| 清单 | [`raw/code-tree.sha256`](../experiments/v3-baseline/raw/code-tree.sha256)，**246 条**（7 个源码目录，排除 `__pycache__`/`*.pyc`） |
| `pyproject.toml` | `vulnmap 0.1.0`，`requires-python >=3.11`，sha256 `a76f3a9a…` |
| 依赖锁 | `requirements.txt` `301f7864…`；`requirements.lock` `19145c3e…`；`requirements-dev.txt` `93c4ab5f…` |
| 运行时依赖（已装） | fastapi 0.141.1 / uvicorn 0.52.4 / starlette 1.6.0 / pydantic 2.13.4 / pytest 9.1.1 |
| 运行 Python（服务侧） | `/home/root_bupt/binsight-next/BinSight/.venv/bin/python3` 3.12.14 |

> **注意：`requirements.txt` 里没有第三方运行时依赖**（全为注释），平台后端靠的是上面这套已装环境。
> 换机器部署时 `pip install -r requirements.txt` 不会带来 fastapi/uvicorn，这是复现的第一个坑。

**漂移复核（Lead 独立做）**：用同一组文件集重算 246 条 sha256 清单，与快照 `diff` 为空，
两份清单自身 `sha256sum` 都是 `15cb6d7b…` → **T0 快照之后无内容漂移**。

### 2.1 基线漂移（T0 → T1 → T2）——必读

基线是**时点**，不是永久承诺。快照之后，一条并行的 V3-P1/P2 执行线（**不是本任务、不是本任务的 4 条执行线**）
在持续写盘。我留了三次观测，全部记录，不掩盖：

| 观测 | 时间 | 文件数 | `tree_hash` | 变化 | pytest |
|---|---|---|---|---|---|
| **T0（基线）** | 21:26 | 246 | `sha256:15cb6d7b0d994950675ecb88b221af5233de1c6eb277fec9a9fffb79286ce15d` | — | 1270 passed / 8 skipped（98.01s / 95.47s 两次） |
| T1 | 21:34 | 247 | `sha256:afc8a28bf05ead9eab1b7ac6d6b25add1cb13dc4ff4f6d4de7b39478f6cc3881` | **+** `agent/platform/adaptive/contracts.py`（1225 行，V3-005 动作契约） | 1270 / 8（94.80s） |
| T2 | 21:36 | 249 | `sha256:48535deb0380305c78990f7c7ec58d311637f1eda2a2b7300f6bbe6f47c1dfad` | **+** `adaptive/snapshot.py`（682 行）、`adaptive/tools.py`（842 行）；`contracts.py` 仍在改（1225→1227 行） | 1270 / 8（96.14s） |

- 三次运行的 `failed / error` **恒为 0**，用例如数不变（1270 + 8 = 1278）。所以并行漂移至今**没有破坏既有用例**。
- 但**绿不等于新代码被验证**：`contracts.py` / `snapshot.py` / `tools.py` 在 T2 **尚无对应用例**。
- T2 之后该执行线仍在写盘（`contracts.py` 行数分钟级变动），所以**任何"当前 py 行数"都是瞬时值**，本基线不作承诺；
  `232 py 文件 / 53 537 行` 只对 T0 成立且可复现。
- 漂移留痕：[`raw/code-drift.json`](../experiments/v3-baseline/raw/code-drift.json)、
  [`raw/code-tree-T1.sha256`](../experiments/v3-baseline/raw/code-tree-T1.sha256)、
  [`raw/code-tree-T2.sha256`](../experiments/v3-baseline/raw/code-tree-T2.sha256)、
  [`raw/t0-lead-pytest.txt`](../experiments/v3-baseline/raw/t0-lead-pytest.txt) /
  [`t1`](../experiments/v3-baseline/raw/t1-lead-pytest.txt) /
  [`t2`](../experiments/v3-baseline/raw/t2-lead-pytest.txt)。

**判断"现在的树是否绿"的唯一正确做法**：拿当前树按 §8 第 1、2 条重跑，得到新 `tree_hash` 与新的 passed 数。
T0 基线证明的是「21:26 那个时点可复现、可回溯」，不是「明天照样绿」。

---

## 3. 测试基线（V3-001）

| 项 | 值 |
|---|---|
| 收集 | `python3 -m pytest --collect-only -q` → **1278 tests collected**（exit 0，无 errors） |
| 运行（执行线 A） | `timeout 600 pytest tests/ -q -p no:randomly` → **1270 passed / 0 failed / 0 error / 8 skipped**，98.01 s，exit 0 |
| 运行（Lead 复核） | `timeout 600 pytest tests/ -q` → **1270 passed / 8 skipped**，95.47 s，exit 0 |
| 一致性 | 1270 + 8 = **1278** = collected ✓ |
| 用例文件 | 115 个 `.py`（与 tree 清单中 `tests/*.py` 条目数一致） |
| 静态 `def test_` | 1198；与 1278 的差额 80 来自 18 处 `parametrize` 展开（不是漏收） |

**已知噪音（不是失败）**：跑测时 stdout 有一条 `Exception occurred during processing of request from (127.0.0.1,…)`，
来自测试内 `http.server` 的 handler 级打印，`failed/error` 计数为 0。

**数字与树绑定**：本次会话期间另一条执行线在 `21:24–21:26` 修改了
`agent/platform/adaptive/{__init__,corpus}.py`、`agent/platform/executors/fuzz.py`、`web/data.json`，
并新增 `tests/test_v3_p1_seed.py`（+8 用例，即 V3-P1 的 V3-003/004，见 `docs/V3-P1-SEED.md`）。
收集数因此在会话中从 1270 变为 **1278**；上表所有数字绑定 `tree_hash=15cb6d7b…`（21:26 快照）。
**树再变，这些数字即失效，必须按新 `tree_hash` 重测。**
实际已经又变了两次（T1 247 文件 / T2 249 文件），三次运行结论一致 —— 全过程见 §2.1。

---

## 4. DB schema 基线（V3-001）

| 项 | 值 |
|---|---|
| DDL 真源 | **`agent/platform/store.py`**（`PlatformStore.__init__` 依次执行 `SCHEMA`(L24) / `SCHEMA_P1`(L98) / `SCHEMA_P2`(L127) / `SCHEMA_P3`(L159)，再 `_ensure_columns()` 做 `ALTER TABLE ADD COLUMN`） |
| 表数 | **11** |
| 表名 | `candidates`, `evidence`, `hypotheses`, `plans`, `program_indexes`, `reports`, `reviews`, `task_events`, `task_evidence`, `tasks`, `verifications` |
| 索引 / 外键 | **17 条 index 条目（7 个命名索引 + 10 个 `sqlite_autoindex_*`，后者由 UNIQUE/主键隐式创建）** / **外键 0** |
| `PRAGMA user_version` | **4** |
| **`schema_sha256`** | **`600eff822243bffc22622c30db88124def3af46ac78068d6b7860ac4c08a0806`**（3 617 B，18 条语句） |
| 仓库库 `.platform/platform.db` | **不存在**（`.platform/` 下只有 `run/`） |
| 可重放性 | 把 `raw/db/schema.sql` 灌进空库：18 个对象、11 张表全等，逐列 `PRAGMA table_info` **0 差异**；Index 17 条、FK 0 条同（Lead 独立复算，哈希一致） |
| 索引口径订正 | 执行线口头汇报"索引 11 个"，但它自己的 `raw/db/result.json` 是 `index_count=17`。以可复算的 `sqlite_master` 为准：**17 = 7 命名 + 10 自动**。订正记录在 [`raw/db/lead-verification.json`](../experiments/v3-baseline/raw/db/lead-verification.json) |

**取法说明**：不是抄源码文本，而是 `import agent.platform.PlatformStore` 实例化一个 `/tmp` 探针库，
让平台自己的初始化代码建表，再从 `sqlite_master` 导真 DDL。
`bin/platform.py status` 之类的子命令**建不出库**（全部强制 `task_id`，argparse 层就退出）。

**两个坑（已写入 `raw/db/result.json` 的 `diff_notes`）**：

1. `candidates.state/exec_id/detail_json`、`reviews.detail_json` 是 `ALTER ADD COLUMN` 补的。
   SQLite 会把列定义追加回 `sqlite_master.sql`，导出形如
   `created_at TEXT NOT NULL\n, state TEXT …` —— **这是真 DDL 的特征，不要"修正"格式，改了会丢列。**
2. `jobs` 表 + 2 个索引**不在基线内**：只由 `vulnmap_platform/api/platform_jobs.py` 的 `_write_conn()`
   在 POST run/cancel 写路径惰性创建。fresh 库 = 11 表；一旦有 job 写入会变 12 表，
   `schema_sha256` 随之改变 —— 预期行为，不是缺陷。

**没有对照物**：仓库库不存在，所以 `repo_db_matches_probe=false` 的语义是"没有库可比"，
**不是 schema 不一致**。给平台建库后必须重跑本节、重记 `schema_sha256`。

---

## 5. 镜像 digest（V3-001）

Docker server **29.7.2**，本地 **36** 个镜像，全量清单在 [`raw/images.json`](../experiments/v3-baseline/raw/images.json)
（rev2，sha256 `19f2b0348c7f292155d5104bd20196a1440daadd81a0a80991e280d953cdc63d`；
rev1 是 21:26 的 35 镜像快照，fix 拉取成功后升到 36，`arvo_family_local` 2→3）。

| 案例 | 作用 | 镜像 ref | digest | 本机 |
|---|---|---|---|---|
| **CG-01** | vul | `n132/arvo:44034-vul` | `sha256:e57980e7ebcd63856a6c1976d603f4bcbac17138f63d57531ee1c08cb38caaef` | ✅ present（4.52 GB，2024-05-01） |
| **CG-01** | fix | `dockerproxy.net/n132/arvo:44034-fix` | `sha256:5d428e8feb3ad8041c136d345e32b852a765d61485cc253b49818378732a9aa9` | ✅ present（4.71 GB，**本次会话拉取成功**） |
| **EG-02** | 声明 ref | `cybergym/arvo:44034-vul.exp.none-nogit` | `null` | ❌ 不存在（见下） |
| **EG-02** | 本地等价 | `n132/arvo:44034-vul`（同 image id） | `sha256:e57980e7…` | ✅ 可替代，但 ref 名不同 |
| **VG-01** | — | 无容器 | — | n/a（纯 Python：`/usr/bin/python3.10` 3.10.12 + nltk 3.10.4） |

**EG-02 的 ref 是构造值，不是拉下来的镜像**：`agent/casekit.py:40` 按约定拼出
`f"cybergym/arvo:{num}-vul.{mode}-nogit"`，仓库内**没有任何 pull 该 ref 的记录**。
本地不存在是设计使然，不是拉取失败。**没有据此推断官方 digest。**

**镜像真实性核查（防"拿 vul 重打冒充 fix"）**：

```text
container binary sha256
  vul: /out/gstoraster_fuzzer = f3a772173f0409d8bcf86076225511f002cab92651b0233adb1b71e66962c9ee
  fix: /out/gstoraster_fuzzer = 747c26a712b40daf5733dc3f9c3cabc4a69341a504aca256070cb2bc8f0937c7   ← 不同
  vul: /bin/arvo               = bb7a2341fcbd7cf6bd3cd4c1896593cba342b7f16b2ef962d147c88ad9631114
  fix: /bin/arvo               = bb7a2341fcbd7cf6bd3cd4c1896593cba342b7f16b2ef962d147c88ad9631114   ← 相同（同一 harness）
```

目标二进制不同、harness 相同 → **确为两份独立构建**。未 retag、未改 spec、未复制镜像。

---

## 6. 平台链路冒烟（V3-002）

### 6.1 8102 服务

| 项 | 值 |
|---|---|
| 启动脚本 | [`scripts/serve-platform.sh`](../scripts/serve-platform.sh) —— **启动前已存在**（6 118 B，mtime 2026-11-18 19:06，`755`），**原样复用，未改一字，也未新写脚本** |
| 启动 | `./scripts/serve-platform.sh start` → exit 0，**2 s 就绪** |
| 进程 | pid **63025**，`LISTEN 127.0.0.1:8102`（`users:(("python3",pid=63025,fd=13))`） |
| ASGI | `vulnmap_platform.api.app:app`；日志 `.platform/run/serve-8102.log` |
| 启动前 | 8102 无监听、无 uvicorn、仅一个陈旧 PID 文件（208138 已死，被脚本自动清理） |

实测（原始响应在 `raw/service-8102/*.http`，Lead 已独立复核一次）：

| 端点 | HTTP | 大小 | 耗时 | 内容 |
|---|---|---|---|---|
| `GET /api/health` | **200** | 82 B | 1.7 ms | `{"ok":true,"workspace":"…/workspace","cases":61}` |
| `GET /` | **200** | 13 730 B | 3.5 ms | 首页，与 `/index.html` **字节一致**（非重定向） |
| `GET /index.html` | **200** | 13 730 B | 1.0 ms | 同上，body sha256 `c346b1f8…` |
| `GET /api/platform/tasks` | **200** | 584 B | 1.4 ms | `exists=false`，`totals.tasks=0`，`auth.mode=open` |
| `GET /openapi.json` | **200** | 17 191 B | 4.6 ms | OpenAPI 3.1.0，**28 path / 29 method** |

`openapi` 的 28 个 path 清单见 [`raw/service-8102/openapi-paths.txt`](../experiments/v3-baseline/raw/service-8102/openapi-paths.txt)：
覆盖 `/api/cases`、`/api/discovery/*`、`/api/benchmark-reports/*`、`/api/platform/tasks/*`（含 `preflight`/`run`/`events`/`evidence`/`casepack`/`stream`）、`/api/platform/jobs/*`、`/api/rerun` 等。

`tasks` 的 `exists=false` 与 §4 一致（库未建），**端点本身可用，属正常态**（`docs/DEPLOY-8102.md` §4 已声明）。

### 6.2 `bin/platform.py smoke CG-01 EG-02 VG-01 --execute`

| 阶段 | 退出码 | 结果 |
|---|---|---|
| dry-run（无 `--execute`） | **0** | `summary={"needs_evidence":3}`，`ready=[]`，`not_ready=[CG-01,EG-02,VG-01]` |
| `--execute` | **0** | `timed_out=false`，`duration_s=0.108`，**`would_execute=false` × 3**，`persisted=false` |
| 拉完 fix 镜像后重跑 dry-run | 0 | blockers **未变**（见 `raw/smoke/dryrun-after-fix-pull.log`） |

逐案例（原文见 [`raw/smoke/result.json`](../experiments/v3-baseline/raw/smoke/result.json)）：

| 案例 | smoke 状态 | blockers | 真实执行 |
|---|---|---|---|
| **CG-01** | `needs_evidence` | `runner_not_configured:cmd`、`image_not_found:n132/arvo:44034-fix` | 平台未跑；**real-runner 层双端已真跑 → pass**（§6.3） |
| **EG-02** | `needs_evidence` | `runner_not_configured:mode`、`runner_not_configured:exploit_target` | 未跑。ExploitGym 需要 host+port 或 `exploit_cmd`；`task.json` 只有 `image_vul`（`image_fix` 为空串），无 `expected_flag` |
| **VG-01** | `needs_evidence` | `runner_not_configured:baseline_url,patched_url` | 未跑。spec 只有 `{"method":"GET"}`，两侧端点未声明 |

`raw/smoke/checksums.sha256` 对 44 个证据文件做了自校验，全部 OK。
**未跑 `--strict`**：dry-run 已显示无一 ready，加 `--strict` 必然返回 1，无额外信息。

### 6.3 CG-01 双端实跑（real-runner 层）

同输入：`workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin`，8882 B，
sha256 `58f7f4b3d8ca65bfa4fbd5838301d5181c6a703df60fad4a444feec80a58c59d`（两端同文件）。

| 端 | 镜像 | exit | 耗时 | 输出 |
|---|---|---|---|---|
| vul | `n132/arvo:44034-vul` | **1** | 0.299 s | `==7==ERROR: AddressSanitizer: stack-buffer-overflow`，`WRITE of size 4096`，`#1 … pdfi_open_CIDFont_substitute_file /src/ghostpdl/./pdf/pdf_font.c:332:9` |
| fix | `dockerproxy.net/n132/arvo:44034-fix` | **0** | 0.660 s | `Executed /tmp/poc in 174 ms`，**sanitizer 命中 0** |

容器硬化参数两端一致：`--network none --cap-drop ALL --security-opt no-new-privileges
--pids-limit 128 --memory 2g --tmpfs /tmp:rw,exec,nosuid,nodev`，`ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0`。

**Lead 独立复跑**（不是引用执行线的结论）：vul exit=1 + 同一条 `pdf_font.c:332` 栈；
fix exit=0 + `Executed /tmp/poc in 174 ms`、零 sanitizer。

### 6.4 fix 镜像的时序修正（重要，别被旧文档误导）

| 时点 | 事实 |
|---|---|
| 2026-11-19T11:14Z（历史） | 两次 `docker pull dockerproxy.net/n132/arvo:44034-fix` 均 exit=1（50.2 s / 30.4 s，TLS handshake timeout），网络探测 `curl_exit=124` → 当时结论 `partial` **属实** |
| 2026-11-19T21:27Z（本次） | `timeout 90 docker pull …` → exit=124（超时，但 stdout 已在逐层 `Download complete`，说明 registry 可达）；`timeout 900 docker pull …` → **exit=0，174.83 s 拉取成功** |

因此 `experiments/cg01-runner/README.md` 里"fix 拉取失败 → partial"**只对 11:14Z 那次成立**。
本次 CG-01 在 real-runner 层是双端真跑通过。**但平台 smoke 仍报 `image_not_found`**，原因是：

- fix 镜像只以 **`dockerproxy.net/n132/arvo:44034-fix`** 标签存在（RepoDigests 里也只有这一条，
  没有 `n132/arvo@sha256:` 的短名 digest，这点与 vul 镜像不同）；
- spec / `task.json` 用的是短名 **`n132/arvo:44034-fix`**（docker.io），该名仍不可达，
  `docker image inspect n132/arvo:44034-fix` → `No such image`。
  两次独立实测拿到的报错**措辞不同、结论一致**，都留档不平滑：
  `dial tcp 31.13.112.4:443: i/o timeout`（已解析、连接超时，30.0 s, exit=1）
  与 `dial tcp: lookup registry-1.docker.io: i/o timeout`（DNS 解析即超时，30.018 s, exit=1）。

**修法（属业务侧改动，本次按边界未做）**：把 spec 的 `image_fix` 指向可用来源，
或对镜像 `docker tag` 成 spec 名，或在 `task.json` 里声明 `cmd=/bin/arvo`。

---

## 7. Blocker 清单（未解决，不许当成已通过）

| # | 级别 | 项 | 事实 | 解除条件 |
|---|---|---|---|---|
| B1 | medium | **CG-01 `runner_not_configured:cmd`** | `task.json` 仍未声明容器内命令（实际 harness 命令是 `/bin/arvo`） | 业务侧在 `task.json` 声明 `cmd` |
| B2 | medium | **CG-01 `image_not_found:n132/arvo:44034-fix`** | fix 镜像只以 `dockerproxy.net/…` 标签存在；短名走 docker.io 超时 | spec 指向可用来源，或本地 `docker tag` |
| B3 | medium | **EG-02 `mode` + `exploit_target` 未接线** | 无 host+port / `exploit_cmd`，`image_fix` 为空串，无 `expected_flag`。历史「官方 socket 10/10 取到 flag」只是 **historical evidence**，不计本次 pass | 补齐 ExploitGym 运行目标 |
| B4 | medium | **VG-01 `baseline_url` + `patched_url` 未接线** | spec 只有 `{"method":"GET"}`；历史 `RESULT.json` 也只是 historical evidence | 声明两侧 HTTP 端点 |
| B5 | medium | **EG-02 声明镜像不存在** | `cybergym/arvo:44034-vul.exp.none-nogit` 是 `agent/casekit.py:40` 拼出的构造值，从未被 pull，digest 无从确认 | 显式声明改用本地等价 `n132/arvo:44034-vul`（同 image id） |
| B6 | info | **`.platform/platform.db` 不存在** | schema 基线取自 `/tmp` 探针库（平台自身初始化路径），与仓库库之间没有对照物；API `tasks` 因此 `exists=false` | 按平台流程建库后重跑 §4 |

**环境层面的已知限制（不是本任务的 blocker，但会咬复现的人）**：docker.io 不可达
（`31.13.112.4:443` 超时），只有 `dockerproxy.net` 等镜像代理可用；
8102 服务跑在 `binsight-next/BinSight/.venv` 的 python 上，而 `requirements.txt` 不含 fastapi/uvicorn。

---

## 8. 复现

```bash
R=/home/root_bupt/桌面/file/vulnmap && cd "$R"

# 1) 代码树哈希（应与 15cb6d7b… 一致）
find vulnmap_platform bin agent tests web scripts schema -type f \
     -not -path '*/__pycache__/*' -not -name '*.pyc' -print0 \
  | xargs -0 sha256sum | LC_ALL=C sort -k2 | sha256sum

# 2) 测试（应 1270 passed / 8 skipped / 0 failed）
python3 -m pytest tests/ -q

# 3) DB schema（应 11 表 / user_version=4 / 600eff82…）
python3 -c "from agent.platform import PlatformStore as P; P('/tmp/probe.db')"
python3 -c "import sqlite3;print([r[0] for r in sqlite3.connect('/tmp/probe.db').execute(\"select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name\")])"

# 4) 8102（若未起：脚本已在，直接 start）
./scripts/serve-platform.sh status
./scripts/serve-platform.sh start
curl -sS -o /dev/null -w 'health=%{http_code}\n' http://127.0.0.1:8102/api/health

# 5) smoke（预期 needs_evidence 3/3，不是通过）
python3 bin/platform.py smoke CG-01 EG-02 VG-01 --execute

# 6) CG-01 两端（real-runner 层）
POC=workspace/CG-01-arvo-44034/artifacts/verify/pdf-basefont4096.bin
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 2g --tmpfs /tmp:rw,exec,nosuid,nodev \
  -v "$PWD/$POC:/tmp/poc:ro" -e ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0 \
  n132/arvo:44034-vul /bin/arvo                       # 期望 exit=1 + ASAN pdf_font.c:332
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 2g --tmpfs /tmp:rw,exec,nosuid,nodev \
  -v "$PWD/$POC:/tmp/poc:ro" -e ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0 \
  dockerproxy.net/n132/arvo:44034-fix /bin/arvo       # 期望 exit=0，零 sanitizer

# 7) 重建 manifest
python3 experiments/v3-baseline/build_manifest.py
```

---

## 9. 本次边界（做了什么 / 没做什么）

**改了**：`docs/V3-P0-BASELINE.md`、`experiments/v3-baseline/**`（含 `build_manifest.py`）。
**没改**：任何业务代码（`vulnmap_platform/`、`bin/`、`agent/`、`schema/`、`tests/`）、
`scripts/serve-platform.sh`（原样复用）、`bin/platform.py` 的 spec 判据、任何镜像 tag。
**没有 git 操作**（该目录也不是 git 仓库，无 commit 可做）。

**留给后续（本次刻意不做）**：
1. 解 B1–B5：都要动 spec / `task.json`（业务侧），不属于 P0 基线固化范围。
2. 建 `.platform/platform.db` 后重跑 §4，把 `schema_sha256` 与仓库真实库对上。
3. `docs/STATUS.md`、`experiments/LEDGER.json` 里 CG-01 的口径尚未同步本次双端结果
   （该文件标注"自动生成，请勿手改"，应走 `python3 experiments/gen_docs.py` 重置生成，不在本次范围）。
4. `raw/images.json` **已升到 rev2**：rev1（21:26 快照）的 `fix_image.present=false` 被本次 fix 拉取推翻，
   rev2 把 `present` 改 true、补 digest 与四段拉取时间线，并把已不成立的 blocker `fix_image_missing`
   换成仍成立的 `fix_image_spec_name_unreachable`；rev1 的观测值存在 `rev1_observation` 里留档，未删除。
   `manifest.json` 的 `images` 段同样带 `superseded_by` 标注，两次快照的差异可追溯（不是静默改数）。

---

## 10. 产物索引

| 文件 | 内容 |
|---|---|
| [`experiments/v3-baseline/manifest.json`](../experiments/v3-baseline/manifest.json) | 机器可读汇总（21.6 KB，由 raw 生成） |
| [`experiments/v3-baseline/build_manifest.py`](../experiments/v3-baseline/build_manifest.py) | manifest 生成器（raw 缺失即置 null 并记 blocker，不填推测值） |
| [`raw/code.json`](../experiments/v3-baseline/raw/code.json) · [`raw/code-tree.sha256`](../experiments/v3-baseline/raw/code-tree.sha256) | 代码指纹 / T0 的 246 文件哈希清单 |
| [`raw/code-drift.json`](../experiments/v3-baseline/raw/code-drift.json) · [`code-tree-T1.sha256`](../experiments/v3-baseline/raw/code-tree-T1.sha256) · [`code-tree-T2.sha256`](../experiments/v3-baseline/raw/code-tree-T2.sha256) | T0→T1→T2 漂移留痕 + 三次 pytest 记录 |
| [`raw/tests.json`](../experiments/v3-baseline/raw/tests.json) | 收集与两次运行记录 |
| [`raw/images.json`](../experiments/v3-baseline/raw/images.json) | 35 镜像全量 + 三案例核对 + 2 blocker |
| [`raw/db/schema.sql`](../experiments/v3-baseline/raw/db/schema.sql) · [`schema.sha256`](../experiments/v3-baseline/raw/db/schema.sha256) · [`tables.json`](../experiments/v3-baseline/raw/db/tables.json) | 真 DDL / 哈希 / 逐表结构 |
| [`raw/service-8102/`](../experiments/v3-baseline/raw/service-8102/) | 启动前后状态、5 个原始 HTTP 响应、28 path 清单 |
| [`raw/smoke/`](../experiments/v3-baseline/raw/smoke/) | dry-run/execute 日志、`result.json`、CG-01 两端原始容器日志、拉取时间线、44 文件自校验 |
