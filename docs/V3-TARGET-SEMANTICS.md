# V3 P1：目标语义拆分（program_started / input_processed / checkpoint_reached）

> 适用范围：`agent/platform/executors/__init__.py`、`agent/platform/adaptive/snapshot.py`、
> `agent/platform/adaptive/session.py`、`agent/platform/adaptive/cli.py`、`fixtures/target_semantics/`、
> `tests/test_v3_target_semantics.py`。
> 本文是这套口径的**唯一出处**；`docs/V3-P2A-CONTRACTS.md`、`docs/V3-P2B-SESSION.md`、
> `docs/V3-P2C-RESEARCH-CLI.md`、`docs/V3-P5-BACKEND.md` 只引用、不另写一套。

---

## 1. 为什么拆

旧实现把三件事压成一个 `target_reached`：

```
execs > 0                → target_reached = true      # 只证明“跑过”
new_coverage_bits > 0    → target_reached = true      # 只证明“覆盖面变了”
new_coverage_bits == 0   → target_reached = unknown
setup_error && execs==0  → target_reached = false
```

后果是三种完全不同的局面在报告里长出同一个结论：

| 真实局面 | 旧结论 | 问题 |
|---|---|---|
| 目标起来了、输入被处理了，但**想要的检查点没走到** | `true` | 把“跑过”说成“命中”，假阳性 |
| 目标起来了，但执行器**没有输入/检查点探针** | `unknown`（理由写在覆盖字段上） | 不知道与没命中混在一起，无法追责 |
| 覆盖涨了但目标分支根本没走到 | `true` | 覆盖变化被当成目标命中 |

拆分后，三段事实**各自独立、各自三值**，任何一段都不许冒充另一段：

| 事实 | 语义 | 谁能给出 `true`/`false` |
|---|---|---|
| `program_started` | 目标进程真的起来了 | 执行计数（`execs>0`）或执行器显式字段；`execs=0 && setup_error` 给 `false` |
| `input_processed` | 输入真的被目标处理过 | **只能**显式探针/显式字段；`execs>0` 不算 |
| `checkpoint_reached` | 目标分支 / 检查点命中 | **只能**显式探针或显式 `checkpoint_reached`/旧 `target_reached` 字段 |
| `target_reached`（兼容） | 与 `checkpoint_reached` 同值 | 只由 `checkpoint_reached` 派生，不再独立推断 |

缺失一律 `None` → 快照层落 `unknown`。**不填 `False`**：`False` 是“观测到没发生”，
不是“没观测”。

---

## 2. 禁止推断矩阵

| 输入事实 | `program_started` | `input_processed` | `checkpoint_reached` / `target_reached` |
|---|---|---|---|
| `execs > 0` | `true` | **unknown** | **unknown** |
| `execs == 0` + `setup_error` | `false` | unknown | **unknown**（不顺手写成 `false`） |
| `execs == 0`（无 setup_error） | unknown | unknown | unknown |
| `new_coverage_bits > 0` | 不推断 | 不推断 | **unknown** |
| `new_coverage_bits == 0` | 不推断 | 不推断 | **unknown** |
| `coverage.covered == coverage.planned` | 不推断 | 不推断 | **unknown** |
| `crashes > 0` | 不推断 | 不推断 | **unknown**（崩溃不是“命中目标分支”） |
| 显式 `checkpoint_reached=True/False` | 不推断 | 不推断 | `true`/`false` |
| 显式 `input_processed=True/False` | 不推断 | `true`/`false` | 不推断 |

一句话：**只有探针能证明“输入被处理”“检查点命中”，统计只能证明“程序跑过”。**

---

## 3. 写入侧：`exec_probe_facts()` 是唯一出口

`agent/platform/executors/__init__.py`：

```python
EXEC_PROBE_FIELDS = ("program_started", "input_processed", "checkpoint_reached")

def exec_probe_facts(stats=None, *, kind="fuzz") -> dict:
    ...
```

规则：

1. **显式优先**：执行器在统计里给出三段中的任一 bool，原样采用；
2. **fuzz 只补 `program_started`**：`execs > 0` → `true`；`execs == 0` 且有
   `setup_error` → `false`；其余 `None`；
3. `input_processed` / `checkpoint_reached` **永不默认**：fuzz 执行器没有探针，
   就只能是 `None`；
4. 返回值里额外带 `target_reached`，其值**恒等于** `checkpoint_reached`（兼容别名）。

所有 `exec.finished` 写入点都带这组字段：

| 写入点 | 取值 |
|---|---|
| `executors/__init__.py` fuzz 正常/取消结算 | `exec_probe_facts(stats)` |
| `executors/__init__.py` static / dynamic / replay 结算 | `exec_probe_facts({})` → 三段全 `None` |
| `executors/__init__.py` 失败兜底 | 三段全 `None`（抛错发生在哪一步不可知，猜“没启动”就是编造） |
| `adaptive/cli.py` `FuzzEpochRunner._applied` | `_probe_facts(stats)`（内部调用同一函数） |
| `adaptive/cli.py` `FuzzEpochRunner._failed` | 三段全 `None` |

`EXEC_FACT_FIELDS["finish"]` 与 `EXEC_FACT_FIELDS["fuzz"]` 都登记了这三个字段，
新增执行字段时仍只改这一处。

### 只读视图 `execution_fact_view()`

- `program_started` / `input_processed` / `checkpoint_reached`：先读 finish 顶层
  显式字段，缺失再读 `fuzz` 统计里的显式字段，`program_started` 允许按 §2 的
  `execs` 规则补一次（与写入侧同一函数，不另写一套）；
- 旧事件只写了 `target_reached` 时，映射为 `checkpoint_reached`，并记
  `target_reached_source = "legacy_target_reached"`；
- `target_reached` 字段只回显 `checkpoint_reached`；
- `flags` 增加 `program_started_observed` / `input_processed_observed` /
  `checkpoint_reached_observed`，`target_reached_observed` 与后者同义。

---

## 4. 快照口径

`adaptive/snapshot.py`：

- `input` 组新增三个字段，同时进入 `_GROUP_PATHS["input"]`（空快照会逐个登记
  `unknown`）与 `OBSERVED_FIELDS["input"]`（程序起来了本身就是实质观测，
  不再需要覆盖读数来“证明跑过”）；
- `_target_reached(view)` **只认** `checkpoint_reached`（或映射来的旧
  `target_reached`）：

| 情形 | `checkpoint_reached` | `target_reached` | `observation_source` |
|---|---|---|---|
| 没有 `exec.finished` | `unknown` | `unknown` | `unknown`（连“有没有探针”都不知道） |
| 有 finish，无探针 | `unknown` | `unknown` | `no_checkpoint_probe` |
| 显式 `checkpoint_reached=true` | `true` | `true` | `checkpoint_probe` |
| 显式 `checkpoint_reached=false` | `false` | `false` | `checkpoint_probe` |
| 只有旧 `target_reached` | 同旧值 | 同旧值 | `legacy_target_reached` |

- `coverage_bits` / `execs` / `new_coverage_bits` / `crashes` 不再进入
  `_target_reached` 的任何分支；
- `program_started` / `input_processed` 与 `target_reached` 一样是纯三值，
  缺失即 `unknown` 并出现在 `unknown_paths()` 里。

---

## 5. 诊断口径（`DiagnoseRole`）

`Observation` 新增 `program_started` / `input_processed` / `checkpoint_reached`
三个三值字段（同时保留 `target_reached`，值与 `checkpoint_reached` 一致或回落到
后端快照的显式值）；三者都进 `facts_hash`——它们代表三种不同的进展。

诊断优先级（前三条不变）：

| 优先级 | 条件 | code | 含义 |
|---|---|---|---|
| 1 | `fault.error == "true"` | `execution_error` | 执行报错 |
| 2 | `fault.timeout == "true"` | `execution_error` | 超时 |
| 3 | `candidates > 0` | `candidate_observed` | 单端候选，交独立验证 |
| 4 | `program_started == "false"` | `program_not_started` | 启动失败/未启动 |
| 5 | `input_processed == "false"` | `input_not_processed` | 输入未处理 |
| 6 | `checkpoint_reached == "false"` | `target_unreached` | 起来了、处理了，但检查点没命中 |
| 7 | `checkpoint_reached == "true"` 且 delta>0 | `progress` | 有可比增益 |
| 8 | `checkpoint_reached == "true"` | `low_coverage` | 命中但无可比增益 |
| 9 | 无 trial 且快照 unknown | `no_execution` | 还没有执行事实 |
| 10 | 其余（含 `checkpoint_reached == "unknown"`） | `coverage_unknown`（理由 `target_reached_unknown`） | 不知道，补探针/换策略 |

`program_not_started` / `input_not_processed` 已加入 `DIAGNOSIS_CODES`，并与
`target_unreached` 走同一条动作路径（seed/字典/重跑），但它们**不是**同一个结论：
报告里能直接看出是“没启动”“没处理输入”还是“处理了但没命中”。

---

## 6. 三组回归

`tests/test_v3_target_semantics.py`（16 条）。夹具
`fixtures/target_semantics/` 是**真跑**的无害解析器（`parser_target.py`）加真探针
（`probe.py`，子进程 + JSONL 探针文件），不是 mock：

| 组 | 用例 | 三元组 | 快照 | 诊断 |
|---|---|---|---|---|
| 启动但未命中 | `started_no_checkpoint` | `true / true / false` | `unknown_paths` 不含 `input.checkpoint_reached` | `target_unreached` |
| 确认命中 | `checkpoint_hit` | `true / true / true` | `input.target_reached == "true"` | `low_coverage` / `progress` |
| 无观测手段 | `no_probe`（`--no-probe`） | `true / unknown / unknown` | `unknown_paths` 含 `input.input_processed` / `input.checkpoint_reached` / `input.target_reached` | `coverage_unknown`（`target_reached_unknown`） |

断言里三组的快照输入组、观测三段、诊断码**两两不同**；第三组必须是字符串
`"unknown"`，不允许出现 `False`。另有针对 `exec_probe_facts`、`execution_fact_view`、
旧字段映射、`setup_error` 只影响 `program_started` 的单点回归。

跑：

```bash
python3 -m pytest tests/test_v3_target_semantics.py -q
python3 -m pytest tests/ -q          # 全量：1483 passed, 8 skipped
```

---

## 7. 兼容与例外

- **兼容字段**：`target_reached` 继续出现在快照与 `Observation` 里，但只由
  `checkpoint_reached` 派生；旧事件里的 `target_reached` 被当作旧拼写映射，
  `target_reached_source` 说明来源。
- **后端快照例外**（`adaptive/backends/base.py`，不在本次改动范围）：HTTP 差分
  后端不跑进程，只把“拿到响应”写成 `input.target_reached`；它的
  `program_started` / `input_processed` / `checkpoint_reached` 保持 `unknown`，
  诊断侧在 `checkpoint_reached == unknown` 时回落到显式 `target_reached`。
  这条路径不改写、不推高，等后端自己补探针。
- **`input_consumed` 不是 `input_processed`**：前者表示“语料被喂进 fuzz 执行器”
  （`execs>0`），后者表示“目标真的处理了输入”（需探针）。文档、报告、诊断都按
  这个区分读；不合并、不互相顶替。
- **不动的边界**：`verify` / `benchmark_policy` / 执行器执行语义 / 对外 API 形态
  都没改；新增的只是字段、诊断码与它们的读写口径。
