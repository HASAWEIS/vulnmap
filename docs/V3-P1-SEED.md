# V3 P1：假设→seed 接线与持久语料（V3-003 / V3-004）

对应《VULNMAP-V3 完整升级方案》第 7 节「种子与语料：Buttercup 机制的轻量落地」，
落地两个 P1 项：

| 项 | 状态 | 验收口径 | 测试 |
|---|---|---|---|
| V3-003 假设到 seed 接线 | 已实施 | 不同假设改变 seed，输入可反查父假设（T01） | `tests/test_v3_p1_seed.py` |
| V3-004 持久语料与构建身份 | 已实施 | 跨轮保留语料；build 改变触发正确失效（T02/T06） | 同上 |

改动边界：只动 `agent/platform/executors/fuzz.py`、`agent/platform/adaptive/`、
`agent/discovery/agents.py` 的必要接口（未改，`propose_seeds(..., hypothesis=)` 已有）、
`tests/`、`docs/`。`verify/`、`policy`、API 层未改。

---

## 1. V3-003：`_seed_pool` 显式接假设

### 1.1 旧口径的问题

```python
sites = list(getattr(index, "call_sites", []) or [])[:3]   # 静默只取前 3 个点
seeds.extend(agents.propose_seeds(site, root, fmt))         # 假设完全没参与
```

- 假设集（`hypothesis.window` 里的源码窗口、`statement` 里的数字/字面量）对种子零影响；
- 调用点被硬截到前 3 个，后面的点既不参与也不记账；
- 种子写成 `seed-<sha16>` 之后只剩字节，`hypothesis_id` / `site_id` 全部丢失，
  事后无法回答“这个输入是哪条假设提出来的”。

### 1.2 新口径

`_seed_pool(index, root, fmt, hypotheses)` 返回 `{"records": [...], "report": {...}}`：

1. **假设优先**：按假设集顺序，用 `site_id` 在 `ProgramIndex.call_sites` 里匹配；
   命中 → `agents.propose_seeds(site, root, fmt, hypothesis=hyp)`，
   `origin="hypothesis"`，`source="hypothesis:<id>"`；
2. **匹配失败显式记账**：`report["unmatched"]` 每项带
   `hypothesis_id / site_id / reason / fallback`，reason 区分
   “`site_id` 为空（锚点/入口假设本来就没有调用点）”与
   “`site_id` 不在 `call_sites` 里”；随后仍以该假设文本生成规则种子
   （`origin="rule_fallback"`），归属不丢；
3. **规则补足遍历全部调用点**：未被假设占用的调用点按索引顺序逐个生成规则种子，
   直到 `MAX_SEEDS`；补不进去的点逐个进 `sites_skipped_cap`，
   没有种子的点进 `sites_without_seeds`，`sites_total` 记录真实规模；
4. **去重但保留来源**：同一字节被多条假设提出时只记一次成员，
   `sources` 列表累积全部来源，`report["duplicates"]` 计数；
5. **兜底显式**：一条种子都没有时才用通用种子，并置 `report["fallback_rule"]=true`。

`report["matched"]` 每项带 `hypothesis_id / site_id / category / seeds / origin`，
台账能直接看出“哪条假设真正产出了几条种子”。

### 1.3 种子归属的字段

每条 record：`data / sha256 / hypothesis_id / site_id / source / origin / basis`。
`basis` 来自 `agents.seed_basis()`，记录假设文本命中了哪些定向策略
（length / comment / width / 注释 / 长度 …），便于核对“假设真的改了种子”。

---

## 2. 语料 manifest：写入即可反查

种子不再只落成裸文件，而是经 `adaptive.corpus.CorpusStore.add()` 写入：

```
entries/<sha256>              原始字节（内容寻址，只增不改）
active/seed-<sha256[:16]>     fuzz 直接读的目录（命名与 Discovery 一致）
manifest.json                 成员台账
```

manifest 成员字段：

```json
{
  "sha256": "…",
  "size": 512,
  "hypothesis_id": "H2",
  "site_id": "a.c:10:memcpy",
  "source": "hypothesis:H2",
  "origin": "hypothesis | rule | rule_fallback | rule_generic | discovered",
  "parent_sha256": "",
  "format": "json",
  "basis": ["length", "长度"],
  "added_at": "2026-11-19T13:00:00+00:00",
  "generation": 1,
  "sources": ["hypothesis:H2", "rule:site:a.c:20:printf"]
}
```

反查接口：

- `store.resolve(sha256) → 成员`（内容哈希 → 父假设）；
- `store.by_hypothesis("H2") → [成员…]`（父假设 → 输入）；
- `store.lineage()`（当前成员的父假设索引，执行结果里也会带一份）。

fuzz 自己写进 `active/` 的新语料在每轮结束由 `store.discover()` 登记，
`origin="discovered"`、`hypothesis_id=""`（无父假设就写无，不硬编）。

---

## 3. V3-004：持久语料与构建身份

### 3.1 目录布局（task / campaign 维度）

```
<workdir>/corpus/<campaign>/<task>/
    manifest.json
    active/
    entries/<sha256>
    history/<gen>-<build_id>/  manifest.json + active/
```

`workdir` 本身就是 `<db>/work/<task>`（CLI 默认），所以默认即 task 维度；
`campaign` 取 `plan["benchmark"]`（如 `cybergym` / `target_yaml`），
不同 campaign 不共享语料。执行器新增的可选参数
`task_id / campaign / corpus_root` 只决定落盘位置，调用方签名不变。

### 3.2 版本与哈希

- `generation`（`corpus_version`）：每重建一次 +1，复用不变；
- `corpus_hash`：成员 `(sha256, size)` 排序后的内容哈希，**不含构建身份**，
  所以“同内容不同构建”可被区分（build_id 不同、corpus_hash 相同）；
- 成员新增（含 fuzz 发现）→ `corpus_hash` 变化，可用来判断本轮是否真有新语料。

### 3.3 构建身份与失效

```python
identity = build_identity(build_spec, binary_sha256=build["sha256"],
                          harness=..., target=...)
# build_id = sha256(spec_hash + binary_sha256 + extra)[:20]
```

`spec_hash` 由 `covfuzz.build` 的身份相关参数（sources/mode/includes/libs/
cflags/extra_objs/out_name…，剔除 `workdir` 等运行期路径）规范化后取 sha256。

`CorpusStore.begin(identity)` 三种结局：

| 结局 | 条件 | 动作 |
|---|---|---|
| `fresh` | 无 manifest | 建代 `generation=1` |
| `reused` | `build_id` 相同 | 沿用 active 与成员，只更新身份与时间 |
| `rebuilt` | `build_id` 变化 | 旧代整体归档到 `history/genNNN-<build>/`，清空 active，`generation+1`，`stale.reasons` 写明变了哪一项 |

失效原因文本区分：`binary sha256 changed: aaaa… -> bbbb…`、
`build spec changed: …`、`build_id changed: …`、
`previous manifest has no build identity`（老台账不可复用也不静默复用）。

**不混用**：重建时 active 目录被整体搬走，新代从空目录开始重放本轮种子；
`entries/` 里的原始字节只归档不删除（方案 §7：崩溃输入与历史语料原件不可因
minimize corpus 删除）。旧覆盖位图随旧 build 一起作废，不会接到新 build 上。

损坏的 manifest 直接抛 `CorpusError`（执行器转 `FuzzExecError`），
不猜、不覆盖、不在坏台账上继续追加。

---

## 4. 执行器接线与结果字段

`fuzz.execute()` 每轮：

1. `_fresh_dir` 仍只用于 `build/`、`crashes/`、`stats/`、`covwork/`；
   **语料目录不再 fresh**；
2. 构建 → `build_identity` → `store.begin(identity)`；
3. `_seed_pool(...)` → 逐条 `store.add(...)` → `finalize()`（先落盘，
   本轮跑崩也不丢归属）；
4. `run_parallel` 直接对 `store.active_dir` 跑；
5. 结束后 `store.discover()`（收 fuzz 新语料）+ `finalize()` → `corpus_after`。

结果新增：

```json
{
  "build_id": "b…",
  "build": {"sha256": "…", "build_id": "b…", "identity": {"spec_hash": "…"}},
  "seed_pool": {"matched": […], "unmatched": […], "sites_total": 6,
                "sites_skipped_cap": [], "duplicates": 20, "seeds": 8},
  "corpus": {
    "store": "…/corpus", "active": "…/corpus/<campaign>/<task>/active",
    "manifest": "…/manifest.json",
    "generation": 1, "status": "fresh|reused|rebuilt", "stale": false,
    "stale_reasons": [],
    "before": {"corpus_version": 1, "corpus_hash": "…", "members": 0, "hypotheses": []},
    "previous": null,            // rebuilt 时是上一代的成员数/哈希快照（归档留证）
    "after":  {"corpus_version": 1, "corpus_hash": "…", "members": 9,
               "hypotheses": ["H1", "H2"]},
    "discovered": 1,
    "lineage": [{"sha256": "…", "hypothesis_id": "H1", "site_id": "…", "source": "…"}]
  },
  "paths": {"corpus": "…/active", "corpus_store": "…", "corpus_manifest": "…"}
}
```

`paths["corpus"]` 语义从“本轮临时目录”改为“本 task 的持久 active 目录”，
下游按路径读语料的行为不变。

---

## 5. 测试

`tests/test_v3_p1_seed.py`（8 例，全部离线、不调 LLM、不联网）：

| 用例 | 断言 |
|---|---|
| `test_different_hypotheses_produce_different_seeds` | 同一调用点、不同假设 → 种子集合双向有差集；每条带 `hypothesis_id/site_id/source` |
| `test_unmatched_hypothesis_has_explicit_reason_and_rule_fallback` | 空 `site_id` 与未知 `site_id` 各有 reason；回退种子仍绑父假设 |
| `test_seed_pool_walks_all_sites_and_reports_cap` | 8 个调用点全参与；`MAX_SEEDS` 限流时逐点记 `sites_skipped_cap` |
| `test_corpus_manifest_records_lineage` | manifest 四字段齐全；`resolve`/`by_hypothesis` 双向可查 |
| `test_corpus_reused_across_rounds_and_hash_tracks_members` | 跨轮 `reused`、成员保留、`corpus_hash` 随成员变化、task/campaign 隔离 |
| `test_build_change_marks_stale_and_rebuilds_without_mixing` | binary sha 变化 → `rebuilt`、generation+1、active 清空、旧代进 `history/`、entries 保留、同身份再开为 `reused` |
| `test_corpus_manifest_corruption_fails_closed` | 坏 manifest 抛 `CorpusError` |
| `test_execute_uses_persistent_corpus_and_records_build_id` | 真跑 `execute`（构建/并行/覆盖率替身）：`build_id`、`corpus.before/after`、第二轮复用不丢第一轮 fuzz 语料、第三轮换 build 后 stale 重建 |

回归：`tests/test_platform_v2_p2.py`、`test_platform_v2_p36.py`、
`test_platform_v2_exec.py`、`test_discovery.py`、`test_agent_seeds.py`、
`test_harness_seeds.py` 全绿（fuzz 执行器既有口径未变）。

---

## 6. 仍未做（不在 P1 范围）

- **两级生成**（SeedSpec 结构化约束 + 受信 builder 产字节、生成器候选在独立沙箱执行）：
  P1 仍只走规则模板，`propose_seeds` 未引入 SeedSpec；
- **语料三层**（原始生成 / 可执行 / 收益）与“parser 拒绝路径单列”：
  台账已按 `origin` 区分假设种子与 fuzz 发现，但还没有收益分层与拒绝路径分类；
- **覆盖位图按 build 存档**：本轮只保证旧 build 语料不接到新 build，
  位图归档要等 V3-006 的可信 Snapshot；
- **minimize**：未实现语料最小化，因此也没有“minimize 误删崩溃输入”的风险；
- **选点策略**（可达性/低覆盖/风险关联/成本排序 + 未知覆盖探索预算）：
  V3-004 只做“假设优先 + 全点补足”，排序策略留给后续实验项。
