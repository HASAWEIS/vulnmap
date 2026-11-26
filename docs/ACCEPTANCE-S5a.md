# S5-a 阶段验收报告（2026-11-10）

审查对象：S5-a「严重性草案（6 例）」
审查方式：结构校验 + 测试复跑 + 证据抽查 + case.json 未被改写核对
结论：**S5-a 通过（草案阶段）；独立高危仍只有 3 例（含 CG-01），距 10 例差 7 例**

---

## 1. 草案结果

| 案例 | is_high_severity | CVSS | 缺失维度 | 独立性 |
|---|---|---|---|---|
| CG-02 (47101) | false | 5.5 | deployment | independent |
| CG-04 (10400) | false | 0.0（C=unproven） | deployment | independent |
| CG-07 (10096) | **true** | 7.1 | deployment | independent |
| CG-14 (11253) | **true** | 7.1 | PR, deployment | independent |
| CG-15 (3940) | false | 4.4 | PR, deployment | independent |
| EG-02 (44034) | **true** | 8.1 | deployment | **duplicate(=CG-01)** |

- 判定口径：`is_high_severity ⇔ CVSS base ≥ 7.0`，测试按官方公式复算，强校验；
- CG-04 只写 `memory_corruption_read` 且 `affected_confidentiality=unproven`，没有写成“信息泄露”；
- 证据不足的维度一律 `unproven` 并进 `missing_dimensions`；
- `workspace/*/case.json` 的 `severity.state` 仍为 `unassessed`，**草案没有自我打分**；
- `tests/test_severity_drafts.py` 11 项全过。

---

## 2. 需要人工裁决的 3 个点（会改等级）

| # | 案例 | 争议 | 若改判 |
|---|---|---|---|
| 1 | CG-02 | `I:N` 是否成立（memset 堆越界写） | 若 I:H → 7.1，升为高危 |
| 2 | CG-04 | `C:N` 是否成立（1 字节越界读） | 若 C:L → 3.3，仍非高危 |
| 3 | CG-15 | ASAN abort 算 `A:L` 还是 `A:H` | 若 A:H → 6.1，仍非高危 |

我的初步意见（供裁决参考，不替代人工）：

- CG-02：memset 写的是 0，越界破坏相邻堆对象可致完整性损失，但无“可控数据写入”证据，**倾向 I:L**，维持 5.5；
- CG-04：越界读到的字节未回传给攻击者，**倾向 C:N**，维持 0.0；
- CG-15：进程 abort 属于可用性完全丧失，**倾向 A:H**，但 6.1 仍未达 7.0。

---

## 3. 证据瑕疵（已记入 limitations）

1. **EG-02 缺 `artifacts/verify/result.json`**：其 `local_verified` 目前缺少直接证据链；
2. **EG-02 与 CG-01 同源**：同一 arvo:44034 漏洞，按口径不计独立分子——这条做对了；
3. `experiments/eg-44034/RESULT.json:2` 的 `case_id` 误写 `EG-03`；
4. CG-14/CG-15 的 `provenance` 缺 `source_sha256`；
5. 六例的 `logs/R3.build.log` 均为 127（宿主机缺 autoreconf/cmake），结论只依赖预置镜像——需在报告中注明。

---

## 4. 计数现状（课程口径）

| 指标 | 数量 |
|---|---|
| 本地双端通过 | 8 |
| 因果链闭合 | 6 |
| **独立高危（草案）** | **3**（CG-01、CG-07、CG-14） |
| 交付缺口 | **还差 7 例独立高危** |

EG-02 虽然 CVSS 8.1，但与 CG-01 同源，不能重复计数——这正是 v3 方案里“同源去重”要防的。

---

## 5. 结论

- S5-a 完成的是“把严重性从口号变成可复核草案”，不是“凑够 10 例”；
- 真正的缺口是 **7 个独立高危案例**，靠改判 CVSS 补不上；
- 下一步必须扩案例池，或把 CG-08/09/10/11/12/13 这些未通过案例的构造器补起来。

**一句话：严重性草案让“3 个高危”变得可信，但也让“还差 7 个”变得无法回避。**
