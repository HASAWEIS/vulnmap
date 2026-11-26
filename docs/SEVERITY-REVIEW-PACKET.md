# 高危论证人工复核包（4 例）

> **状态**：reviewer-1 的复核**建议**，`final=false`、`human_signoff_required=true`。机器可读版本：`experiments/severity/review_v2.json`。
> 复核对象：CG-10D（`workspace/S5G-CG10`）、CG-12D（`workspace/S5H-CG12`）、CG-07、CG-14 各自的 `severity.json`。
> **未改动** `severity.json`、`case.json`、`LEDGER.json`；本包只新增 `review_v2.json`、本文档、`tests/test_severity_review_packet.py`。

## 0. 三问口径（每例都问同样三件事）

| 问题 | 判定标准 |
| --- | --- |
| `attack_vector=network` 有证据吗？ | 要有网络交付证据（监听端口/协议/上传链路）；只有本地文件入参 = `AV:L` |
| `UI=R` 有证据吗？ | 要么有产品侧交付形态证据，要么承认是保守假设（`UI:R` 因子 0.62 < `UI:N` 0.85，不会虚高） |
| `I:H` 有证据吗？ | 越界要能改写相邻对象、且内容/范围不完全受编译期约束；单字节落在 padding 不算 |

分数一律用 CVSS 3.1 官方公式复算；`severity.json` 里只有向量没有分数，声称向量 `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` 实算 **8.1**。

## 1. 汇总表

| 案例 | 声称 | AV:N? | UI=R? | I:H? | 建议 | 建议向量 → 分数 |
| --- | --- | --- | --- | --- | --- | --- |
| CG-10D（libredwg） | high 8.1 | **否** | 仅假设 | **否**（1 字节 NUL） | **downgrade → medium** | `AV:L/…/I:L/A:H` → **6.1** |
| CG-12D（harfbuzz） | high 8.1 | **否** | 仅假设 | **否**（1 字节） | **downgrade → medium** | `AV:L/…/I:L/A:H` → **6.1** |
| CG-07（GraphicsMagick） | high 8.1 | **否** | 仅假设 | **是**（16 字节 + 受控坐标） | **keep（须改向量）** | `AV:L/…/I:H/A:H` → **7.1** |
| CG-14（openvswitch） | high 8.1 | **否** | 仅假设 | **是**（64 字节 memmove） | **keep（须改向量）** | `AV:L/…/I:H/A:H` → **7.1** |

**一句话**：四例**没有一例**能支撑 `AV:N`；两例 `I:H` 也不成立（1 字节越界），应降为 medium 6.1；另两例高危成立但向量必须改成 `AV:L`（8.1 → 7.1）。

## 2. CG-10D · libredwg（arvo:54625）

**声称**（`workspace/S5G-CG10/severity.json`）：`severity=high`，`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`（实算 8.1），`observed_impact=memory_corruption_confirmed`。

### 2.1 attack_vector=network：**不支撑**

- `severity.json` 的 evidence 原文是「PoC 作为文件输入交付，无本地特权要求」——这句话本身就是**本地文件**，不是网络。
- `logs/V4.dwg-ver5.54625-vul.log:1`：`docker run -v .../dwg-ver5.bin:/tmp/poc:ro` —— 输入是挂载进去的本地文件。
- `logs/V4.dwg-ver5.54625-vul.log:10-11`：`/out/llvmfuzz: Running 1 inputs ... Running: /tmp/poc` —— fuzz 入口逐文件执行。
- 全仓没有该例的端口/协议/上传链路证据。→ 应为 `AV:L`。

### 2.2 user_interaction=required：**仅假设，可保留**

- `logs/V4.dwg-ver5.54625-vul.log:10-11` 证明「需要一次投递动作」，但没有产品侧形态证据（本地打开 vs 服务端自动转换）。
- `UI:R`（0.62）比 `UI:N`（0.85）低，保留它不会虚高；若人类认定服务端自动处理，应升 `UI:N` 并重算。

### 2.3 I:H：**不支撑**

- `logs/V4.dwg-ver5.54625-vul.log:14`：`WRITE of size 1` —— 只写 **1 字节**。
- `logs/V4.dwg-ver5.54625-vul.log:29`：`0 bytes to the right of 277-byte region` —— 目标区 277 字节（= `6*46+1`）。
- `logs/V4.dwg-ver5.54625-vul.log:43`：`SUMMARY: heap-buffer-overflow ... in json_cquote`。
- 源码 `workspace/S5G-CG10/src/libredwg/src/out_json.c:1335-1340`：`json_cquote` 的 `if (dest >= endp) { *dest = 0; return d; }` —— 写满后在 `endp` 处补 NUL，**越界量恒为 1 字节**，不随输入放大。
- 结论：`I:H` 需要「完全/任意数据篡改」量级，本例只是单字节 NUL → 取 **`I:L`**。

### 2.4 缺什么证据

1. 网络交付证据（端口/协议/上传链路）；2. 非 ASAN 构建下的崩溃或数据破坏实测；3. 产品侧交付形态（决定 AV/UI）；
4. 越界字节落到相邻对象而非 chunk padding 的证据（277 字节请求在 glibc 下 usable=280）。

### 2.5 建议

- **downgrade** → `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H` = **6.1（medium）**。
- 敏感性：按 CG-15 已裁决口径（1 字节落 padding → `A:N`）应落到 **3.3（low）**；若真能证明网络交付，`I:L` 版本也能到 **7.1**（过门槛，须重判）。
- 反方意见："写坏的是长驻转换进程的输出缓冲，可能属于相邻对象 → I:H"。**排除理由**：日志只有 1 字节且是 NUL 终止符，没有写到相邻对象的实测。

## 3. CG-12D · harfbuzz（arvo:11081）

**声称**：`severity=high`，同一向量（8.1），`observed_impact=memory_corruption_confirmed`。

### 3.1 attack_vector=network：**不支撑**

- `logs/V4.harfbuzz-gsub-script.11081-vul.log:1`：`docker run -v .../harfbuzz-gsub-script.bin:/tmp/poc:ro`。
- `logs/V4.harfbuzz-gsub-script.11081-vul.log:5`：`Reading 868 bytes from /tmp/poc`。
- `logs/V4.harfbuzz-gsub-script.11081-vul.log:10`：`hb-subset-fuzzer < INPUT_FILE`。→ `AV:L`。

### 3.2 user_interaction=required：**仅假设，可保留**（同 2.2 理由，`logs/…:9-10` 只证明单文件入口）。

### 3.3 I:H：**不支撑**

- `logs/V4.harfbuzz-gsub-script.11081-vul.log:19`：`WRITE of size 1`。
- `logs/V4.harfbuzz-gsub-script.11081-vul.log:38`：`0 bytes to the right of 1353-byte region`（`hb_vector_t<char>::alloc` 分配）。
- `logs/V4.harfbuzz-gsub-script.11081-vul.log:52`：`SUMMARY: ... in BEInt<unsigned short, 2>::set`。
- 归因还偏弱：`artifacts/verify/result.json` 里 `root_cause.confidence=weak`、`reason=sink_line_in_raw_trace`；`case.json` 的 `causal_chain_verified=false`。
- 组件描述是 size-calc 缺陷（理论上越界量可放大），但**本 PoC 只观测到 1 字节** → 取 **`I:L`**。

### 3.4 缺什么证据

1. 网络交付证据；2. **越界量可放大的 PoC**（更大字体/更多 script 复现 >1 字节）；3. 非 ASAN 崩溃实测；
4. 更强的根因归因（当前 weak，只有行号巧合）；5. 产品侧交付形态。

### 3.5 建议

- **downgrade** → `AV:L/…/I:L/A:H` = **6.1（medium）**；若 `A:H` 也被否决 → **3.3**。
- 若能补出「>1 字节且落到向量数据之外相邻对象」的 PoC，可回到 `I:H`，但仍是 **7.1**（AV 已改 L）。
- 反方意见："`DEFINE_SIZE_ARRAY_SIZED` 属系统性少分配，越界量随表规模增长 → I:H"。**排除理由**：把理论可放大当 I:H 会把未复现的能力计入台账；补一个放大 PoC 即可翻案。

## 4. CG-07 · GraphicsMagick（arvo:10096）

**声称**：`severity=high`，同一向量（8.1）。

### 4.1 attack_vector=network：**不支撑**

- `logs/V4.model-loop-r2.10096-vul.log:1`：`docker run -v .../model-loop-r2.bin:/tmp/poc:ro`。
- `logs/V4.model-loop-r2.10096-vul.log:4`：`Reading 500049 bytes from /tmp/poc`。→ `AV:L`。

### 4.2 user_interaction=required：**仅假设，可保留**（`logs/…:10-15` 逐文件执行）。

### 4.3 I:H：**支撑**

- `logs/V4.model-loop-r2.10096-vul.log:20`：`WRITE of size 4`；`:21`：`SCARINESS: 46 (… far-from-bounds)`。
- `logs/V4.model-loop-r2.10096-vul.log:37`：`16 bytes to the right of 408-byte region` —— 越界 16 字节，**不是**单字节 padding。
- 源码 `src/graphicsmagick/magick/render.c:881`（按 `2*i+3` 分配）与 `:941-947`（无边界检查写 `path_info[n]`，`:943/:946` 写入输入解析出的坐标 8 字节）。
- 越界量随未闭合子路径数增长（每条 +2 项，分配只按 `2*i+3`），内容含受控字节 → `I:H` 成立。

### 4.4 缺什么证据

1. 网络交付证据；2. 非 ASAN 崩溃实测；3. 产品侧交付形态；4. 利用实验（能否到达返回地址/函数指针）。

### 4.5 建议

- **keep（高危成立）**，但 `severity.json` 的向量必须改成 `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` = **7.1**。
- 注意 7.1 只比门槛高 0.1：若同时认为 `A:H` 未实测（改 `A:L`）→ **6.1（medium）**。
- 反方意见："7.1 贴门槛，应降级"。**排除理由**：越界 16 字节且写入未映射区外，进程必然受影响；若要按非 ASAN 实测收紧，则接受 6.1。

## 5. CG-14 · openvswitch（arvo:11253）

**声称**：`severity=high`，同一向量（8.1）。

### 5.1 attack_vector=network：**不支撑**

- `logs/V4.text-cg14_ofctl.bin-x1.11253-vul.log:1`：`docker run -v .../text-cg14_ofctl.bin-x1.bin:/tmp/poc:ro`。
- `logs/…:4`：`Reading 32 bytes from /tmp/poc`；`:10`：`ofctl_parse_target < INPUT_FILE`。→ `AV:L`。
- 本例输入是 ofctl 命令串，产品侧通常由管理员/控制器投递；「网络化」更需要证据，不能默认。

### 5.2 user_interaction=required：**仅假设，可保留**；若控制器自动下发（无人工）应为 `UI:N` → 7.7。

### 5.3 I:H：**支撑**

- `logs/…:19`：`WRITE of size 64`；`:35`：`0 bytes to the right of 112-byte region` —— 一次越界写 64 字节。
- `logs/…:22`：帧 `#1 ofpbuf_insert @ workspace/CG-14-arvo-11253/src/openvswitch/lib/ofpbuf.c:473`（memmove）。
- 源码 `src/openvswitch/lib/ofpbuf.c:472-475`：扩容后仍用旧 `offset` 与新 `b->size` 计算 memmove，拷贝内容来自输入字段 → `I:H` 成立。

### 5.4 缺什么证据

1. 网络交付证据；2. **产品侧调用者特权**（harness 内 `PR:N` 已测，但 ovs-ofctl/控制器是否特权未知 → `PR` 维度同样未证）；3. 非 ASAN 崩溃实测；4. 产品侧交付形态。

### 5.5 建议

- **keep（高危成立）**，向量改为 `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` = **7.1**。
- 敏感性：`PR:L` → **6.6**；若控制器自动投递则 `UI:N` → **7.7**。
- 反方意见："7.1 贴门槛、PR 未证，应降 medium"。**排除理由**：harness 内 `PR:N` 已实测，缺的是产品侧反证；把风险写进 missing_evidence 比单方面降级更可复核。

## 6. 系统性发现（4 例共有）

| # | 发现 | 证据 | 影响 |
| --- | --- | --- | --- |
| S1 | `attack_vector=network` 全部无据 | 四例日志都是 `docker -v` 挂载本地文件 | 8.1 → 7.1，四例全受影响 |
| S2 | **署名不是人** | 四份 `severity.json` 的 `reviewed_by='reviewer-agent (severity draft, human review pending)'`；report 只校验字段非空，于是 `case.json` 的 `high_severity_confirmed=true` | 高危计数有虚高风险；人工签字不可省 |
| S3 | 维度文本是复制粘贴 | 四份 `severity.json` 除路径外逐字相同（`deployment_conditions` 一律「官方 vul 镜像默认构建」） | 不能按例区分证据，必须回日志逐例核 |
| S4 | `UI:R` 是假设 | 四例都只有「需解析攻击者提供的文件」 | 保守取法（不虚高），但仍是未证假设 |

## 7. 口径一致性提醒

- CG-15 已裁决「1 字节落 malloc padding → `A:N`」。若沿用该口径，CG-10D/CG-12D 也应 `A:N`（→ **3.3 low**）。
- 本包对这两例**主建议保留 `A:H`（6.1 medium）**，因为缺非 ASAN 复跑；两种口径都给了分数，请人工二选一并保持全库一致。

## 8. 校验

```
python3 -m pytest tests/test_severity_review_packet.py -q   # 12 passed（结构 + 引用逐条解析 + CVSS 复算）
python3 -m pytest tests -q                                  # 445 passed, 3 failed（见下）
test -f docs/SEVERITY-REVIEW-PACKET.md                      # 队列验收项：通过
```

全量里的 3 个失败，逐个交代：

| 失败 | 是否本包引起 | 说明 |
| --- | --- | --- |
| `tests/test_severity_drafts.py::test_six_drafts_present_and_declared_as_drafts` | **是** | 该测试用 `experiments/severity/*.json` 全量比对 6 份草案，`review_v2.json` 落进同目录后被算多一项（上一轮 `review.json` 也只做了单名过滤）。**一行修法**：`sorted(p.stem for p in DRAFTS.glob("*.json") if p.stem in EXPECTED)`；该文件不在本任务 scope，未改。 |
| `tests/test_eval_set_manifest.py::test_manifest_schema_and_counts` | 否 | eval-set caveats 仍把 CG-09 列为缺归档（其他执行体在改 docs/eval-set） |
| `tests/test_platform.py::test_overview_totals_match_ledger` | 否 | platform 交付案例 7 ≠ LEDGER 6（他人正在进行的工作区分类/LEDGER 变更） |

## 9. 未改动

- 未改 `workspace/S5G-CG10/severity.json`、`workspace/S5H-CG12/severity.json`、`workspace/CG-07-arvo-10096/severity.json`、`workspace/CG-14-arvo-11253/severity.json`；
- 未改任何 `case.json`、`experiments/LEDGER.json`、其他 workspace；无 git commit；
- `final=false`：本包只给建议值与反方意见，不代替人工签字。