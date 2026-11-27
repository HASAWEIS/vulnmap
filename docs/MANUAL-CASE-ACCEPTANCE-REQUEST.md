# 人工案例认定征询（MANUAL-CASE-ACCEPTANCE）

> 状态：**pending_external（未发送）**。本文件只是待发问句与材料清单，
> 发出并取得具名答复前，AR6/AR7 **不计入严格提交数**。

## 1. 要问的唯一问题

课程是否接受**人工验证案例**（研究者读源码 → 手工构造 PoC → 本地双端容器执行，无 Agent 运行记录）
计入「10 个独立且经验证的高危漏洞案例」？

若不接受，**哪些替代日志可以接受**（用于替代 `COURSE-CRITERIA-V2` 的 D1 事件流与源数据库）？

## 2. 为什么问（事实，不含辩解）

AR6（wget2 `arvo:42470179`）与 AR7（haproxy `arvo:42485152`）现状：

| 项 | 状态 |
|---|---|
| 双端差分 | ✅ vul 崩溃 / fix 干净 / 同一 PoC 哈希 |
| 崩溃点与声明 sink | ✅ 帧一致（`options.c:492` / `cfgparse.c:1909`） |
| 危害六维论证 | ✅ `severity.json` |
| 传播链四要素 + refs | ✅ `propagation.json` |
| 具名内部复核 | ✅ `review.json`（`third_party=false`） |
| 包内自写复算 | ✅ 13/13 |
| **Agent 事件流（JSONL + 源库）** | ❌ 无（`trajectory.kind=manual`，0 次模型调用） |
| **冻结包结构**（`MANIFEST`/`SHA256SUMS`/`judgments/`） | ❌ 无 |

用冻结包同一实现复核：两份包在**完整性门**即被拒，A/B/C/D **未进入评估**。

## 3. 我们准备的替代材料（若课程认可人工案例）

1. `trajectory.json`：逐步命令 + 每步产物 sha256（读码 → 推导 → vul → fix）；
2. 双侧原始日志（含完整 ASAN 栈与退出码）；
3. PoC 实体与哈希；
4. `severity.json` / `propagation.json` / `review.json`（具名、内部）；
5. 复算脚本 `verify_case.py`（只读包内文件，退出码可判）。

## 4. 明确不做的事

- 不把人工轨迹伪装成 Agent 运行记录；
- 不伪造 JSONL 事件流或源数据库；
- 不在取得答复前把 AR6/AR7 写成「严格可提交」或把首页改成 7；
- 不因本条征询改变任何已有数字（严格 5、根因 11、第三方 0）。

## 5. 记录方式

取得答复后，在本文件追加一张表：`日期 / 答复人 / 认定结论 / 认可的替代材料`，
并把 AR6/AR7 的状态从 `manual_reference` 改为结论对应值；未取得前保持 `manual_reference`。
