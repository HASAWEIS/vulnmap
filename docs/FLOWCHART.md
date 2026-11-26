# Discovery v1.0 流程图

![Discovery v1.0 流程图](assets/flowchart.png)

- 源文件：`assets/flowchart.svg`
- 生成脚本：`scripts/gen_discovery_flowchart.py`（改流程时改脚本并重渲染，不手改 SVG）
- 工具标注版：`assets/flow-tools.png`（`assets/flow-tools.svg`）
- 旧五阶段复现流程图已归档；本图只描述 Discovery v1.0。

## Mermaid 源

```mermaid
flowchart TD
  A[源码/二进制 + target.yaml] --> B[D0 静态档案<br/>后缀 / ELF magic / main / 函数 / 格式]
  B --> C[D1 危险调用点<br/>权重 + 近似可达 + 参数可控 → score]
  C --> D[D1.5 只读分析<br/>默认 LLM，无 key 回退 heuristic<br/>假设 + 定向种子]
  D --> E[D2 构建 harness<br/>ASAN + trace-pc/trace-cmp<br/>cov_rt.c 单独编译]
  E --> F[初始语料 + 字典<br/>假设种子 + 格式模板]
  F --> G[变异<br/>字节 / 长度 / 字典 / PNG/TIFF 结构]
  G --> H[隔离执行<br/>bwrap 默认：网络 none / 只读根 / cap-drop<br/>2s 超时]
  H --> I{ASAN 崩溃?}
  I -- 是 --> J[保存 crash-*.bin/.log<br/>停止该 worker]
  I -- 否 --> K{新 bitmap 位 / cmp?}
  K -- 是 --> L[加入 corpus ≤300<br/>更新字典 ≤96]
  L --> G
  K -- 否 --> G
  J --> M[D3 分诊门禁<br/>有效诊断 + 干净重建 3/3]
  G -. 预算结束 .-> N[覆盖率归属<br/>COV_PCS → addr2line]
  N --> M
  M --> O[D3.5 复核<br/>规则 / 可选 LLM 单次复核]
  O --> P[D4 报告 + SQLite]
  P --> Q[D5 对照<br/>ranked vs random / 种子 A/B]
  Q --> R[只读 API / UI<br/>/api/discovery/campaigns]
```

## 关键口径

- **输入**：只有源码/二进制与构建方式；不读 `error.txt`、`patch.diff`、官方 PoC；
- **Fuzz 循环**：变异 → 隔离执行 → ASAN 判定 → 新覆盖/新比较常量入库 → 再变异；崩溃是搜索副产品；
- **门禁**：有效诊断（非 `unknown/allocator/OOM`）+ 独立目录干净重建 3/3；干净构建失败或复用旧构建只能 `needs_human`；
- **结论**：写 + 3/3 = `confirmed`；读/UB + 3/3 = `weakened`；0/3 = `excluded`；不稳定 = `needs_human`；
- **负结果**：0 崩溃、覆盖率不足、构建失败都保留，不删除、不改写；
- **边界**：每个输入一个进程（约 500–1000 exec/s），没有 persistent mode；覆盖率以函数级为主；真实目标 WRITE/UAF 尚未命中；受控 fixture 的 confirmed 不能当作真实目标战果；
- **与旧流程的区别**：旧流程读 task.json/error/patch，跑 vul/fix 双端；Discovery 不依赖已知崩溃位置，vul/fix 差分/flag 不属于本图。

## 复现

```bash
cd vulnmap
python3 scripts/gen_discovery_flowchart.py
microsoft-edge --headless=new --disable-gpu --no-sandbox \
  --user-data-dir=/tmp/edge-flow --window-size=1440,1960 \
  --screenshot="$PWD/docs/assets/flowchart.png" "file://$PWD/docs/assets/flowchart.svg"
```
