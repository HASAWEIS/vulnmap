# 平台架构 / 技术路线

![系统总体架构](assets/architecture-slide.png)

![技术路线：五阶段](assets/pipeline-slide.png)

源文件：`assets/architecture.svg`（可编辑），Mermaid 源如下。

```mermaid
flowchart TB
  subgraph IN[输入与任务层]
    T[task.json<br/>case_id / benchmark / image / binary]
    D[description / error / patch]
    I[Docker 镜像 vul / fix]
    B[Benchmark 适配<br/>CyberGym / ExploitGym / VulnGym]
  end
  subgraph OR[编排与状态层]
    O[Orchestrator<br/>run_id / stage 调度]
    C[Stage 契约<br/>role / prompt / budget]
    K[Checkpoint<br/>image digest + 输入/工件 sha]
    S[(SQLite Store<br/>runs/stages/attempts/evidence/claims)]
    Q[TeamQueue<br/>claim / lease / release]
  end
  subgraph ST[五阶段流水线]
    R1[Recon] --> R2[Locate] --> R3[Verify] --> R4[Exploit] --> R5[Report]
  end
  subgraph CAP[能力组件]
    L[LLM Client<br/>DeepSeek / prompt 版本]
    BR[Builders Registry<br/>mng/pdf/dwg/... + 通用 hex]
    H[Harness 契约<br/>min/max / seeds]
    SB[Sandbox<br/>docker --network none]
    SC[扫描与诊断<br/>binscan / ASAN 解析]
  end
  subgraph OUT[验收与交付]
    G[验收门禁<br/>local / causal / severity / materials]
    LED[LEDGER / STATUS<br/>自动生成]
    PK[案例包<br/>日志/PoC/报告/哈希]
    UI[看板与文档]
  end
  T --> O; D --> O; I --> SB; B --> O
  O --> C --> R1
  R1 --> R2 --> R3 --> R5
  R3 <--> L; R3 <--> BR; R3 <--> H; R3 --> SB; R3 --> SC
  R5 --> G --> LED
  G --> PK --> UI
  S -. 记录 .- ST
```

## 各层职责

| 层 | 职责 | 关键约束 |
|---|---|---|
| 输入层 | 任务描述、崩溃信息、镜像、benchmark 适配 | 镜像 digest 必须可查，否则 checkpoint 拒绝 |
| 编排层 | 阶段调度、预算、租约、检查点、SQLite 证据 | run_id 贯穿；checkpoint 绑定 digest+sha |
| 五阶段 | recon→locate→verify→exploit→report | 每阶段产物落盘，失败保留 |
| 能力组件 | 模型、构造器、harness 契约、沙箱、扫描 | 构造器可被 `allow_builders=false` 禁用 |
| 验收交付 | 门禁、台账、案例包、看板 | 门禁不过不得 pass |

## 技术路线（当前定位）

1. 先保证“可复现”：镜像、输入、日志、哈希可追溯；
2. 再保证“可判定”：vul 崩 / fix 干净 / 根因匹配；
3. 最后区分贡献：builder / model / rule，不混算；
4. 自主性用冻结盲测单独验证，当前 0/4。
## 工具边界（2026-11-15）

- 当前 benchmark 是**源码 + 容器内预编译二进制**，不是固件；
- 定位用源码检索 + ASAN 帧 + binutils（nm/readelf/addr2line），不依赖 IDA/Ghidra；
- IDA/Ghidra 仅在未来接入无源码/固件任务时考虑，现阶段不列入“已实现”；
- 方案修订版中的 IDA-MCP 已改为“源码优先，无源码场景可选”。
