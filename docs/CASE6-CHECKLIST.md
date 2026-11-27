# 第 6 份案例：候选材料清单（2026-11-27）

> 只做两件事：给两个候选各开一页清单，判断**谁能更早形成完整证据包**。
> 两个名额独立：`42470179` 是 CG-18 的替代候选，`67968` 是新增根因候选，**不能互相顶替**。
> 验收事件是**第 6 份包在干净目录复算通过**，不是“候选准入”。

## 0. 结论

| 候选 | 项目 | 缺陷 | 镜像 | 元数据来源 | 输入构造 | 先做 |
|---|---|---|---|---|---|---|
| **arvo:42470179** | wget2 | Heap-buffer-overflow **WRITE 1**，High/asan | ✅ vul+fix manifest 可解析 | arvo.db v3.0.0 | 配置文本（`key = value`） | **先做** |
| arvo:67968 | lcms | Heap-buffer-overflow WRITE {*}，High/asan | ✅ vul+fix manifest 可解析 | archive_data/meta/67968.json（旧 issue tracker） | IT8/CGATS 文本 | 次选 |

先做 `42470179` 的理由：

1. 元数据在主库（`arvo.db`）里，字段完整，可复算；
2. 崩溃栈直接给出三段调用链与行号，触发路径清楚；
3. 输入是**配置文本**，不依赖二进制格式；
4. 镜像已在拉取中（同一批任务）。

`67968` 不是放弃：它仍作为**新增根因**的名额（`planned`），只有在 `42470179` 之后再投入。

## 1. arvo:42470179 材料清单

| 项 | 状态 | 说明 |
|---|---|---|
| 独立根因（G1） | ✅ | `localId` 不在已用 45 个；`wget2` 不在已用项目；根 `(42470179, src/options.c:492)` 与 9 根无交集 |
| 课程/授权范围（G2） | ✅ | 官方 ARVO/CyberGym 任务；`patch_located=1`；`fix_commit=f6e7621…`；只在本地容器 `--network none` 跑 |
| 镜像 | ✅ 待拉取完成 | `dockerproxy.net/n132/arvo:42470179-{vul,fix}` manifest 可解析 |
| 触发点 | ✅ | `#0 set_char_prefix options.c:492` ← `parse_included_directories:502` ← `set_long_option:2341` |
| PoC 输入 | ⬜ 待构造 | 配置文本；需读镜像内 `src/wget2/src/options.c` 确认字段与缓冲区边界 |
| 双端差分 | ⬜ 待跑 | vul 崩 / fix 干净 / 同输入哈希 |
| severity.json（六维） | ⬜ 待写 | 攻击面、权限、交互、影响、可达性、部署条件 |
| review.json（具名） | ⬜ 待写 | `internal_attested`，注明非第三方 |
| 轨迹导出 | ⬜ 待导 | runs/stages/attempts/blackboard + 账本（若走模型） |
| Case Pack + 干净复算 | ⬜ 待做 | 包内 `verify_pack.py` 通过、`strict_submittable=true` |

## 2. arvo:67968 材料清单

| 项 | 状态 | 说明 |
|---|---|---|
| 独立根因（G1） | ✅ | 与现有 9 根、`42470179` 均不同 |
| 课程/授权范围（G2） | ✅ | 官方 ARVO 任务；`fix_commit=dbb4a1a…`；repo 公开 |
| 元数据 | ⚠️ 旧 tracker | 只在 `archive_data/meta/67968.json`，不在 arvo.db 主库；需在材料里注明来源 |
| 镜像 | ✅ manifest 可解析 | 体积较大，拉取成本高（约 1.4 GiB 内容） |
| 触发点 | ⚠️ 需确认 | 预期 `ParseIT8` / `cmscgats.c`；镜像内源码核对后才算确定 |
| 输入 | ⬜ 待构造 | IT8/CGATS 文本 |
| 其余材料 | ⬜ | 同上一节的 5 项 |

## 3. 施工顺序

```text
1) 42470179：读 options.c → 构造配置文本 → 双端差分 → 材料 → 打包 → 干净复算
2) 只有第 6 份包复算通过，计数才 +1
3) 67968 保持 planned；不与 42470179 共用名额
```

停止条件：`42470179` 两轮内构造不出稳定双端差分 → 转 `67968`；两者都失败则此名额留空，不硬凑。
---

## 4. CG-14 的独立替代候选（2026-11-27）

CG-14 的旧材料只作参考；替代候选必须与现有 9 根、`42470179`、`67968` 都不重复。

| 候选 | 项目 | 缺陷 | sink | 镜像 | 判断 |
|---|---|---|---|---|---|
| **arvo:42471192** | harfbuzz | Heap-buffer-overflow WRITE 1（High/asan） | `hb-machinery.h` `BEInt<unsigned short,2>::set` | ✅ vul+fix | **首选**（已有 harfbuzz 构造经验，subset 输入是字体二进制 + 表操作） |
| arvo:42471578 | librawspeed | Heap-buffer-overflow WRITE 2 | `VC5Decompressor::...::decode` | ✅ vul+fix | 备选（RAW 格式，构造复杂） |
| arvo:42473118 | kimageformats | Heap-buffer-overflow WRITE {*} | `__asan_memset`（sink 在拦截器，需再定位） | ✅ vul+fix | 备选（sink 不明，先排除） |

说明：

- `42471192` 与既有 harfbuzz 案例**是否同根**需在镜像内核对 sink 行；若与旧案例同一 sink 则不得使用，改 `42471578`；
- `42473118` 的 `#0` 落在 ASAN 拦截器上，真实 sink 需再看 `#1`，暂不作首选；
- 三个候选都只做**准入记录**，未拉镜像、未跑双端、计数 0。

若最终无合格候选，此项**留空**，不用旧材料硬凑。
