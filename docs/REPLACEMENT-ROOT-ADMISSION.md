# 替代根准入表（2026-11-27）：wget2 `arvo:42470179`

> 背景：CG-18 名额转替换（见 COURSE-GAP-DISPOSITION §8）。
> 本文只做准入判定与施工计划，**不改变任何计数**。

## 0. 结论

| 项 | 主选 | 备选 |
|---|---|---|
| ID | **arvo:42470179** | arvo:42473305 |
| 项目 | wget2 | capstonenext |
| 缺陷 | Heap-buffer-overflow **WRITE 1**（High, asan） | Stack-buffer-overflow WRITE 5（High, asan） |
| sink | `src/options.c:492 set_char_prefix` | `SStream.c:49 SStream_concat` |
| 输入 | wget2 配置文本（`key = value`） | 原始字节（`cs_disasm`） |
| 三闸 | **全部通过** | 全部通过 |
| 结论 | **准予立项（planned，计数 0）** | 备选，主选失败再启用 |

## 1. 候选来源（可复算）

```text
数据集   n132/ARVO-Meta releases v3.0.0 → arvo.db（6138 行）
筛选     severity=High ∧ sanitizer=asan ∧ crash_type LIKE '%WRITE%'
         ∧ localId ∉ 已用 45 个 ∧ project ∉ 已用 10 个项目
剩余     841 条
```

选择理由：项目全新、缺陷是写越界、镜像在库、崩溃栈直接给出 `file:line`、
输入是**文本配置**（可手工构造，不依赖复杂二进制格式）。

## 2. 三闸

### G1 与现有 9 根不重复

| 判据 | 结果 |
|---|---|
| `localId` 不在已用 45 个 | ✅ |
| `project=wget2` 不在已用项目（ghostpdl/graphicsmagick/openvswitch/libidn2/libarchive/fio/exiv2/libredwg/nltk/lcms） | ✅ |
| 根 `(arvo:42470179, src/options.c:492)` 与现有 9 根无交集 | ✅ |

### G2 课程与授权范围

| 判据 | 结果 |
|---|---|
| 官方 benchmark 任务（ARVO/CyberGym 任务号，有 vul/fix 镜像） | ✅ |
| 不是自建双 commit 题 | ✅ |
| `patch_located=1`，`fix_commit=f6e7621…`，repo 公开 | ✅ |
| 执行边界：仅本地容器、`--network none`、官方 fuzzer 喂自造输入 | ✅ |

### G3 基准验证与材料可得

| 判据 | 结果 |
|---|---|
| 镜像 `n132/arvo:42470179-vul` / `-fix` registry 可解析 | ✅（manifest inspect 通过） |
| 崩溃栈含 sink 行号 | ✅ `#0 set_char_prefix options.c:492` ← `parse_included_directories:502` ← `set_long_option:2341` |
| 判定方自足 | ✅ CyberGym 语义：本仓自跑 vul/fix 差分 + 内部复核，无需 controller/receipt |
| 待产出材料 | `severity.json`（六维）、`review.json`（internal_attested）、轨迹导出 |

## 3. 施工计划

1. 读 `options.c:480-510` 与 `fix_commit f6e7621`，确认触发字段（include/exclude directories 列表）；
2. 手工构造配置文本，长度刚好跨过缓冲区边界；
3. 双端跑：vul 崩溃、fix 干净、同一输入哈希；
4. 写 `severity.json` + `review.json` + 轨迹导出；
5. 重算 `strict_submittable`——**只有 A∧B∧C∧D 全过才计数**。

**止损**：2 轮内构造不出稳定双端差分 → 换备选 `arvo:42473305`；再失败则此名额留给下一个候选。

## 4. 计数

```text
10 = 5 已通过 + arvo:67968（planned） + 4 个名额
     （CG-07 低优先 / CG-18→arvo:42470179 / CG-14→替换 / VG-01 阻塞）
```

当前可提交仍是 **5/8**；`42470179` 与 `67968` 都是 `planned`，不计数。

机读：experiments/replacement-admission.json。
