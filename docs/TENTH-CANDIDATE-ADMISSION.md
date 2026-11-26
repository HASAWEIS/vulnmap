# 第 10 例候选准入表（三闸判定 + `arvo:67968` 逐项预检）

> 依据：[TENTH-CASE-PLAN.md](TENTH-CASE-PLAN.md)（通道/计数口径）、[COURSE-EVIDENCE-DECISIONS.md](COURSE-EVIDENCE-DECISIONS.md)（D1/D2/D3 决策与候选排序）、
> [COURSE-CRITERIA-V2.md](COURSE-CRITERIA-V2.md)（A/B/C/D 四层）、[REVIEW-POLICY.md](REVIEW-POLICY.md)（2026-11-12 起不再要求逐例人工签署）、
> [STAGED_GOALS.md](STAGED_GOALS.md) §6.2/§7.2、`experiments/LEDGER.json`、`workspace/*/task.json`、`workspace/**/case.json`（只读）。
> 写于：2026-11-25。机读件：[experiments/tenth-admission.json](../experiments/tenth-admission.json)。
> 写入范围：**只写 `docs/` 与 `experiments/`**。未改 `workspace/**`、任何历史 `case.json` / `severity.json` / `RESULT.json` / `logs/`、
> `experiments/LEDGER.json`；**未改业务代码**（`agent/**`、`scripts/**`、`bin/**`）；**未拉任何镜像、未跑任何双端**；**无 git commit**（仓库根不是 git 工作区）。

---

## 0. 结论先行

| 项 | 结论 |
|---|---|
| 候选 | **`arvo:67968`**（lcms / `cmsIT8_load_fuzzer` / `Heap-buffer-overflow WRITE {*}` / High / asan） |
| **G1 不重复** | **PASS**（机器判据实测：`NEW-ID arvo:67968`、`NEW-ROOT arvo:67968`；库内 45 原始 id / 44 归一化 id / 51 根，无 COLLIDE） |
| **G2 课程·授权范围** | **PASS（带两条必须写进材料的限定）**：①这是 ARVO/CyberGym **benchmark 任务号**，不是 D1 自建双端；②缺陷类别与既有 9 根**同族**（CWE-122 家族，已有 6 例），**类别新颖性不能作为准入理由**，只能作为打分项 |
| **G3 基准验证 + 内部复核材料可取得性** | **CONDITIONAL-PASS（可取得，但今日 0 证据）**：三个"外部判定方"依赖全部为 **0**（CyberGym 双端由本仓自跑；内部复核按 REVIEW-POLICY 由 agent reviewer 具名 + 用户终审；无需 controller/receipt）→ 材料链**自足**；但镜像未拉、双端未跑、severity 未写、review.json 未签 → **当前不计数** |
| **准入裁决** | **准予立项（S1 立项 → S2 双端）**，**计数值仍为 0**，直到 S2/S3/S4 产物到位 |
| 计数净影响 | 独立高危根 **9（不变）**；**V2 内部复核可提交 5/8**（2026-11-25 重审后；本文初稿写的“严格可提交 0”是 2026-11-25 早期旧快照，已被 5 例提交包取代）；第三方独立复核 **0**；后端 `course_ready` **0**；第 10 例状态 = **`planned`**，不是 `verified` |
| 一句话 | **发现根因 ≠ 可提交案例**：本轮只把"根"和"材料路径"钉死，**没有一个 `case.json` 字段可以因为本文档而变绿**。 |

> **口径更新（2026-11-26）**：上表初稿的“严格可提交 0”是早期旧快照；当前按 COURSE-CRITERIA-V2 重审后为 **V2 内部复核可提交 5/8、第三方独立复核 0、后端 course_ready 0**。5 例提交包见 [COURSE-SUBMISSION-PACK-20261125.md](COURSE-SUBMISSION-PACK-20261125.md)。

---

## 1. 准入三闸（先写死，再判题，不因结果调整）

一道候选要进入"第 10 例"的施工序列，必须**同时**过三闸；任一道不过 → 不入施工序列、**不计入分子**、只在候选表留 `rejected`/`blocked` 行。

### G1 · 与现有 9 根因不重复

| 判据 | 具体要求 | 判定动作 |
|---|---|---|
| G1-a `task_id` 不重复 | `norm_task_id` 不在 44 个归一化 id 内 | 跑 §2 脚本 |
| G1-b `root_key` 不重复 | `(norm_task_id, norm_sink_file, sink_line)` 不在 51 个根内 | 同上 |
| G1-c sink 路径**必须先归一化** | 去掉仓库顶层目录前缀（`ghostpdl/pdf/pdf_font.c` 与 `pdf/pdf_font.c` 是同一 sink） | 归一化函数随脚本固化 |
| G1-d 同 bug 多号排除 | `fix_commit` 相同的多个 ARVO 号只算 1 个（如 `42938/42939/42940/42944` 全为 `afdbc940c601`） | 落表时逐条记 `fix_commit` |
| G1-e 断言冒充写排除 | `VERIFY`/`ak_verification_failed` 类首帧不得当"无界写"（如 `62083`） | 看 `crash_type` 原文 |

> **口径提醒（X4）**：字面 `root_key` 去重会把 EG-02 与 CG-01 判成两根（`ghostpdl/pdf/pdf_font.c:332` vs `pdf/pdf_font.c:332`），
> 从而**虚增出假第 10 例**。G1-c 因此是硬步骤，不是建议。

### G2 · 课程 / 授权范围内

| 判据 | 要求 | 本候选 |
|---|---|---|
| G2-a 有 benchmark 任务身份 | `task_id` 可追溯到 ARVO/CyberGym 目录（有 meta 原件 + 哈希），不是自建题 | ✅ `/tmp/ARVO-Meta/archive_data/meta/67968.json`，`sha256 e08cc478…0815` |
| G2-b 不是 D1 | 不得用"自己 checkout 两个 commit 起服务"当官方根 | ✅ 镜像对 `n132/arvo:67968-vul/-fix` |
| G2-c 授权边界清楚 | 只在镜像内的官方 fuzzer 上喂自造输入；不联网打第三方、不使用真实目标 | ✅ 容器 `--network none`（沿用 CG-01 命令形态） |
| G2-d 缺陷类别不得靠"新"来充数 | 课程只要求 **A 独立 = 不同项目/不同缺陷函数**（STAGED_GOALS §7.2-A），不要求 CWE 不同 | ⚠️ 本候选 CWE-122 家族与既有 6 例同族；**独立性的依据只能是 root_key，不是 CWE** |

### G3 · 能取得完整基准验证 + 内部复核材料

"能取得"= 三条同时成立（**不是**"已经取得"）：

| 判据 | 要求 | 判定方法 |
|---|---|---|
| G3-a 判定方自足 | CyberGym 语义的双端差分由**本仓自跑**即可成立（vul 崩 + fix 干净 + 根因匹配），不依赖外部 controller | 对照 STAGED_GOALS §6.2；与 EG 的 `receipt` 型判定**不同** |
| G3-b 输入/镜像/归属可锚定 | PoC 可自造或可得；镜像 digest 可追溯；源码归属有 commit 全 sha + blob sha + 字节三方一致 | 见 §6.1 已钉项 |
| G3-c 内部复核路径存在 | 按 [REVIEW-POLICY.md](REVIEW-POLICY.md)（2026-11-12）：`severity.reviewed_by` 由 agent reviewer 签署即可计数；`review.json` v2 要求**具名 reviewer + ≥6 条 `evidence_refs` 逐条 sha256**；用户终审 | 对照 COURSE-CRITERIA-V2 §2.3 |

> **G3 不是**"有回执"。ARVO 通道从不产 `receipt.json`；把 EG 的 D 层口径套到 ARVO 上会造出**永远过不了**的假门槛（V1 的老毛病）。

---

## 2. G1 机器判据（本轮实跑，可复跑）

```bash
cd /home/root_bupt/桌面/file/vulnmap && python3 - <<'PY'
import json, glob, re
CAND = [("arvo:67968", "lcms/src/cmscgats.c", 1251)]     # task_id, 归一化 sink, 行号
def norm(t):
    m = re.match(r"^(?:user:cybergym/)?arvo[:_](\d+)$", str(t) or "")
    return f"arvo:{m.group(1)}" if m else t
raw, ids, roots = set(), set(), set()
for p in glob.glob('workspace/*/task.json'):
    t = json.load(open(p)).get('task_id'); raw.add(t); ids.add(norm(t))
for p in glob.glob('**/case.json', recursive=True):
    try: c = json.load(open(p))
    except Exception: continue
    s = c.get('sink') or {}
    roots.add((norm(c.get('task_id')), s.get('file'), s.get('line')))
print('raw task_ids:', len(raw), '| normalized:', len(ids), '| roots:', len(roots))
for tid, sf, ln in CAND:
    n = norm(tid)
    print('NEW-ID ' if n not in ids else 'COLLIDE-ID', n)
    hit = [r for r in roots if r[0] == n]
    print('COLLIDE-ROOT '+str(hit[:3]) if hit else 'NEW-ROOT', n)
PY
```

本轮输出（2026-11-25 实跑）：

```text
raw task_ids: 45 | normalized: 44 | roots: 51
NEW-ID  arvo:67968
NEW-ROOT arvo:67968
```

另：全仓 `case.json` / `workspace/*/task.json` 对 `lcms`、`67968` 的字符串检索 **0 命中**（无历史接触）。

**G1 判定：PASS。**

---

## 3. 候选表（全通道，含三闸逐项）

| 槽 | 候选 | project / sink | G1 不重复 | G2 范围 | G3 材料可取得 | 今日裁决 |
|---|---|---|---|---|---|---|
| **A1** | **`arvo:67968`** | lcms / `src/cmscgats.c:1251`（`AllocTable`，内联进 `ParseIT8`） | ✅ NEW-ID + NEW-ROOT | ✅ benchmark / 镜像内 | ✅ 自足（无回执依赖） | **准入（立项）** |
| A1-fb | `arvo:35870` | dnsmasq / `dhcp_reply` | ✅（待同法复算） | ✅ | ✅ | 备选，A1 失败即启用 |
| A2 | `arvo:28262` | qpdf / `Pl_ASCII85Decoder::write` | ✅（待复算） | ✅ | ✅ 但**严重性大概率落 medium**（`WRITE 1`） | 备选，不建议首选 |
| A3 | `arvo:18130` | imagemagick / `GetVirtualPixelCacheNexus` | ✅（待复算） | ✅ | ⚠️ 与已计 CG-07（GraphicsMagick）**同 draw 家族**，可能被裁定"需人工并入" | 不建议今天 |
| B1/B2 | `vulngym/<PROJECT>/<COMMIT>` | — | 待定 | ✅ | ❌ 缺 `baseline_url`/`patched_url`（全仓 0 命中）→ **G3 不成立** | **不入施工序列**（不是资源问题，是任务身份缺失） |
| C1/C2 | `user:cybergym/arvo_[ID]` | — | 待定 | ✅ | ❌ 缺 controller / `CYBERGYM_SERVER_FLAG_SEED` / 回执 | **blocked** |
| D1 | 本地自建双端（nltk 等） | — | — | ❌ 无 benchmark 任务号 | 材料可做但**不计分子** | 只做门禁回归 |

> 排序沿用 [COURSE-EVIDENCE-DECISIONS.md](COURSE-EVIDENCE-DECISIONS.md) §4.5 实测改序：**A1 > A1-fb > A2 > B > C > D1**。

---

## 4. `arvo:67968` 逐项预检

### 4.1 已知信息（硬事实，逐条带来源）

| # | 项 | 值 | 来源 / 取法 |
|---|---|---|---|
| K1 | `task_id` | `arvo:67968`（ARVO `localId=67968`） | `meta/67968.json` |
| K2 | meta 文件 `sha256` | `e08cc478ce782befc0eedac37ce17f959ee812644437de9856bc4d26e8880815` | 本机复算 |
| K3 | project / fuzzer / sanitizer | `lcms` / `libfuzzer` / `asan` | meta |
| K4 | `crash_type` | **`Heap-buffer-overflow WRITE {*}`**（`{*}` = 写长度未知，符合指针写） | meta |
| K5 | severity（上游） | `High`（ClusterFuzz `Recommended Security Severity`） | meta |
| K6 | crash state（上游原始） | `ParseIT8` → `cmsIT8LoadFromMem` → `cmsIT8_load_fuzzer.c` | meta 引 ClusterFuzz 详报 |
| K7 | 缺陷位置（**代码定位，非上游给定**） | `AllocTable()`：`t = it8->Tab + it8->TablesCount;` 后紧接 3 次指针写，**无上限检查**；`MAXTABLES=255`，`TABLE Tab[MAXTABLES]` 是定长数组 | `/src/lcms/src/cmscgats.c` @ commit `d1652a06…`，`MAXTABLES@35`、`TABLE Tab[255]@143`、`AllocTable@1245`、首个写 `t->HeaderList = NULL;@1251` |
| K8 | 上游 fix | `dbb4a1a4fbb4fe3708155cfa15947ccd2c3d290b`（2024-04-11，"Add more checks to CGATS parser"）：`AllocTable` 改返回 `cmsBool`，`TablesCount >= MAXTABLES-1` 时 `return FALSE`；`ParseIT8` 调用点改为 `if (!AllocTable(it8)) return FALSE;` | GitHub API `commits/dbb4a1a4` |
| K9 | vul 镜像构建 commit | `d1652a06dc7308da9819624188181f20ce10fd93`（fallback：`git log --before=2017-08-13T05:06:00-03:00`） | 镜像 config `history[48]` |
| K10 | fix 镜像构建 commit | `1176e61afea4b58c5f92c6f226cdb7b1c76797d5`（fallback：`--before=2024-04-12T06:33:00-03:00`） | 镜像 config `history[77]` |
| K11 | fix 镜像内源码**确已修** | 该 commit 的 `src/cmscgats.c`（blob `0a1905c3…`，85983 B，`sha256 d85b3dba…2 32 9c0f`）含 `if (it8->TablesCount >= (MAXTABLES-1)) return FALSE;@1382` | GitHub `git/blobs` |
| K12 | vul 镜像内源码锚点 | `src/cmscgats.c` blob `7df5bbc4da494a4763a0aae13b3d3a913fc3cf9b`、**73602 B**、`sha256 0d0a2a421b25cefc27538a845993b5cc67f38668938bb826ee15ecf037d91ba7` | GitHub `git/blobs`；本地按 `blob <len>\0` 复算 = API sha（一致） |
| K13 | 输入接口 | `LLVMFuzzerTestOneInput` → `cmsIT8LoadFromMem(0, data, size)`；成功后再 `cmsIT8SaveToFile("/tmp/fuzzer-it.<pid>.it8")` | oss-fuzz `projects/lcms/cmsIT8_load_fuzzer.c`（1115 B，HTTP 200） |
| K14 | 输入格式 | **CGATS/IT8 文本**，多表流：每个 `BEGIN_DATA…END_DATA` 段在不 EOF 时会 `AllocTable()` 一次（`cgats.c@2079`）；`TablesCount` 在 `cmsIT8Alloc` 里已由 `AllocTable()` 置 **1**（`@1291`） | 同上，vul 源码 |
| K15 | 越界机制（推导） | 写地址 ≈ `16 + N*sizeof(TABLE)`，`sizeof(TABLE)=1064`（`MAXSTR 1024` + 3×int + pad + 3×ptr）；`N≈255` 的写仍落在 `cmsIT8` 内（撞 `MemorySink/Allocator/sy` 等尾字段），**`N≈256` 才越过分配边界** → ASAN 报 heap-buffer-overflow WRITE | `cmscgats.c` 结构体定义 + 手算；**需 U4 实测校准** |
| K16 | 所需镜像对 | `n132/arvo:67968-vul`（26 层）+ `n132/arvo:67968-fix`（40 层） | `docker manifest inspect`（dockerproxy.net 与 hub 两次均 rc=0） |
| K17 | 镜像体量 | vul **727,038,897 B**（0.6771 GiB）／fix **783,331,727 B**（0.7295 GiB）／**合计 1,510,370,624 B = 1.4066 GiB** | manifest 层大小求和 |
| K18 | config digest（声明用） | vul `sha256:12ccd23162537725c0b9c2d261ae6a05f528b09c16f811982d6c3da3afb18f01`；fix `sha256:438d5f12c254c1bfa9dc28a30e6011c3ba8244ff5d3c6a8d5d1c9d265a20dd61` | 两次成功取到的 manifest |
| K19 | 容器形态 | `Cmd=["sleep","infinity"]`、`WorkingDir=/src/lcms`、`Env` 含 `OUT=/out SRC=/src SANITIZER=address FUZZING_ENGINE=libfuzzer`；镜像内有 `build.sh` 与 `cmsIT8_load_fuzzer.*`（`history[50]`） | config blob |
| K20 | 单流带宽实测 | 16 MiB 分片下载 9.51 s = **1.76 MB/s**（307 → CDN） | `curl -r 0-16777215` 打 registry blob |

### 4.2 未知项（必须在 S2 之前或期间消掉，逐项带消法）

| # | 未知 | 为什么重要 | 消法（成本） | 不消的后果 |
|---|---|---|---|---|
| **U1** | **真正触发所需的表数 N**（K15 手算 ≈256，非实测） | 构造器参数；差 1 就"不崩" | 容器内一次 `offsetof/sizeof` 探针（编译 10 行 C，<2 min），或直接以 240/256/280/320 四档扫 | 反复跑空，误判"题不可复现" |
| **U2** | 每段 `BEGIN_DATA` 前是否必须给 `NUMBER_OF_FIELDS`/`NUMBER_OF_SETS`（`DataSection` 有 `(iSet+1) != nPatches` 计数校验 `@1913`） | 决定最小合法块 | 读源码即可定形（已读：需要），再在 vul 端试最小块（<10 min） | 构造器写错，早退 `SynError`，永远到不了 `AllocTable` |
| **U3** | `N≈255` 时写坏 `MemorySink/Allocator/sy` 会不会**先**变成 SEGV/语法错（而不是 ASAN 越界） | 决定 `defect_class` 与 `crash_type` 是否仍为 `heap-buffer-overflow WRITE` | vul 端跑 U1 的四档，看 ASAN 首帧 | 若首帧变成 SEGV/其他函数 → **G1 的 sink 与类别一起变**，必须重判 |
| **U4** | vul 镜像内 `sizeof(cmsIT8)` / `Tab` 偏移的真实值 | 同上（K15 是手算） | 容器内 `printf("%zu %zu", sizeof(cmsIT8), offsetof(cmsIT8,Tab))`（需源码树，镜像内有） | 估算错 → N 估错 |
| **U5** | 镜像内 `/bin/arvo` 是否存在、其默认命令是否 `cmsIT8_load_fuzzer /tmp/poc` | 决定 `docker run` 的命令形态（CG-01 是 `/bin/arvo`） | 拉完 `docker run --entrypoint sh` 列 `/bin`、`cat /bin/arvo` | 命令写错 → 空跑，日志无意义 |
| **U6** | `/out/cmsIT8_load_fuzzer` 是否存在、sha256 是多少 | 证据包 `container-binaries.sha256` 必需 | 同上 | D4 哈希链缺口 |
| **U7** | `/out/cmsIT8_load_fuzzer_seed_corpus.zip` 是否随镜像（build.sh 有 `cp $SRC/seed_corpus.zip`，但 2017 版构建未必有） | 有语料 → 构造器直接"改一个真种子"，省 30 min | 同上 | 构造器需从零写 CGATS（仍可行，只是慢） |
| **U8** | 镜像 manifest **digest**（`RepoDigest`）今日未能钉住 | D4 要求 `images[vul|fix].digest` 可追溯 | 拉取成功时自动得到；或 hub 稳定时再取一次 | 只能记 `config digest`，D4 记 `pass_with_caveats` |
| **U9** | fix 端同输入是否 `exit 0` **且无 sanitizer 签名** | B 层硬判据 | S2 实跑 | 若 fix 端也崩 → 该题**没有干净 fix 端**，G3 崩，止损 S3 |
| **U10** | 上游是否另有同 `fix_commit` 的 ARVO 号（同 bug 多号） | G1-d | 在 `/tmp/ARVO-Meta` 全量 grep `dbb4a1a4fbb4` | 可能把一个 bug 当两例（假计数） |

### 4.3 所需镜像 / 服务 / 资源

| 项 | 需求 | 现状（本轮实测） |
|---|---|---|
| 镜像 | `n132/arvo:67968-vul` + `-fix`（各 1 个 tag，不预拉全量） | ❌ 未拉；manifest 两次解析成功（proxy + hub） |
| 镜像站 | `dockerproxy.net`（200 / 1.9 s）或 `registry-1.docker.io` | ⚠️ **抖动**：20:18 取 `/v2/` 得 401（可达）、20:26 起连续 `连接超时`；`docker manifest inspect` 亦从 rc=0 变 rc=1 → **按"每题 2 次重试，失败记 blocked"执行** |
| docker 守护 | 29.7.2 / overlayfs / 20 CPU / 30.8 GiB | ✅ 可用（`docker info` 实读） |
| 磁盘 | ≈1.41 GiB 内容 → **≈4.8 GB 峰值**（×3.4 实测系数） | ✅ 484 GB 可用（`df`） |
| 服务（HTTP） | **无**。本题只要两个容器 | — |
| 容器运行时约束 | `--network none --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 2g --tmpfs /tmp:rw,exec`（沿用 CG-01 形态；`cmsIT8SaveToFile` 要可写 `/tmp`） | 待 S2 执行 |
| 外部凭证 / controller | **不需要**（ARVO 通道无回执） | ✅ 不构成阻塞 |

### 4.4 预算（用 K17 + K20 校准，公式同 COURSE-EVIDENCE-DECISIONS §4.4）

`拉取分钟 ≈ 内容 MiB ÷ 1.8 ÷ 60`；`磁盘 GB ≈ 内容 GiB × 3.4`

| 阶段 | 内容 | 实测/估算 | 累计 |
|---|---|---|---|
| S1 立项（规则先行落盘） | 本文档 + JSON 已是产物 | 已完成 | 0 |
| **拉取** | vul 727 MB + fix 783 MB = 1.51 GB @1.76 MB/s | **14.3 min**（+ 抖动重试 ≤2×） | 14–30 min |
| **探针**（U1/U4/U5/U6/U7） | 容器内 `sizeof/offsetof` + 列 `/out` + 取二进制 sha256 | **10 min** | ~25 min |
| **构造** | CGATS 多表文本生成器（首选：改 seed corpus；兜底：从零写 ~30 行生成器） | **20–45 min**（1 轮；若 U1 需扫 4 档 +15 min） | ~70 min |
| **双端** | 同输入 → vul/fix 各 1 次 + 证据包落盘 | **15 min** | ~85 min |
| **严重性** | `docs/SEVERITY-67968.md` 六维 + CVSS + 边界 | **40 min** | ~125 min |
| **材料/复核** | `case.json` + `review.json`（具名 + ≥6 refs 逐条 sha256）+ `task_version_id` | **50 min** | **≈2.9 h** |
| 兜底重跑（U3/U9 触发） | +1 轮构造 + 双端 | +60 min | **≈3.9 h（最坏）** |

峰值磁盘 **≈4.8 GB**；阈值：**超出 2× 预算（>5.8 h）仍无 S2 证据 → 止损 S9**。

### 4.5 预计材料（对照 COURSE-CRITERIA-V2 的 A/B/C/D 与 case.json 字段）

| 层 | 材料 | 落点 | 现在有吗 |
|---|---|---|---|
| **B** 基准 | vul/fix 同输入的 `cmd/stdout/stderr/exit_code/seconds`；镜像 digest；PoC sha256 | `experiments/tenth-67968/runs/<UTC>/{vul,fix,pull,provenance}/` | ❌（待 S2） |
| **B** 归属 | commit 全 sha（`d1652a06…` / `1176e61a…`）+ 文件 blob sha + sha256 三方一致 | `provenance/upstream.json` | ✅ **已具备**（K9–K12） |
| **A** 高危 | `docs/SEVERITY-67968.md`：六维 value+evidence、`observed_impact=memory_corruption_confirmed`、CVSS 自洽、`reviewed_by`/`reviewed_at` | `docs/` | ❌（待 S3） |
| **C** 因果链 | `root_cause.confidence=strong`、`propagation` 四要素（输入字段 → 到达 sink → 缺失检查 → 实际越界）逐条 `file:line` | `case.json` | ❌（待 S2/S3） |
| **D1** 轨迹 | 平台 run 的 JSON 全量 + JSONL 事件流（`seq` 有序、四类计数与库相等） | `experiments/` | ❌（若要 D1 达标，必须走平台跑，而不是纯 CLI） |
| **D2** 参数 | 逐阶段 `model / role_version / prompt_version / temperature / max_tokens`；缺则写 `missing` + 贡献判定 | `experiments/` | ❌（**本条最容易翻车**：本轮是 agent 手工跑） |
| **D3** 复核 | `workspace/<CASE>/review.json`：具名 `reviewer` + `reviewer_id`（**不得** `manual-review`/`agent`/`auto`）、ISO8601 带时区、`scope` 含 A/B/C/D、`evidence_refs ≥6` 且逐条 sha256 | 新增文件 | ❌（待 S4） |
| **D4** 哈希 | PoC 四处一致、上游件全等、镜像 digest 可追溯、`task_version` 指纹 | `case.json` | ⚠️ 镜像 digest 见 U8 |

### 4.6 构造方案（预检结论：**可造，且成本低**）

```text
形态：CGATS/IT8 文本，重复"最小合法表块"
块骨架（每块 ≈85 B）：
  NUMBER_OF_FIELDS 1
  NUMBER_OF_SETS   1
  BEGIN_DATA_FORMAT
  SAMPLE_ID
  END_DATA_FORMAT
  BEGIN_DATA
  0
  END_DATA
重复 N 次（N≈255–300，见 U1）→ 总量 ≈22–26 KB
```

- 依据链：`ParseIT8@2064` 循环 → `SBEGIN_DATA` → `DataSection@2075`（计数校验通过）→ `sy != SEOF` → **`AllocTable@2079`** → `TablesCount++`（初值 1，见 `@1291`）。
- **关键风险（U3）**：`N=255` 那次写已经落在 `cmsIT8` 内部（撞 `MemorySink`/`Allocator`/`sy`），可能先产生"语法错早退"或"分配器崩"。
  因此构造器必须**扫描 N**（240/256/280/320），并把首个 ASAN 帧是 `ParseIT8`（内联 `AllocTable`）、`crash_type` 仍为 `heap-buffer-overflow WRITE` 作为通过条件。
- 次选：若镜像内有 `cmsIT8_load_fuzzer_seed_corpus.zip`（U7），取一个真 `.it8` 种子，在尾部追加块，减少格式试错。

### 4.7 严重性预判（**预判不是论证**，S3 必须逐维落地）

| 维度 | 预判值 | 依据 | 风险 |
|---|---|---|---|
| AV | `L` | 输入是本地文本/文件，经 `cmsIT8LoadFromMem`；与既有 CWE-122 系列同口径（**禁 AV:N**） | 若强调"lcms 被图像/打印软件调用"→ 仍只能写 `AV:L`（本仓既有判例） |
| AC | `L` | 确定性：同一输入恒定触发 | 若 U3 需精确 N → 可议 `AC:H`，**会掉到 5.5–6.1** |
| PR / UI | `N` / `R` | 无需认证；需受害者处理恶意 CGATS | — |
| C / I / A | `N` / `H` / `H` | 3×8 B 越界写（指针 NULL 写）+ 结构体内邻近字段破坏；ASAN abort | 若只能证"单次 8 B 写"→ 按 `SEVERITY-11011` 的边界表可能降 `I:L` → **6.1，medium，G3 的 A 层直接失败** |
| **CVSS 预判** | **7.1（high，阈值 ≥7.0）** | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H` | 见上两行；**这是本题最可能翻车的一处**，不是构造 |

---

## 5. 为什么"发现根因 ≠ 可提交案例"

本文档已经把 67968 的**根因写到行号**（`cmscgats.c:1251`，缺失检查 = `ALLOC_TABLE` 无上限），
**但它现在连一条 `case.json` 字段都不能置真**。四个层级各自独立，缺一层都不计数：

| 层 | 达成条件 | 67968 现状 | 反例（本仓已发生） |
|---|---|---|---|
| L1 根因 | 能指到 `file:line` + 说清缺失检查 | ✅ 已达成（K7） | `arvo:60983`：有 task、有根，但 `run_summary.status=blocked`（`No such image …-fix`）→ **不计** |
| L2 双端 | vul 崩（ASAN + exit≠0）+ fix 干净（exit 0） | ❌ 未跑 | CG-01 的 fix 端两次拉取失败 → 只到 `partial`，**不许写 `verified`** |
| L3 严重性 | 逐维论证 ≥7.0，且 `reviewed_by/reviewed_at` 齐 | ❌ 未写；预判 7.1 但 `I:H` 需实测支撑 | `arvo:1065`：**双端通过**，但逐维论证 = **3.3 low** → 不入高危；`arvo:54625` = **6.1 medium**（`AV:L` 封顶） |
| L4 材料/复核 | D1–D4 齐（轨迹/参数/具名 review/哈希指纹） | ❌ 全缺 | EG-02：10/10 取 flag，但 `accepted=null`、10 份日志字节相同 → 只到 `historical_verified`，且**与 CG-01 同根，永不新增计数** |

**结论写法纪律**：

- 可以写：`planned`、`候选已过 G1，G3 可取得，未取得`。
- 不可写：`benchmark_passed`、`verified`、`第 10 例已达成`、`根因明确即计数`。
- 同根第二份快照（`artifacts.prior-run/`、`deliverables/`、`cases/`）**任何时候都不算新例**。

---

## 6. 止损条件（触发即停，停也要留痕）

| # | 触发条件 | 动作 | 记录 |
|---|---|---|---|
| **S1** | G1 任一子判据 COLLIDE（含归一化后 sink 相同、或 `fix_commit` 与已用号重复） | 弃题，换 A1-fb | `experiments/tenth-admission.json` → `rejected` + 命中项 |
| **S2** | vul 端 3 次尝试（含 N 扫描）均**无** `heap-buffer-overflow WRITE`，或首帧不在 `ParseIT8/AllocTable` | 记 `not_reproducible`；若崩在别的函数 → 回 G1 重判 sink | 每次 `stdout/stderr/exit_code` 全留 |
| **S3** | fix 端同输入**也崩**（或有 sanitizer 签名） | 记 `no_clean_fix`，**不得**写 `benchmark_verified`；本题弃 | `fix/` 全量日志 |
| **S4** | 构造 2 轮内不能稳定触发（命中 < 3/3） | 降 `planned`，不计 | 生成器 + 各轮 N 值表 |
| **S5** | 拉取 2 次重试均失败（TLS 超时/EOF） | 记 `blocked`（不消耗计分），保留 `pull/attempt-{1,2}/` | 镜像站与时间戳 |
| **S6** | 严重性论证落 `medium`（如 `I:L` 或 `AC:H`） | 只记 medium，**不进高危分子** | `docs/SEVERITY-67968.md` 保留降级理由 |
| **S7** | 发现同 `fix_commit` 的其它 ARVO 号已被用过 | 弃（同 bug 多号） | 号 + `fix_commit` |
| **S8** | 验收需要联网/第三方目标才能成立 | 弃（越出 G2 授权边界） | 触发场景 |
| **S9** | 总耗时 > 5.8 h（2× 预算）仍无 S2 证据 | 停，写 `partial` + 已消耗清单 | 时间戳 + 阶段表 |
| **S10** | `sink.line` 用了 fix-parent 的行号（`1384`）而非 vul 镜像内的行号（`1251`） | **证据作废**，按镜像内源码重取 | 旧/新行号对照 |
| **S11** | 有人把"根因清楚"写进 `case.json` 让字段变绿 | 回滚该字段，按 L4 重走 | 变更前后 diff |

---

## 7. 本轮观测（证据表，供复核对照）

| 观测 | 值 | 时间/来源 |
|---|---|---|
| G1 复算 | `raw 45 / norm 44 / roots 51`；`NEW-ID`、`NEW-ROOT` | 2026-11-25 本机 |
| LEDGER | `rows=30`，`high_severity_confirmed=9` | `experiments/LEDGER.json` 只读 |
| lcms/67968 历史接触 | `case.json`+`task.json` 检索 **0 命中** | 本机 |
| `docker images` | 仅 `44034-vul/-fix`（4.52/4.71 GB），**无 67968** | 本机 |
| manifest（proxy） | `67968-vul` 26 层 / `67968-fix` 40 层，均 rc=0 | 20:19 |
| manifest（hub 直连） | 同层数、同字节数（rc=0） | 20:19 |
| 单流带宽 | 16 MiB / 9.51 s = **1.76 MB/s** | 20:20 |
| registry 抖动 | `registry-1.docker.io/v2/`：20:18 → 401；20:26 → 连续超时（`docker manifest inspect` 同步变 rc=1） | 本机 |
| `dockerproxy.net/v2/` | 200 / 1.9 s（20:18） | 本机 |
| GitHub | `api.github.com` 200 / 1.4 s；`raw.githubusercontent.com` 404/超时 → **取证一律 `git/blobs` 或 Contents API** | 本机 |
| Contents API 陷阱 | `contents/src/cmscgats.c?ref=d1652a06` 返回 **73613 B**，而 `git/blobs` 返回 **73602 B**（blob sha 与后者一致）→ **字节级取证只用 `git/blobs`（`Accept: application/vnd.github.raw+json`）** | 本机复算 |

---

## 8. 边界声明

- **只写**：`docs/TENTH-CANDIDATE-ADMISSION.md`、`experiments/tenth-admission.json`。
- **未改**：`workspace/**`、任何历史 `case.json` / `severity.json` / `RESULT.json` / `logs/` / `artifacts/`、
  `experiments/LEDGER.json`、`experiments/LEDGER-AUDIT.json`、业务代码（`agent/**`、`scripts/**`、`bin/**`）。
- **未做**：拉镜像（只做 manifest/config 级只读探测）、跑容器、写 `workspace/`、git commit。
- **外部只读请求**：GitHub API（`commits` / `git/blobs` / `contents`）、`raw.githubusercontent`（1 次 404）、
  Docker Hub（`manifest inspect`、`blobs` 分片 16 MiB）、`dockerproxy.net`（`manifest inspect`）。
- 本文档**不替任何案例签复核**，也**不改变**任何历史判定；`arvo:67968` 的计数状态是 **`planned`**。

---

## 附录 A · 复跑命令

```bash
ROOT=/home/root_bupt/桌面/file/vulnmap

# A1 G1 判据（应输出 NEW-ID / NEW-ROOT）
sed -n '/^## 2\. G1/,/^```$/p' $ROOT/docs/TENTH-CANDIDATE-ADMISSION.md >/dev/null   # 见 §2 正文脚本

# A2 镜像层数与字节（不拉镜像，只读 manifest）
for T in 67968-vul 67968-fix; do
  docker manifest inspect n132/arvo:$T | python3 -c "
import sys,json;d=json.load(sys.stdin);L=d['layers']
print(len(L), sum(l['size'] for l in L))"
done

# A3 源码锚点（vul 镜像的 commit）
curl -sS "https://api.github.com/repos/mm2/Little-CMS/contents/src/cmscgats.c?ref=d1652a06dc7308da9819624188181f20ce10fd93" \
 | python3 -c "import sys,json;print(json.load(sys.stdin)['sha'])"
# 期望 blob: 7df5bbc4da494a4763a0aae13b3d3a913fc3cf9b（字节级取用 git/blobs）

# A4 镜像 config 里的构建 commit
docker manifest inspect n132/arvo:67968-vul | python3 -c "import sys,json;print(json.load(sys.stdin)['config']['digest'])"
# 再取该 blob，看 history 里的 git reset --hard d1652a06…
```

## 附录 B · 与既有文档的关系（含修正项）

| # | 修正/更新 | 影响 |
|---|---|---|
| **X9** | **`docker.io` 不再"完全不可达"**：20:19 直连 hub 取 manifest 成功；20:26 起又超时 → 准确表述是**抖动**，不是"不可达" | `TENTH-CASE-PLAN` §6 的"只能走镜像站"要改成"hub 与镜像站二选一 + 2 次重试" |
| **X10** | **sink 已定位**：`src/cmscgats.c:1251`（`AllocTable`，内联进 `ParseIT8`），不是 `cmsio1.c`（`TENTH-CASE-PLAN` §3 A1 只写到 `ParseIT8`、`COURSE-EVIDENCE-DECISIONS` §4.3 写 `lcms 自身 ParseIT8`） | 落 `case.json.sink` 时按镜像内行号（见 S10） |
| **X11** | **vul 镜像构建在 2017 commit** `d1652a06…`，**不是 fix 的父提交** `af6c5655…` → 两者行号不同（`1251` vs `1384`） | 拿 fix-parent 行号当 sink 会直接作废（S10） |
| **X12** | **Contents API 字节不可信**（73613 vs 73602）→ 归属一律走 `git/blobs` + blob sha 复算 | 影响所有 A 通道候选的 provenance 做法 |
| **X13** | 预算校准：K17/K20 得**14.3 min 拉取 / 1.4066 GiB / ≈4.8 GB 磁盘**，与 `COURSE-EVIDENCE-DECISIONS` 的 14 min / 1.41 GiB / 5.2 GB 一致（磁盘略低） | 预算表沿用，磁盘修正为 4.8 GB |
| **X14** | **内部复核不需要"第二人签字"**：按 [REVIEW-POLICY.md](REVIEW-POLICY.md)（2026-11-12）agent reviewer 具名即可计数；`review.json` v2 仍需**具名 reviewer_id**（denylist 排除 `manual-review`/`agent`） | `COURSE-EVIDENCE-DECISIONS` §5 第 4 行"需第二人"只对**对外口径**成立 |
| **X15** | **类别新颖性不构成准入理由**：既有 9 根中 6 个是 CWE-122（`10096/11011/11253/12420/54839/61675` 中的堆写族） | `TENTH-CASE-PLAN` §5 规则 5 的"类别不同 +1"仍是**打分**，不是闸门 |
