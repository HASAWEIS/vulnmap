# Discovery v1.0 实现方案

> 状态：v1.0 已实现并实跑；Discovery 是唯一的发现入口，旧复现平台归档，不做双轨、不设备选路径。
> 代码：`agent/discovery/`；CLI：`bin/discover.py`、`bin/covfuzz.py`；证据：`discovery/`；受控 fixture：`fixtures/discovery/`。

## 1. 输入与边界

- **唯一输入**：源码 / 二进制 + 构建方式。禁止读取 `error.txt`、`patch.diff`、官方 PoC、上游 issue、CVE 页面。
- **角色分工**：
  - 分析 Agent：只读源码、不执行目标、只产假设（`hypothesis.json`），不产出 verdict；
  - Fuzz：唯一证明手段，崩溃必须由 ASAN 在干净构建上重放；
  - Triage / Review：判定 confirmed / weakened / excluded / needs_human；
  - 报告：只写证据，不把崩溃数当高危数。
- **不做**：固件解包、跨架构仿真、把 IDA/Ghidra 设为必需依赖。
- **安全**：目标本地、授权、隔离；默认在 `bwrap`（网络 none + 只读根 + 独立 PID 命名空间 + 能力清空，
  不可用时退 `unshare -rn` 且补 no_new_privs）中执行，目标进程带资源上限；
  显式 `--isolation container` 可升级到容器（docker/podman：`--network none --read-only --cap-drop ALL
  --security-opt no-new-privileges` + 只读目标绑定/可写 workdir 绑定），引擎或镜像不可用时明确报错；
  `--require-isolation` 可要求隔离不可用即失败；不对外提交；失败不删除、不伪造结论。

## 2. 流水线

```text
D0 profile      源码/ELF/入口/函数/格式        → target.json
D1 callsites    危险调用点 + 近似可达 + 分数     → callsites.json
D1.5 agents     只读分析 + 结构化种子           → hypotheses.json
D2 covfuzz      ASAN + trace-pc 并行 fuzz        → crashes/ stats/
   coverage_map COV_PCS → addr2line → 调用点      → callsites.json(覆盖回写)
D3 triage       ASAN 解析 + 干净构建 3 次重放    → triage.json
D3.5 review     单次复核，四类结论               → reviews.json
D4 report       固定三段式                       → report.json / report.md
D5 campaign     ranked vs random、种子 A/B       → eval.* / ab.*
```

### D0 `profile.py`

- 源文件后缀：`.c/.cc/.cpp/.h/.hpp`；
- ELF 以 magic `\x7fELF` 识别，记录 `sha256` 与 `size`；
- 入口用 `main(` 探测；函数用“类型前缀 + 名字(参数) + {”近似识别（不做语法分析，宏/跨行返回类型可能漏检）；
- 格式优先 magic，其次扩展名，无法识别记 `unknown`；
- 输出字段：`target / root / sources / binaries[{path,sha256,size}] / entries[{kind,file,line}] / functions[{name,file,line}] / formats / source_count`。

### D1 `callsites.py`

危险函数表与权重是固定契约：

| 类别 | 函数 | 权重 |
|---|---|---:|
| copy | memcpy / memmove / strcpy / strcat | 3 |
| format | sprintf / vsprintf | 3 |
| format | snprintf | 2 |
| alloc | malloc / realloc | 1 |
| input | read / fread / recv | 2 |

- `score = 权重 × (可达?2:1) × (参数可控?2:1)`；
- 可达：从 `main` 出发的近似调用图 BFS（函数体内“名字 + (”即认为有边）；
- 可控：实参词元命中 `data/buf/input/len/size/n/p/src`；
- 台账字段：`function/file/line/callee/category/args/controlled/reachable/score/status(unanalyzed)`；
- 覆盖率台账恒有 `planned / covered / uncovered / status(complete|partial)`，报告同时给出三者。

### D1.5 `agents.py`

- `Task(task_id,kind,payload)` / `Result(task_id,ok,data,error,seconds)`；
- `run_pool(tasks, handler, workers=4, timeout=60)`：每任务一个 `tempfile.mkdtemp` 工作目录，ThreadPoolExecutor 并发，单任务失败不影响整批；
- **LLM 默认开启**：调用点分析 Worker 默认走 LLM，密钥读 `DISCOVERY_LLM_API_KEY / BDVE_LLM_API_KEY / DEEPSEEK_API_KEY / LLM_API_KEY / OPENAI_API_KEY`，
  endpoint/model 读 `DISCOVERY_LLM_* / LLM_* / BDVE_LLM_ENDPOINT / BDVE_LLM_MODEL`；prompt 只给 site 元数据 + 30 行源码窗口 + 可达性，要求 JSON；
  `citations` 必须能在源码中解析（文件存在、行号有效），否则整条假设丢弃并回退 `heuristic_analyze`；
  超时/无 key/显式 `--analysis heuristic` 时回退，LLM 不产出 verdict；
  API key 只从环境变量读取，不写入配置、台账、日志或文档；请求默认关闭思考链（`thinking.disabled`），保证 content 是 JSON；
- `propose_seeds(site, ..., hypothesis)`：
  - JSON：长字符串、`\u0000`、未闭合注释、长数字、反斜杠、数组骨架；
  - PNG：合法 IHDR/IDAT/IEND chunk，按假设追加 interlace/palette/tRNS/超大宽高变体；
  - TIFF：按假设追加 count/offset/Strip 定向变体；
  - 其他：通用 magic + 长度字段；
  - 假设文本（`hypothesis` + 源码窗口）决定追加哪些定向种子，`hypotheses.json` 记录 `seed_count` 与 `seed_basis`；
  - 种子只写入 fuzz corpus，不直接判漏洞。

### D2 `covfuzz.py`

构建契约（`cov_rt.c` 必须单独编译，否则回调自递归）：

```bash
gcc -c -O1 cov_rt.c -o cov_rt.o
gcc -g -O1 -no-pie -fsanitize=address -fsanitize-coverage=trace-pc,trace-cmp -I. \
    target.c harness.c cov_rt.o -o fuzz_target
```

- 每个目标一个最小 harness：`main` 读文件（上限 64KB）后调用 `target_api(buf,len)`；
- **结构化变异（P2）**：`--format png` 保持 PNG chunk 骨架，集中变异 IHDR 宽高/位深、IDAT、声明长度、chunk 顺序与 CRC；`--format tiff` 保持 TIFF endian/IFD 骨架，变异 tag 类型、count、offset 与 Strip 字段；其他格式回退通用变异；
- `cov_rt.c`：64K bitmap 语料反馈 + PC 数组写 `COV_PCS`；回调标 `no_sanitize_address`；`SIGABRT/SIGSEGV/SIGBUS/SIGILL/SIGFPE` 与析构函数都会落盘一次（ASAN abort 时也能拿到崩溃前覆盖）；
- **比较操作数（P2 深度）**：`cov_rt.c` 提供 `__sanitizer_cov_trace_cmp1/2/4/8`、`__sanitizer_cov_trace_const_cmp1/2/4/8`
  与 `__sanitizer_cov_trace_switch`（GCC 对 `switch` 单独发射，缺失会直接链接失败），全部 `no_sanitize_address`，
  记录 `(size, is_const, a, b)` 到定长表（上限 512 条）并写 `COV_CMP`；
- **字典（P2 深度）**：两个来源——①源码窗口里抽字符串字面量与数字字面量（`dictionary_from_source`，
  数值同时产出 ASCII 与定宽小端/大端形态）；②运行期比较操作数（`dictionary_from_operands`，跳过 0/1 这类无信息常量）。
  worker 每轮把新操作数并入进程内字典（上限 96 项），变异器新增一条字典变异算子；campaign 把源码字典写 `dictionary.json`；
- 循环：语料种子 → 变异 → 执行 → ASAN 判定；出现新 bitmap 位则加入 corpus（上限 300）；崩溃保存 `crash-<sha16>.bin + .log` 并停止该 worker；
- 并行：`multiprocessing`，每 worker 独立工作目录；输入上限 64KB，单次超时 2s，`Popen.wait(timeout)+kill` 避免管道卡死；
- 执行隔离：`auto` 优先 `bwrap`（硬化最全），其次 `unshare -rn`（用户+网络命名空间，网络 none）；
  都不可用则 `none`（网络 host），`--require-isolation` 直接失败；目标进程带 CPU/FSIZE/NOFILE/CORE 资源上限；
  **bwrap 硬化**：`--unshare-net --unshare-pid --die-with-parent --cap-drop ALL --ro-bind / / --dev /dev --proc /proc`
  （断网 + 独立 PID 命名空间 + 父死子死 + 清空 capability + 整根只读）；
  **unshare 硬化**：`--unshare-net` + exec 前 `prctl(PR_SET_NO_NEW_PRIVS, 1)`（禁止 setuid/setcap 反向提权）；
  注意 unshare 的用户命名空间内 capability 仍在、根目录可写，因此 `auto` 把 bwrap 排在前面：
  默认即只读根 + cap 清空。需要吞吐时显式 `--isolation unshare` 是知情降级，不是默认行为；
- 只读根下的落盘：目标要写 `COV_FILE/COV_PCS/COV_CMP`，因此 `prefix_for()` 在只读根之后
  用 `--bind <workdir> <workdir>` 把工作目录单独挂成可写；绑定路径要求是**真实存在的具体目录**，
  `/` 或非目录直接 `ValueError`（否则等于把只读根改回可写）；命令统一排在 `--` 之后；
- **container 模式（P4 硬化，显式选择）**：`--isolation container` / `resolve("container")` → docker 或 podman
  （bwrap 侧的 `--seccomp` 需要外部编译的 BPF 过滤器，仓库里没有可用的生成器，因此硬化走容器这一支）
  `run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges
  --pids-limit 128 --memory 2g --tmpfs /tmp:rw,exec,nosuid,nodev`，源码/目标目录 `-v <path>:<path>:ro`，
  工作目录 `-v <work>:<work>:rw` + `-w <work>`，需要透传的变量走 `-e NAME`，镜像名排在命令前；
  **引擎不可达或镜像不在本地 → `RuntimeError`（写清缺什么、用 `DISCOVERY_ISOLATION_IMAGE` 指定镜像），
  不静默退化到 bwrap/unshare/宿主**；容器模式不设 RLIMIT_CPU/NOFILE（那会先杀 docker 客户端而不是容器），
  资源上限改由 `--pids-limit`/`--memory`/`--tmpfs` 承担；`auto` 保持 bwrap 默认，`container` 只作为显式选择；
- **隔离里目标没起来也不静默**：缺动态库（container 跑宿主 ASAN 目标最典型）、绑定/权限不对时，
  `run_input` 返回 `setup_error`（`rc` + 命中的 marker，如 `error while loading shared libraries`），
  `crash` 仍为 False（不伪造崩溃）；worker 计 `setup_errors`，连续 3 次且零覆盖时写
  `aborted=setup_error` 提前收工，`aggregate()` 汇总 `setup_errors`/`setup_error`，
  随 `campaign.json.fuzz` 落盘——不允许把“根本没跑起来”当成 0 覆盖糊过去；
- `--require-isolation` 时隔离不可用直接失败，不回退宿主网络（fail-closed）：`resolve()` 抛错 →
  campaign 记录 `execution_isolation.mode=unavailable` 且不执行 fuzz（不降级为宿主执行）；
- ASAN 运行参数含 `allocator_may_return_null=1`：超大分配返回 NULL，避免把 allocator OOM 误判为漏洞；
- 覆盖率归属：`COV_PCS → addr2line -f -C → file:line/function → covered_by_pc`。

**覆盖口径**：调用点被计为 covered 的条件是 PC 落点命中该行（`covered_by_pc=true`），或 PC 命中该调用点所在函数（`covered_by_function=true`，单独标记）。cJSON 的 14/80 全部是函数级命中——目标函数被执行、但 PC 行号落在相邻语句；这个口径在报告中显式标注，不把函数级命中伪装成行级命中。

### D3 `triage.py`

- 解析 ASAN `type`、`READ|WRITE of size N`、第一条非 interceptor / 非系统头帧的 `file:line`；
- `stack_hash = sha1(type|function|file:line)[:16]`；
- 确认门禁：有效诊断（非 unknown/allocator/OOM，根因帧有效，READ/WRITE 或 UB）+ 干净构建，缺一不可；
- 干净构建（独立目录重新编译）重跑 3 次，按签名判同源；
- verdict：`写 + 3/3 = confirmed`；`读/UB + 3/3 = weakened`；`0/3 = excluded`；`不稳定 = needs_human`；
- rebuilder 失败 → `needs_human / clean_build_failed`；复用旧构建 → `needs_human / clean_build_unavailable`；
- 复核同样要求 `build_clean=true`，否则不得写 confirmed/weakened。

### D3.5 复核

输入 triage 结果 + 栈哈希，单次判断，不做多轮辩论，不做二次利用/堆布局；输出四类结论 + reason。

**可选 LLM 复核（P2，默认关闭）**：`--llm-review` / `campaign.run(use_llm_review=True)` 打开后，
复核只做一次独立判断（`agents.llm_review`），prompt 里带 triage 事实与门禁状态，不要求也不允许利用步骤。

- 默认 `use_llm_review=False`，行为与既有规则复核完全一致（`reviews.json` 与台账不变）；
- 失败（无 key / 超时 / 非 JSON / `verdict` 不在四类枚举内）→ 严格回退 `heuristic_review`，
  记录 `llm_status=invalid_or_timeout` 与 `llm_review_failed=true`，不影响整批；
- **门禁不放宽**：`review_gate()` 先判 `diagnostic_valid` / `build_clean=true` / `reproduced>0`。
  门禁未开时任何 `confirmed` 都被降级为 `needs_human`；门禁已开时 LLM 结论强度也不得超过规则复核的上限
  （例如读型 3/3 的规则上限是 `weakened`，LLM 给 `confirmed` 会被限制回 `weakened`）。
  降级会写 `llm_downgraded=true`、`llm_verdict`（原始）与 `llm_gate`（门禁原因）；
- 记录 `llm_usage`（prompt/completion/total tokens）与 `llm_attempts`；任何返回值/落盘文件都不含密钥
  （失败路径只保留异常类型名，异常文本不入盘）；
- `review_gate()` 只认显式 `diagnostic_valid is True`：字段缺失/`None` 一律按"诊断未验证"处理（fail-closed）；
- 复核记录自带门禁输入（`build_clean`、`diagnostic_valid`、`repeats`），审计时可复原"为什么能确认"；
- `store.record(reviews=...)` 会把 D3.5 结论回写 `review` 行（LLM 复核在 notes 前缀 `[llm:<verdict>]`），
  保证 `reviews.json` 与 SQLite 台账不出现互相矛盾的 verdict。

### D4 `report.py`

固定结构：

1. **分析完整性**：静态档案、调用点、输入构造/执行，每段给 planned/covered/uncovered/status；
2. **风险统计**：planned / covered / confirmed / weakened / excluded（另列 needs_human）；
3. **发现条目**：函数、`file:line`、类型、读写、栈哈希、复现次数（含是否干净构建）。

P2 受控 fixture：`fixtures/discovery_png/`（IHDR 宽高 32 位相乘溢出 → 写越界）、`fixtures/discovery_tiff/`（IFD count 驱动拷贝 → 写越界）；基线 fixture 仍在 `fixtures/discovery/`，避免子目录污染 D0 格式识别。

报告显式声明：崩溃条数只是候选数量；`confirmed` 仅代表写入型越界在干净构建 3/3 复现，`weakened` 代表读/UB；严重级别不在本报告按崩溃数推定。

### D5 `campaign.py`

- 编排 D0→D4；
- `ranked vs random`：同批候选按分数序 / 随机序，比较覆盖率、confirmed、首次崩溃耗时；
- Agent 种子 vs 纯 fuzz：比较首次崩溃执行数与耗时；
- 指标：覆盖率、confirmed、time-to-first-crash；负结果保留（不删除、不改写）。

## 3. 落盘

```text
<out>/target.json
<out>/callsites.json
<out>/hypotheses.json
<out>/reviews.json
<out>/crashes/crash-<sha16>.bin + .log
<out>/triage.json
<out>/report.json + report.md
<out>/campaign.json
<out>/campaign.db
```

SQLite 表（`schema/discovery.sql` 与 `store.py` 一致）：

| 表 | 字段 |
|---|---|
| campaign | id,target,commit,build_flags,budget,status,created_at |
| binary | id,campaign,path,sha256,arch,bits,endian |
| call_site | id,campaign,function,file,line,callee,score,status |
| candidate | id,call_site,input_sha256,crash_type,stack_hash,log_path |
| review | id,candidate,verdict,root_cause,reproducible,notes |
| finding | id,review,severity,cwe,report_path |
| coverage | id,campaign,stage,planned,covered,uncovered |

## 4. CLI

```bash
python3 bin/discover.py fixtures/discovery --out /tmp/out --seconds 3 --max-sites 3
python3 bin/covfuzz.py /tmp/cJSON/cjson_fuzz \
  --corpus /tmp/cjson-corpus2 --crashes /tmp/cjson-crashes2 \
  --stats /tmp/cjson-stats2 --seconds 60 --workers 4
python3 experiments/agent_seed_ab.py
```

`discover.py` 另有 `--eval`（ranked vs random）、`--ab`（种子 A/B）、`--format`、`--no-llm`、`--db`、`--target-yaml`、`--init-target`、
`--isolation auto|bwrap|unshare|container|none`、`--require-isolation`、`--analysis llm|heuristic`（默认 llm）、
`--llm-review`（D3.5 走一次 LLM 复核，默认关闭 = 规则复核）。

## 5. target.yaml（P4 构建/harness 自动化）

`bin/discover.py <target>` 自动探测 `<target>/target.yaml` 或 `.yml`；也可用 `--target-yaml` 显式指定。
YAML 只描述“怎么构建、怎么喂输入”，不做漏洞判断。字段：

```yaml
name: cJSON-1.7.10
root: /tmp/cJSON          # 可选；路径字段相对它解析，默认 yaml 所在目录
format: json              # 传给种子生成/结构化变异
sources: [cJSON.c]        # 编译单元
includes: [.]
build:
  mode: api               # main（目标自带 main）| api（生成/引用 harness）
  system: auto            # auto | main | api | configure | cmake；auto 按布局探测
  harness: cjson          # 内置 harness：cjson | libpng
  harness_path: harness.c # 或自定义 harness（与 harness 二选一）
  extra_objs: []          # 预构建对象
  extra_objs_glob: "*.o"  # 或按 glob 展开
  exclude_objs: [pngtest.o]
  libs: [-lz, -lm]
  cflags: []
  out: fuzz_target
  # ↓ 仅 configure/cmake 隔离构建用
  asan: true              # 构建库时加 -fsanitize=address
  coverage: true          # 构建库时加 -fsanitize-coverage=trace-pc,trace-cmp
  shared: false           # false = --disable-shared --enable-static / BUILD_SHARED_LIBS=OFF
  cc: gcc
  ldflags: ""
  configure_args: []      # 追加给 ./configure
  make_targets: []        # 默认 make -jN（all）；也可只 make 某个库目标
  cmake_args: []
  cmake_targets: []
  copy_source: auto       # auto|true|false：源树已 in-tree 配置时复制干净副本
fuzz:
  seconds: 60             # CLI 显式 --seconds 优先
  workers: 4
  timeout: 2.0
```

示例：`examples/targets/cjson.yaml`、`examples/targets/libpng.yaml`、`examples/targets/libtiff.yaml`。

没有现成 YAML 时可用 `--init-target` 从源码布局生成草稿：

- 有 `cJSON.c` → `mode: api` + 内置 `harness: cjson`；
- 单一 main 源码 → `mode: main`（同目录 .c 一起编译）；
- 有 `configure` / `CMakeLists.txt` / `Makefile.am` / `meson.build` → 生成 `harness_path: harness.c` 草稿并标 `needs_review: true`，
  预构建归档按 `**/.libs/*.a`、`**/*.a` 静态枚举（`prebuilt_objs`，上限 16 个）并写入 `extra_objs`，需人工补 `libs` 与 harness；
- `needs_review_reasons`：逐条给出人工复核理由（自带构建系统 / 已识别到 N 个预构建静态库 / 未发现 `.a` 需先手工构建 /
  harness 需手写）。main 分支遇到自带构建系统时也会标 `needs_review` 并给理由；
- **安全约束**：`--init-target` 只做只读识别，不执行目标自带的 `configure`/`make`/脚本
  （单测用 `subprocess.run/Popen/check_output` 全抛错的 monkeypatch 证明这一点）。

两条路严格分开：草稿只做只读识别（上面这几条），`build.system` 只描述“该用哪个构建系统”，
真正执行 configure/cmake 的只有下面的隔离构建 API（§5.2）。
PyYAML 可选：未安装时 `target.yaml` 可用 JSON 语法（JSON 是 YAML 子集）。

### 5.2 隔离构建（`targetspec.build_library`）

`system` 取值：`auto`（按布局探测：有 `configure` → configure，其次 `CMakeLists.txt` → cmake，都没有 → 按 `mode`）、
`main`/`api`（不外部构建，直接 `covfuzz.build`）、`configure`、`cmake`。
没有单独的 `--build-system` CLI 开关：构建系统只由 `target.yaml` 的 `build.system` 描述，避免 CLI 与 yaml 两处真相
（CLI 已有 `--target-yaml` 指定文件，`--isolation` 只管执行隔离）。

```python
from agent.discovery import targetspec
spec = targetspec.load("examples/targets/libtiff.yaml")      # build.system 缺失时默认 auto
res  = targetspec.build_library(spec, "/tmp/out/tiff", isolation="bwrap")
auto = targetspec.autobuild(spec, "/tmp/out/tiff")            # 顺手给出 covfuzz.build 的关键字参数
```

- **执行位置与隔离**：在 `workdir/build-<system>` 里 out-of-tree 构建，源码只读；bwrap 前缀
  `--ro-bind / /` + `--bind <builddir> <builddir>`（构建脚本属于不可信输入，默认 `isolation="bwrap"`、
  `require_isolation=True`；bwrap 不可用 → `BuildError("build isolation unavailable: ...")`，
  **不静默落到宿主执行**）；`TMPDIR`/`HOME`/`XDG_CACHE_HOME` 指向 builddir 内可写子目录。
- **configure**：`<src>/configure --prefix=<builddir>/prefix --disable-shared --enable-static`
  （`shared: true` 时去掉后两项）→ `make -jN [make_targets]`；CFLAGS = `-g -O1 -fno-omit-frame-pointer
  -fsanitize=address -fsanitize-coverage=trace-pc,trace-cmp` + yaml `cflags`（`asan`/`coverage: false` 可关）。
- **cmake**：`cmake -S <src> -B <builddir> -DCMAKE_C_COMPILER=gcc -DCMAKE_C_FLAGS=<同上>
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=OFF [-DCMAKE_EXE_LINKER_FLAGS=...]`
  → `cmake --build <builddir> -jN [cmake_targets]`；PATH 上没有 cmake 时直接
  `BuildError("cmake not found on PATH ...")`，不假装构建成功。
- **弱符号垫片**：`-fsanitize-coverage=trace-pc` 需要回调符号，而 configure/cmake 自己要编译并链接探测程序，
  缺符号会让 `AC_CHECK_FUNCS` 这类探测**静默失败**（探测不到，构建却“成功”）。因此构建期生成
  `<builddir>/.covshim/libcovshim.a`：`__sanitizer_cov_trace_pc`、`cmp1/2/4/8`、`const_cmp1/2/4/8`、
  `cmpf`/`cmpd`、`const_cmpf`/`const_cmpd`、`switch`、`div4/div8` 全部 **weak** 定义，
  通过 `LIBS=-L<covshim> -lcovshim` 交给目标构建系统；最终 fuzz 链接时 `cov_rt.o` 的强定义覆盖它们。
  垫片不进 `archives`，也绝不进 `extra_objs`。
- **已配置过的源码树**：源树里有 `config.status`/`CMakeCache.txt` 时，out-of-tree 会被 autoconf 拒绝
  （`source directory already configured`）。`copy_source: auto` 先把源码复制到 `workdir/src`
  （剔除 `config.status`/`config.log`/`config.cache`/`CMakeCache.txt`/`.libs`/`*.o`/`*.lo`/`*.la`/`*.a`），
  原树保持不动；`copy_source: true|false` 可强制。
- **日志落盘**：每条命令的 `$ cmd`、`cwd`、`env`（CC/CFLAGS/LIBS/TMPDIR/HOME）、`rc`、耗时、
  stdout/stderr（各留 200KB 尾部）追加写 `<workdir>/build.log`；成功时再写 `archives (N)` 与每个归档的
  size + sha256。
- **失败不静默**：任一步非零退出 → `BuildError`（消息带命令、rc、日志路径与 stderr 尾部），
  `exc.result["commands"]` 保留全部执行记录、`archives=[]`；超时（默认 1800s）同理；不存在“空归档但成功”。
- **归档收集**：`collect_archives()` 按 `**/.libs/*.a`、`**/*.a` 顺序确定地收集（上限 32、跳过 `.covshim`），
  结果可直接传给 `to_build_spec(spec, workdir, extra_objs=...)` 的 `extra_objs`（替换 yaml 里的旧归档）。

### 5.3 真实冒烟（libpng 1.6.37 / libtiff 4.0.9，隔离构建日志）

两棵源码树（`/tmp/libpng-1.6.37`、`/tmp/tiff-4.0.9`）都已被 in-tree 配置过，因此都走 `copy_source`：

```bash
python3 -c "from agent.discovery import targetspec as t; \
print(t.build_library({'root': '/tmp/libpng-1.6.37', 'sources': [], 'includes': [], \
'build': {'system': 'configure'}}, '/tmp/vulnmap-smoke/png', isolation='bwrap'))"
```

libpng（完整日志 `/tmp/vulnmap-smoke/png/build.log`，四段：header / source copy / configure / make）：

```text
=== build_library: configure ===
root: /tmp/libpng-1.6.37
cflags: -g -O1 -fno-omit-frame-pointer -fsanitize=address -fsanitize-coverage=trace-pc,trace-cmp
jobs: 8
=== source copy ===
reason: source tree already configured (config.status); out-of-tree build refused
from: /tmp/libpng-1.6.37
to: /tmp/vulnmap-smoke/png/src
=== step: /tmp/vulnmap-smoke/png/src/configure ===
$ bwrap --unshare-net --unshare-pid --die-with-parent --cap-drop ALL --ro-bind / / --dev /dev
        --proc /proc --bind /tmp/vulnmap-smoke/png/build-configure
        /tmp/vulnmap-smoke/png/build-configure --
        .../src/configure --prefix=... --disable-shared --enable-static
--- stdout (rc=0, 1.872s) ---
checking whether the C compiler works... yes
checking whether to build shared libraries... no
checking whether to build static libraries... yes
config.status: creating libpng.pc
=== step: make ===
--- stdout (rc=0, 1.934s) ---
=== done ===
archives (1):
  /tmp/vulnmap-smoke/png/build-configure/.libs/libpng16.a  3183564B  sha256=6ffefb28bac53fa6
seconds: 3.861
```

libtiff（完整日志 `/tmp/vulnmap-smoke/tiff/build.log`，configure 5.079s / make 3.578s）：

```text
  C compiler: gcc -g -O1 -fno-omit-frame-pointer -fsanitize=address -fsanitize-coverage=trace-pc,trace-cmp -Wall -W
  ZLIB support:  yes
  JPEG support:  no
=== done ===
archives (3):
  .../libtiff/.libs/libtiff.a     5073742B  sha256=1c1b4111d11f5a9e
  .../libtiff/.libs/libtiffxx.a     85686B  sha256=d65fb3f7c25b135b
  .../port/.libs/libport.a           4080B  sha256=1180747fea77ddaf
seconds: 8.862
```

端到端（隔离构建产物 → `covfuzz.build` 链接既有 harness → 跑一个种子，`isolation=bwrap`）：

| 目标 | 归档 | fuzz_target sha256 | bitmap | cmp 操作数 | 结果 |
|---|---|---|---:|---:|---|
| libpng 1.6.37 | `libpng16.a` | `feeac9cd…` | 65536 B | 512（上限） | 种子不崩，覆盖位图与比较操作数都非空 |
| libtiff 4.0.9 | `libtiff.a` + `libtiffxx.a` + `libport.a` | `9afa4d78…` | 65536 B | 512（上限） | 种子不崩，覆盖位图与比较操作数都非空 |

这两行证明“隔离构建出来的库确实被插桩”：库内代码的 trace-pc / trace-cmp 回调真的在执行
（cmp 表打满 512 条上限），而不是只覆盖 harness。

容器模式真实探测（`DISCOVERY_ISOLATION_IMAGE=python:3.12-slim` 下的 `resolve("container")`）：

```text
docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 2g --tmpfs /tmp:rw,exec,nosuid,nodev \
  -v <work>:<work>:rw -e HOME -w <work> python:3.12-slim sh -c '...'
CapEff: 0000000000000000
NoNewPrivs: 1
lo                                  # 只有回环，无外网设备
touch: cannot touch '/vulnmap-probe': Read-only file system
ROOT_READONLY
TMPFS_WRITABLE
```

本机默认镜像 `debian:stable-slim` 不在本地，所以默认 `pytest` 下
`test_isolation_container_real_probe` 是 skip（skip 理由就是 `container_problem()` 的原文）；
把 `DISCOVERY_ISOLATION_IMAGE` 指向本地已有镜像后该测试真跑并通过。

同一个镜像上跑**宿主构建的 ASAN 目标**则会明确失败（镜像里没有 libasan），且不会被算成崩溃或静默 0 覆盖：

```text
run_input(..., isolation="container")
→ {"crash": False, "returncode": 127, "isolation": "container", "bitmap": 0,
   "setup_error": "run_setup_failed (rc=127): error while loading shared libraries"}
# run.log: /tmp/cont-build/fuzz_target: error while loading shared libraries:
#          libasan.so.6: cannot open shared object file: No such file or directory
```

要真在容器里 fuzz ASAN 目标，镜像里必须有匹配的 libasan（或把目标改静态链接），
这是容器模式的边界，不是被吞掉的错误。

## 5.1 本地 CI（`scripts/ci.sh`）

一条命令复现验收，全部离线（脚本内 `DISCOVERY_LLM_DISABLED=1`，不需要任何 key）：

```bash
bash scripts/ci.sh          # compile → tests → 示例 campaign
```

- `compile`：`python3 -m compileall -q agent bin`；
- `tests`：`tests/test_discovery*.py tests/test_agents.py tests/test_agent_seeds.py`（glob 自动纳入新增 discovery 测试），
  并带**测试数下限守卫**（总数 < 60 即失败；且 `tests/test_discovery.py` 单独 < 55 即失败 ——
  两道守卫一起挡住"删掉整段新测试后总数仍够 30"的缩水方式）；
- `campaign`：对 `fixtures/discovery` 跑一次端到端 campaign 并校验输出 JSON 含 `risk_stats`；
- 环境开关：`PYTHON` / `ISO` / `REQUIRE_ISO` / `SKIP_TESTS` / `SKIP_CAMPAIGN` / `KEEP`；
- 每个阶段带 `timeout`（存在该命令时）且首次失败即非零退出。仓库不是 git 仓库，因此没有 `.github/workflows`。

## 6. 路线图

| 阶段 | 内容 | 状态 |
|---|---|---|
| P1 | Agent 种子接入 + A/B | 已完成：假设文本驱动定向种子；cJSON 上无显著优势，如实保留 |
| P2 | PNG/TIFF 结构化变异，至少一个 WRITE/UAF confirmed | 变异引擎已完成；受控 PNG/TIFF fixture 各 1 个 WRITE confirmed；真实 libpng 4×120s、libtiff 4×240s 均 0 崩溃（负结果保留） |
| P3 | 旧平台下线，Discovery 成为唯一入口（新前端五页 + 单 CLI） | 入口已唯一；前端未迁移 |
| P4 | 构建/harness 自动化（target.yaml → campaign） | 已完成：YAML 加载 + 自动探测 + `--init-target` 草稿 + 内置/自定义 harness + 预构建对象/库；**新增 `build.system: auto|main|api|configure|cmake` + `build_library()` 隔离构建（bwrap 只读源码 + 可写 build 目录 + 日志落盘 + 弱符号垫片 + 归档自动收集）**；libpng 1.6.37 / libtiff 4.0.9 真实冒烟通过（§5.3） |
| P2/P3 硬化 | 比较操作数字典、隔离硬化、可选 LLM 复核、LLM 运营化、本地 CI | 已完成（见 §2 D2/D3.5、§4、§5.1）；**新增 container 隔离模式（docker/podman，显式选择，不可用明确报错）** |


## 7. 已知限制

1. 函数识别与调用图是近似的，宏/函数指针/跨文件间接调用会漏；
2. 覆盖率含函数级命中，粒度粗于行级；
3. harness 只覆盖最小 API 入口，不是完整应用入口；
4. 复杂构建（libpng/libtiff 等）现在有两条路：`build.system: configure|cmake` 的隔离构建（§5.2），
   或继续用 `target.yaml` 的预构建对象/自定义 harness 接入。cmake 分支本机没有 cmake，
   只有命令形状单测（`test_build_library_cmake_command_shape`）覆盖，没有真机 cmake 冒烟；
   configure 分支有 libpng/libtiff 真机冒烟；
5. 真实 libpng 1.6.37、libtiff 4.0.9 的结构化 fuzz 均未命中 WRITE/UAF；P2 的 WRITE confirmed 来自受控 fixture；
6. 未做 CVE 编号断言，避免对号入座；
7. 执行隔离分三档：bwrap（默认）/ unshare（namespace 级）/ container（显式 `--isolation container`）；
   宿主不支持时需 `--require-isolation` 强制失败。bwrap 模式有 `--unshare-pid`、`--die-with-parent`、
   `--cap-drop ALL` 与 `--ro-bind / /`（整根只读），unshare 模式以 `prctl(PR_SET_NO_NEW_PRIVS)` 补齐；
   但 unshare 的用户命名空间内 capability 仍然存在，`--cap-drop` 只在 bwrap 分支生效，三者不等价。
   container 模式要求本地有 docker/podman 守护进程与镜像（`DISCOVERY_ISOLATION_IMAGE`，默认
   `debian:stable-slim`），缺任一项直接 `RuntimeError`（不静默降级）；容器里跑 **ASAN 目标**时，
   动态依赖（libasan 等）必须由镜像提供，否则宿主构建的二进制在容器内起不来——日志会落盘，但那是
   运行期失败而不是“隔离成功”（`run_input.setup_error` 会把它标出来，`campaign.json.fuzz.setup_errors` 可审计）；
   容器模式不设 RLIMIT_CPU/NOFILE（只 setsid + core=0），资源上限由 `--pids-limit`/`--memory`/`--tmpfs` 承担；容器构建（configure/cmake）还要求镜像自带工具链，
   所以构建路径默认走 bwrap；
8. 调用点分析已默认走 LLM，但无 key/超时会回退规则；现有证据均为 `llm_status=no_key`，只能证明“规则假设→定向种子”，不能证明 LLM 增益；
9. D3.5 的 LLM 复核默认关闭，且只能在证据门禁之内收紧结论；它不能把规则复核拒绝的崩溃提成 confirmed，
   因此打开它也不会改变 confirmed 的判定口径（只是让复核理由多一层独立判断）；
10. 比较操作数有 512 条上限、字典有 96 项上限：高频比较的目标会截断，字典只能覆盖前若干常量；
11. `scripts/ci.sh` 的测试数下限硬编码为总数 60 / `test_discovery.py` 55（不可用环境变量放宽）：
    删掉新增的 27 条会同时踩两条下限，CI 直接失败；
12. `auto` 默认 `bwrap` 会让每次 exec 多一次沙箱 setup 开销（长跑吞吐低于 `unshare`）；
    这是"默认即硬化"的有意取舍，要吞吐请显式 `--isolation unshare`；`container` 不参与 `auto`
    （它依赖本地镜像，属于知情选择）；
13. 隔离构建的 `make -jN` 默认跑 `all`：libpng/libtiff 会连自带工具一起链接，这靠 `.covshim` 的弱符号
    垫片才成立（工具链接要 `__sanitizer_cov_trace_cmpf/cmpd` 等回调）。只想出库时给 `build.make_targets`
    指定库目标即可；
14. `collect_archives()` 有 32 个归档上限、`build.log` 每条命令的 stdout/stderr 各留 200KB 尾部：
    超大工程会截断日志（截断处显式标注 `[truncated ... tail kept]`）；
15. `analysis.mode` 按实际结果标注（全部 LLM 调用失败时为 `llm_fallback`，不再自报 `llm`）。
