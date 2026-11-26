# Discovery v1.0 实跑结果

> 所有数字来自本机实跑，命令与证据目录可复核；负结果原样保留。
> 环境：Ubuntu 22.04 / gcc 11.4.0 / Python 3.12.14 / ASAN（gcc 内置）。

## 1. 受控 fixture（基础 write 越界）

命令：

```bash
python3 bin/discover.py fixtures/discovery --out discovery/fixture --seconds 3 --max-sites 3
```

| 指标 | 结果 |
|---|---|
| planned / covered / uncovered | 4 / 4 / 0（complete） |
| confirmed / weakened / excluded | 1 / 0 / 0 |
| 崩溃 | WRITE of size 64，`parse_record` `vuln_parser.c:16` |
| 复现 | 3/3（独立目录干净构建） |
| stack_hash | `d33104e0a3d79e44` |
| 首次崩溃 | 0.145s，16 execs（4 workers，bwrap 隔离） |

说明：ASAN 将本例报为 `unknown-crash`，原因是 Ubuntu 默认启用 fortify，`memcpy` 被内联为 `__memcpy_chk`，ASAN 无法归类；日志仍给出 `WRITE of size 64` 与 16 字节堆区间，verdict 按写 + 3/3 判为 confirmed。证据：`discovery/fixture/`。

## 2. P2：PNG/TIFF 结构化变异（WRITE confirmed）

P2 变异器保持格式骨架，只打结构字段：PNG 的 IHDR 宽高/位深、IDAT、声明长度、chunk 顺序；TIFF 的 endian/IFD、tag 类型、count、offset、Strip 字段。

### 2.1 受控 PNG fixture

fixture：`fixtures/discovery_png/png_parser.c`。IHDR 宽高按 32 位相乘分配，随后按真实宽高写入；宽高 65536×65536 时乘积回绕为 0，分配 1 字节后写入 64KB。

```bash
python3 bin/discover.py fixtures/discovery_png --out discovery/png-fixture \
  --seconds 5 --max-sites 3 --format png
```

| 指标 | 结果 |
|---|---|
| planned / covered / uncovered | 3 / 3 / 0（complete） |
| confirmed | 1 |
| 崩溃 | heap-buffer-overflow，WRITE of size 100000，`parse_ihdr` `png_parser.c:27` |
| 复现 | 3/3（干净构建） |
| stack_hash | `43810c4d1f96ef5a` |
| 首次崩溃 | 0.188s，63 execs（4 workers） |

### 2.2 受控 TIFF fixture

fixture：`fixtures/discovery_tiff/tiff_parser.c`。IFD 第一项的 count 驱动拷贝，count 被结构化成大值后写入 64 字节缓冲区。

```bash
python3 bin/discover.py fixtures/discovery_tiff --out discovery/tiff-fixture \
  --seconds 5 --max-sites 3 --format tiff
```

| 指标 | 结果 |
|---|---|
| planned / covered / uncovered | 4 / 4 / 0（complete） |
| confirmed | 1 |
| 崩溃 | WRITE of size 4062，`parse_ifd` `tiff_parser.c:39` |
| 复现 | 3/3（干净构建） |
| stack_hash | `935f142456f68e7c` |
| 首次崩溃 | 0.243s，282 execs（4 workers） |

说明：TIFF 用例同样因 fortify 内联被判为 `unknown-crash`，但日志给出 `WRITE of size 4062`，verdict 按写 + 3/3 判为 confirmed。两个 P2 结论都是**受控 fixture**，不冒充真实目标发现。

## 3. 真实目标：cJSON 1.7.10（验收基线）

无 error.txt / patch.diff / 官方 PoC；只用 cJSON 源码 + 自写最小 harness。

```bash
python3 bin/discover.py /tmp/cJSON --out discovery/real-cjson --seconds 60 --max-sites 8
```

| 验收项 | 基线 | 本次实测 | 结论 |
|---|---|---|---|
| 崩溃类型 | heap-buffer-overflow READ of size 1 | heap-buffer-overflow READ of size 1 | 一致 |
| 位置 | `cJSON_Minify` cJSON.c:2642 | `cJSON_Minify` /tmp/cJSON/cJSON.c:2642 | 一致 |
| 复现 | 3/3 | 3/3（独立目录干净构建） | 一致 |
| verdict | weakened | weakened | 一致 |
| 覆盖率 | 14/80 | 14/80（uncovered 66，partial） | 一致 |
| 首次崩溃 | 0.17s | 0.225s（36 execs，bwrap 隔离；4 worker 分别 0.236/0.231/0.279/0.225） | 同量级 |
| stack_hash | 2b707abbebd7eeb9 | 2b707abbebd7eeb9 | 一致 |

构建产物 sha256：`64d1c6889d080720012afa04b88d03b956dc1f736cccb44f3c8ef396c5cb7751`；构建命令见 `discovery/real-cjson/campaign.json` 的 `build.cmd`。

覆盖口径补充：14 个命中全部是**函数级命中**（`covered_by_pc=false`、`covered_by_function=true`）；即调用点所在函数被执行，PC 行号落在相邻语句。报告与台账都保留这两个布尔字段，不把函数级命中写成行级命中。

结论：这是**读越界**，verdict 为 weakened，不写成高危；没有把它包装成可利用漏洞。证据：`discovery/real-cjson/`（target/callsites/hypotheses/crashes/triage/reviews/report/db）。

## 3.1 确认门禁、执行隔离与假设驱动种子

### 确认门禁

- 有效诊断：`crash_type` 不能是 `unknown/allocator/out-of-memory`，根因帧必须有 `function/file/line`，且 `access` 为 READ/WRITE（UB 例外）；
- 干净构建失败 → `needs_human / clean_build_failed`，不会输出 confirmed；
- 复用旧构建 → `needs_human / clean_build_unavailable`，只能作为线索；
- 复核要求 `build_clean=true` 才可能给出 confirmed/weakened。

隔离模拟检查已固化为测试：空日志 → `invalid_diagnostic`；rebuilder 抛错 → `clean_build_failed`；无 rebuilder → `clean_build_unavailable`；复核对 `build_clean=false` 返回 `needs_human`。

## 3.2 Live LLM 验证（2026-11-16）

配置 key 后实测：调用点分析进入 `analysis.mode=llm`、`llm_status=ready`、`llm_hypotheses=1`，不再是回退路径。

| 目标 | LLM 假设 | 种子 | 最终判定（Fuzz/Triage） |
|---|---|---|---|
| fixture | `memcpy` 的 16 位长度未校验，len>16 写越界；citations 有效 | 11 | confirmed WRITE（未被 LLM 直接改写） |
| cJSON（1 个调用点） | 怀疑 `fread` 返回值未校验、`buf[r]=0` 越界（citations `harness.c:14`） | 13 | 仍为 weakened READ（`cJSON_Minify` cJSON.c:2642） |

说明：

- LLM 假设可以错（cJSON 这条就偏离了实际崩溃点），Fuzz/Triage 才是判定方；
- 种子由 LLM 假设文本驱动（fixture basis 含 size/overflow/长度/越界，cJSON 含 size/长度/越界）；
- API key 只从环境变量读取，不写入配置、台账、报告或文档；证据目录中已检查无 key 字面量；
- 现场证据：`discovery/llm-fixture-live/`、`discovery/llm-cjson-live/`。

### 执行隔离

- 默认 `bwrap`：断网 + `--unshare-pid` + `--die-with-parent` + `--cap-drop ALL` + `--ro-bind / /`（只读根）；
  不可用时回退 `unshare -rn`（网络 none + `no_new_privs`）；
- 每个目标进程带 CPU / FSIZE / NOFILE / CORE 资源上限，不限制虚拟内存（ASAN 需要）；
- `--require-isolation` 在隔离不可用时直接失败，不回退宿主网络；
- 重跑证据：fixture、cJSON 的 campaign 均记录 `execution_isolation.mode=bwrap`、`network=none`、`cap_drop=true`、`ro_root=true`。

### 假设驱动种子

`propose_seeds(site, ..., hypothesis=...)` 现在读取假设文本与源码窗口，按 comment/array/length/count/offset/width/interlace/palette/tRNS 等关键词追加定向种子；
`hypotheses.json` 记录 `seed_count` 与 `seed_basis`。cJSON 各假设生成 10–13 个种子（basis 含 length/size/count/offset），fixture 生成 11–12 个（basis 含 size/长度/越界）。

调用点分析已改为**默认 LLM**（`--analysis llm`），无 key/超时/显式关闭时回退规则；本轮环境无可用 key，
`hypotheses.json` 记录 `llm=false / llm_status=no_key`，因此只能证明“规则假设→定向种子”，不能据此宣称 LLM 提升了发现能力。

> 注：第 2、4、7 节的真实目标长跑数字产生于执行隔离改造之前；隔离后的 fixture 与 cJSON 已重新跑过。

## 4. 负结果：libpng 1.6.37 与 libtiff 4.0.9

沿用已构建的 ASAN + trace-pc 二进制（sha256 `19ccc30c9ccf171797d5c82af76a92611681a2e70e65b0272ce551f4af7b22ba`，harness 见 `discovery/real-libpng/harness.c`），语料为 PNG 结构种子。

```bash
python3 bin/covfuzz.py /tmp/png/png_fuzz \
  --corpus discovery/real-libpng/corpus --crashes discovery/real-libpng/crashes \
  --stats discovery/real-libpng/stats --seconds 60 --workers 4
```

| 轮次 | 变异 | execs | crashes | 语料 | 新覆盖位 |
|---|---|---|---:|---:|---:|
| run1 | 通用 | 58,457 | 0 | 86 | 2,678 |
| run2 | 通用 | 59,809 | 0 | 86 | 2,678 |
| run3 | PNG 结构化 | 90,619（4×120s） | 0 | 301（上限） | 4,388 |

基线写的是 4 workers × 60s ≈ 62,400 execs；通用两轮为 58.5k / 59.8k，同一量级（差异来自每执行 Python 记账与机器负载）。结构化变异把覆盖位从 2,678 提到 4,388，仍未触发崩溃。**crashes = 0 的负结果保留**，不因未命中而删除。

### 4.2 真实目标：libtiff 4.0.9（TIFF 结构化）

源码 `tiff-4.0.9.tar.gz`（sha256 `6e7bdeec2c31…`），`libtiff` 静态库以 ASAN + trace-pc 重建；harness 用
`TIFFOpen` + `TIFFReadRGBAImage`，通过 `examples/targets/libtiff.yaml` 接入（预构建静态库 + `-lz -lm`）。

| 轮次 | 变异 | execs | crashes | 备注 |
|---|---|---:|---:|---|
| 1 | TIFF 结构化 | 34,828 | 1（排除） | ASAN allocator OOM，非内存安全缺陷 |
| 2 | TIFF 结构化 | 56,193 | 0 | `allocator_may_return_null=1` |
| 3 | TIFF 结构化 | 180,538 | 0 | 4×240s |
| 4 | TIFF 结构化 + tile 字段 | 176,583 | 0 | 4×240s；24 次超时 |

首轮崩溃是 `_TIFFmalloc` 申请 `0x33ff980034` 字节触发 ASAN allocator OOM；已把 `allocator_may_return_null=1` 加入运行参数，
避免把“分配失败”误判为漏洞。其余轮次 0 崩溃，负结果保留。campaign 证据：`discovery/real-libtiff/`（planned 329 / covered 13 / crashes 0）。

## 5. 种子 A/B（cJSON）

命令：`python3 experiments/agent_seed_ab.py --attempts 10`

| 配置 | 初始种子 | 崩溃轮次 | 平均首次崩溃执行数 | 平均耗时 |
|---|---:|---:|---:|---:|
| 纯 fuzz | 4 | 10/10 | 10.0 | 0.163s |
| Agent 种子 | 10 | 10/10 | 7.0 | 0.148s |

差异仅 3 次执行 / 15ms，且发生在“首个种子附近就崩溃”的饱和区间，属于进程启动与隔离包装抖动；结论为**该目标上无显著优势**，如实保留，不据此宣称 Agent 种子有效。证据：`discovery/ab-cjson/ab.json`。

## 6. ranked vs random（fixture）

| 策略 | 覆盖率 | confirmed | execs | 首次崩溃 |
|---|---|---|---:|---:|
| ranked | 4/4 | 1 | 16 | 0.13s |
| random | 4/4 | 1 | 20 | 0.14s |

fixture 只有 4 个调用点且种子直接命中，两种顺序无差异；作为负结果保留（`discovery/eval-fixture/eval.md`）。

## 7. P4：target.yaml → campaign（构建/harness 自动化）

`bin/discover.py <target>` 自动探测 `<target>/target.yaml`，也可 `--target-yaml` 指定。fixture 用 `build.mode: main`；
cJSON 用内置 `harness: cjson`；libpng 用预构建 ASAN 对象 + `harness_path` 链接。

| 目标 | YAML | planned | covered | crashes | execs | 备注 |
|---|---|---|---:|---:|---:|---:|---|
| fixtures/discovery | 自动探测 | 4 | 4 | 1（confirmed WRITE） | 12 | 与直接构建一致 |
| cJSON 1.7.10 | `examples/targets/cjson.yaml` | 80 | 14 | 1（weakened READ） | 8 | 首次崩溃 0.123s，stack_hash 不变 |
| libpng 1.6.37 | `examples/targets/libpng.yaml` | 223 | 27 | 0 | 33,681 | 负结果保留；构建 sha256 `11c367a02e71…` |
| libtiff 4.0.9 | `examples/targets/libtiff.yaml` | 329 | 13 | 0 | 55,619 | 负结果保留；构建 sha256 `81d6c42a5d58…` |

另：没有 YAML 时可 `python3 bin/discover.py <target> --init-target` 生成草稿；fixture 被识别为 `mode: main`，
libtiff 这类 configure 项目被识别为 `mode: api + harness.c` 并标记 `needs_review: true`。

libpng 的 YAML 构建命令由 15 个预构建 `.o` + harness + `cov_rt.o` + `-lz -lm` 组成，构建产物 sha256
`11c367a02e717b297e55999a9dab42a01da845f5d102066d4f5617c22a8a600e`；campaign 用时 65.84s，223 个调用点覆盖 27 个（函数级命中 20），0 崩溃。
结构化 PNG 变异会生成更大的图像，因此 60s 执行数（33,681）低于通用变异的 58k，这是输入尺寸差异，不是引擎退化。

## 8. 复现

```bash
cd vulnmap
python3 -m pytest tests/test_discovery.py tests/test_agents.py tests/test_agent_seeds.py -q
python3 bin/discover.py fixtures/discovery --out /tmp/out --seconds 3 --max-sites 3
python3 bin/discover.py fixtures/discovery_png --out /tmp/png-out --seconds 5 --max-sites 3 --format png
python3 bin/discover.py fixtures/discovery_tiff --out /tmp/tiff-out --seconds 5 --max-sites 3 --format tiff
python3 bin/discover.py /tmp/cJSON --out discovery/real-cjson --seconds 60 --max-sites 8
# P4：target.yaml 自动构建
python3 bin/discover.py /tmp/cJSON --target-yaml examples/targets/cjson.yaml --out /tmp/cjson-yaml --seconds 5
python3 bin/discover.py /tmp/libpng-1.6.37 --target-yaml examples/targets/libpng.yaml \
  --out discovery/real-libpng/campaign --seconds 60 --max-sites 8
python3 bin/discover.py /tmp/tiff-4.0.9 --target-yaml examples/targets/libtiff.yaml \
  --out discovery/real-libtiff --seconds 60 --max-sites 8
python3 bin/covfuzz.py /tmp/png/png_fuzz --corpus discovery/real-libpng/corpus \
  --crashes /tmp/libpng-crashes --stats /tmp/libpng-stats --seconds 60 --workers 4
python3 experiments/agent_seed_ab.py
```

## 9. 限制

1. 真实目标 cJSON 只找到读越界（weakened）；真实 libpng 仍为 0 崩溃，P2 的 WRITE 结论来自受控 fixture；
2. 覆盖率为函数级为主，粒度粗于行级；cJSON 的 14/80 不能理解为 14 个调用点被逐行执行；
3. harness 是最小 API 入口，不是完整应用入口；
4. libpng 通过 `target.yaml` 链接既有 ASAN+trace-pc 对象，configure/CMake 自动生成仍未做；
5. 未做 CVE 编号断言；未做二次利用、堆布局、固件解包、跨架构仿真；
6. 执行隔离为 namespace 级（unshare/bwrap），不是完整容器/VM；长跑数字受隔离包装开销影响；
7. 调用点分析默认 LLM，但本轮无 key（`llm_status=no_key`）实际走规则回退；种子由规则假设驱动，不能据此评估 LLM 发现能力。

## 10. P1 追加：真实目标新 API 路径（2026-11-16）

三条路线同时开跑，全部经 `examples/targets/*.yaml` 构建，`--isolation auto`（`campaign.json` 记录
`execution_isolation.mode=bwrap`、`network=none`）；harness 与证据都在 `discovery/real-*/`。
语料起点是随源码发布的测试图 / JSON 种子，不是 PoC；未读取任何 error.txt、patch.diff 或官方 PoC。

| 路线 | 目标 / harness | execs | crashes | 判定 |
|---|---|---:|---:|---|
| 1 | libtiff 4.0.9 目录/Strip/Scanline（`real-libtiff-strip/`） | 41,208（4×120s） | 2（1 类） | **weakened READ**，3/3 干净构建 |
| 2 | libpng 1.6.37 逐行 + 变换链（`real-libpng-row/`） | 70,147（4×120s） | 0 | 负结果 |
| 3 | cJSON 1.7.10 Parse/Print，跳过 Minify（`real-cjson-parse/`） | 76,939（4×120s） | 0 | 负结果 |

### 10.1 libtiff 4.0.9：`TIFFRawStripSize64` 堆越界读（新，weakened）

harness：`TIFFOpen` → `TIFFReadDirectory` 循环（≤32 目录）→ `TIFFGetField` →
`TIFFScanlineSize`/`TIFFStripSize`/`TIFFRawStripSize`/`TIFFNumberOfStrips` →
`TIFFReadScanline`（≤8 行）→ `TIFFReadEncodedStrip`（≤64 strip）；不进入 `TIFFReadRGBAImage`，
与第 4.2 节的 RGBA harness 互补。

```bash
python3 bin/discover.py /tmp/tiff-4.0.9 \
  --target-yaml examples/targets/libtiff-strip.yaml \
  --out discovery/real-libtiff-strip --seconds 120 --max-sites 8 --workers 4 --isolation auto
```

| 指标 | 值 |
|---|---|
| 构建 sha256 | `c2ee18c033fe2f0e25e6b771f2dde994fef4425aea503c5a0402f1e9dbea6a` |
| execs / crashes / timeouts | 41,208 / 2（同一 stack）/ 1 |
| 首次崩溃 | 20.854s |
| 覆盖率 | 13/329 调用点（partial） |
| triage | `build_clean=true`，3/3，`stack_hash=619fbaa9bdb7e2fa` |
| 崩溃 | heap-buffer-overflow **READ of size 8**，`TIFFRawStripSize64` `tif_strip.c:153` |

根因（`probe.c` 实测）：崩溃输入是 tiled 图（512×384，tile 128×128，spp=3，Compression=7），
同时携带 `RowsPerStrip=2`。`TIFFNumberOfStrips()` 用 `ImageLength/RowsPerStrip` 推算返回 **192**，
而 `TIFFNumberOfTiles()` 与目录里 `TileByteCounts` 只有 **12** 项；`td_stripbytecount` 数组即 96 字节
（12×8，由 `TIFFReadDirEntryLong8ArrayWithLimit` 分配）。按公开 API 顺序取 strip 12 时，
`tif_strip.c:153` 直接索引 `td_stripbytecount[12]`，越过数组。这是库侧缺少与 `td_nstrips`
的一致性检查导致的越界读，同时也说明 `TIFFNumberOfStrips()` 对 tiled 文件的返回值不可用于
strip 字节计数数组的索引。

复现：

```bash
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
  discovery/real-libtiff-strip/build/fuzz_target \
  discovery/real-libtiff-strip/crashes/crash-0ed652f39ebd754d.bin
```

第二轮（剔除已崩溃种子后 4×240s）：execs 101,998、crashes 2（3 个 crash 文件）、timeouts 10、
首次崩溃 7.957s；`round2-triage.json` 中两个新输入仍是 `build_clean=true`、3/3、
`stack_hash=619fbaa9bdb7e2fa`，与第一轮同一缺陷类，没有新类别。

**这不是 WRITE/UAF**：本 harness 不进入 `tif_getimage.c`，且崩溃输入的 Compression=7（JPEG）
在构建里未启用，解码在写入光栅前即退出，时间盒内没有可升级为写越界的执行序列。
按门禁判 weakened，不写成 confirmed，不写 CVE 编号。

### 10.2 libpng 1.6.37：逐行 + 变换链负结果

harness：`png_read_info` → `png_set_expand`/`png_set_strip_16`/`png_set_palette_to_rgb`/
`png_set_tRNS_to_alpha`/`png_set_gray_to_rgb`/`png_set_interlace_handling` →
`png_read_update_info` → `png_read_row`（≤4096 行）→ `png_read_end`；语料起点为
`contrib/testpngs/*.png`（104 张）。4×120s、**70,147 execs、0 crashes、0 timeouts**，
覆盖率 30/225 调用点，`triage.json` 为空。与第 4 节（`png_image_*` 简化 API）不矛盾，
两条公开读取路径本轮都未被击穿。

### 10.3 cJSON 1.7.10：Parse/Print 负结果

harness 不调用 `cJSON_Minify`，直接 `cJSON_Parse` → `cJSON_PrintUnformatted`/`cJSON_Print`/
`cJSON_PrintBuffered(item, 1, 0)` → `cJSON_Delete`，以避开第 3 节已确认的 Minify 读越界。
4×120s、**76,939 execs、0 crashes**，覆盖率 14/80 调用点。第 3 节的 Minify 结论不变，
本路线没有发现第二个缺陷。

### 10.4 小结

- 本轮唯一新发现是 libtiff 的越界**读**（weakened，3/3 干净构建）；P1 要求的
  `build_clean=true` 的 WRITE/UAF 在本时间盒内**未达成**，不把它包装成高危；
- 门禁未放宽：崩溃仍需干净构建 3/3；分配上限只压 ASAN allocator OOM 噪声，
  不改变越界判定；
- 负结果（libpng 逐行、cJSON Parse/Print）连同 execs/crashes 原样保留，
  不因未命中而删除。

## 11. 二轮：tif_getimage.c（tiled RGBA）与 libpng 特殊 chunk（2026-11-16）

上一轮（第 10 节）的 READ 与两条负结果都保留。本轮换两条**新 API 路径**重开，均由
`examples/targets/*.yaml` 构建、`--isolation auto` 解析为 **bwrap**（`campaign.json`
记录 `mode=bwrap`、`network=none`、`ro_root=true`、`pidns=true`）。语料由
`discovery/real-*-r2/gen_corpus.py` 本地生成（不读任何 PoC/patch/error.txt）。

| 路线 | 目标 / harness | execs | crashes | 判定 |
|---|---|---:|---:|---|
| 1 | libtiff 4.0.9 `tif_getimage.c`：整图 RGBA + `TIFFReadRGBATile` + `TIFFReadRGBAStrip`（`real-libtiff-rgba-r2/`） | 40,180（4×180s） | 0（1 超时） | 负结果 |
| 2 | libpng 1.6.37 逐行 + sBIT/bKGD/tRNS + 背景合成（`real-libpng-chunks-r2/`） | 44,843（4×180s） | 0 | 负结果 |

### 11.1 libtiff 4.0.9：tiled 输入进 `tif_getimage.c`（负结果）

harness（`discovery/real-libtiff-rgba-r2/harness.c`）：
`TIFFOpen` → `TIFFReadDirectory`（≤8 目录）→ 三条 RGBA 入口：
`TIFFRGBAImageOK/Begin/Get/End`（缓冲 `img.width*img.height*4`）、
`TIFFReadRGBATile`（缓冲 `TileWidth*TileLength*4`，逐 tile）、
`TIFFReadRGBAStrip`（缓冲 `Width*RowsPerStrip*4`，逐 strip）。三条缓冲全部按库上报尺寸
**精确分配**，不做多分配兜底。

压缩路径的现实边界：系统只有 `libjpeg-turbo8` **运行时**，没有 `jpeglib.h`
（`/usr/include/jpeglib.h` 不存在，`find` 无结果），`configure --enable-jpeg` 无法通过，
所以本轮没有重开 JPEG；改为把既有构建**已启用**的 LZW / Deflate / PackBits / CCITT /
Thunder / PixarLog 真正喂到（第 4.2 节的语料基本是未压缩条带），并补 tiled / palette
1-4-8bpp / 16bpp / `PlanarConfig=2` 组合。语料起点 67 个（`gen_corpus.py` 58 + 源码
`test/images` 9），其余由覆盖反馈扩充到 635。

```bash
python3 bin/discover.py /tmp/tiff-4.0.9 \
  --target-yaml examples/targets/libtiff-rgba-r2.yaml \
  --out discovery/real-libtiff-rgba-r2 --seconds 180 --max-sites 8 --workers 4 --isolation auto
```

| 指标 | 值 |
|---|---|
| 构建 sha256 | `2c7b2776b18a7cd6…`（`-fsanitize=address -fsanitize-coverage=trace-pc,trace-cmp`） |
| execs / crashes / timeouts | 40,180 / **0** / 1 |
| 覆盖 | 14/329 调用点；PC 2,304、函数 231（strip harness 为 171） |
| triage | 空（无崩溃） |
| 判定 | **负结果**（`negative_result=true`） |

第一轮噪声（证据在 `discovery/real-libtiff-rgba-r2/round1-noise/`）：12–28s 内 4 个 worker
各报 1 个“崩溃”，总 execs 只有 3,987。日志是
`Warning, Nonstandard tile width 2147483647` → `==N==WARNING: AddressSanitizer failed to
allocate 0x…` → `No space for tile buffer.`——这是 `_TIFFmalloc` 超大尺寸申请的**分配告警**，
不是内存错误：手动复跑 `rc=0`、无 `ERROR: AddressSanitizer`，`triage.json` 记为
`needs_human / invalid_diagnostic`、`reproduced 0/3`。处置是在 harness 里对
`TileWidth/TileLength` 做几何预检（>8192 或乘积超出 64MB 上限时只跳过 RGBA 层，
目录解析照跑），再跑即无告警。分配上限仍只压 OOM 噪声，不改变越界判定。

结论：`tif_getimage.c` 的整图 / 逐 tile / 逐 strip 三条入口在 4×180s 内没有 WRITE/UAF、
也没有 READ；`Compression=7`（JPEG）输入仍在解码前退出，与第 10.1 节边界一致。

### 11.2 libpng 1.6.37：sBIT/bKGD/tRNS palette + 背景合成（负结果）

harness（`discovery/real-libpng-chunks-r2/harness.c`）：`png_read_info` → 取
`sBIT`/`bKGD`/`tRNS` → `png_set_expand` / `png_set_strip_16` / `png_set_palette_to_rgb` /
`png_set_tRNS_to_alpha` / `png_set_gray_to_rgb` / `png_set_interlace_handling` →
**`png_set_background`（用文件里的 bKGD 作合成背景）** → `png_read_update_info` →
`png_read_row`（≤4096 行）→ `png_read_end`；行缓冲按 `png_get_rowbytes` 精确分配。
与第 10.2 节相比多了 bKGD 合成（`png_do_background`/`png_do_compose`）与 sBIT 读取。

语料起点 157 个：`gen_corpus.py` 生成 53 个（palette 1/2/4/8bpp × tRNS 部分/全透明 ×
bKGD × sBIT × Adam7 交错/非交错；RGB 8/16bpp；gray 1/2/4/8/16bpp tRNS 键；GA/RGBA 边界
尺寸；多 IDAT / 空 IDAT / 截断 IDAT）+ `contrib/testpngs/*.png` 104 个。交错样本由生成器
按 Adam7 自己写出（源码测试集无交错图）。

```bash
python3 bin/discover.py /tmp/libpng-1.6.37 \
  --target-yaml examples/targets/libpng-chunks-r2.yaml \
  --out discovery/real-libpng-chunks-r2 --seconds 180 --max-sites 8 --workers 4 --isolation auto
```

| 指标 | 值 |
|---|---|
| 构建 sha256 | `d675959fab43645c…` |
| execs / crashes / timeouts | 44,843 / **0** / 0 |
| 覆盖 | 30/225 调用点；PC 1,677、函数 156 |
| triage | 空（无崩溃） |
| 判定 | **负结果**（`negative_result=true`） |

调用点覆盖与第 10.2 节 row harness 相同（30/225），本轮新增的 bKGD 合成与 sBIT 读取
没有被击穿，也没有出现 READ。为确认合成路径不是“设了没跑”，做了同名输入的对照实验
（带 `png_set_background` / 去掉该调用）：`palette-trns0-i1` 的 PC 采样 71,156 vs 64,892、
`rgba4-bkgd-i1` 34,292 vs 32,204，差分说明 `png_do_background`/`png_do_compose` 确实执行。

### 11.3 小结

- 二轮两条新路径都跑满 4×180s，**0 崩溃**，按门禁记负结果，`triage.json` 为空，
  没有把任何东西包装成 confirmed；本时间盒内仍未取得 `build_clean=true` 的 WRITE/UAF。
- 门禁未动：confirmed 仍需“干净构建 3/3 + access=WRITE”；首轮的分配告警按
  `invalid_diagnostic` 判为噪声并保留证据，不当作漏洞。
- 负结果（libtiff RGBA/tiled、libpng 特殊 chunk）连同 execs/crashes/timeouts 原样保留；
  未改 `agent/discovery/`、`vulnmap_platform/`、README，未提交 git。
