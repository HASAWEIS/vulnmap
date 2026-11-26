# CG-17 / arvo:1065（file magic，CWE-457）严重性草案

> **状态**：Agent 草案，`final=false`、`human_signoff_required=true`、`reviewed_by=agent`；**未使用 `_status=DRAFT`**（避免被 report 判成未评估）。
> 机器可读版本：`workspace/S7-CG17-arvo-1065/severity.json`；结构校验：`tests/test_severity_1065.py`。
> 未改 `case.json`、`LEDGER.json`、其他 workspace。

## 0. 结论一句话

MSan 实测到 **magiccheck 里的 `pmatch` 未初始化**：`regexec` 返回 0 却不写 `pmatch`（description.txt 原文：*A bug in glibc/regex/msan causes regexec to return 0 but not initialize pmatch*），
`file` 侧直接把 `pmatch.rm_so/rm_eo` 当作有效值用于类型判定与描述串构造。**输入是本地文件 → `AV:L`（不照抄 CG-12D 的 `AV:N`）**；
没有越界写、没有实测泄露、没有目标自身崩溃 → **`I:L` / `C:N` / `A:N`，CVSS 3.3（low）**。

## 1. 向量与分数

```
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N = 3.3  (low)
```

| 维度 | 取值 | 逐维理由（CVSS 3.1） |
| --- | --- | --- |
| AV | **L** | 输入是 `docker run -v .../file-magic-php.bin:/tmp/poc:ro` 挂载的本地文件（vul.log:1），日志里没有任何 socket/网络交付；`AV:N` 在本例无据 |
| AC | **L** | 17 字节固定输入两次运行输出逐行一致（`vul.log` 与 `vul-retry1.log` 仅 seed/ASLR 地址不同），不需要额外条件 |
| PR | **N** | 容器内未加特权、未指定 `-u` 即触发（vul.log:1-2） |
| UI | **R** | 每次只跑一个输入（vul.log:8-9），需要一次投递动作；产品侧自动扫描无证据 → 取保守值（0.62 < 0.85） |
| S | **U** | 影响局限在 `file` 进程的文件类型判定 |
| C | **N** | 未实测泄露；`mprint` 使用的 `search` 指向**攻击者自己的文件缓冲**（softmagic.c:1896-1904），即使打印长度异常也只回吐攻击者输入 |
| I | **L** | 未初始化值进入判定与描述串（softmagic.c:1896-1904 → :365），同一文件可被判成不同类型，但无写、无任意修改 → L 非 H |
| A | **N** | 目标自身无崩溃；`exit=77` 是 MSan 的退出（vul.log:2、:49 'Exiting'），fix 侧 exit=0（fix.log:2、:10） |

## 2. 六维证据（逐条可核）

| 维度 | 值 | 证据（文件:行） |
| --- | --- | --- |
| attack_vector | local | `workspace/S7-CG17-arvo-1065/logs/V4.file-magic-php.1065-vul.log:1`（`-v ...:/tmp/poc:ro`）、`:8-9`（`Running: /tmp/poc`） |
| privileges_required | none | `logs/V4.file-magic-php.1065-vul.log:1`（无 `--privileged`/`-u`）、`:2`（exit=77） |
| user_interaction | required | `logs/V4.file-magic-php.1065-vul.log:8-9`（单输入逐次执行） |
| observed_impact | uninitialized_value_read | `logs/V4.file-magic-php.1065-vul.log:10`（MSan use-of-uninitialized-value）、`:11`（使用点 match @ `src/file/src/softmagic.c:365`）、`:40-41`（origin: `pmatch` in `magiccheck` @ `softmagic.c:1706`）、`:26`（store: `magiccheck` @ `softmagic.c:1904`） |
| reachability_evidence | confirmed | `logs/V4.file-magic-php.1065-vul.log:11-15`（`match ← file_softmagic ← file_buffer ← magic_buffer ← LLVMFuzzerTestOneInput`）、`logs/V4.file-magic-php.1065-fix.log:2,10`（fix 干净） |
| deployment_conditions | unproven | 已知只有 MSan 构建可观测（`vul.log:10,49`；`fix.log:2,10`）；生产消费方式无证据 |

## 3. 因果链（为什么是 CWE-457，不是越界读写）

```
softmagic.c:1896-1898   rc = file_regexec(&rx, search, 1, &pmatch, 0);
                        // glibc/msan: 返回 0 但 pmatch 未初始化
softmagic.c:1899-1904   case 0: ms->search.s += pmatch.rm_so;
                        ms->search.offset += pmatch.rm_so;
                        ms->search.rm_len = pmatch.rm_eo - pmatch.rm_so;   // 未初始化值被写入
softmagic.c:365         if (print && mprint(ms, m) == -1) return -1;      // 未初始化值在此被使用（MSan #0）
```

日志侧对应关系：`vul.log:26`（store 点 1904）、`vul.log:40-41`（origin 1706 的 `pmatch`）、`vul.log:11`（使用点 365）。三处行号与源码一致，`root_cause.confidence=strong`（`artifacts/verify/result.json`）。

## 4. 缺证据清单

1. **deployment_conditions**：谁在生产里把不可信文件交给 `file`/libmagic（本地 CLI？上传扫描服务？），没有证据；因此 UI/AV 只能取保守值。
2. **非 MSan 构建下的可观测后果**：普通构建里这次未初始化读静默通过，没有"类型判错导致下游放行"的实测。
3. **泄露实测**：若 `rm_len` 能读到文件缓冲之外的内存并回显，才可把 C 从 N 提到 L；目前 `search` 指向攻击者输入，缺这一环。
4. **放大 PoC**：若能把"判错类型"变成绕过某种安全检查（例如上传过滤把 PHP 判成图片），I 才可能上调。

## 5. 敏感性（人工裁决时的备选分数）

| 变更 | 向量 | 分数 |
| --- | --- | --- |
| `A:L`（若认为未初始化长度可致崩溃） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L` | 4.4 |
| `C:L`（若能实测回显文件外内存） | `AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | 4.4 |
| `UI:N`（若产品侧自动扫描） | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` | 4.0 |
| `AC:H`（若认为后果依赖未初始化内容） | `AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` | 2.5 |
| `I:N`（若认为只是信息性问题） | `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N` | 0.0 |

**对照 CG-12D**：若照抄那套 `I:H/A:H`，即使把 `AV` 改成本例正确的 `AV:L`，也会算出 **7.1（high）**；而本例**没有写、没有崩溃**，
所以 `I:H` 无据 → 按任务口径写 `I:L`，最终 3.3。这也说明"照抄高危向量"会把低危样本抬成高危。

## 6. 反方意见

- **I:N**（0.0）："未初始化读只影响一条规则是否命中，既不改内存也不改文件"。**回应**：它确实改变了 `file` 对同一输入的结论（判定/描述串），属"可修改且后果不受控"，取 I:L。
- **I:H**（配 A:H 会到 7.1）："`rm_len` 可被放大成越界读/错误分类，进而绕过依赖 file 结论的上传过滤"。**回应**：没有任何越界读写或分类绕过的实测；补出 PoC 即可翻案。

## 7. 可复现性

- PoC：`artifacts/verify/file-magic-php.bin`，17 字节，内容 `<?php echo 1; ?>` + 换行。
- 两次运行（`V4.file-magic-php.1065-vul.log` 与 `...-retry1...`）除 seed 与 libc 地址外输出一致，未观察 flaky。
- `artifacts/verify/result.json` 里的 `c-1`/`c-2` 是同名候选的重试记账，不是两个 PoC。

## 8. 校验

```
python3 -m pytest tests/test_severity_1065.py -q
```

该测试会：复算 CVSS 向量与 `cvss_base_score` 是否一致、把六维 evidence 里的 `文件:行` 逐条解析并检查行存在、
断言向量是 `AV:L` 且不含 `I:H`、断言 `final=false` / `human_signoff_required=true` / 没有 `_status` 草稿标记。
