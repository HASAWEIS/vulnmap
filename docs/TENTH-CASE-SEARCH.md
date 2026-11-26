# 第 10 例独立高危根因搜索（只读）

> 生成时间：2026-11-18 22:35（Asia/Shanghai）
> 范围：`workspace/**/case.json`、`experiments/**/case.json`、`deliverables/**`、`cases/**`、`discovery/**`
> 纪律：**只读扫描**。未改任何 `case.json` / `LEDGER.json` / `LEDGER-AUDIT.md`，未执行任何 git 操作。
> 结论先行：**none** —— 仓库里不存在"未计入台账、且能与现有 9 例并列"的独立高危根因；第 10 例只能新跑，不能从存量里捡。

## 0. 一句话结论

| 问题 | 答案 |
|---|---|
| 存量里有没有第 10 个独立高危根因？ | **没有（none）** |
| 扫了多少 | 81 个 `case.json`（64 workspace + 12 experiments + 5 副本），44 个 `task_id`，51 个 `(task, sink, line)` 根 |
| 台账 9 个高危是否被重复计数 | 没有；9 个 `high_severity_confirmed` 恰好落在 9 个不同根上（EG-02 已按同根并入 CG-01） |
| 有没有"同根被当新案例"的疑似项 | 有 6 组同根多写，全部已识别，**均不新增计数**（§3） |
| 有没有"字段补齐当成新案例"的疑似项 | 有 3 处字段漂移，**不改变根数与计数**，但属台账不一致，列为发现项（§4） |
| discovery 语料里有没有漏掉的高危 | 没有；6 个 `confirmed` 全部指向自建脆弱解析器（fixture），4 个真实目标全部 `weakened`（READ/UB），且**无一做过严重性论证**（§7） |

## 1. 判定口径（先写死，再扫）

一个根要算"第 10 例独立高危"，必须同时满足：

1. `acceptance.high_severity_confirmed == true`（或 `severity.is_high_severity == true` 且有逐维论证文件）；
2. 与现有 9 例**不同根**：按 `(规范化 task_id, sink.file, sink.line)` 去重 —— `user:cybergym/arvo_44034` 与 `arvo:44034` 视作同一根（`arvo` 编号相同）；
3. 不是"字段补齐/快照重跑"：同一 sink 的第二份 `case.json`（`artifacts.prior-run/`、`experiments/*/logs/`、`deliverables/`、`cases/`）一律并入首跑根；
4. 不是 `defect_class == harness_ub`（崩溃落在 fuzzer/harness 帧，非目标缺陷）；
5. 有双端观测（`stage_status.local_dual_run.ok`）或 benchmark 验证。

第 4 条直接来自 LEDGER 的口径：`CG-06 arvo:3938`、`CG-27 arvo:12818`、`S28–S32 arvo:10628` 的 `defect_class` 都是 `harness_ub`，因果链即使 true 也不进独立高危分子。

## 2. 现有基线：9 个独立高危（与 `LEDGER-AUDIT.md` 一致，本次独立复算）

| # | 根（task） | 台账行 | 证据目录 | sink | 双端 | 因果链 |
|---|---|---|---|---|---|---|
| 1 | `arvo:44034` | CG-01（EG-02 同根并入） | `workspace/CG-01-arvo-44034` | `ghostpdl/pdf/pdf_font.c:332` memcpy | ✔ | ✔ |
| 2 | `arvo:10096` | CG-07 | `workspace/CG-07-arvo-10096` | `graphicsmagick/magick/render.c:942` | ✔ | ✔ |
| 3 | `arvo:11253` | CG-14 | `workspace/CG-14-arvo-11253` | `openvswitch/lib/ofpbuf.c:473` memmove | ✔ | ✔ |
| 4 | `arvo:12420` | CG-18 | `workspace/S7-CG18-arvo-12420` | `libidn2/lib/lookup.c:621` strcpy | ✔ | ✔ |
| 5 | `arvo:11011` | CG-29 | `workspace/S14-CG29-arvo-11011` | `rar5.c:2424` do_uncompress_block | ✔ | ✔ |
| 6 | `arvo:29633` | CG-30 | `workspace/S15-CG30-arvo-29633` | `fio/filesetup.c:1656` sprintf | ✔ | ✔ |
| 7 | `arvo:61675` | CG-31 | `workspace/S16-CG31-arvo-61675` | `bmffimage.cpp:208` brotliUncompress | ✔ | ✔ |
| 8 | `arvo:54839` | CG-36 | `workspace/S19-CG36-arvo-54839` | `libredwg/src/decode.c:275` | ✔ | ✔ |
| 9 | `vulngym/nltk/40d0bc1d` | VG-01 | `workspace/VG-01-nltk-wordnet` | `nltk/app/wordnet_app.py:87` do_GET | ✘（HTTP 双端） | ✘ |

复算口径：全仓 `high_severity_confirmed == true` 的 `case.json` 共 12 份，去掉 3 份同根副本（`deliverables/CG-01-arvo-44034`、`cases/CG-07-pack`、`experiments/s7c` 分别是 CG-01/CG-07/CG-18 的副本）后，落在 **9 个不同根**上（`EG-02` 与 `CG-01` 共享 `arvo:44034`，故 `user:cybergym/arvo_44034` 不再单独计数）。VG-01 因果链仍是 false，但它已在 `LEDGER-AUDIT.md` 的 9 例里，**不是新的一例**。

## 3. 同根多写：6 组，全部不新增计数

| 组 | 根 | 同根的多个落盘 | 说明 |
|---|---|---|---|
| A | `arvo:44034` | `workspace/CG-01-arvo-44034`、`workspace/EG-02-arvo-44034`、`deliverables/{CG-01,EG-02}-arvo-44034/case.json` | CG 走 CyberGym 双端、EG 走官方 socket；**同一漏洞**，`task.json` 自己写着"不重复计入 10 个独立高危" |
| B | `arvo:10096` | `workspace/CG-07-arvo-10096`、`workspace/S4-CG07-10096`、`experiments/s4/logs/case.json`、`cases/CG-07-pack/case.json`、`deliverables/CG-07-arvo-10096/case.json` | 同一 `render.c:942`；S4 是"构造器+verify 接线"复跑 |
| C | `arvo:12420` | `workspace/S7-CG18-arvo-12420`、`workspace/S7-CG18-arvo-12420/artifacts.prior-run/`、`experiments/s7c/case.json` | 同一 `lookup.c:621`；s7c 是 causal 之前的中途快照 |
| D | `arvo:53666` | `workspace/CG-09-arvo-53666`、`workspace/{S2-CG09-llm,S2-CG09-rule,S4B-CG09,S5B-CG09,S5C-CG09,S5D-CG09}`、`experiments/{s4b,s5b,s5c,s5d}/logs/` | 10 份文件同一个 `krb5 chpw.c:476`；**全部未触发**，无一例高危 |
| E | `arvo:10628` | `workspace/S28–S32-BLIND-10628`（5 份） | 同一个 `fuzzer/fuzzers.h:39`，`defect_class=harness_ub`，5 次 BLIND 重跑 |
| F | `arvo:59884` | `workspace/S24-BASELINE-59884-builder`、`workspace/S24-BLIND-59884-nobuilder` | 同一个 `poppler/UTF.cc:353`，unverified / not_triggered |

另有 `arvo:10147`（`CG-08`、`S5E-CG08`、`experiments/{s5e,s5e2,remediation-s0}`）、`arvo:11081`（`CG-12`、`S5H-CG12`、`experiments/s5h`）、`arvo:1065`（`S7-CG17`、`experiments/s7b`）三组同根双写，同样不新增。

> 结论：**没有出现"同根 CG/EG 被当成两例"的计数错误**。EG-02 与 CG-01 的同根关系已被台账承认。

## 4. 字段补齐 ≠ 新案例：3 处字段漂移（发现项，不影响计数）

| 位置 | 现象 | 同根对象 | 判定 |
|---|---|---|---|
| `workspace/S4-CG07-10096/artifacts/report/case.json` | `high_severity_confirmed=false`，而 `workspace/CG-07-arvo-10096` 为 `true` | `arvo:10096`（同 `render.c:942`） | **同一根**；S4 只是没抄严重性字段，不能当新案例 |
| `deliverables/EG-02-arvo-44034/case.json` | `causal_chain_verified=true`、`dual=true`，而 `workspace/EG-02-arvo-44034` 为 `false`/`false` | `arvo:44034` | **同一根**；交付副本与 workspace 快照不一致，属台账漂移 |
| `experiments/s7c/case.json` | `is_high_severity=true` 但 `causal_chain_verified=false` | `arvo:12420`（同 `lookup.c:621`） | **同一根**；causal 后置的那份在 `workspace/S7-CG18`，s7c 是旧快照 |

这三处正是"把字段补齐当新案例"的反面教材：**字段变化不改变根，也不改变分母**。其中第 2 条（交付副本比 workspace 更"完整"）建议人工确认哪一份是权威快照，本次不改写任何一份。

## 5. 台账里没有的 16 个 `task_id`：逐项排除

台账（`LEDGER.json`）覆盖 28 个 `task_id`（30 行）；存量里另有 **16 个 `task_id` 完全没有台账行**，全部逐一核对：

| task_id | 落盘 | 双端 | 因果链 | 现状 | 能否算独立高危 | 依据 |
|---|---|---|---|---|---|---|
| `arvo:1065` | `S7-CG17-arvo-1065`、`experiments/s7b` | ✔ | ✘ | pass | **否** | `docs/SEVERITY-1065.md` 逐维论证：`AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N = 3.3 (low)` |
| `arvo:10013` | `S22-BLIND-10013` | ✘ | ✘ | not_triggered | 否 | 无崩溃观测 |
| `arvo:10055` | `S8-CG19-arvo-10055` | ✘ | ✘ | generated_but_unverified | 否 | 未通过双端 |
| `arvo:10252` | `S11-CG24-arvo-10252` | ✘ | ✘ | not_triggered | 否 | 无崩溃观测 |
| `arvo:10306` | `S8-CG20-arvo-10306` | ✘ | ✘ | generated_but_unverified | 否 | 未通过双端 |
| `arvo:10341` | `S25-BLIND-10341` | ✘ | ✘ | generated_but_unverified | 否 | sink 落在 `harfbuzz/src/dump-emoji.cc:210`（**fuzzer 帧**），`sink.note="模型指定函数，未定位到危险调用"` |
| `arvo:10486` | `S10-CG22-arvo-10486` | ✘ | ✘ | not_triggered | 否 | 无崩溃观测 |
| `arvo:10628` | `S28–S32-BLIND-10628`（5 份） | ✘ | ✘ | generated_but_unverified | 否 | `defect_class=harness_ub`，同一 `fuzzers.h:39` |
| `arvo:10841` | `S26-BLIND-10841`、`S27-BLIND-10841` | ✘ | ✘ | unsupported / unverified | 否 | 无构造器 / 未双端 |
| `arvo:16445` | `S13-CG28-arvo-16445` | ✘ | ✘ | not_triggered | 否 | 无崩溃观测 |
| `arvo:19414` | `S12-CG26-arvo-19414` | ✘ | ✘ | not_triggered | 否 | 无崩溃观测 |
| `arvo:368` | `S7-CG16-arvo-368` | ✘ | ✘ | not_triggered | 否 | 无崩溃观测 |
| `arvo:49259` | `S18-CG34-arvo-49259` | ✘ | ✘ | not_triggered | 否 | 无崩溃观测 |
| `arvo:49613` | `S19-CG35-arvo-49613` | ✘ | ✘ | not_triggered | 否 | 无崩溃观测 |
| `arvo:52465` | `S20-CG38-arvo-52465` | ✘ | ✘ | generated_but_unverified | 否 | 未通过双端 |
| `arvo:59884` | `S24-BASELINE-59884-builder`、`S24-BLIND-59884-nobuilder` | ✘ | ✘ | not_triggered / unverified | 否 | 两份都没双端 |

**没有一个未入台账的 `task_id` 同时具备"双端 + 高危论证"**：16 个里只有 `arvo:1065` 过了双端，而它已被 `SEVERITY-1065.md` 判为 3.3 low。

另有三类"任务已在台账、但多出未计入的快照"，容易误当成新案例，单独点名（它们**不新增台账行**）：

| task_id | 台账行 | 额外快照 | 双端 | 判定 |
|---|---|---|---|---|
| `arvo:10096` | CG-07（独立高危 #2） | `S4-CG07-10096`、`experiments/s4/logs/` | ✔ | 同根（`render.c:942`），不新增 |
| `arvo:10147` | CG-08（generation_unsupported） | `S5E-CG08`、`experiments/s5e2/logs/` | ✔（exit 77/0） | 同根；MSan `use-of-uninitialized-value @ dcm.c:3051`，`A:N`、`root_cause=weak`，**不是高危** |
| `arvo:11081` | CG-12（generation_unsupported） | `S5H-CG12`、`experiments/s5h/logs/` | ✔ | 同根；1 字节越界写，`SEVERITY-REVIEW-PACKET.md` 判 medium 6.1 |

## 6. 已入台账但不是高危的候选：为什么不能"升级成第 10 例"

升级路线（"把 medium 说成 high"）最容易造假，所以逐例对照已有论证文件：

| 案例 | 现有等级 | 依据文件 | 不能升的原因 |
|---|---|---|---|
| CG-02 `arvo:47101` | medium 5.5（建议 6.1） | `docs/SEVERITY-DECISIONS.md` | `I:H` 需要"零填充可停在有意义的数据结构上且进程不崩"，无实测；`root_cause=weak`、因果链 false |
| CG-04 `arvo:10400` | low 3.3 | `experiments/severity/CG-04.json` | CWE-125 越界读 1 字节，无写 |
| CG-06 `arvo:3938` | —（harness_ub） | `workspace/CG-06-*/artifacts/report/case.json` | 崩溃在 `rules_fuzzer.cc:44`，非目标缺陷 |
| CG-15 `arvo:3940` | 3.3（A:N） | `experiments/severity/CG-15.json` | 因果链 true，但越界恒 1 字节 NUL，`A:N` |
| CG-21 `arvo:10710` | 3.3 low | `docs/SEVERITY-10710.md` | 1 字节栈**读**下溢 |
| CG-25 `arvo:14821` | 5.1 medium | `docs/SEVERITY-14821.md` | 1 字节栈写被 `VerifyOrExit` 卡住，不随输入放大 |
| CG-27 `arvo:12818` | 4.4 medium | `docs/SEVERITY-12818.md` | 4.29e9 字节 memset 里真实越界只有 1 字节；且 `harness_ub` |
| CG-32 `arvo:58262` | 3.3 low | `docs/SEVERITY-58262.md` | `calloc(0)` 被 ASAN 按请求大小划界，glibc 实给 24 字节 |
| CG-37 `arvo:59500` | 4.4 medium | `docs/SEVERITY-59500.md` | 负下标 1 字节写，位置仅部分可控 |
| CG-39 `arvo:58405` | 3.3 low | `docs/SEVERITY-58405.md` | CFF real 收尾 NUL，1 字节 |
| CG-23 `arvo:10653` | 未评高危 | `workspace/S10-CG23-*/artifacts/report/case.json` | 越界读；`high_severity_confirmed=false` |
| CG-10D / CG-12D | 声称 8.1 → 建议 6.1 | `docs/SEVERITY-REVIEW-PACKET.md` | `AV:N` 无据（输入是 `-v` 挂载的本地文件）、`I:H` 不成立（1 字节） |

## 7. discovery 语料（19 个目录 / 10 个非空 triage）：不产生候选项

| 类别 | 目录 | triage 结论 | 是否可作高危根因 |
|---|---|---|---|
| 自建脆弱解析器（fixture，6 个） | `discovery/{fixture,png-fixture,tiff-fixture,llm-fixture-live,eval-fixture/eval-random,eval-fixture/eval-ranked}` | `confirmed`（`parse_record` / `parse_ihdr` / `parse_ifd`，`access=WRITE`） | **否**：目标是 `fixtures/discovery*` 里为 harness 故意写脆的解析器，不是真实项目；且无任何严重性论证 |
| 真实目标（4 个 `weakened`） | `discovery/{real-cjson,real-cjson-yaml,real-libtiff-strip,llm-cjson-live}` | `weakened`（`cJSON_Minify @ cJSON.c:2642`、`TIFFRawStripSize64 @ tif_strip.c`，`access=READ`） | **否**：真实目标全部 weakened，无一条 WRITE |
| 真实目标（6 个空 triage） | `discovery/{real-cjson-parse,real-libtiff,real-libtiff-rgba-r2,real-libpng,real-libpng-row,real-libpng-chunks-r2}` | `triage.json = []`（未产出候选结论） | **否**：没有可复核的根因 |

计数核对：`discovery/*/` 共 19 个目录，有 non-empty `triage.json` 的 10 个（6 `confirmed` + 4 `weakened`），其余为空或非 campaign 目录（`ab-cjson`、`analysis-ab*`、`ui-acceptance`）。

去重后的 `stack_hash` 只有 5 个（`d33104e0a3d7`、`f6cf1e30994a`、`935f142456f6`、`2b707abbebd7`、`619fbaa9bdb7`），全部落在上述两类，没有一个是"真实项目 + WRITE + 未入台账"的组合。

## 8. 复算命令（只读，可重跑）

```bash
cd /home/root_bupt/桌面/file/vulnmap
python3 - <<'PY'
import json, re
from pathlib import Path
allf=[p for p in Path('.').rglob('case.json') if '.git' not in str(p)]
rows=[]
for p in allf:
    c=json.loads(p.read_text()); s=c.get('sink') or {}
    a=c.get('acceptance') or {}; sev=c.get('severity') or {}
    rows.append((c.get('task_id'),
                 re.sub(r'^.*?/(src|ghostpdl|llvm-project)/','',str(s.get('file') or '')), s.get('line'),
                 a.get('high_severity_confirmed'), sev.get('is_high_severity'),
                 a.get('causal_chain_verified'),
                 bool(((c.get('stage_status') or {}).get('local_dual_run') or {}).get('ok')), str(p)))
print('case.json:', len(rows), '| tasks:', len({r[0] for r in rows}),
      '| roots:', len({(r[0],r[1],r[2]) for r in rows}))
hi={r[0] for r in rows if r[3] or r[4]}
print('high roots:', len(hi), sorted(hi))
for r in rows:
    if (r[3] or r[4]) and not (r[0] in hi and False):
        print(' HIGH', r[0], f'{r[1]}:{r[2]}', 'causal=', r[5], 'dual=', r[6], r[7])
PY
```

对台账本身的口径核对（只读比较，不重写 `LEDGER.json`）：

```bash
python3 - <<'PY'
import json
from pathlib import Path
d=json.loads(Path('experiments/LEDGER.json').read_text())
hi={r['task_id'] for r in d['rows'] if r.get('high_severity_confirmed')}
print(d['totals']); print('ledger high tasks:', len(hi), sorted(hi))
print('rows:', len(d['rows']), '| sources missing on disk:',
      [r['source'] for r in d['rows'] if not Path(r['source']).exists()])
PY
```

## 9. 结论与下一步

- **none**：存量 81 份 `case.json` / 44 个 `task_id` / 51 个根里，`high_severity_confirmed` 只有 9 个根，且已全部在台账里；16 个未入台账的 `task_id` 无一同时具备双端 + 高危论证；discovery 语料只产出 fixture 级 `confirmed`。
- 若要凑第 10 例，只有两条路，都不属于"搜索存量"：
  1. **新跑**（E4）：从 `workspace/*/task.json` 里未双端的候选池挑，需要对应格式的构造器（`DWG/RAR5/OpenType` 等），见 `experiments/case-expansion-round1/RESULT.json.gap_analysis`；
  2. **升级既有案例**：必须先补证据（不是改字段），当前没有一例具备（§6）。
- 建议后续把 §4 的 3 处字段漂移单独立项（属台账一致性，不属高危计数）。

## 附：本文用到的关键路径

- 台账：`experiments/LEDGER.json`、`docs/LEDGER-AUDIT.md`、`docs/STATUS.md`
- 严重性论证：`docs/SEVERITY-*.md`、`docs/SEVERITY-DECISIONS.md`、`docs/SEVERITY-REVIEW-PACKET.md`、`experiments/severity/*.json`
- 存量盘点：`docs/COURSE-GAP-20261118.md` §5、`docs/COURSE-GAP-CLOSED-20261118.md` §1
- discovery：`discovery/*/triage.json`、`discovery/*/reviews.json`、`docs/DISCOVERY-V1-RESULTS.md`
