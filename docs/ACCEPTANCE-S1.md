# S1 阶段验收报告（2026-11-10）

审查对象：S1「可信运行与隔离」
审查方式：代码核对 + 测试复跑 + 容器实测
结论：**S1 通过**

---

## 1. 验收标准核对

| # | 标准 | 证据 | 结果 |
|---|---|---|---|
| 1 | 故障注入 5/5 不产生 pass | `_classify_run` 将 125/126/127（docker）、137/143（资源，需 OOM 证据）、timeout、无 sanitizer 分类；`test_verify_no_falsepass` 12 项覆盖 125/137/timeout/77/无 ASAN/fix 侧 infra | ✅ |
| 2 | 空输入/harness UB 不计高危 | `test_defect_class`：harness 入口判 `harness_ub`，且 `counts_as_target_defect=False`、不能 `course_ready` | ✅ |
| 3 | 容器内 sealed 不可见 | 实测：`docker run --network none --user 1000:1000 -v workspace:/work` → `/work` 可见，`experiments/sealed-3938` 返回 No such file | ✅ |
| 4 | 越权读取被记录 | `agent/isolation.py` 的 `ReadAuditor` + `test_auditor_does_not_claim_no_read_during_run`；`test_workspace_leak_detector_finds_identical_copy` | ✅ |
| 5 | 回归 ≥210 且全过 | `pytest tests -q` → **306 passed, 6 skipped, 0 failed** | ✅ |

---

## 2. 关键实现位置

| 能力 | 位置 |
|---|---|
| 退出码分类 | `agent/stages/verify.py`：`DOCKER_EXIT_CODES={125,126,127}`、`RESOURCE_EXIT_CODES={137,143}`、`_classify_run` |
| 候选循环 | 只有 `pass` 才提前结束；`infra_error/fail_both` 继续试后续候选 |
| harness UB | `agent/stages/report.py` `_defect_class`；`tests/test_defect_class.py` |
| 隔离 | `agent/sandbox.py`：`--network none`、`--user 1000:1000`、只挂 workspace、sealed 探测 |
| 泄漏检测 | `agent/isolation.py` + `experiments/leak_scan.py`（跨任务 0 命中） |

---

## 3. 残留（不阻塞 S1，但要在 S4 前处理）

- `126/127` 未单列测试，仅由分类集合覆盖；建议补 2 条显式用例；
- 测试副作用：`test_exploit.py` 写真实 workspace 的 `p.bin`，`test_dashboard.py` 重写 `web/data.json`（P2）。

**一句话：误报路径已被代码和测试双重堵住，S1 的“通过”本身现在是可信的。**
