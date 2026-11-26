# scripts/

`ci.sh` is the offline local CI entrypoint (run from any cwd): `compile -> tests -> campaign`.

Env toggles: `PYTHON`, `ISO=auto|unshare|bwrap|none`, `REQUIRE_ISO=1`, `SKIP_TESTS=1`, `SKIP_CAMPAIGN=1`, `KEEP=1` (keep temp dir); guard: min 30 tests.
No network or API key is used: `DISCOVERY_LLM_DISABLED=1` is exported for the whole run.

`serve-platform.sh` 启停本地平台后端（uvicorn，默认 `127.0.0.1:8102`）：

```bash
./scripts/serve-platform.sh start|stop|restart|status
PORT=8103 PLATFORM_ROOT=/tmp/vm-platform ./scripts/serve-platform.sh start   # 端口/DB 可配
```

`setsid`+`nohup` 后台常驻，PID/日志在 `.platform/run/serve-<PORT>.{pid,log}`；
端口被别的进程占用时只报告占用者（退出码 75），不杀无关服务。详见 `docs/DEPLOY-8102.md`。

`check_course_metrics.py` 只读校验新版仪表盘的三张课程卡片（`5/8 · 0/8 · 0/8`）与
`experiments/course-review-*/` 的 judgments/summary、`workspace/<case>/artifacts/report/case.json`
的 `acceptance.course_ready` 是否一致：81 条断言，一致退出 0，不一致退出 2 并逐条 `FAIL [CODE]`，
找不到 `dashboard.js`/快照不可解析退出 3。不改任何数字，详见
`docs/COURSE-METRICS-CONSISTENCY.md`。

```bash
python3 scripts/check_course_metrics.py          # 全量
python3 scripts/check_course_metrics.py --quiet  # 只打印结论与失败项
python3 scripts/check_course_metrics.py --json   # 机读
```
