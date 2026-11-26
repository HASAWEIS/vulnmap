"""V2 P2 fuzz 执行器：包装 Discovery D2（构建 harness + run_parallel + 覆盖率）。

输入：Plan（target_yaml 或 workspace benchmark）、ProgramIndex、假设集；
输出：候选原始记录（崩溃输入、ASAN 日志、栈哈希、证据哈希）+ 覆盖率/执行统计。

边界：
- 不重写 Discovery：构建用 `covfuzz.build`，并行 fuzz 用 `covfuzz.run_parallel`，
  覆盖率归属用 `covfuzz.attribute_coverage`，崩溃解析用 `triage.parse_log`；
- 不判定可利用性：崩溃只标 crash_type / stack_hash，结论留给 P3 独立验证；
- 构建失败、隔离里目标起不来（setup_error）都抛 `FuzzExecError`，由编排层落 FAILED，
  不能把“没跑起来”记成 negative result。

V3 P1（V3-003 / V3-004）：
- `_seed_pool()` 显式接 `hypotheses`：按 site_id 匹配后把假设传给
  `agents.propose_seeds(..., hypothesis=hyp)`，每条 seed 记
  `hypothesis_id / site_id / source`；匹配失败写明 reason 并回退规则种子，
  不再默默只取前 3 个调用点；
- 语料落到 `adaptive.corpus.CorpusStore`（task/campaign 维度、跨轮复用、
  manifest 可反查父假设），构建身份（binary sha256 + build spec）变化时
  旧代语料标记 stale 并整体归档重建，不混用；
- 执行结果带 `build_id` 与 `corpus.before / corpus.after`，不再每轮丢语料。
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

from ...discovery import agents, covfuzz, profile as d0, targetspec, triage
from ...discovery import campaign as d2campaign
from ..adaptive import corpus as corpus_mod

MAX_SEEDS = 24
MAX_CRASHES = 16

#: P3.6：单次 run_parallel 的时长上限（秒）。长跑被切成若干片，片上做预算/取消判定，
#: 这样 max_seconds / max_execs / 取消信号不必等整段跑完才生效。
SLICE_SECONDS = 5.0

#: 跨片累加的统计键（aggregate() 每次只覆盖 stats 目录里本片的 w*.json）
SUM_STATS_KEYS = ("execs", "crashes", "timeouts", "new_coverage_bits",
                  "setup_errors")


class FuzzExecError(RuntimeError):
    """执行器失败（构建/运行环境/输入缺失），必须落 FAILED 而不是 NO_REPRO。"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _format_hint(index) -> str:
    for fmt in list(getattr(index, "formats", []) or []):
        if fmt and fmt != "unknown":
            return str(fmt)
    return "unknown"


def _target_path(plan: dict) -> Path:
    inputs = plan.get("inputs") or {}
    target = str(inputs.get("target") or plan.get("target") or "")
    if not target or target.startswith(("http://", "https://")):
        raise FuzzExecError(
            f"fuzz executor needs a local target, got {target!r}")
    return Path(target)


def resolve_build_spec(plan: dict, index, workdir: Path) -> dict:
    """target.yaml 优先；CG/EG workspace 用 Discovery 的构建探测。"""
    workdir = Path(workdir)
    inputs = plan.get("inputs") or {}
    yaml_path = str(inputs.get("target_yaml") or "")
    if yaml_path and Path(yaml_path).is_file():
        spec = targetspec.load(Path(yaml_path))
        return targetspec.to_build_spec(spec, workdir)

    target = _target_path(plan)
    benchmark = str(plan.get("benchmark") or "")
    if benchmark in ("cybergym", "exploitgym") and target.is_dir():
        prof = d0.scan(target)
        spec = d2campaign.detect_build(target, prof)
        spec["workdir"] = workdir
        return spec
    raise FuzzExecError(
        f"no buildable spec for {benchmark} target {target}: "
        "target.yaml missing and workspace build cannot be detected")


def _seed_pool(index, root: Path | None, fmt: str,
               hypotheses: list[dict] | None = None) -> dict:
    """假设驱动的规则种子（不调 LLM），每条种子带可反查的归属。

    顺序：**假设优先**（按假设集顺序，site_id 命中 → 用该调用点 + 假设文本），
    匹配不上的假设显式记 reason 并回退规则种子（仍绑在它自己的 hypothesis_id 上），
    再用**其余全部调用点**的规则种子补足到 `MAX_SEEDS`。补不进去的调用点
    逐个记入 `sites_skipped_cap`，不再默默只取前 3 个点。

    返回 `{"records": [...], "report": {...}}`，record 字段：
    `data / sha256 / hypothesis_id / site_id / source / origin / basis`。
    """
    sites = [dict(s) for s in (getattr(index, "call_sites", []) or [])]
    by_site_id = {str(s.get("id")): s for s in sites if s.get("id")}
    records: list[dict] = []
    by_digest: dict[str, dict] = {}
    report = {
        "policy": "hypothesis-first+rule-fill",
        "format": fmt,
        "hypotheses": len(hypotheses or []),
        "sites_total": len(sites),
        "matched": [],
        "unmatched": [],
        "sites_used": [],
        "sites_without_seeds": [],
        "sites_skipped_cap": [],
        "duplicates": 0,
        "dropped_by_cap": 0,
        "capped": False,
        "fallback_rule": False,
    }

    def emit(data: bytes, *, hypothesis_id: str = "", site_id: str = "",
             source: str = "", origin: str, basis: list[str] | None = None) -> None:
        if not data:
            return
        digest = _sha256(data)
        if digest in by_digest:
            report["duplicates"] += 1
            existing = by_digest[digest]
            extra = source or origin
            if extra not in existing["sources"]:
                existing["sources"].append(extra)
            return
        if len(records) >= MAX_SEEDS:
            report["capped"] = True
            report["dropped_by_cap"] += 1
            return
        record = {
            "data": data,
            "sha256": digest,
            "hypothesis_id": str(hypothesis_id or ""),
            "site_id": str(site_id or ""),
            "source": str(source or origin),
            "origin": str(origin),
            "basis": list(basis or []),
            "sources": [str(source or origin)],
        }
        records.append(record)
        by_digest[digest] = record

    for pos, hyp in enumerate(list(hypotheses or [])):
        if not isinstance(hyp, dict):
            continue
        hid = str(hyp.get("id") or hyp.get("hypothesis_id")
                  or f"H{pos + 1}")
        sid = str(hyp.get("site_id") or "")
        site = by_site_id.get(sid) if sid else None
        before = len(records)
        entry: dict = {"hypothesis_id": hid, "site_id": sid}
        if site is None:
            reason = ("hypothesis.site_id is empty (anchor/entry-point "
                      "hypothesis has no call site)"
                      if not sid else
                      f"site_id {sid!r} not found in ProgramIndex.call_sites")
            entry.update({"reason": reason,
                          "fallback": "rule:generic+hypothesis_text"})
            report["unmatched"].append(entry)
            seeds = agents.propose_seeds({}, root, fmt, hypothesis=hyp)
            origin = "rule_fallback"
            site_id_used = sid
        else:
            entry["category"] = site.get("category", "")
            report["matched"].append(entry)
            report["sites_used"].append(sid)
            seeds = agents.propose_seeds(site, root, fmt, hypothesis=hyp)
            origin = "hypothesis"
            site_id_used = sid
        for data in seeds:
            emit(data, hypothesis_id=hid, site_id=site_id_used,
                 source=f"hypothesis:{hid}", origin=origin,
                 basis=agents.seed_basis(hyp))
        entry["seeds"] = len(records) - before
        entry["origin"] = origin

    # 规则补足：其余调用点全部参与（顺序即 ProgramIndex 顺序，确定性）
    used_ids = set(report["sites_used"])
    for site in sites:
        sid = str(site.get("id") or "")
        if sid and sid in used_ids:
            continue
        if len(records) >= MAX_SEEDS:
            report["capped"] = True
            report["sites_skipped_cap"].append(sid)
            continue
        seeds = agents.propose_seeds(site, root, fmt)
        if not seeds:
            report["sites_without_seeds"].append(sid)
            continue
        before = len(records)
        for data in seeds:
            emit(data, site_id=sid, source=f"rule:site:{sid}",
                 origin="rule")
        if len(records) > before:
            report["sites_used"].append(sid)

    if not records:
        # 连规则种子都没有：通用种子兜底（仍然显式记账，不当成“有假设输入”）
        report["fallback_rule"] = True
        for data in agents.propose_seeds({}, root, fmt):
            emit(data, source="rule:generic", origin="rule_generic")

    report["seeds"] = len(records)
    return {"records": records, "report": report}


def _dictionary(index, root: Path | None, hypotheses: list[dict]) -> list[bytes]:
    paths = []
    for rel in {str(s.get("file") or "") for s in
                (getattr(index, "call_sites", []) or [])}:
        if not rel or root is None:
            continue
        path = Path(root) / rel
        if path.is_file():
            paths.append(path)
    tokens = covfuzz.dictionary_from_sources(paths[:8])
    for hyp in (hypotheses or [])[:8]:
        tokens.extend(covfuzz.dictionary_from_source(str(hyp.get("window") or "")))
    return covfuzz.merge_dictionary(tokens)


def _collect_crashes(crash_dir: Path) -> list[dict]:
    """读 crash-<digest>.bin/.log，按 D3 口径解析并去重（同 stack_hash 留一条）。"""
    records: list[dict] = []
    seen: set[str] = set()
    for path in sorted(Path(crash_dir).glob("crash-*.bin")):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        log_path = path.with_suffix(".log")
        try:
            log = log_path.read_text(errors="ignore") if log_path.exists() else ""
        except OSError:
            log = ""
        parsed = triage.parse_log(log)
        stack = triage.stack_hash(parsed)
        if stack in seen:
            continue
        seen.add(stack)
        records.append({
            "input_sha256": _sha256(data),
            "input_bytes": data,
            "input_path": str(path),
            "log": log[-8000:],
            "log_path": str(log_path) if log_path.exists() else "",
            "parsed": parsed,
            "crash_type": parsed.get("crash_type") or "unknown",
            "stack_hash": stack,
            "access": parsed.get("access"),
            # D3 诊断门禁：无效诊断（未知类型/缺失根因帧）不能升为正常候选
            "diagnostic_valid": triage.valid_diagnostic(parsed),
        })
        if len(records) >= MAX_CRASHES:
            break
    records.sort(key=lambda c: (c["stack_hash"], c["input_sha256"]))
    return records


def _empty_stats() -> dict:
    return {
        "execs": 0, "crashes": 0, "timeouts": 0, "new_coverage_bits": 0,
        "setup_errors": 0, "setup_error": None, "workers": 0,
        "first_crash_seconds": None, "crash_files": 0, "corpus_files": 0,
        "per_worker": [], "slices": 0, "stopped": "",
    }


def _merge_stats(acc: dict, part: dict) -> dict:
    """把一片的 aggregate() 结果累加进总账（累加型求和，瞬时型取最新）。"""
    for key in SUM_STATS_KEYS:
        acc[key] = int(acc.get(key) or 0) + int(part.get(key) or 0)
    if part.get("setup_error"):
        acc["setup_error"] = part["setup_error"]
    first = part.get("first_crash_seconds")
    if first is not None:
        acc["first_crash_seconds"] = (
            first if acc.get("first_crash_seconds") is None
            else min(acc["first_crash_seconds"], first))
    for key in ("workers", "crash_files", "corpus_files", "per_worker"):
        if part.get(key) is not None:
            acc[key] = part[key]
    return acc


def _run_slices(binary, corpus_dir: Path, crash_dir: Path, stats_dir: Path, *,
                seconds: float, workers: int, timeout: float, fmt: str,
                isolation: str, require_isolation: bool,
                dictionary: list[bytes], max_execs: int | None = None,
                deadline: float | None = None, should_stop=None,
                max_slice: float = SLICE_SECONDS) -> dict:
    """分片跑 D2：每片后按 fuzz stats / 耗时 / 取消信号决定是否继续。

    `stopped` 取值：

    - `completed`：片预算跑完（正常收工）；
    - `workers_exited`：worker 提前退出（崩溃即停/abort/启动失败）——
      与 P2 单次 `run_parallel` 的语义一致，本轮到此为止，不再开新片；
    - `deadline`：`max_seconds` 到点；
    - `execs`：`max_execs` 到量；
    - `cancelled`：`should_stop()` 命中（任务已被取消）。
    """
    acc = _empty_stats()
    remaining = float(seconds)
    stopped = "completed"
    while True:
        if should_stop is not None and should_stop():
            stopped = "cancelled"
            break
        allowance = remaining
        if deadline is not None:
            allowance = min(allowance, deadline - time.monotonic())
        span = allowance if max_slice is None else min(float(max_slice), allowance)
        if span <= 0:
            stopped = "deadline" if deadline is not None else "completed"
            break
        slice_start = time.monotonic()
        part = covfuzz.run_parallel(
            binary, corpus_dir, crash_dir, stats_dir,
            seconds=span, workers=workers, timeout=timeout, fmt=fmt,
            isolation=isolation, require_isolation=require_isolation,
            dictionary=dictionary)
        _merge_stats(acc, part)
        acc["slices"] = int(acc["slices"]) + 1
        slice_elapsed = max(0.0, time.monotonic() - slice_start)
        remaining -= slice_elapsed
        if max_execs is not None and int(acc["execs"]) >= int(max_execs):
            stopped = "execs"
            break
        if deadline is not None and time.monotonic() >= deadline:
            stopped = "deadline"
            break
        if slice_elapsed < span * 0.5:
            # worker 提前收工（崩溃即停 / abort / 起不来）：本轮已到终点，
            # 不再开新片——保持 P2 “一次 run_parallel 就是一轮”的语义
            stopped = "workers_exited"
            break
        if remaining <= 0:
            stopped = "completed"
            break
    acc["stopped"] = stopped
    return acc


def _fresh_dir(path: Path) -> Path:
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def execute(plan: dict, index, hypotheses: list[dict], *, workdir: Path,
            seconds: float | None = None, workers: int | None = None,
            timeout: float | None = None, isolation: str = "auto",
            require_isolation: bool = False, max_execs: int | None = None,
            deadline: float | None = None, should_stop=None,
            max_slice: float = SLICE_SECONDS, task_id: str = "",
            campaign: str = "", corpus_root: Path | None = None) -> dict:
    """跑一次 D2：构建 → 种子/字典 → 并行 fuzz（分片）→ 覆盖率 → 收集崩溃。

    P3.6 新增执行中控制：`max_execs` 是本次执行允许的 exec 数上限（跨片累加），
    `deadline` 是单调时钟截止点，`should_stop()` 是取消探针（读状态机）。
    三者都在**片边界**生效，触发后不再开新片，已产生的崩溃照常收集。

    V3 P1：`task_id/campaign/corpus_root` 只决定持久语料的落盘位置
    （缺省从 workdir 推导，`<db>/work/<task>` 天然是 task 维度），
    调用方无需改签名；语料与 manifest 跨轮复用，结果里带
    `build_id` 与 `corpus.before / corpus.after`。
    """
    started = time.time()
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    budget = plan.get("budget") or {}
    eff_seconds = float(seconds if seconds is not None else budget.get("seconds") or 5.0)
    eff_workers = int(workers if workers is not None else budget.get("workers") or 2)
    eff_timeout = float(timeout if timeout is not None else budget.get("timeout") or 2.0)
    if eff_seconds <= 0 or eff_workers <= 0 or eff_timeout <= 0:
        raise FuzzExecError(
            f"invalid budget: seconds={eff_seconds} workers={eff_workers} "
            f"timeout={eff_timeout}")

    root = Path(index.root) if getattr(index, "root", "") else None
    if root is not None and not root.exists():
        root = None
    fmt = _format_hint(index)

    build_dir = _fresh_dir(workdir / "build")
    crash_dir = _fresh_dir(workdir / "crashes")
    stats_dir = _fresh_dir(workdir / "stats")
    covwork = _fresh_dir(workdir / "covwork")

    spec = resolve_build_spec(plan, index, build_dir)
    try:
        build = covfuzz.build(**spec)
    except Exception as exc:  # noqa: BLE001 - 构建失败必须显式落 FAILED
        raise FuzzExecError(f"build failed: {type(exc).__name__}: {exc}") from exc

    identity = corpus_mod.build_identity(
        spec, binary_sha256=str(build.get("sha256") or ""),
        harness=str(build.get("harness") or ""),
        target=str(spec.get("target") or plan.get("target") or ""))
    store = corpus_mod.CorpusStore(
        corpus_root if corpus_root is not None else (workdir / "corpus"),
        task_id=task_id or workdir.name,
        campaign=campaign or str(plan.get("benchmark") or ""))
    try:
        corpus_state = store.begin(identity)
    except corpus_mod.CorpusError as exc:
        raise FuzzExecError(f"corpus unavailable: {exc}") from exc

    pool = _seed_pool(index, root, fmt, hypotheses)
    for record in pool["records"]:
        store.add(record["data"],
                  hypothesis_id=record["hypothesis_id"],
                  site_id=record["site_id"],
                  source=record["source"],
                  origin=record["origin"],
                  format=fmt,
                  basis=record["basis"])
    seeds = [record["data"] for record in pool["records"]]
    # 种子先落盘：即使本轮跑崩，manifest 里的父假设归属也是既成事实
    store.finalize()
    dict_tokens = _dictionary(index, root, hypotheses)
    (workdir / "dictionary.json").write_text(
        json.dumps([t.decode("utf-8", "backslashreplace") for t in dict_tokens],
                   ensure_ascii=False, indent=2) + "\n")
    (workdir / "corpus_lineage.json").write_text(
        json.dumps(store.lineage(limit=0), ensure_ascii=False, indent=2) + "\n")

    try:
        stats = _run_slices(
            build["binary"], store.active_dir, crash_dir, stats_dir,
            seconds=eff_seconds, workers=eff_workers, timeout=eff_timeout,
            fmt=fmt, isolation=isolation, require_isolation=require_isolation,
            dictionary=dict_tokens, max_execs=max_execs, deadline=deadline,
            should_stop=should_stop, max_slice=max_slice)
    except Exception as exc:  # noqa: BLE001 - 隔离器/运行期错误不是负结果
        raise FuzzExecError(f"fuzz run failed: {type(exc).__name__}: {exc}") from exc

    crashes = _collect_crashes(crash_dir)
    # fuzz 自己写进 active 的新语料也要进台账（无父假设，来源=fuzzer）
    discovered = store.discover()
    corpus_after = store.finalize()
    if (not crashes and stats.get("setup_error")
            and stats.get("new_coverage_bits", 0) == 0
            and stats.get("stopped") not in ("cancelled", "deadline", "execs")):
        raise FuzzExecError(
            "target never started in isolation: "
            f"{stats.get('setup_error')}")

    coverage = _coverage(build["binary"], store.active_dir, covwork, index,
                         root, isolation, require_isolation)
    return {
        "ok": True,
        "format": fmt,
        "seconds": round(time.time() - started, 2),
        "budget": {"seconds": eff_seconds, "workers": eff_workers,
                   "timeout": eff_timeout},
        "build": {"binary": build.get("binary"), "sha256": build.get("sha256"),
                  "cmd": list(build.get("cmd") or []),
                  "harness": build.get("harness"),
                  "build_id": identity["build_id"],
                  "identity": identity},
        "build_id": identity["build_id"],
        "seeds": len(seeds),
        "seed_pool": pool["report"],
        "corpus": {
            "store": str(store.root),
            "active": str(store.active_dir),
            "manifest": str(store.manifest_path),
            "task_id": store.task_id,
            "campaign": store.campaign,
            "generation": corpus_state["generation"],
            "status": corpus_state["status"],
            "stale": corpus_state["stale"],
            "stale_reasons": corpus_state["reasons"],
            "before": corpus_state["corpus_before"],
            "previous": corpus_state.get("previous"),
            "after": corpus_after,
            "discovered": len(discovered),
            "lineage": store.lineage(limit=len(pool["records"]) * 4
                                     or MAX_SEEDS),
        },
        "dictionary_tokens": len(dict_tokens),
        "stats": stats,
        "coverage": coverage,
        "crashes": crashes,
        "paths": {"workdir": str(workdir), "corpus": str(store.active_dir),
                  "corpus_store": str(store.root),
                  "corpus_manifest": str(store.manifest_path),
                  "crashes": str(crash_dir), "stats": str(stats_dir)},
    }


def _coverage(binary: str, corpus_dir: Path, covwork: Path, index,
              root: Path | None, isolation: str,
              require_isolation: bool) -> dict:
    """覆盖率归属是增强证据：失败时如实记录 error，不吞掉已产生的候选。"""
    sites = [dict(s) for s in (getattr(index, "call_sites", []) or [])]
    ledger = {"sites": sites, "planned": len(sites), "covered": 0,
              "uncovered": len(sites), "status": "partial" if sites else "complete"}
    try:
        cov = covfuzz.attribute_coverage(
            binary, corpus_dir, ledger, root or Path("."), covwork,
            isolation=isolation, require_isolation=require_isolation)
        return cov
    except Exception as exc:  # noqa: BLE001 - 覆盖率失败不改变候选事实
        return {
            "planned": len(sites), "covered": 0, "uncovered": len(sites),
            "status": "unavailable", "pcs": 0, "mapped_locations": 0,
            "mapped_functions": 0, "function_level_only": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }
