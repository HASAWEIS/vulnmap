r"""V3 第 2 周回归：配置白名单变更 + **实际加载版本**（`docs/V3-W2-CONFIG.md` §6）。

口径（唯一出处是文档，这里不另立一套）：

1. **白名单只放行两种变更**（§1.2）：切换目录里**已有**的样例、启用**已有**的
   观测点。`target.py` / `runner.py` / `config/samples.json` /
   `config/observation_points.json` / `samples/*.txt` 一律不可写；`stage()` 里写
   `config/active.json` 之外的路径 → `config_path_not_whitelisted`，绕过 `stage()`
   直接改 `current/` → `commit()` 的差异守卫 `config_source_edit_forbidden`。
   原件（origin，0444）哈希全程不变。
2. **计划版本不能冒充实际加载版本**（§2）：`planned` 只来自 revision 侧，
   `loaded` 只来自执行器回报；`loaded` 缺失一律 `unknown`，**绝不回填 planned**。
3. **「配置改了」≠「配置生效了」**（§5.3）：`--stale-config` 真跑出
   `not_effective` → 控制器 `blocked/config_not_effective`、不写采纳、不产生
   verification、工作树回退到父 revision；`unknown` 支线是 `config_unverified`。

夹具 `tests/fixtures_config/` 全是**真跑**的（真 `subprocess.run`）：

| 文件 | 作用 |
|---|---|
| `config/samples.json` / `config/observation_points.json` | 两个原件目录（样例 alpha/beta/gamma；观测点 input_processed/guard） |
| `config/active.json` | 唯一可写文件：当前样例 + 启用的观测点 |
| `samples/alpha.txt` | 合法头 `VMAP1`、无 `GUARD` → 处理过、检查点 false |
| `samples/beta.txt` | 坏 magic `VMAP0` → 目标侧不处理输入（smoke 真失败） |
| `samples/gamma.txt` | 合法头 + `GUARD token=deadbeef` → 检查点 true |
| `target.py` | 无害解析器：按启用的观测点写 JSONL 探针（本身也是「禁止改」的对照物） |
| `runner.py` | 执行器：读它**真的**加载的那份配置 → 用 `config_file_sha256` 算 `loaded_config_sha256` → 子进程跑 `target.py` → 报事实 JSON |

四组（§6 表格）：

| 组 | 用例 | 断言要点 |
|---|---|---|
| 白名单拒绝 | `test_whitelist_rejects_source_edits` / `test_whitelist_rejects_unknown_ids` / `test_generator_mode_keeps_week1_behaviour` | 源码/目录/样例 → `config_path_not_whitelisted`；造 id → `unknown_sample`/`unknown_observation_point`；改 schema/加键 → `config_field_not_whitelisted`；原件哈希不变 |
| 实际加载版本 | `test_loaded_version_is_reported_not_planned` / `test_unreported_load_is_unknown_not_planned` | `loaded == planned` → `effective`；**没报** → `unknown`（`config_effective is None`，不是 False，也不回填 planned） |
| 未生效反例 | `test_stale_load_is_not_effective` | `--stale-config` 真跑 → `not_effective`；`adoptions.jsonl` 无新增、无 verification、`stop_reason=="config_not_effective"`、`status=="blocked"`、工作树回退 |
| 回退哈希/行为 | `test_baseline_modify_revert_restores_hash_and_behavior` / `test_bad_magic_sample_fails_smoke_on_target_side` | 配置哈希、`working_manifest()`、真跑行为（`checkpoint_reached`/`probe_hits`）三者都回到 baseline；revision 3 条且 `reverted_to` 指回被回退的 revision |
| 控制器自己提议（§5.2/§5.3 的端到端） | `test_controller_proposes_and_lands_whitelisted_config_change` / `test_config_mode_rejects_plan_that_edits_source` | ConfigRole 的 `RevisionPlan` 经 `workspace.stage()` 落地成 `tool="config_editor"` 的 revision（`changed_against==("config/active.json",)`），真跑回报 `effective`；同一条流程改成"执行器不报"→ `config_unverified`；把配置变更提成源码变更 → STAGE 就被 `config_path_not_whitelisted` 拒绝，一条 revision 都不新增 |
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform.adaptive.controller import ResearchController  # noqa: E402
from agent.platform.adaptive.policy import AdoptionPolicy          # noqa: E402
from agent.platform.adaptive.revision import (ConfigEffectRecord,  # noqa: E402
                                             RevisionError)
from agent.platform.adaptive.session import (ContextRole,          # noqa: E402
                                             DiagnoseRole,
                                             ResearchSession, RevisionPlan)
from agent.platform.adaptive.tools import (build_registry,        # noqa: E402
                                           make_binding)
from agent.platform.adaptive.snapshot import (                     # noqa: E402
    TrustedExecutionSnapshot)
from agent.platform.adaptive.workspace import (TaskWorkspace,      # noqa: E402
                                              WorkspaceError)
from agent.platform.executors import (config_doc_sha256,           # noqa: E402
                                     config_effect_view, config_facts,
                                     config_file_sha256)
from agent.platform.program import ProgramIndex                    # noqa: E402
from agent.platform.store import PlatformStore                     # noqa: E402
from agent.platform.task import Budget, TaskSpec                   # noqa: E402

TASK = "task-v3-w2-config"
PY = sys.executable
FIXTURES = ROOT / "tests" / "fixtures_config"

ACTIVE = "config/active.json"
SCHEMA = "vulnmap.active_config.v1"
BASELINE_CONFIG = {"schema": SCHEMA, "sample": "alpha",
                   "observation_points": ["input_processed"]}
GAMMA_CONFIG = {"schema": SCHEMA, "sample": "gamma",
                "observation_points": ["input_processed", "guard"]}
#: 真构建（py_compile 两个脚本）+ 真冒烟（目标按当前配置解析样例）
BUILD_COMMAND = [PY, "-m", "py_compile", "target.py", "runner.py"]
SMOKE_COMMAND = [PY, "target.py", "--config", ACTIVE, "--probe", "smoke.jsonl"]
FACT_FIELDS = ("program_started", "input_processed", "checkpoint_reached")


# ------------------------------------------------------------------ 夹具装配
def _env() -> dict[str, str]:
    """子进程环境：让 runner.py 找到 `agent.platform.executors` 的唯一实现。"""
    env = dict(os.environ)
    env["VULNMAP_ROOT"] = str(ROOT)
    env["PYTHONPATH"] = str(ROOT) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return env


def _origin(base: Path, *, with_config: bool = True) -> Path:
    """把真夹具复制成任务原件（绝不写仓库里的夹具）。"""
    origin = base / "origin"
    if with_config:
        shutil.copytree(FIXTURES, origin)
    else:
        origin.mkdir(parents=True)
        (origin / "notes.txt").write_text("generator task\n", encoding="utf-8")
    return origin


def _workspace(base: Path, *, with_config: bool = True) -> TaskWorkspace:
    """真 taskworkspace：origin 只读 + current 可写 + 初始 revision。"""
    return TaskWorkspace.create(
        base / "ws", _origin(base, with_config=with_config), task_id=TASK,
        build_command=BUILD_COMMAND, smoke_command=SMOKE_COMMAND)


def _run_runner(root: Path, *, probe: Path, config: Path | None = None,
                stale: Path | None = None, no_report: bool = False) -> dict:
    """真 subprocess 跑夹具执行器，返回它报的事实 JSON。"""
    root = Path(root)
    command = [PY, str(root / "runner.py"), "--root", str(root),
               "--config", str(config or (root / ACTIVE)),
               "--probe", str(probe)]
    if stale is not None:
        command += ["--stale-config", str(stale)]
    if no_report:
        command += ["--no-report-config"]
    proc = subprocess.run(command, capture_output=True, text=True,
                          timeout=180, cwd=str(root), env=_env(),
                          check=False)
    assert proc.returncode in (0, 1), (proc.returncode, proc.stdout, proc.stderr)
    lines = [line for line in proc.stdout.strip().splitlines() if line.strip()]
    assert lines, proc.stderr
    return json.loads(lines[-1])


def _facts(report: dict) -> dict:
    return {name: report[name] for name in FACT_FIELDS}


def _active_bytes(ws: TaskWorkspace) -> bytes:
    return (ws.current_dir / ACTIVE).read_bytes()


def _events(store: PlatformStore, exec_id: str) -> tuple[dict, dict]:
    """把一次执行的两条事件读回来（`config_effect_view` 的入参就是这两个 payload）。"""
    start: dict = {}
    finish: dict = {}
    for event in store.list_events(TASK):
        payload = dict(event.get("payload") or {})
        if payload.get("exec_id") != exec_id:
            continue
        if event.get("event_type") == "exec.started":
            start = payload
        elif event.get("event_type") == "exec.finished":
            finish = payload
    return start, finish


def _store_with_task(base: Path) -> tuple[PlatformStore, dict]:
    store = PlatformStore(base / "platform.db")
    store.create_task(TaskSpec(
        task_id=TASK, benchmark="vulngym", target="fixtures_config",
        mode="fuzz",
        budget=Budget(max_seconds=600, max_execs=1000, max_tokens=1000,
                      max_turns=8),
        metadata={"authorized": True}))
    store.save_hypotheses(TASK, [{
        "id": "hyp-1", "statement": "VMAP1 头被解析后才处理 body",
        "falsifiable_by": "diff", "evidence_gap": [], "cost": {"level": "low"},
        "confidence": 0.5, "source": "static", "site_id": "cs-1",
        "hypothesis": "header", "window": "target.py:1-40",
        "falsification": "none"}])
    return store, store.get_task(TASK)


def _index(base: Path) -> ProgramIndex:
    src = base / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "target.py").write_text("def parse(b):\n    return b\n",
                                   encoding="utf-8")
    return ProgramIndex(
        benchmark="vulngym", root=str(src), task_id=TASK,
        entry_points=[{"name": "parse", "file": "target.py"}],
        functions=[{"name": "parse", "file": "target.py"}],
        call_sites=[{"id": "cs-1", "file": "target.py", "line": 1,
                     "function": "parse", "callee": "parse"}],
        formats=["raw"], source_count=1, warnings=[])


class ConfigRunner:
    """执行器替身：**真的**跑 `runner.py`，并且只回报它报的东西。

    `loaded_config_sha256` 只来自子进程输出（`runner.py` 用
    `config_file_sha256` 算它真的加载的那一份）——这里不抄 planned、不猜。
    """

    def __init__(self, workspace: TaskWorkspace, store: PlatformStore, *,
                 probe_dir: Path, stale: Path | None = None,
                 report: bool = True, report_until: int | None = None) -> None:
        self.workspace = workspace
        self.store = store
        self.probe_dir = Path(probe_dir)
        self.stale = stale
        self.report = bool(report)
        #: 只对**前 N 次**执行回报实际加载版本（None = 每次都报）
        self.report_until = None if report_until is None else int(report_until)
        self.calls: list[dict] = []

    def __call__(self, *, kind: str, mode: str, params: dict, binding) -> dict:
        n = len(self.calls) + 1
        exec_id = f"exec-{n:04d}"
        workdir = Path(self.workspace.current_dir)
        planned = str(self.workspace.active_config_sha256() or "")
        reports = self.report and (self.report_until is None
                                   or n <= self.report_until)
        report = _run_runner(workdir, probe=self.probe_dir / f"probe-{exec_id}.jsonl",
                             stale=self.stale, no_report=not reports)
        fuzz = {"execs": 6, "crashes": 0, "timeouts": 0, "new_coverage_bits": 1,
                "setup_error": "", "stopped": "completed", "workers": 1}
        self.store.append_event(TASK, "exec.started", stage="RUNNING", payload={
            "exec_id": exec_id, "kind": kind, "plan_sha256": "p" * 40,
            "benchmark": "vulngym", "target": "fixtures_config",
            "budget": {"seconds": 1.0, "workers": 1, "timeout": 5.0},
            "workdir": str(workdir),
            "config_planned_sha256": planned})
        self.store.append_event(TASK, "exec.finished", stage="RUNNING", payload={
            "exec_id": exec_id, "kind": kind, "outcome": "no_repro",
            "plan_sha256": "p" * 40, "candidates": 0, "seconds": 0.3,
            "build": {"sha256": "b" * 64, "build_id": "b" * 64,
                      "harness": "covfuzz"},
            "fuzz": fuzz, "seeds": 1, "dictionary_tokens": 0, "format": "raw",
            "evidence_sha256": "e" * 64, "error": None,
            "budget_usage": {"seconds": 0.3, "execs": 6, "tokens": 0,
                             "turns": 1},
            "program_started": report["program_started"],
            "input_processed": report["input_processed"],
            "checkpoint_reached": report["checkpoint_reached"],
            "config_planned_sha256": planned,
            "config_loaded_sha256": report["loaded_config_sha256"],
            "config_source": report["loaded_source"]})
        self.calls.append(report)
        return {
            "execution_id": exec_id, "kind": kind, "mode": mode,
            "outcome": "no_repro", "candidates": 0,
            "build": {"sha256": "b" * 64}, "fuzz": fuzz,
            "coverage": {"status": "unavailable"}, "seeds": 1,
            "dictionary_tokens": 0, "format": "raw",
            "budget_usage": {"seconds": 0.3, "execs": 6, "tokens": 0,
                             "turns": 1},
            "evidence_sha256": "e" * 64, "error": None,
            "program_started": report["program_started"],
            "input_processed": report["input_processed"],
            "checkpoint_reached": report["checkpoint_reached"],
            "loaded_config_sha256": report["loaded_config_sha256"]}


# ================================================== 0. 夹具自己能真跑
def test_runner_runs_standalone_and_reports_loaded_version(tmp_path):
    """`python3 runner.py` 在临时目录里就能给出合法 JSON（不依赖 pytest 内部）。"""
    work = tmp_path / "copy"
    shutil.copytree(FIXTURES, work)
    report = _run_runner(work, probe=tmp_path / "p.jsonl")
    assert report["schema"] == "vulnmap.config_fixture.run.v1"
    assert report["loaded_config_sha256"] == config_file_sha256(work / ACTIVE)
    assert len(report["loaded_config_sha256"]) == 64
    assert report["sample"] == "alpha"
    assert _facts(report) == {"program_started": True, "input_processed": True,
                              "checkpoint_reached": None}
    # 观测点没启用 → checkpoint 是 unknown（None），不是 False
    assert report["checkpoint_reached"] is None
    assert report["probe_hits"] == ["input_processed"]


# ================================================== 1. 白名单拒绝
def test_whitelist_rejects_source_edits(tmp_path):
    """源码/目录/样例/执行器一律不可写；绕过 stage() 也进不了 revision。"""
    ws = _workspace(tmp_path)
    assert ws.config_mode == "config"
    origin_bytes = {rel: (ws.origin_dir / rel).read_bytes()
                    for rel in ("target.py", "runner.py", "config/samples.json",
                                "config/observation_points.json",
                                "samples/alpha.txt")}
    before_manifest = ws.working_manifest()
    before_active = _active_bytes(ws)

    rejected = ["target.py", "runner.py", "config/samples.json",
                "config/observation_points.json", "samples/alpha.txt",
                "samples/gamma.txt"]
    for rel in rejected:
        with pytest.raises(WorkspaceError) as excinfo:
            ws.stage({rel: "tampered\n"})
        assert str(excinfo.value).startswith("config_path_not_whitelisted"), rel
    # 整次调用被拒：一个字节都没写
    assert ws.working_manifest() == before_manifest
    assert _active_bytes(ws) == before_active

    # 绕过 stage() 直接改 current/ → commit 的差异守卫
    revisions_before = len(ws.revisions.all())
    pristine = (ws.current_dir / "target.py").read_bytes()
    (ws.current_dir / "target.py").write_text("# tampered\n", encoding="utf-8")
    with pytest.raises(WorkspaceError) as excinfo:
        ws.commit(reason="bypass stage")
    assert str(excinfo.value).startswith("config_source_edit_forbidden")
    assert len(ws.revisions.all()) == revisions_before       # 没有半截 revision

    # 原件哈希全程不变（origin 0444 + 与基线 manifest 逐文件一致）
    assert ws.origin_integrity()["ok"] is True
    assert ws.config_integrity()["ok"] is True, ws.config_integrity()["problems"]
    for rel, data in origin_bytes.items():
        assert (ws.origin_dir / rel).read_bytes() == data, rel
        assert not os.access(ws.origin_dir / rel, os.W_OK), rel

    # 白名单内的变更照常放行：只有 config/active.json 进 revision
    (ws.current_dir / "target.py").write_bytes(pristine)
    assert ws.working_manifest() == before_manifest
    parent = ws.current_revision()
    staged = ws.stage_config(GAMMA_CONFIG, reason="switch to gamma + guard")
    assert staged.changed_paths == (ACTIVE,)
    revision = ws.commit(reason="switch to gamma + guard")
    assert revision.changed_against(parent) == (ACTIVE,)
    assert ws.config_integrity()["ok"] is True, ws.config_integrity()["problems"]
    assert ws.origin_integrity()["ok"] is True
    for rel, data in origin_bytes.items():
        assert (ws.origin_dir / rel).read_bytes() == data, rel
    # 换配置必然换 revision 身份（配置哈希写进 environment）
    assert revision.environment["active_config_sha256"] == \
        ws.active_config_sha256()
    assert revision.environment["baseline_config_sha256"] == \
        ws.baseline_config_sha256()
    assert ws.active_config_sha256() != ws.baseline_config_sha256()


def test_whitelist_rejects_unknown_ids(tmp_path):
    """不能凭空造样例/观测点；schema 与键集合都是白名单；坏配置不落盘。"""
    ws = _workspace(tmp_path)
    before_active = _active_bytes(ws)
    before_manifest = ws.working_manifest()

    cases = [
        ({"schema": SCHEMA, "sample": "delta",
          "observation_points": ["input_processed"]}, "unknown_sample"),
        ({"schema": SCHEMA, "sample": "alpha",
          "observation_points": ["guardian"]}, "unknown_observation_point"),
        ({"schema": SCHEMA, "sample": "alpha",
          "observation_points": ["input_processed", "input_processed"]},
         "config_invalid"),
        ({"schema": "vulnmap.active_config.v2", "sample": "alpha",
          "observation_points": []}, "config_field_not_whitelisted"),
        ({"schema": SCHEMA, "sample": "alpha",
          "observation_points": ["input_processed"], "mode": "yolo"},
         "config_field_not_whitelisted"),
        ({"schema": SCHEMA, "sample": "alpha"}, "config_invalid"),
        (["not", "an", "object"], "config_invalid"),
        (BASELINE_CONFIG, "no_change"),
    ]
    for doc, code in cases:
        with pytest.raises(WorkspaceError) as excinfo:
            ws.stage_config(doc)
        assert str(excinfo.value).startswith(code), (doc, code,
                                                     str(excinfo.value))
    # 坏 JSON 走 stage() 也进不来，且失败不留痕
    with pytest.raises(WorkspaceError) as excinfo:
        ws.stage({ACTIVE: "{not json"})
    assert str(excinfo.value).startswith("config_invalid")
    assert _active_bytes(ws) == before_active
    assert ws.working_manifest() == before_manifest
    assert ws.config_integrity()["ok"] is True

    # 目录里登记了、但工作副本里没有那个文件 → unknown_sample（不是"能跑就行"）
    missing = _workspace(tmp_path / "missing")
    (missing.current_dir / "samples" / "beta.txt").unlink()
    with pytest.raises(WorkspaceError) as excinfo:
        missing.stage_config({"schema": SCHEMA, "sample": "beta",
                              "observation_points": ["input_processed"]})
    assert str(excinfo.value).startswith("unknown_sample")
    assert missing.active_config_sha256() == missing.baseline_config_sha256()


def test_generator_mode_keeps_week1_behaviour(tmp_path):
    """origin 没有配置面 → generator 模式：`stage()` 行为不变，也没有配置身份。"""
    ws = _workspace(tmp_path, with_config=False)
    assert ws.config_mode == "generator"
    parent = ws.current_revision()
    staged = ws.stage({"notes.txt": "changed\n"})
    assert staged.changed_paths == ("notes.txt",)
    revision = ws.commit(reason="week1 style edit")
    assert revision.changed_against(parent) == ("notes.txt",)
    assert "active_config_sha256" not in revision.environment
    assert ws.active_config_sha256() == ""
    assert ws.baseline_config_sha256() == ""
    with pytest.raises(WorkspaceError) as excinfo:
        ws.stage_config(BASELINE_CONFIG)          # 没有目录就没法校验
    assert str(excinfo.value).startswith("config_invalid")


# ================================================== 2. 实际加载版本
def test_loaded_version_is_reported_not_planned(tmp_path):
    """真跑后 `loaded == planned` → `effective`；两版都拿到才能写这个状态。"""
    ws = _workspace(tmp_path)
    store, _task = _store_with_task(tmp_path)
    planned = ws.active_config_sha256()
    assert planned == config_file_sha256(ws.current_dir / ACTIVE) == \
        config_doc_sha256(BASELINE_CONFIG)
    # 配置身份是**规范化 JSON** 的哈希：键顺序不同、缩进不同，同一版配置
    assert config_doc_sha256({"observation_points": ["input_processed"],
                              "sample": "alpha",
                              "schema": SCHEMA}) == planned

    report = _run_runner(ws.current_dir, probe=tmp_path / "p.jsonl")
    assert report["loaded_config_sha256"] == planned       # 算出来的，不是抄的
    assert report["loaded_source"] == "reported"

    runner = ConfigRunner(ws, store, probe_dir=tmp_path / "probe")
    runner(kind="fuzz", mode="explore", params={}, binding=None)
    exec_id = f"exec-{1:04d}"
    start, finish = _events(store, exec_id)
    assert start["config_planned_sha256"] == planned
    assert finish["config_loaded_sha256"] == report["loaded_config_sha256"]

    view = config_effect_view(start, finish)
    assert view["config_status"] == "effective"
    assert view["config_effective"] is True
    assert view["config_present"] == {"planned": True, "loaded": True}
    assert view["config_loaded_sha256"] == view["config_planned_sha256"]

    revision = ws.current_revision()
    effect = ConfigEffectRecord(
        revision_id=revision.revision_id,
        planned_sha256=view["config_planned_sha256"],
        loaded_sha256=view["config_loaded_sha256"],
        status=view["config_status"], source=view["config_source"],
        execution_id=exec_id, round_no=1)
    saved = ws.revisions.record_config_effect(effect)
    assert saved.effect_id.startswith("ce-") and len(saved.effect_id) == 19
    assert saved.adoptable is True
    assert ws.revisions.latest_config_effect(revision.revision_id) == saved
    assert ws.revisions.config_effect_for_execution(exec_id) == saved
    assert ws.revisions.config_adoptable(revision.revision_id) is True

    # 不变量：写不进去的假话不该存在于账本里
    with pytest.raises(RevisionError):
        ConfigEffectRecord(revision_id=revision.revision_id,
                           planned_sha256=planned, loaded_sha256="f" * 64,
                           status="effective")
    with pytest.raises(RevisionError):
        ConfigEffectRecord(revision_id=revision.revision_id,
                           planned_sha256=planned, loaded_sha256=planned,
                           status="not_effective")


def test_unreported_load_is_unknown_not_planned(tmp_path):
    """执行器没报实际加载版本 → `unknown`：`config_effective is None`，不是 False。"""
    ws = _workspace(tmp_path)
    store, _task = _store_with_task(tmp_path)
    planned = ws.active_config_sha256()

    report = _run_runner(ws.current_dir, probe=tmp_path / "p.jsonl",
                         no_report=True)
    assert report["loaded_config_sha256"] == ""
    assert report["reported"] is False and report["loaded_source"] == ""

    runner = ConfigRunner(ws, store, probe_dir=tmp_path / "probe",
                          report=False)
    runner(kind="fuzz", mode="explore", params={}, binding=None)
    start, finish = _events(store, "exec-0001")
    view = config_effect_view(start, finish)
    assert view["config_status"] == "unknown"
    assert view["config_status"] != "not_effective"     # "没观测" ≠ "观测到没生效"
    assert view["config_effective"] is None             # 三值：不是 False
    assert view["config_effective"] is not False
    assert view["config_source"] == "loaded_unreported"
    assert view["config_planned_sha256"] == planned     # 计划版本照给
    assert view["config_loaded_sha256"] == ""           # 但绝不回填 planned
    assert view["config_present"] == {"planned": True, "loaded": False}

    # 纯函数口径（§3 三值表）：没报 → `config_effective is None`
    facts = config_facts(planned_sha256=planned)
    assert facts["config_effective"] is None
    assert facts["config_source"] == "loaded_unreported"
    assert facts["config_planned_sha256"] == planned
    assert facts["config_loaded_sha256"] == ""

    revision = ws.current_revision()
    effect = ws.revisions.record_config_effect(
        revision_id=revision.revision_id, planned_sha256=planned,
        loaded_sha256="", status=view["config_status"],
        source=view["config_source"], execution_id="exec-0001", round_no=1)
    assert effect.adoptable is False
    assert ws.revisions.config_adoptable(revision.revision_id) is False

    # 快照/观测/诊断：unknown 只能报 config_unverified（warn），不能冒充 false
    snapshot = TrustedExecutionSnapshot.collect(store, TASK,
                                               execution_id="exec-0001")
    # 快照只登记文档 §5.1 的四个字段；status 由 effective 的拼写规范回来
    assert {"planned_config_sha256", "loaded_config_sha256",
            "config_effective", "config_source"} <= \
        set(snapshot.to_dict()["groups"]["config"])
    assert snapshot.get("config.config_effective") == "unknown"
    assert snapshot.get("config.config_effective") != "false"   # 不是"没生效"
    assert snapshot.get("config.loaded_config_sha256") == "unknown"
    assert snapshot.get("config.planned_config_sha256") == planned
    observation = ContextRole().observe(snapshot)
    assert observation.config["status"] == "unknown"
    assert observation.config["loaded"] == "unknown"
    diagnosis = DiagnoseRole().diagnose(observation)
    assert diagnosis.code == "config_unverified"
    assert diagnosis.severity == "warn"
    # 目标三态不因配置 unknown 被改写（第 1 周口径不动）
    assert observation.program_started == "true"
    assert observation.input_processed == "true"
    assert observation.checkpoint_reached == "unknown"


# ================================================== 3. 未生效反例
def test_stale_load_is_not_effective(tmp_path):
    """配置已写盘、执行器仍加载旧副本：`not_effective` → 不采纳、不回写裁决。"""
    base = tmp_path
    ws = _workspace(base)
    store, task = _store_with_task(base)
    index = _index(base)

    baseline = ws.current_revision()
    baseline_hash = ws.active_config_sha256()
    stale_file = base / "stale_active.json"
    stale_file.write_bytes(_active_bytes(ws))           # 旧配置的真实副本
    staged = ws.stage_config(GAMMA_CONFIG, reason="switch to gamma + guard")
    assert staged.changed_paths == (ACTIVE,)
    planned_revision = ws.commit(reason="switch to gamma + guard")
    planned_hash = ws.active_config_sha256()
    assert planned_hash != baseline_hash

    runner = ConfigRunner(ws, store, probe_dir=base / "probe",
                          stale=stale_file)
    ctl = ResearchController(
        task=task, store=store, workspace=ws, index=index,
        exec_runner=runner, policy=AdoptionPolicy(), max_rounds=1)
    result = ctl.run()

    # 真跑出来的反例事实：执行器加载的是旧配置（旧样例 alpha，不是 gamma）
    assert len(runner.calls) == 1
    assert runner.calls[0]["loaded_config_sha256"] == baseline_hash
    assert runner.calls[0]["sample"] == "alpha"
    assert runner.calls[0]["stale"] is True

    assert result.stop_reason == "config_not_effective"
    assert result.status == "blocked"
    assert result.error == ""
    phases = [(record.phase, record.status) for record in result.timeline]
    assert ("CONFIG", "not_effective") in phases
    assert ("STOP", "blocked") in phases
    assert any(record.phase == "REVERT" and record.status == "ok"
               for record in result.timeline)

    round_record = result.rounds[0]
    assert round_record.config_effect["status"] == "not_effective"
    assert round_record.config_effect["planned_sha256"] == planned_hash
    assert round_record.config_effect["loaded_sha256"] == baseline_hash
    assert round_record.adopted is False
    assert round_record.reverted not in ("", None)

    # 账本：一条 not_effective，不可采纳
    effects = ws.revisions.config_effects()
    assert [effect.status for effect in effects][-1] == "not_effective"
    assert effects[-1].planned_sha256 == planned_hash
    assert effects[-1].loaded_sha256 == baseline_hash
    assert effects[-1].adoptable is False
    assert ws.revisions.config_adoptable(planned_revision.revision_id) is False

    # 不写采纳、不产生 verification（裁决只认 verify，这条路没走到）
    assert ws.revisions.adoptions() == ()
    assert not (ws.root / "store" / "adoptions.jsonl").exists()
    assert store.list_verifications(TASK) == []
    assert result.verification is None

    # 事实链上也是「观测到的没生效」，不是「不知道」：
    # 与第 2 组的 unknown 对照组逐字段不同（effective=true/false/unknown 三态）
    snapshot = TrustedExecutionSnapshot.collect(store, TASK,
                                               execution_id="exec-0001")
    assert snapshot.get("config.config_effective") == "false"
    assert snapshot.get("config.loaded_config_sha256") == baseline_hash
    assert snapshot.get("config.planned_config_sha256") == planned_hash
    observation = ContextRole().observe(snapshot)
    assert observation.config == {"planned": planned_hash,
                                  "loaded": baseline_hash,
                                  "effective": "false",
                                  "status": "not_effective",
                                  "source": "reported"}
    diagnosis = DiagnoseRole().diagnose(observation)
    assert diagnosis.code == "config_not_effective"
    assert diagnosis.severity == "blocked"

    # 工作树回退到父 revision（配置变更之前那一版），配置哈希也回退
    current = ws.current_revision()
    assert current.reverted_to == baseline.revision_id
    assert current.parent_id == planned_revision.revision_id
    assert ws.working_manifest() == baseline.manifest
    assert ws.active_config_sha256() == baseline_hash
    assert ws.config_integrity()["ok"] is True, ws.config_integrity()["problems"]
    assert ws.origin_integrity()["ok"] is True
    assert len(ws.revisions.all()) == 3                 # create/commit/revert


# ================================================== 4. 回退哈希 + 行为
def test_baseline_modify_revert_restores_hash_and_behavior(tmp_path):
    """baseline → modify（换样例+开观测点）→ revert：哈希、工作树、真跑行为都回来。"""
    ws = _workspace(tmp_path)

    baseline = ws.current_revision()
    baseline_hash = ws.active_config_sha256()
    baseline_manifest = ws.working_manifest()
    baseline_run = _run_runner(ws.current_dir, probe=tmp_path / "b.jsonl")
    assert baseline_run["sample"] == "alpha"
    # baseline 只启用 input_processed：检查点没观测 → unknown（不是 false）
    assert _facts(baseline_run) == {"program_started": True,
                                    "input_processed": True,
                                    "checkpoint_reached": None}
    assert baseline_run["probe_hits"] == ["input_processed"]
    build0 = ws.build(baseline)
    assert build0.status == "ok" and build0.exit_code == 0
    smoke0 = ws.smoke(baseline, build=build0)
    assert smoke0.status == "passed" and smoke0.kind == ""

    ws.stage_config(GAMMA_CONFIG, reason="switch sample + enable guard")
    modified = ws.commit(reason="switch sample + enable guard")
    modified_hash = ws.active_config_sha256()
    assert modified_hash != baseline_hash
    assert modified.changed_against(baseline) == (ACTIVE,)
    modified_run = _run_runner(ws.current_dir, probe=tmp_path / "m.jsonl")
    assert modified_run["sample"] == "gamma"
    assert _facts(modified_run) == {"program_started": True,
                                    "input_processed": True,
                                    "checkpoint_reached": True}
    assert modified_run["probe_hits"] == ["checkpoint:guard", "input_processed"]
    build1 = ws.build(modified)
    assert build1.status == "ok" and build1.build_id != build0.build_id
    smoke1 = ws.smoke(modified, build=build1)
    assert smoke1.status == "passed"

    reverted = ws.revert(to_revision=baseline.revision_id,
                         reason="back to baseline config")
    assert ws.active_config_sha256() == baseline_hash == \
        ws.baseline_config_sha256()
    assert ws.working_manifest() == baseline_manifest
    assert _active_bytes(ws) == (ws.origin_dir / ACTIVE).read_bytes()
    assert ws.config_integrity()["ok"] is True, ws.config_integrity()["problems"]
    assert ws.origin_integrity()["ok"] is True

    # 真跑行为一起回来（同一份配置 → 同一组事实，逐字段相等）
    reverted_run = _run_runner(ws.current_dir, probe=tmp_path / "r.jsonl")
    assert _facts(reverted_run) == _facts(baseline_run)
    assert reverted_run["sample"] == baseline_run["sample"]
    assert reverted_run["probe_hits"] == baseline_run["probe_hits"]
    assert reverted_run["loaded_config_sha256"] == baseline_hash == \
        baseline_run["loaded_config_sha256"]

    # 账本：create + commit + revert 三条；revert 指回被回退的那一版
    revisions = ws.revisions.all()
    assert len(revisions) == 3
    assert [item.revision_id for item in revisions] == [
        baseline.revision_id, modified.revision_id, reverted.revision_id]
    assert reverted.reverted_to == baseline.revision_id
    assert reverted.parent_id == modified.revision_id
    assert reverted.manifest_sha256 == baseline.manifest_sha256
    # 旧 revision 没被改写
    assert ws.revisions.get(modified.revision_id).manifest_sha256 == \
        modified.manifest_sha256


def test_bad_magic_sample_fails_smoke_on_target_side(tmp_path):
    """换到坏 magic 样例：冒烟**真**失败，且是 target 侧（不是装置坏了）。"""
    ws = _workspace(tmp_path)
    ws.stage_config({"schema": SCHEMA, "sample": "beta",
                     "observation_points": ["input_processed"]},
                    reason="switch to bad magic sample")
    revision = ws.commit(reason="switch to bad magic sample")
    build = ws.build(revision)
    assert build.status == "ok" and build.exit_code == 0     # 脚本本身是好的
    smoke = ws.smoke(revision, build=build)
    assert smoke.status == "failed"
    assert smoke.kind == "target"                            # 目标侧行为不符
    assert smoke.harness_failed is False
    assert smoke.exit_code == 1

    report = _run_runner(ws.current_dir, probe=tmp_path / "beta.jsonl")
    assert report["sample"] == "beta"
    assert _facts(report) == {"program_started": True,
                              "input_processed": False,
                              "checkpoint_reached": None}
    assert report["target_exit_code"] == 1
    assert report["loaded_config_sha256"] == ws.active_config_sha256()


# ================================================== 5. 控制器自己提议的配置变更
NEXT_POINT_CONFIG = {"schema": SCHEMA, "sample": "alpha",
                     "observation_points": ["input_processed", "guard"]}


class RogueConfigRole:
    """把「配置变更」提成源码变更的角色：控制器必须把它挡在 STAGE。

    形状与 `ConfigRole` 一致（`revision_plan(observation, diagnosis, *, attempt)`），
    但产物是 `target.py`——配置模式的白名单只放行 `config/active.json`。
    """

    def __init__(self, files: dict | None = None) -> None:
        self.files = dict(files or {"target.py": "print('rogue')\n"})
        self.calls: list[int] = []

    def revision_plan(self, observation, diagnosis, *, attempt: int):
        self.calls.append(int(attempt))
        return RevisionPlan(files=dict(self.files),
                            reason=f"rogue plan at attempt {attempt}",
                            hypothesis_id=observation.hypothesis_id,
                            tool="config_editor")


def _controller(ws: TaskWorkspace, store: PlatformStore, index: ProgramIndex,
                runner, *, max_rounds: int, session=None) -> ResearchController:
    return ResearchController(
        task=store.get_task(TASK), store=store, workspace=ws, index=index,
        exec_runner=runner, policy=AdoptionPolicy(), max_rounds=max_rounds,
        session=session)


def test_controller_proposes_and_lands_whitelisted_config_change(tmp_path):
    """ConfigRole 自己提议 → `workspace.stage()` 落地 → 真跑回报 effective。

    第 1 轮 `no_execution` 按原配置跑（attempt 0 不改），第 2 轮由 ConfigRole 的
    `RevisionPlan` 启用下一个未启用观测点（`guard`），经白名单落成新 revision，
    再真跑一次：`loaded == planned` → `CONFIG=effective`，配置门不拦。
    """
    base = tmp_path / "main"
    ws = _workspace(base)
    store, _task = _store_with_task(base)
    index = _index(base)
    baseline = ws.current_revision()
    baseline_hash = ws.active_config_sha256()

    runner = ConfigRunner(ws, store, probe_dir=base / "probe")
    result = _controller(ws, store, index, runner, max_rounds=2).run()

    # ---- 提议这一环：revision 由控制器按 ConfigRole 产出的 plan 落地 ----
    revisions = ws.revisions.all()
    assert len(revisions) == 2                       # create + 控制器提议的那一版
    landed = revisions[1]
    plan = result.rounds[1].plan
    assert plan is not None and plan.revision is not None
    assert plan.revision.tool == "config_editor"
    assert dict(plan.revision.files) == {ACTIVE: plan.revision.files[ACTIVE]}
    assert landed.revision_id == result.rounds[1].revision
    assert landed.tool == "config_editor"
    assert landed.changed_against(baseline) == (ACTIVE,)     # 只改配置面，没碰源码
    assert result.rounds[1].build["status"] == "ok"
    assert result.rounds[1].smoke["status"] == "passed"

    # ---- 落地的配置是「目录里的下一个观测点」，哈希是算出来的 ----
    assert ws.active_config_doc() == NEXT_POINT_CONFIG
    new_hash = config_doc_sha256(NEXT_POINT_CONFIG)
    assert new_hash != baseline_hash
    assert ws.active_config_sha256() == new_hash
    assert landed.environment["active_config_sha256"] == new_hash
    assert landed.environment["baseline_config_sha256"] == baseline_hash

    # ---- 门：配置真生效（执行器回报的这一版 == 计划这一版） ----
    config_rows = [row for row in result.timeline if row.phase == "CONFIG"]
    assert [row.status for row in config_rows] == ["effective", "effective"]
    assert result.stop_reason == "max_rounds"
    assert result.status == "completed"
    assert result.stop_reason not in ("config_not_effective", "config_unverified")
    assert all(record.config_effect["status"] == "effective"
               for record in result.rounds)
    effects = ws.revisions.config_effects()
    assert [effect.status for effect in effects] == ["effective", "effective"]
    assert ws.revisions.config_adoptable(landed.revision_id) is True

    # ---- 行为证据：同一份样例，观测点开了以后检查点从 unknown 变成 false ----
    assert [(call["sample"], call["observation_points"],
             call["input_processed"], call["checkpoint_reached"])
            for call in runner.calls] == [
        ("alpha", ["input_processed"], True, None),
        ("alpha", ["input_processed", "guard"], True, False)]
    assert runner.calls[1]["loaded_config_sha256"] == new_hash
    # 采纳只写工程结论，不产生 verification
    assert len(ws.revisions.adoptions()) == 1
    assert ws.revisions.adoptions()[0]["subject"] == landed.revision_id
    assert store.list_verifications(TASK) == []
    assert ws.origin_integrity()["ok"] is True
    assert ws.config_integrity()["ok"] is True, ws.config_integrity()["problems"]

    # ---- 反向：同一条流程里执行器改成「不报」→ 停 config_unverified ----
    reverse_base = tmp_path / "reverse"
    reverse_ws = _workspace(reverse_base)
    reverse_store, _t = _store_with_task(reverse_base)
    reverse_index = _index(reverse_base)
    quiet = ConfigRunner(reverse_ws, reverse_store,
                         probe_dir=reverse_base / "probe", report_until=1)
    reverse = _controller(reverse_ws, reverse_store, reverse_index, quiet,
                          max_rounds=3).run()

    assert len(reverse_ws.revisions.all()) == 2       # 变更真的落地了才被门拦住
    assert [row.status for row in reverse.timeline if row.phase == "CONFIG"] == \
        ["effective", "unknown"]
    assert reverse.stop_reason == "config_unverified"
    assert reverse.status == "blocked"
    assert quiet.calls[1]["reported"] is False
    assert quiet.calls[1]["loaded_config_sha256"] == ""
    # unknown ≠ not_effective：不回退、也不采纳（配置还停在新的一版上）
    assert reverse_ws.active_config_doc() == NEXT_POINT_CONFIG
    assert reverse_ws.current_revision().reverted_to == ""
    assert reverse_ws.revisions.adoptions() == ()
    assert reverse_store.list_verifications(TASK) == []


def test_config_mode_rejects_plan_that_edits_source(tmp_path):
    """配置模式里「改源码」的 plan 在 STAGE 就被挡：一条 revision 都不新增。"""
    base = tmp_path / "rogue"
    ws = _workspace(base)
    store, _task = _store_with_task(base)
    index = _index(base)
    current = ws.current_revision()
    before_manifest = ws.working_manifest()
    before_target = (ws.current_dir / "target.py").read_bytes()

    registry = build_registry()
    role = RogueConfigRole()
    session = ResearchSession(
        binding=make_binding(store.get_task(TASK), campaign="vulngym",
                             registry=registry, index=index),
        registry=registry, store=store, config_role=role)
    runner = ConfigRunner(ws, store, probe_dir=base / "probe")
    result = _controller(ws, store, index, runner, max_rounds=2,
                         session=session).run()

    # plan 真的提出来了（不是根本没提议就停），然后被 stage() 的白名单拒绝
    assert role.calls, "ConfigRole 替身一次都没被调用，等于没测到这条路径"
    stage_rows = [row for row in result.timeline if row.phase == "STAGE"]
    assert len(stage_rows) == 1
    assert stage_rows[0].status == "failed"
    assert "config_path_not_whitelisted" in stage_rows[0].detail
    assert result.stop_reason == "stage_failed"
    assert result.status == "blocked"
    assert result.rounds[0].note == "config_path_not_whitelisted"

    # 一条 revision 都没新增；工作副本与原件都没被改写；没有采纳/裁决
    assert len(ws.revisions.all()) == 1
    assert ws.current_revision().revision_id == current.revision_id
    assert ws.working_manifest() == before_manifest
    assert (ws.current_dir / "target.py").read_bytes() == before_target
    assert (ws.origin_dir / "target.py").read_bytes() == before_target
    assert ws.origin_integrity()["ok"] is True
    assert ws.config_integrity()["ok"] is True, ws.config_integrity()["problems"]
    assert ws.revisions.adoptions() == ()
    assert store.list_verifications(TASK) == []
    assert runner.calls == []                        # 连执行都没走到
