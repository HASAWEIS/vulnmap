r"""V3 隔离验收：**隔离是跑出来的事实，不是计划里的一行字**。

被测实现：`agent/platform/adaptive/workspace.py`（构建/冒烟的隔离执行与记录）、
`agent/platform/adaptive/handoff.py`（平台侧隔离验收记录 + `ProposalGate`）、
`agent/platform/store.py` 的 `isolation_acceptance` 台账。
口径唯一出处：`docs/V3-ISOLATION-ACCEPTANCE.md`。

夹具全部自己搭（不 import 其它测试模块）：真 `TaskWorkspace`（真副本 + 真
`RevisionStore`）、真子进程、真 socket 监听、真 `PlatformStore`。

八组用例：

| 组 | 用例 | 用的是什么事实 / 断言什么 |
|---|---|---|
| 1 正常回归 | `test_normal_regression_miss_hit_miss_inside_isolation` | 一个无害解析器：baseline（token=raw）→ 改 `config.json`（token=MAGIC）→ revert。每次 build/smoke 都带隔离前缀真跑：未命中→命中→未命中；revert 的 `manifest_sha256` 回到 baseline 且原件哈希不变；每条记录 `executed_isolated=True`、`network=none`、`cap_drop/ro_root=True`，台账逐条落盘 |
| 2 越界写 | `test_write_outside_workspace_is_denied` | 冒烟脚本往**工作区外**写标记：`exit_code==3`（脚本自己判定 OSError）、宿主上标记**不存在**、该次冒烟仍 `executed_isolated=True`——拒绝是隔离干的，不是没跑 |
| 3 断网 | `test_network_connect_is_denied` | 宿主侧先证明监听可用（同端口 `connect` 成功），再在隔离里连同一端口：`exit_code==3`、日志里没有 `CONNECTED` |
| 4 缺隔离 | `test_missing_isolation_refuses_and_runs_nothing` | monkeypatch `isolation.resolve` 返回 `mode=none`（以及直接抛错）：`WorkspaceError`（`strong_isolation_required` / `isolation_unavailable`），**命令一次都没跑**（痕迹文件不存在、`revisions.builds()==()`、台账为空）；显式 `mode=none` 且要求隔离 → 建工作区就拒绝 |
| 5 自报放行 | `test_self_reported_isolation_is_advisory_only` | `metadata.isolation_accepted="yes"` 只进 `Acceptance.declared_isolation`（advisory）：`advisory` + `isolation:missing`；**改动过一个字节**的平台记录 → `rejected`（`evidence_hash_mismatch`），仍不放行 |
| 6 平台记录放行 | `test_platform_record_grants_apply` | 真隔离 build+smoke+真越界探针 → `build_isolation_acceptance()` 判 `accepted` → 落库+落文件 → `ProposalGate` 走 `apply`；换一个任务借不走这条记录（`missing`）；提交者自填字段在记录里**不存在**；另有一条“只有计划、没有执行”的记录只能是 `rejected` |

核心口径（**不因绿灯放宽**）：

- 只有**强隔离**执行器（`bwrap`/`container`）能承载 build/smoke；解析到 `unshare`
  （不管 auto 降级还是显式选择）或 `none` 就在 spawn 前拒绝，**绝不回退弱隔离或
  宿主 subprocess**；
- `executed_isolated` 只在“真带着隔离前缀 spawn 过 + 模式是强隔离”时为真；计划里的
  `isolation=bwrap` 永远进不了记录；`unshare` 记录一律 `qualified=False` /
  `strong=False` / `executed_isolated=False`；
- 放行只读平台侧记录（检查项 + 证据哈希 + 时间），任务提交者填的字段恒为 advisory。
"""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.discovery import isolation as isolation_mod  # noqa: E402
from agent.platform.adaptive import handoff  # noqa: E402
from agent.platform.adaptive.revision import BuildRecord  # noqa: E402
from agent.platform.adaptive.workspace import (  # noqa: E402
    ISOLATION_LEDGER,
    QUALIFIED_ISOLATION_MODES,
    STRONG_ISOLATION_MODES,
    IsolatedBuildRecord,
    TaskWorkspace,
    WorkspaceError,
    _observed_isolation_facts,
)
from agent.platform.store import PlatformStore  # noqa: E402
from agent.platform.task import Budget, TaskSpec  # noqa: E402

PY = sys.executable
TASK = "task-v3-isolation"
OTHER_TASK = "task-v3-isolation-other"

#: 当前机器能给出的隔离能力（只影响“越界写/断网”两组：没有只读根或断网能力时
#: 那两个断言本来就证明不了任何事，跳过比假绿好）
DETECTED = isolation_mod.detect()
HARD_ISOLATION = pytest.mark.skipif(
    DETECTED.get("mode") not in ("bwrap", "container")
    or DETECTED.get("network") != "none",
    reason=f"当前隔离执行器不足以证明越界被拒：{DETECTED.get('mode')}")

# ------------------------------------------------------------------ 无害解析器
PARSER = (
    '"""无害解析器：只有 token 命中 MAGIC 才算命中（不碰网络、不写目录外）。"""\n'
    "import json\n"
    "import pathlib\n"
    "import sys\n\n"
    "def parse(config):\n"
    '    return bool(config.get("token") == "MAGIC")\n\n'
    "def main():\n"
    '    cfg = json.loads(pathlib.Path("config.json").read_text(encoding="utf-8"))\n'
    "    hit = parse(cfg)\n"
    '    print("hit" if hit else "miss")\n'
    "    return 0 if hit else 1\n\n"
    'if __name__ == "__main__":\n'
    "    sys.exit(main())\n"
)
CONFIG_RAW = '{"token": "raw"}\n'
CONFIG_MAGIC = '{"token": "MAGIC"}\n'

# ------------------------------------------------------------------ 越界探针
PROBE_WRITE = (
    '"""越界写探针：工作区外写标记；写成功才算“隔离失败”。"""\n'
    "import pathlib\n"
    "import sys\n\n"
    "target = pathlib.Path(sys.argv[1])\n"
    "try:\n"
    "    target.write_text('escaped', encoding='utf-8')\n"
    "except OSError as exc:\n"
    "    print('write_denied:', exc)\n"
    "    sys.exit(3)\n"
    "print('WROTE_OUTSIDE')\n"
    "sys.exit(0)\n"
)
PROBE_NET = (
    '"""断网探针：连宿主上确实在监听的端口；连上就算“隔离失败”。"""\n'
    "import socket\n"
    "import sys\n\n"
    "sock = socket.socket()\n"
    "sock.settimeout(2.0)\n"
    "try:\n"
    "    sock.connect(('127.0.0.1', int(sys.argv[1])))\n"
    "except OSError as exc:\n"
    "    print('net_denied:', exc)\n"
    "    sys.exit(3)\n"
    "print('CONNECTED')\n"
    "sys.exit(0)\n"
)


# ------------------------------------------------------------------ fixtures
def _parser_workspace(base: Path, **kwargs) -> TaskWorkspace:
    """真任务副本：原件只读 + 副本可写 + 隔离内构建/冒烟。"""
    origin = base / "origin"
    origin.mkdir(parents=True, exist_ok=True)
    (origin / "parser.py").write_text(PARSER, encoding="utf-8")
    (origin / "config.json").write_text(CONFIG_RAW, encoding="utf-8")
    return TaskWorkspace.create(
        base / "ws", origin, task_id=TASK,
        build_command=[PY, "-m", "py_compile", "parser.py"],
        smoke_command=[PY, "parser.py"], **kwargs)


def _probe_workspace(base: Path, name: str, body: str, args: list[str]):
    """一个只为探针存在的工作区：构建是 no-op（ok），冒烟就是探针本身。"""
    root = base / f"probe-{name}"
    origin = root / "origin"
    origin.mkdir(parents=True, exist_ok=True)
    (origin / f"{name}.py").write_text(body, encoding="utf-8")
    (origin / "noop.py").write_text("print('build ok')\n", encoding="utf-8")
    ws = TaskWorkspace.create(
        root / "ws", origin, task_id=f"{TASK}-{name}",
        build_command=[PY, "noop.py"],
        smoke_command=[PY, f"{name}.py", *args])
    build = ws.build()
    assert build.status == "ok", build.to_dict()
    assert build.executed_isolated is True, build.to_dict()
    return ws, ws.smoke(build=build)


def _write_probe(base: Path) -> tuple[Path, object]:
    marker = base / "out-of-workspace-marker.txt"
    if marker.exists():
        marker.unlink()
    _ws, smoke = _probe_workspace(base, "probe_write", PROBE_WRITE, [str(marker)])
    return marker, smoke


def _net_probe(base: Path) -> tuple[str, object]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = int(server.getsockname()[1])
    try:
        # 先证明这个端口在宿主上是**真的能连**：隔离里连不上才有意义
        probe = socket.create_connection(("127.0.0.1", port), timeout=2.0)
        probe.close()
        _ws, smoke = _probe_workspace(base, "probe_net", PROBE_NET, [str(port)])
    finally:
        server.close()
    return str(port), smoke


def _probes(base: Path) -> list[dict]:
    """真跑两条越界探针并压成 `handoff.isolation_probe()` 行（证据是哈希）。"""
    marker, write_smoke = _write_probe(base)
    port, net_smoke = _net_probe(base)
    write_ok = (write_smoke.exit_code == 3 and not marker.exists()
                and write_smoke.executed_isolated is True)
    net_body = Path(net_smoke.log_path).read_text(encoding="utf-8")
    net_ok = (net_smoke.exit_code == 3 and "CONNECTED" not in net_body
              and net_smoke.executed_isolated is True)
    return [
        handoff.isolation_probe(
            "write_confined", ok=write_ok,
            evidence={"smoke_id": write_smoke.smoke_id,
                      "exit_code": write_smoke.exit_code,
                      "marker_absent": not marker.exists(),
                      "log_sha256": write_smoke.log_sha256,
                      "isolation": write_smoke.isolation}),
        handoff.isolation_probe(
            "network_denied", ok=net_ok,
            evidence={"smoke_id": net_smoke.smoke_id,
                      "exit_code": net_smoke.exit_code,
                      "port": port, "log_sha256": net_smoke.log_sha256,
                      "isolation": net_smoke.isolation}),
    ]


def _acceptance_record(*, task_id: str = TASK) -> dict:
    """一条自洽的验收记录（**替身事实**，只用于“记录被改就失效”的单元断言）。"""
    from types import SimpleNamespace

    def facts(tag: str, **over):
        doc = {"isolation": "bwrap", "network": "none", "cap_drop": True,
               "ro_root": True, "pidns": True, "no_new_privs": True,
               "executed_isolated": True, "log_sha256": tag * 64}
        doc.update(over)
        return SimpleNamespace(build_id="bd-" + tag * 16,
                               smoke_id="sm-" + tag * 16, **doc)

    probes = [handoff.isolation_probe("write_confined", ok=True,
                                      evidence={"marker_absent": True}),
              handoff.isolation_probe("network_denied", ok=True,
                                      evidence={"exit_code": 3})]
    return handoff.build_isolation_acceptance(
        task_id=task_id, build=facts("a"), smoke=facts("b"),
        probes=probes).to_dict()


def _task_spec(metadata: dict) -> TaskSpec:
    return TaskSpec(task_id=TASK, benchmark="vulngym", target="parser",
                    mode="smoke", budget=Budget(), metadata=metadata)


def _none_info() -> dict:
    """`mode=none` 的隔离信息：宿主执行，绝不合格。"""
    return {"mode": "none", "prefix": [], "network": "host",
            "no_new_privs": False, "cap_drop": False, "ro_root": False,
            "pidns": False}


def _unshare_info() -> dict:
    """`mode=unshare` 的隔离信息：断网 + no_new_privs，但**不是强隔离**。"""
    return {"mode": "unshare", "prefix": ["unshare", "-rn"], "network": "none",
            "no_new_privs": True, "cap_drop": False, "ro_root": False,
            "pidns": False}


# ================================================== 1. 正常回归（隔离内三态）
def test_normal_regression_miss_hit_miss_inside_isolation(tmp_path):
    """baseline → modify → revert：行为未命中→命中→未命中，哈希与隔离事实都回来。"""
    ws = _parser_workspace(tmp_path)
    baseline = ws.current_revision()
    baseline_manifest = ws.working_manifest()

    build0 = ws.build()
    assert build0.status == "ok", build0.to_dict()
    assert build0.executed_isolated is True
    assert build0.isolation in handoff.ISOLATION_EXECUTORS
    assert build0.network == "none" and build0.cap_drop and build0.ro_root
    smoke0 = ws.smoke(build=build0)
    assert (smoke0.status, smoke0.kind, smoke0.exit_code) == ("failed", "target", 1)
    assert smoke0.executed_isolated is True
    assert smoke0.to_dict()["executed_isolated"] is True

    ws.stage({"config.json": CONFIG_MAGIC}, reason="token -> MAGIC")
    modified = ws.commit(reason="token -> MAGIC")
    build1 = ws.build(modified)
    smoke1 = ws.smoke(modified, build=build1)
    assert (smoke1.status, smoke1.exit_code) == ("passed", 0)
    assert build1.build_id != build0.build_id

    reverted = ws.revert(to_revision=baseline.revision_id, reason="back to raw")
    build2 = ws.build(reverted)
    smoke2 = ws.smoke(reverted, build=build2)
    assert (smoke2.status, smoke2.exit_code) == ("failed", 1)

    # 回退哈希一致：manifest 回到 baseline，原件没动
    assert reverted.manifest_sha256 == baseline.manifest_sha256
    assert ws.working_manifest() == baseline_manifest
    assert ws.origin_integrity()["ok"] is True

    # 六次执行（3 build + 3 smoke）全部在隔离里，逐条落台账
    ledger = ws.isolation_ledger()
    assert [row["stage"] for row in ledger] == [
        "build", "smoke", "build", "smoke", "build", "smoke"]
    assert all(row["executed_isolated"] is True for row in ledger)
    assert all(row["network"] == "none" for row in ledger)
    assert {row["record_id"] for row in ledger} >= {
        build0.build_id, smoke0.smoke_id,
        build1.build_id, smoke1.smoke_id,
        build2.build_id, smoke2.smoke_id}
    policy = ws.state()["isolation"]
    assert policy["executions"] == 6
    assert policy["mode"] == "auto" and policy["require_isolation"] is True
    # policy 里只写“要求什么”，不写“跑没跑过”
    assert "executed_isolated" not in policy
    # 快照里的“实际”在另一个键下（逐条来自台账）
    snapshot = ws.state()["isolation_executions"]
    assert snapshot["count"] == 6
    assert snapshot["builds"] == 3 and snapshot["smokes"] == 3
    assert snapshot["executed_isolated"] == 6
    assert snapshot["last"]["stage"] == "smoke"
    assert snapshot["last"]["executed_isolated"] is True
    assert snapshot["last"]["network"] == "none"
    meta = json.loads((ws.root / "workspace.json").read_text(encoding="utf-8"))
    assert meta["isolation"] == "auto" and meta["require_isolation"] is True
    assert "executed_isolated" not in json.dumps(meta)
    assert (ws.root / ISOLATION_LEDGER).is_file()


# ================================================== 2. 越界写
@HARD_ISOLATION
def test_write_outside_workspace_is_denied(tmp_path):
    """工作区外写标记：脚本自己判失败，宿主上标记不存在，且它确实在隔离里跑过。"""
    marker, smoke = _write_probe(tmp_path)
    assert smoke.status == "failed"
    assert smoke.exit_code == 3, Path(smoke.log_path).read_text(encoding="utf-8")
    assert smoke.executed_isolated is True
    assert not marker.exists(), "工作区外被写穿了：隔离没生效"
    body = Path(smoke.log_path).read_text(encoding="utf-8")
    assert "WROTE_OUTSIDE" not in body
    assert "write_denied" in body


# ================================================== 3. 断网
@HARD_ISOLATION
def test_network_connect_is_denied(tmp_path):
    """宿主监听可用（同端口在宿主上连得通），隔离里连同一端口必须失败。"""
    port, smoke = _net_probe(tmp_path)
    body = Path(smoke.log_path).read_text(encoding="utf-8")
    assert smoke.executed_isolated is True
    assert smoke.exit_code == 3, body
    assert "CONNECTED" not in body
    assert "net_denied" in body
    evidence = {"port": port, "exit_code": smoke.exit_code,
                "log_sha256": smoke.log_sha256}
    probe = handoff.isolation_probe("network_denied", ok=True, evidence=evidence)
    assert len(probe["evidence_sha256"]) == 64


# ================================================== 4. 缺隔离
def test_missing_isolation_refuses_and_runs_nothing(tmp_path, monkeypatch):
    """解析不到合格执行器：`WorkspaceError`，命令一次都不许跑，台账不许有行。"""
    ws = _parser_workspace(tmp_path)
    trace = tmp_path / "command-ran.txt"
    mono = tmp_path / "pyc-marker.txt"
    ws.build_command = (PY, "-c",
                        f"open({str(trace)!r}, 'w').write('ran')")
    ws.smoke_command = (PY, "-c", f"open({str(mono)!r}, 'w').write('ran')")

    monkeypatch.setattr(isolation_mod, "resolve",
                        lambda mode="auto", require=False: _none_info())
    with pytest.raises(WorkspaceError) as exc:
        ws.build()
    assert "strong_isolation_required" in str(exc.value)
    assert not trace.exists(), "缺隔离时构建命令仍被执行了"
    assert ws.revisions.builds() == ()
    assert ws.isolation_ledger() == []

    def _boom(mode="auto", require=False):
        raise RuntimeError("bubblewrap unavailable")

    monkeypatch.setattr(isolation_mod, "resolve", _boom)
    with pytest.raises(WorkspaceError) as exc2:
        ws.smoke(build=BuildRecord(
            build_id="bd-" + "d" * 16, revision_id=ws.current_revision().revision_id,
            status="ok", workdir=str(tmp_path)))
    assert "isolation_unavailable" in str(exc2.value)
    assert not mono.exists()
    assert ws.isolation_ledger() == []

    # 显式要宿主执行却又要求隔离 → 建工作区就拒绝（fail-closed 写在最前面）
    with pytest.raises(WorkspaceError):
        TaskWorkspace(tmp_path / "nowhere", task_id=TASK,
                      isolation="none", require_isolation=True)
    with pytest.raises(WorkspaceError):
        _parser_workspace(tmp_path / "bogus", isolation="chroot")


# ================================================== 4b. auto 降级 / 显式 unshare
def test_auto_unshare_downgrade_refuses_before_spawn(tmp_path, monkeypatch):
    """auto 只剩 unshare、显式 unshare：build 与 smoke 都在 spawn 前拒绝。

    断言的是**没发生**的事：工作区外 marker 不存在、构建/冒烟目录没落、台账为空、
    记录一条都没有。弱隔离能跑起来的旧口径在这里必须失效。
    """
    ws = _parser_workspace(tmp_path)
    build_marker = tmp_path / "out-of-workspace-build-marker.txt"
    smoke_marker = tmp_path / "out-of-workspace-smoke-marker.txt"
    build_marker.unlink(missing_ok=True)
    smoke_marker.unlink(missing_ok=True)
    ws.build_command = (PY, "-c",
                        f"import pathlib; pathlib.Path({str(build_marker)!r})"
                        ".write_text('ran')")
    ws.smoke_command = (PY, "-c",
                        f"import pathlib; pathlib.Path({str(smoke_marker)!r})"
                        ".write_text('ran')")

    monkeypatch.setattr(isolation_mod, "resolve",
                        lambda mode="auto", require=False: _unshare_info())

    with pytest.raises(WorkspaceError) as exc:
        ws.build()
    assert "strong_isolation_required" in str(exc.value)
    assert "unshare" in str(exc.value)
    assert not build_marker.exists(), "auto 降级到 unshare 仍执行了构建"
    assert ws.revisions.builds() == ()
    assert ws.isolation_ledger() == []
    assert list((ws.root / "builds").iterdir()) == [], "拒绝之前不该复制构建目录"

    # 冒烟：先给一条“自报隔离”的构建记录，唯一能挡住它的就是强隔离口径
    revision = ws.current_revision()
    workdir = tmp_path / "declared-isolated-build"
    workdir.mkdir()
    declared = IsolatedBuildRecord(
        build_id="bd-" + "a" * 16, revision_id=revision.revision_id,
        status="ok", exit_code=0, workdir=str(workdir),
        isolation="bwrap", network="none", cap_drop=True, ro_root=True,
        pidns=True, no_new_privs=True, executed_isolated=True,
        prefix_sha256="0" * 64)
    with pytest.raises(WorkspaceError) as exc2:
        ws.smoke(revision, build=declared)
    assert "strong_isolation_required" in str(exc2.value)
    assert not smoke_marker.exists(), "auto 降级到 unshare 仍执行了冒烟"
    assert ws.revisions.smokes() == ()
    assert ws.isolation_ledger() == []

    # 强隔离闸在 smoke 里是**第一道**：没有构建记录也先报强隔离缺失，而不是 setup_error
    with pytest.raises(WorkspaceError) as exc4:
        ws.smoke()
    assert "strong_isolation_required" in str(exc4.value)

    # 显式 unshare 也不是“知情降级”的入口：同样在 spawn 前拒绝
    explicit = _parser_workspace(tmp_path / "explicit", isolation="unshare")
    with pytest.raises(WorkspaceError) as exc3:
        explicit.build()
    assert "strong_isolation_required" in str(exc3.value)
    assert explicit.revisions.builds() == ()
    assert explicit.isolation_ledger() == []


def test_unshare_never_recorded_as_isolated_execution(tmp_path):
    """`unshare` 的记录只能是 qualified=False / strong=False / executed=False。"""
    assert STRONG_ISOLATION_MODES == ("bwrap", "container")
    assert tuple(QUALIFIED_ISOLATION_MODES) == STRONG_ISOLATION_MODES
    assert "unshare" not in QUALIFIED_ISOLATION_MODES

    weak = _observed_isolation_facts(
        _unshare_info(), ["unshare", "-rn", "--", "true"], executed=True)
    assert weak["qualified"] is False and weak["strong"] is False
    assert weak["executed_isolated"] is False

    strong = _observed_isolation_facts(
        {"mode": "bwrap", "network": "none", "cap_drop": True,
         "ro_root": True, "pidns": True, "no_new_privs": True},
        ["bwrap", "--", "true"], executed=True)
    assert strong["qualified"] is True and strong["strong"] is True
    assert strong["executed_isolated"] is True

    # 旧台账里的 unshare 行读回来也按强隔离口径复算（文件不改，结论不能洗白）
    ws = _parser_workspace(tmp_path)
    legacy = {"schema": "vulnmap.adaptive.isolation_execution.v1",
              "stage": "build", "record_id": "bd-" + "f" * 16,
              "revision_id": ws.current_revision().revision_id,
              "task_id": TASK, "argv": ["unshare", "-rn", "--", "true"],
              "isolation": "unshare", "network": "none", "cap_drop": False,
              "ro_root": False, "pidns": False, "no_new_privs": True,
              "executed_isolated": True, "prefix_sha256": "0" * 64,
              "at": "2026-01-01T00:00:00+00:00"}
    (ws.root / ISOLATION_LEDGER).write_text(
        json.dumps(legacy, ensure_ascii=False) + "\n", encoding="utf-8")
    row = ws.isolation_ledger()[0]
    assert row["qualified"] is False and row["strong"] is False
    assert row["executed_isolated"] is False
    facts = ws.isolation_facts_for(legacy["record_id"])
    assert facts["strong"] is False and facts["executed_isolated"] is False
    summary = ws.isolation_summary()
    assert summary["count"] == 1 and summary["executed_isolated"] == 0
    assert summary["strong_executions"] == 0
    assert summary["low_assurance_executions"] == 1


@HARD_ISOLATION
def test_bwrap_strong_isolation_still_executes(tmp_path):
    """强隔离正常路径不受影响：bwrap 下 build/smoke 仍真跑且记为强隔离。"""
    ws = _parser_workspace(tmp_path)
    build = ws.build()
    assert build.status == "ok", build.to_dict()
    assert build.isolation == "bwrap"
    assert build.executed_isolated is True
    assert build.qualified is True and build.strong is True
    assert build.to_dict()["strong"] is True
    smoke = ws.smoke(build=build)
    assert smoke.executed_isolated is True
    assert smoke.strong is True
    assert [row["stage"] for row in ws.isolation_ledger()] == ["build", "smoke"]
    assert all(row["strong"] is True for row in ws.isolation_ledger())


# ================================================== 5. 自报放行（必须不放行）
def test_self_reported_isolation_is_advisory_only(tmp_path):
    """提交者填 `isolation_accepted` 只留痕：判定仍是 advisory，伪造记录也放不行。"""
    task = {"task_id": TASK,
            "metadata": {"authorized": True, "isolation_accepted": "yes"}}
    gate = handoff.ProposalGate.from_task(task)
    decision = gate.admit(action="propose", params={"revision": {"files": {}}})
    assert decision.status == "advisory"
    assert decision.to_dict()["applied"] is False
    assert decision.blockers == ("isolation:missing",)
    assert gate.acceptance.ok is False
    assert gate.acceptance.declared_isolation == "declared"      # 自填留痕
    assert gate.acceptance.isolation == "missing"                # 判定仍缺
    assert decision.acceptance["declared"]["authority"] == "advisory"

    # 空文件 / 不存在的文件都不是记录
    empty = tmp_path / handoff.ISOLATION_ACCEPTANCE_FILE
    empty.write_text("", encoding="utf-8")
    assert handoff.ProposalGate.from_task(task, path=empty).admit().status == \
        "advisory"
    assert handoff.ProposalGate.from_task(
        task, path=tmp_path / "missing.jsonl").admit().status == "advisory"

    # 记录被改一个字段 → 复算不上 → rejected，仍然不放行
    forged = _acceptance_record()
    forged["ro_root"] = False
    gate2 = handoff.ProposalGate(
        task={"task_id": TASK, "metadata": {"authorized": True}},
        isolation_record=forged)
    verdict = gate2.admit(action="propose")
    assert verdict.status == "advisory"
    assert verdict.blockers == ("isolation:rejected",)
    assert gate2.acceptance.reason == "evidence_hash_mismatch"

    # 检查项被抹掉（哈希也一起改得很自洽）→ 检查项不全仍 rejected
    forged2 = _acceptance_record()
    forged2["checks"] = {**forged2["checks"], "network_denied": False}
    state, detail = handoff.verify_isolation_acceptance(forged2, task_id=TASK)
    assert state == "rejected"
    assert detail["reason"].startswith("evidence_hash_mismatch") or \
        detail["reason"].startswith("checks_failed")


# ================================================== 6. 平台记录放行
def test_platform_record_grants_apply(tmp_path):
    """真隔离执行 + 真越界探针 → 平台侧记录 accepted → 才 `apply`。"""
    ws = _parser_workspace(tmp_path)
    build = ws.build()
    smoke = ws.smoke(build=build)
    probes = _probes(tmp_path)
    assert all(probe["ok"] is True for probe in probes), probes

    acceptance = handoff.build_isolation_acceptance(
        task_id=TASK, build=build, smoke=smoke, probes=probes)
    assert acceptance.status == "accepted", acceptance.reason
    assert acceptance.executed_isolated is True
    assert acceptance.isolation in handoff.ISOLATION_EXECUTORS
    assert all(acceptance.checks[name] is True
               for name in handoff.ISOLATION_CHECKS)
    assert len(acceptance.evidence_sha256) == 64
    assert acceptance.checked_at

    store = PlatformStore(tmp_path / "platform.db")
    store.create_task(_task_spec({"authorized": True,
                                  "isolation_accepted": "yes"}))
    path = tmp_path / handoff.ISOLATION_ACCEPTANCE_FILE
    row = handoff.record_isolation_acceptance(store, acceptance=acceptance,
                                              path=path)
    assert row["status"] == "accepted"
    assert row["evidence_sha256"] == acceptance.evidence_sha256
    assert row["checks"] == dict(acceptance.checks)
    assert [item["kind"] for item in row["evidence"]].count("probe") == 2
    # 记录里没有提交者自填字段：那份“自报”没进平台台账
    assert "isolation_accepted" not in json.dumps(row, ensure_ascii=False)
    assert store.latest_isolation_acceptance(TASK)["acceptance_id"] == \
        acceptance.acceptance_id
    assert handoff.load_isolation_acceptance(path)[-1]["acceptance_id"] == \
        acceptance.acceptance_id

    task = store.get_task(TASK)
    for gate in (handoff.ProposalGate.from_task(task, store=store),
                 handoff.ProposalGate.from_task(task, path=path),
                 handoff.ProposalGate.from_task(
                     task, isolation_record=row)):
        assert gate.acceptance.ok is True
        decision = gate.admit(scope="engineering", action="propose",
                             params={"revision": {"files": {}}})
        assert decision.status == "apply"
        assert decision.blockers == ()
        assert decision.acceptance["authorization"] == "true"
        assert decision.acceptance["isolation"] == "accepted"
        assert decision.acceptance["acceptance_id"] == acceptance.acceptance_id

    # 别的任务借不走这条记录（库按 task_id 查）
    other = handoff.ProposalGate.from_task(
        {"task_id": OTHER_TASK, "metadata": {"authorized": True}}, store=store)
    assert other.acceptance.isolation == "missing"
    assert other.admit(action="propose").status == "advisory"

    # 记录只增不改：同 id 改内容 → 拒绝写
    from agent.platform.task import TaskError
    broken = dict(row)
    broken["reason"] = "rewritten"
    with pytest.raises(TaskError):
        store.save_isolation_acceptance(broken)


# ================================================== 7. 计划 ≠ 实际
def test_planned_isolation_never_masquerades_as_executed(tmp_path):
    """计划里写 bwrap、没真跑过 → 记录只能 rejected；宿主 build 不许拿来隔离冒烟。"""
    planned = {"isolation": "bwrap", "network": "none", "cap_drop": True,
               "ro_root": True, "pidns": True, "no_new_privs": True,
               "executed_isolated": False, "log_sha256": "c" * 64,
               "build_id": "bd-" + "c" * 16, "smoke_id": "sm-" + "d" * 16}
    probes = [handoff.isolation_probe("write_confined", ok=True,
                                      evidence={"marker_absent": True}),
              handoff.isolation_probe("network_denied", ok=True,
                                      evidence={"exit_code": 3})]
    acceptance = handoff.build_isolation_acceptance(
        task_id=TASK, build=planned, smoke=planned, probes=probes)
    assert acceptance.status == "rejected"
    assert acceptance.checks["network_denied"] is True
    assert acceptance.checks["capability_dropped"] is True
    assert acceptance.checks["executed_isolated"] is False
    assert "check_failed:executed_isolated" in acceptance.reason
    assert handoff.verify_isolation_acceptance(acceptance.to_dict(),
                                              task_id=TASK)[0] == "rejected"

    # 什么都没跑：证据为空 → rejected（不靠“计划”签发记录）
    empty = handoff.build_isolation_acceptance(task_id=TASK)
    assert empty.status == "rejected" and empty.evidence == ()
    assert handoff.verify_isolation_acceptance(None) == (
        "missing", {"reason": "no_platform_record",
                    "authority": "platform_record_only"})

    # 宿主时代留下的 BuildRecord（无隔离事实）不能拿去隔离冒烟
    ws = _parser_workspace(tmp_path)
    revision = ws.current_revision()
    workdir = tmp_path / "legacy-build"
    workdir.mkdir(parents=True, exist_ok=True)
    legacy = BuildRecord(build_id="bd-" + "e" * 16,
                         revision_id=revision.revision_id, status="ok",
                         exit_code=0, workdir=str(workdir))
    with pytest.raises(WorkspaceError) as exc:
        ws.smoke(revision, build=legacy)
    assert "isolation_violation" in str(exc.value)
    assert ws.revisions.smokes() == ()
