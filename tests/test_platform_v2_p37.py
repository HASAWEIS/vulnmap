"""V2 P3.7 验收：CG/EG 源码包自动解包 + 镜像 digest + replay 执行路径。

口径（与需求逐条对应）：

1. **自动解包**：workspace 只有 `repo-vul.tar.gz` 时，`understand` 自动把源码包解到
   `<workspace>/.unpacked/<sha256[:16]>/` 并接入 D0/D1——`source_count`/`entry_points`/
   `call_sites` 必须来自解包树，`unpack` 元数据（archive/sha256/files/bytes/cached）
   进 ProgramIndex；同包第二次构建命中缓存、不重复解包；
2. **不写仓库外**：解包写入点只可能在 workspace 内；`../`、绝对路径、盘符、
   符号链接等成员一律 `UnpackError`（写盘前拒绝），恶意包不会在 workspace 外留下文件；
3. **镜像 digest**：从 task.json 推镜像名并取 digest 写进 `ProgramIndex.images`；
   docker inspect 失败**不阻断**索引，记 `warnings`（审计字段，不是错误）；
4. **replay**：CG/EG 工作区有旧 PoC 时 planner 优先 `kind=replay`，
   `inputs.replay` 记 PoC 溯源；`run --kind replay` 重放 PoC + 日志，产出 Candidate
   （input/log 证据）+ 可直接喂 `verify --spec` 的判据输入；
   没有 PoC / 没有执行手段 / 超时 → `ReplayError` → 状态 FAILED（绝不落 NO_REPRO）。

全局硬约束：replay 产物不得出现 `confirmed` 之类结论；单侧重放只到 Candidate。
"""
from __future__ import annotations

import hashlib
import io
import json
import shlex
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import (EventBus, PlatformStore, TaskSpec, build_candidates,
                            run_execution, run_hypotheses, run_plan,
                            run_preflight, run_understand)
from agent.platform.program import (ProgramError, ProgramIndex, UnpackError,
                                    discover_archives, ensure_sources,
                                    unpack_archive)
from agent.platform.verify import normalize_spec

BIN = ROOT / "bin" / "platform.py"

POC_BYTES = b"%PDF-1.4\n" + b"A" * 128
ASAN_LINE = ("==7==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x0\n"
             "    #0 0x4bf1e2 in pdfi_open_CIDFont_substitute_file "
             "/src/ghostpdl/pdf/pdf_font.c:332\n")


# ------------------------------------------------------------------ helpers
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _task(ws: Path, *, task_id: str = "p37",
          benchmark: str = "cybergym") -> dict:
    return {"task_id": task_id, "benchmark": benchmark, "target": str(ws)}


def _write_tar(path: Path, members: dict[str, bytes],
               links: tuple[str, ...] = ()) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tf.addfile(info, io.BytesIO(body))
        for name in links:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = "../../etc/passwd"
            tf.addfile(info)
    return path


def _cg_workspace(base: Path, *, sources: int = 0, archive: int = 0,
                  poc: bool = False) -> Path:
    """造一个 CG 工作区：可选 src/、repo-vul.tar.gz、旧 PoC + 旧日志。"""
    ws = base / "CG-37-arvo-1"
    ws.mkdir(parents=True)
    (ws / "task.json").write_text(json.dumps({
        "schema": "vulnmap.task.v1", "case_id": "CG-37", "task_id": "arvo:1",
        "benchmark": "cybergym", "project": "demo",
        "component": "src/a.c main", "target_cwe": "CWE-121",
        "image_vul": "n132/arvo:1-vul", "image_fix": "n132/arvo:1-fix",
    }, ensure_ascii=False), encoding="utf-8")
    if sources:
        src = ws / "src"
        src.mkdir()
        for index in range(sources):
            body = ("#include <string.h>\nint main(void){char b[4];"
                    " memcpy(b, \"aaaaaaaa\", 8); return 0;}\n"
                    if index == 0 else f"void helper_{index}(void) {{}}\n")
            (src / f"f{index}.c").write_text(body, encoding="utf-8")
    if archive:
        members = {}
        for index in range(archive):
            members[f"demo/src/g{index}.c"] = (
                "#include <string.h>\nint main(void){char b[4];"
                " memcpy(b, \"bbbbbbbb\", 8); return 0;}\n"
                if index == 0 else f"int g_{index}(void) {{ return {index}; }}\n"
            ).encode("utf-8")
        _write_tar(ws / "repo-vul.tar.gz", members)
    if poc:
        (ws / "artifacts" / "verify").mkdir(parents=True)
        (ws / "artifacts" / "verify" / "pdf-basefont4096.bin").write_bytes(POC_BYTES)
        (ws / "artifacts" / "verify" / "result.json").write_text(json.dumps({
            "schema": "vulnmap.verify.v1",
            "poc": {"path": "artifacts/verify/pdf-basefont4096.bin",
                    "sha256": _sha256(POC_BYTES), "size": len(POC_BYTES)},
            "vul": {"exit_code": 1, "log": "logs/V4.pdf-basefont4096.44034-vul.log"},
            "fix": {"exit_code": 0, "log": ""},
        }, ensure_ascii=False), encoding="utf-8")
        (ws / "logs").mkdir()
        (ws / "logs" / "V4.pdf-basefont4096.44034-vul.log").write_text(
            "$ docker run ...\n" + ASAN_LINE, encoding="utf-8")
    return ws


def _driver(tmp_path: Path, *, exit_code: int = 1, body: str = "") -> str:
    """假 benchmark 驱动：读 {poc}，打印 ASAN 后按 exit_code 退出。"""
    script = tmp_path / f"driver-{exit_code}.py"
    script.write_text(
        "import sys\n"
        f"data = open(sys.argv[1], 'rb').read()\n"
        f"sys.stdout.write({body or ASAN_LINE!r})\n"
        f"sys.exit({exit_code})\n", encoding="utf-8")
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(script))} {{poc}}"


def _prepared(tmp_path, ws: Path, *, task_id: str = "p37") -> tuple:
    store = PlatformStore(tmp_path / "p37.db")
    store.create_task(TaskSpec(
        task_id=task_id, benchmark="cybergym", target=str(ws),
        metadata={"authorized": True, "task_id": "arvo:1",
                  "image_vul": "n132/arvo:1-vul"}))
    bus = EventBus(store)
    assert run_preflight(task_id, store, bus)["state"] == "READY"
    assert run_understand(task_id, store, bus)["state"] == "UNDERSTANDING"
    assert run_hypotheses(task_id, store, bus)["state"] == "HYPOTHESES"
    return store, bus


def _run(*args: str, db: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(BIN), "--db", str(db), *args],
                          capture_output=True, text=True, timeout=180)


# ------------------------------------------------------- 1. 自动解包 + D0/D1
def test_archive_is_unpacked_into_workspace_cache(tmp_path):
    ws = _cg_workspace(tmp_path, archive=3)
    archive = ws / "repo-vul.tar.gz"
    expected = _sha256(archive.read_bytes())
    assert discover_archives(ws) == [archive]

    index = ProgramIndex.build(_task(ws))
    doc = index.to_dict()

    assert doc["unpack"], "解包元数据必须进 ProgramIndex"
    assert doc["unpack"]["sha256"] == expected
    assert doc["unpack"]["archive"] == str(archive)
    assert doc["unpack"]["files"] == 3
    assert doc["unpack"]["bytes"] > 0
    assert doc["unpack"]["cached"] is False

    # 写入点只在 workspace 内，且是内容寻址缓存
    cache_dir = Path(doc["unpack"]["cache_dir"])
    assert cache_dir.is_relative_to(ws)
    assert cache_dir.name == expected[:16]
    assert cache_dir.parent.name == ".unpacked"
    assert cache_dir.is_dir()

    # D0/D1 真的吃到了解包树：源文件计数/入口/调用点都来自 archive
    assert doc["source_count"] == 3
    assert doc["coverage"]["scanned_sources"] == 3
    assert doc["coverage"]["total_sources"] == 3
    assert doc["root"] == doc["unpack"]["src_root"]
    assert sorted(doc["sources"]) == ["g0.c", "g1.c", "g2.c"]
    assert any(e["kind"] == "main" and e["file"] == "g0.c"
               for e in doc["entry_points"])
    assert any(s["callee"] == "memcpy" and s["file"] == "g0.c"
               for s in doc["call_sites"])
    assert any("解包 repo-vul.tar.gz" in note for note in doc["notes"])
    assert ProgramIndex.from_dict(doc).sha256 == doc["sha256"]


def test_unpack_cache_is_reused_on_second_build(tmp_path):
    ws = _cg_workspace(tmp_path, archive=2)
    first = ProgramIndex.build(_task(ws)).to_dict()
    manifest = Path(first["unpack"]["cache_dir"]) / "manifest.json"
    stamp = manifest.stat().st_mtime_ns

    second = ProgramIndex.build(_task(ws)).to_dict()
    assert second["unpack"]["cached"] is True
    assert second["unpack"]["cache_dir"] == first["unpack"]["cache_dir"]
    assert second["source_count"] == first["source_count"] == 2
    assert manifest.stat().st_mtime_ns == stamp, "命中缓存不应重写解包树"


def test_src_takes_precedence_over_archive(tmp_path):
    ws = _cg_workspace(tmp_path, sources=1, archive=4)
    doc = ProgramIndex.build(_task(ws)).to_dict()
    assert doc["source_count"] == 1
    assert doc["unpack"] == {}, "workspace 自带 src/ 时不该再解包（避免双份索引）"
    assert doc["root"].endswith("src")
    assert sorted(doc["sources"]) == ["f0.c"]


def test_ensure_sources_returns_none_without_archive(tmp_path):
    ws = _cg_workspace(tmp_path)
    assert discover_archives(ws) == []
    assert ensure_sources(ws) is None
    doc = ProgramIndex.build(_task(ws)).to_dict()
    assert doc["source_count"] == 0
    assert doc["unpack"] == {}
    assert any("没有可解的源码包" in note for note in doc["notes"])


def test_missing_site_packages_style_archive_is_rejected(tmp_path):
    ws = _cg_workspace(tmp_path)
    bad = ws / "repo-vul.tar.gz"
    bad.write_bytes(b"not a tar archive at all")
    with pytest.raises(UnpackError):
        ProgramIndex.build(_task(ws))


# ------------------------------------------------- 2. 路径穿越 / 链接被拒绝
@pytest.mark.parametrize("member", [
    "../escape.c", "demo/../../escape.c", "/tmp/vulnmap-escape.c",
    "C:/Windows/escape.c", "demo\\..\\..\\escape.c",
])
def test_path_traversal_members_are_rejected(tmp_path, member):
    ws = _cg_workspace(tmp_path)
    archive = _write_tar(ws / "repo-vul.tar.gz",
                         {"demo/src/ok.c": b"int ok(void){return 0;}\n", member: b"pwn"})
    before = {p for p in tmp_path.rglob("*")}

    with pytest.raises(UnpackError) as excinfo:
        unpack_archive(archive)
    assert "escape" in str(excinfo.value) or "absolute" in str(excinfo.value) \
        or "drive" in str(excinfo.value)

    after = {p for p in tmp_path.rglob("*")}
    # 只允许缓存根目录被创建；不允许任何解包文件落到 workspace 外
    outside = {p for p in after - before
               if not p.is_relative_to(ws / ".unpacked")}
    assert outside == set(), f"解包写到了仓库外/缓存外：{sorted(map(str, outside))}"
    assert not (tmp_path / "escape.c").exists()
    assert not Path("/tmp/vulnmap-escape.c").exists()

    # 恶意包不能留下“可用缓存”
    assert not list((ws / ".unpacked").glob("*/manifest.json"))


def test_symlink_member_is_rejected(tmp_path):
    ws = _cg_workspace(tmp_path)
    archive = _write_tar(ws / "repo-vul.tar.gz",
                         {"demo/src/ok.c": b"int ok(void){return 0;}\n"},
                         links=("demo/src/link.c",))
    with pytest.raises(UnpackError) as excinfo:
        unpack_archive(archive)
    assert "not allowed" in str(excinfo.value)
    assert not (ws / "repo-vul.tar.gz").with_suffix("").exists()


def test_traversal_in_program_index_raises_and_leaves_no_cache(tmp_path):
    ws = _cg_workspace(tmp_path)
    _write_tar(ws / "repo-vul.tar.gz", {"../escape.c": b"pwn"})
    with pytest.raises(UnpackError):
        ProgramIndex.build(_task(ws))
    assert not list((ws / ".unpacked").glob("*/manifest.json"))


# --------------------------------------------------------- 3. 镜像 digest
def test_image_digest_written_and_failure_only_warns(tmp_path, monkeypatch):
    import agent.casekit as casekit
    import agent.checkpoint as checkpoint

    monkeypatch.setattr(casekit, "image_for",
                        lambda ws, side: f"n132/arvo:1-{side}")

    def _missing(image):
        raise LookupError(f"image not present locally: {image}")

    monkeypatch.setattr(checkpoint, "image_digest", _missing)
    ws_missing = _cg_workspace(tmp_path / "a", sources=1)
    index = ProgramIndex.build(_task(ws_missing))
    assert index.images["vul"] == {"name": "n132/arvo:1-vul",
                                   "digest": "", "present": False}
    assert index.images["fix"]["present"] is False
    assert any("docker inspect" in w for w in index.warnings)
    assert any("不阻断静态索引" in note for note in index.notes)
    index.validate()          # 失败只记 warning，索引仍然合法

    digest = "sha256:" + "a" * 64
    monkeypatch.setattr(checkpoint, "image_digest", lambda image: digest)
    ws_ok = _cg_workspace(tmp_path / "b", sources=1)
    ok = ProgramIndex.build(_task(ws_ok))
    assert ok.images["vul"]["digest"] == digest
    assert ok.images["vul"]["present"] is True
    assert ok.images["fix"]["digest"] == digest
    assert ok.warnings == []


def test_exploitgym_only_declares_vul_side(tmp_path, monkeypatch):
    import agent.casekit as casekit
    import agent.checkpoint as checkpoint

    monkeypatch.setattr(casekit, "image_for", lambda ws, side: f"cybergym/arvo:1-{side}")
    monkeypatch.setattr(checkpoint, "image_digest", lambda image: "sha256:" + "b" * 64)
    ws = _cg_workspace(tmp_path, sources=1)
    (ws / "task.json").write_text(json.dumps({
        "task_id": "arvo:1", "benchmark": "exploitgym", "project": "demo",
        "image": "cybergym/arvo:1-vul.exp.none-nogit", "image_mode": "exp.none",
    }), encoding="utf-8")
    index = ProgramIndex.build(_task(ws, benchmark="exploitgym"))
    assert set(index.images) == {"vul"}


# ------------------------------------------------------------- 4. replay
def test_planner_prefers_replay_when_old_poc_exists(tmp_path):
    ws = _cg_workspace(tmp_path, sources=1, poc=True)
    store, bus = _prepared(tmp_path, ws, task_id="p37-plan")
    out = run_plan("p37-plan", store, bus)
    plan = out["plan"]

    assert plan["kind"] == "replay"
    assert "旧 PoC" in plan["reason"] and "优先" in plan["reason"]
    pocs = plan["inputs"]["replay"]["pocs"]
    assert len(pocs) == 1
    assert pocs[0]["sha256"] == _sha256(POC_BYTES)
    assert pocs[0]["log"].endswith("V4.pdf-basefont4096.44034-vul.log")
    assert Path(plan["inputs"]["replay"]["poc_path"]).is_file()


def test_replay_success_writes_candidate_and_verification_spec(tmp_path):
    from agent.platform.executors.replay import discover_pocs

    ws = _cg_workspace(tmp_path, sources=1, poc=True)
    found = discover_pocs(ws)
    assert [p["sha256"] for p in found] == [_sha256(POC_BYTES)]
    assert found[0]["known_exit"] == 1

    store, bus = _prepared(tmp_path, ws, task_id="p37-replay")
    run_plan("p37-replay", store, bus)
    out = run_execution(
        "p37-replay", store, bus,
        workdir=tmp_path / "work", evidence_root=tmp_path / "evidence",
        kind_override="replay", replay_cmd=_driver(tmp_path))

    assert out["outcome"] == "candidate"
    assert out["state"] == "CANDIDATE"
    assert out["kind"] == "replay"
    assert out["exit_code"] == 1
    assert out["crashed"] is True
    assert out["replay_summary"]["method"] == "cmd"
    assert out["replay_summary"]["poc_sha256"] == _sha256(POC_BYTES)
    assert out["replay"]["spec"]["vul"]["exit_code"] == 1

    rows = store.list_candidates("p37-replay")
    assert len(rows) == 1
    cand = rows[0]
    assert cand["input_sha256"] == _sha256(POC_BYTES)
    assert cand["state"] == "new"
    assert cand["crash_type"] == "stack-buffer-overflow"
    assert cand["detail"]["source"] == "replay"
    assert cand["detail"]["input_evidence_sha256"]

    kinds = {row["kind"] for row in store.list_evidence("p37-replay")}
    assert {"replay_input", "replay_log", "replay_spec", "exec_stats"} <= kinds

    events = [e for e in bus.list("p37-replay") if e["event_type"] == "exec.finished"]
    payload = events[-1]["payload"]
    assert payload["kind"] == "replay"
    assert payload["outcome"] == "candidate"
    assert payload["replay"]["poc_sha256"] == _sha256(POC_BYTES)

    # 判据输入可直接喂 verify：只含该 benchmark 的字段，不混口径
    replay_row = [r for r in store.list_evidence("p37-replay")
                  if r["kind"] == "replay_spec"][0]
    spec_path = Path(replay_row["path"])
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    assert spec["input"]["sha256"] == _sha256(POC_BYTES)
    assert spec["vul"]["crashed"] is True and spec["vul"]["exit_code"] == 1
    assert spec["benchmark"] == "cybergym"
    normalized = normalize_spec("cybergym", spec)
    assert normalized["kind"] == "vuln_fix_diff"
    assert "verified" not in spec and "confirmed" not in spec


def test_replay_without_executor_fails_explicitly(tmp_path, monkeypatch):
    from agent.platform import TaskError
    from agent.platform.executors.replay import ReplayError

    ws = _cg_workspace(tmp_path, sources=1, poc=True)
    store, bus = _prepared(tmp_path, ws, task_id="p37-nofail")
    run_plan("p37-nofail", store, bus)

    monkeypatch.delenv("VULNMAP_REPLAY_CMD", raising=False)
    with pytest.raises(ReplayError):
        run_execution("p37-nofail", store, bus,
                      workdir=tmp_path / "work",
                      evidence_root=tmp_path / "evidence",
                      kind_override="replay",
                      replay_cmd=str(tmp_path / "does-not-exist") + " {poc}")

    task = store.get_task("p37-nofail")
    assert task["state"] == "FAILED"
    kinds = {row["kind"] for row in store.list_evidence("p37-nofail")}
    assert "exec_error" in kinds
    assert store.list_candidates("p37-nofail") == []
    finished = [e for e in bus.list("p37-nofail") if e["event_type"] == "exec.finished"]
    assert finished[-1]["payload"]["outcome"] == "failed"
    assert "replay" in finished[-1]["payload"]["error"].lower()


def test_replay_without_poc_fails_explicitly(tmp_path):
    from agent.platform.executors.replay import ReplayError

    ws = _cg_workspace(tmp_path, sources=1)          # 有源码，没有旧 PoC
    store, bus = _prepared(tmp_path, ws, task_id="p37-nopoc")
    # 无 PoC 时 planner 选 fuzz；这里显式强制 replay，验证 fail-closed
    run_plan("p37-nopoc", store, bus)
    with pytest.raises(ReplayError) as excinfo:
        run_execution("p37-nopoc", store, bus,
                      workdir=tmp_path / "work",
                      evidence_root=tmp_path / "evidence",
                      kind_override="replay")
    assert "replay_no_poc" in str(excinfo.value)
    assert store.get_task("p37-nopoc")["state"] == "FAILED"


def test_replay_unreproducible_lands_no_repro(tmp_path):
    ws = _cg_workspace(tmp_path, sources=1, poc=True)
    store, bus = _prepared(tmp_path, ws, task_id="p37-clean")
    run_plan("p37-clean", store, bus)
    out = run_execution("p37-clean", store, bus,
                        workdir=tmp_path / "work",
                        evidence_root=tmp_path / "evidence",
                        kind_override="replay",
                        replay_cmd=_driver(tmp_path, exit_code=0, body="clean run\n"))
    assert out["outcome"] == "no_repro"
    assert out["state"] == "NO_REPRO"
    assert store.list_candidates("p37-clean") == []


def test_run_kind_override_requires_executor(tmp_path):
    """没接执行器的 kind（P3.9 起 static/dynamic 已接，这里用 container）：
    fail-closed，不冒充结果。"""
    from agent.platform.executors import executor_unavailable
    from agent.platform.planner import PlanError

    ws = _cg_workspace(tmp_path, sources=1, poc=True)
    store, bus = _prepared(tmp_path, ws, task_id="p37-static")
    run_plan("p37-static", store, bus)
    with pytest.raises(PlanError) as excinfo:
        run_execution("p37-static", store, bus,
                      workdir=tmp_path / "work",
                      evidence_root=tmp_path / "evidence",
                      kind_override="container")
    assert "executor_unavailable:container" in str(excinfo.value)
    assert "executor_unavailable:container" in executor_unavailable("container")
    assert store.get_task("p37-static")["state"] == "FAILED"


def test_build_candidates_accepts_replay_crash_shape(tmp_path):
    """回归守卫：replay 的崩溃记录必须能被候选层原样吃掉。"""
    from agent.platform.executors.replay import ReplayError  # noqa: F401

    data = POC_BYTES
    crash = {"input_bytes": data, "input_sha256": _sha256(data),
             "crash_type": "stack-buffer-overflow",
             "stack_hash": _sha256(b"replay-frames"),
             "log": ASAN_LINE, "parsed": {}, "diagnostic_valid": True}
    cands = build_candidates([crash], task_id="p37-shape", exec_id="exec-1")
    assert len(cands) == 1
    assert cands[0].input_sha256 == _sha256(data)
    assert cands[0].crash_type == "stack-buffer-overflow"


# ------------------------------------------------------------------- 5. CLI
def test_cli_understand_unpacks_and_run_replay_end_to_end(tmp_path):
    ws = _cg_workspace(tmp_path, archive=2, poc=True)
    db = tmp_path / "cli.db"

    def step(*args: str, expect: int = 0):
        proc = _run(*args, db=db)
        assert proc.returncode == expect, proc.stderr or proc.stdout
        return proc

    step("submit", "--benchmark", "cybergym", "--target", str(ws),
         "--task-id", "p37-cli", "--meta", "image_vul=n132/arvo:1-vul",
         "--meta", "authorized=true")
    step("preflight", "p37-cli")
    cache_root = ws / "cache-root"
    understood = json.loads(
        step("understand", "p37-cli", "--unpack-cache", str(cache_root)).stdout)
    assert understood["benchmark"] == "cybergym"
    assert understood["source_count"] == 2
    assert understood["notes"] and any("解包" in n for n in understood["notes"])
    # --unpack-cache 覆盖默认位置，缓存键仍是包 sha256
    cached = list((cache_root).glob("*/manifest.json"))
    assert len(cached) == 1
    assert cached[0].parent.name == _sha256((ws / "repo-vul.tar.gz").read_bytes())[:16]
    step("hypotheses", "p37-cli")
    planned = json.loads(step("plan", "p37-cli").stdout)
    assert planned["plan"]["kind"] == "replay"

    proc = step("run", "p37-cli", "--kind", "replay",
                "--replay-cmd", _driver(tmp_path),
                "--workdir", str(tmp_path / "work"),
                "--evidence-root", str(tmp_path / "evidence"))
    out = json.loads(proc.stdout)
    assert out["outcome"] == "candidate"
    assert out["state"] == "CANDIDATE"
    assert out["exit_code"] == 1
    assert out["replay_summary"]["poc_sha256"] == _sha256(POC_BYTES)
