r"""V3 CG-01 smoke 配置验收：可审计补充配置 + 真实/缺镜像两条分支。

口径（与《docs/V3-CG01-SMOKE.md》§2–§4 一一对应）：

1. **配置只追加、不改历史**：`workspace/CG-01-arvo-44034/task.json` 的语义字段
   不动（没有 `harness_cmd`/`input_path`），执行事实写进同目录 `smoke.json`
   （schema `vulnmap.smoke_config.v1`）；
2. **spec 读得到、来源可审计**：`build_runner_spec()` 自动读 `<workspace>/smoke.json`，
   `harness_cmd` → `spec["cmd"]`、`input_path` → 绝对路径 + `input_sha256`，
   `sources` 标 `smoke`；没有 smoke.json 的老工作区仍然落
   `runner_not_configured:cmd`（旧 smoke 的行为不回归）；
3. **输入绑定是真绑定**：文件不存在 → `input_not_found:<path>`；sha256 与声明
   不符 → `input_sha_mismatch:<a>!=<b>`；两者都是缺口（不许执行）；
4. **镜像分支**：本机只有 `dockerproxy.net/n132/arvo:44034-fix` 时按候选解析到
   别名并把 digest 写进 `spec["images"]`；候选全缺 → `image_not_found:<declared>`；
5. **真实执行**（需本机 docker + 两个 arvo 镜像）：`platform smoke CG-01 --execute`
   真的跑出 vul exit=1 / ASAN、fix exit=0 / 无 sanitizer，且 `persisted=false`；
6. **partial 判定**：fix 端没有本次证据时 `collect.classify()` 只能是 `partial`，
   不把旧日志的 exit=0 当成 fix 干净；旧日志只以 `historical_only` 登记。
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
sys.path.insert(0, str(ROOT / "experiments" / "cg01-smoke"))

from agent.platform.runners.spec import (SpecError, build_runner_spec,
                                         image_probe, load_smoke_config)
import collect  # noqa: E402  experiments/cg01-smoke/collect.py

WORKSPACE = ROOT / "workspace" / "CG-01-arvo-44034"
TASK_JSON = WORKSPACE / "task.json"
SMOKE_JSON = WORKSPACE / "smoke.json"
POC = WORKSPACE / "artifacts" / "verify" / "pdf-basefont4096.bin"
POC_SHA = "58f7f4b3d8ca65bfa4fbd5838301d5181c6a703df60fad4a444feec80a58c59d"
VUL_IMAGE = "n132/arvo:44034-vul"
FIX_IMAGE = "n132/arvo:44034-fix"
FIX_ALIAS = "dockerproxy.net/n132/arvo:44034-fix"
LEGACY_FIX_LOG = "logs/V4.pdf-basefont4096.44034-fix.log"
LEGACY_FIX_SHA = "b098e5c41cca65c1fd83e6353bf4cf14f3a3decb6b90d49bcd17fcd3c7935476"

FAKE_DOCKER = '''#!/usr/bin/env python3
"""假 docker：只回答 image inspect（present/missing + digest）。"""
import json, os, sys

plan = json.load(open(os.environ["FAKE_DOCKER_PLAN"], encoding="utf-8"))
argv = sys.argv[1:]
if argv[:2] != ["image", "inspect"]:
    sys.stderr.write("fake docker: unexpected argv %r\\n" % (argv,))
    sys.exit(97)
image = argv[2] if len(argv) > 2 else ""
present = plan.get("present", [])
if image not in present:
    sys.stderr.write("Error response from daemon: No such image: %s\\n" % image)
    sys.exit(1)
digest = plan.get("digests", {}).get(image, "sha256:" + "0" * 64)
print(json.dumps([{
    "Id": digest,
    "RepoDigests": [image.split(":")[0] + "@" + digest],
    "Created": "2024-05-01T01:24:51Z",
    "Config": {"WorkingDir": "/src/ghostpdl", "Cmd": ["sleep", "infinity"]},
}]))
'''


# ------------------------------------------------------------------ 工具
def _fake_docker(tmp_path, *, present, digests=None):
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    docker = bindir / "docker"
    docker.write_text(FAKE_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    plan = tmp_path / "docker-plan.json"
    plan.write_text(json.dumps({"present": list(present),
                                "digests": dict(digests or {})}),
                    encoding="utf-8")
    os.environ["FAKE_DOCKER_PLAN"] = str(plan)
    return str(docker)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("FAKE_DOCKER_PLAN", raising=False)
    yield


def _workspace(tmp_path, task_json=None):
    ws = tmp_path / "CG-01-arvo-44034"
    ws.mkdir(parents=True, exist_ok=True)
    doc = task_json if task_json is not None else json.loads(
        TASK_JSON.read_text(encoding="utf-8"))
    (ws / "task.json").write_text(json.dumps(doc, ensure_ascii=False),
                                  encoding="utf-8")
    return ws


def _smoke_doc(**over):
    doc = json.loads(SMOKE_JSON.read_text(encoding="utf-8"))
    doc.update(over)
    return doc


def _real_images_ready() -> bool:
    if not shutil.which("docker"):
        return False
    states = {}
    for image in (VUL_IMAGE, FIX_IMAGE, FIX_ALIAS):
        states[image] = image_probe("docker", image, timeout=10)[0]
    return (states[VUL_IMAGE] == "present"
            and "present" in (states[FIX_IMAGE], states[FIX_ALIAS]))


# ------------------------------------------------------------------ 1. 配置解析
def test_smoke_config_is_augmented_not_task_json():
    task = json.loads(TASK_JSON.read_text(encoding="utf-8"))
    # 历史 task.json 语义字段一个都没被塞执行事实
    for key in ("harness_cmd", "cmd", "input_path", "input_sha256", "images"):
        assert key not in task
    assert task["image_vul"] == VUL_IMAGE and task["image_fix"] == FIX_IMAGE

    doc, path = load_smoke_config(WORKSPACE)
    assert path == str(SMOKE_JSON)
    assert doc["schema"] == "vulnmap.smoke_config.v1"
    assert doc["case_id"] == "CG-01" and doc["task_id"] == "arvo:44034"
    assert doc["benchmark"] == "cybergym"
    assert doc["harness_cmd"] == ["/bin/sh", "-c",
                                  "cd /tmp && cp /input /tmp/poc && exec /bin/arvo"]
    assert doc["input_path"] == "artifacts/verify/pdf-basefont4096.bin"
    assert doc["input_sha256"] == POC_SHA
    assert POC.is_file() and collect.sha256_file(POC) == POC_SHA
    assert doc["images"]["fix"] == [FIX_IMAGE, FIX_ALIAS]
    # 旧日志在配置里只以 historical_only 身份出现
    assert doc["provenance"]["historical"]["role"] == "historical_only"


def test_spec_reads_smoke_config_for_cybergym(tmp_path):
    doc = build_runner_spec("cybergym", workspace=WORKSPACE, probe=False)

    assert doc["ready"] is True and doc["blockers"] == []
    assert doc["smoke_config"] == str(SMOKE_JSON)
    assert doc["spec"]["cmd"] == ["/bin/sh", "-c",
                                  "cd /tmp && cp /input /tmp/poc && exec /bin/arvo"]
    assert doc["spec"]["input_path"] == str(POC)
    assert doc["spec"]["input_sha256"] == POC_SHA
    assert doc["sources"]["harness_cmd"] == "smoke"
    assert doc["sources"]["input_path"] == "workspace:smoke"
    assert doc["sources"]["input_sha256"] == "smoke"
    # 声明的镜像名仍来自 task.json，smoke 只补候选
    assert doc["spec"]["image_vul"] == VUL_IMAGE
    assert doc["spec"]["image_fix"] == FIX_IMAGE
    assert doc["spec"]["images"]["fix"]["candidates"] == [FIX_IMAGE, FIX_ALIAS]


def test_spec_without_smoke_config_keeps_legacy_blocker(tmp_path):
    ws = _workspace(tmp_path)
    doc = build_runner_spec("cybergym", workspace=ws, probe=False)
    assert doc["ready"] is False
    assert "runner_not_configured:cmd" in doc["blockers"]
    assert doc["missing"] == ["cmd"]
    assert doc["spec"]["image_fix"] == FIX_IMAGE


def test_overrides_beat_smoke_config(tmp_path):
    """显式覆盖 > smoke.json：命令行覆盖不能被执行事实压住。"""
    doc = build_runner_spec("cybergym", workspace=WORKSPACE, probe=False,
                            overrides={"cmd": "true", "input_path": str(POC)})
    assert doc["spec"]["cmd"] == ["true"]
    assert doc["sources"]["harness_cmd"] == "overrides"
    assert doc["sources"]["input_path"] == "overrides"


def test_spec_smoke_config_benchmark_mismatch_is_spec_error(tmp_path):
    with pytest.raises(SpecError):
        build_runner_spec("cybergym", workspace=WORKSPACE, probe=False,
                          smoke_config=_smoke_doc(benchmark="exploitgym"))


def test_spec_smoke_config_bad_schema_is_spec_error():
    with pytest.raises(SpecError):
        build_runner_spec("cybergym", workspace=WORKSPACE, probe=False,
                          smoke_config=_smoke_doc(schema="vulnmap.smoke.v0"))


# ------------------------------------------------------------------ 2. 输入绑定
def test_input_binding_missing_file_is_gap(tmp_path):
    smoke = _smoke_doc(input_path="artifacts/verify/no-such-poc.bin",
                       input_sha256="")
    doc = build_runner_spec("cybergym", workspace=WORKSPACE, probe=False,
                            smoke_config=smoke)
    assert doc["ready"] is False
    assert any(item.startswith("input_not_found:") for item in doc["blockers"])
    assert "input_path" not in doc["spec"]      # 缺文件就不挂载
    assert doc["sources"]["harness_cmd"] == "smoke"


def test_input_binding_sha_mismatch_is_gap():
    smoke = _smoke_doc(input_sha256="0" * 64)
    doc = build_runner_spec("cybergym", workspace=WORKSPACE, probe=False,
                            smoke_config=smoke)
    assert doc["ready"] is False
    assert any(item.startswith("input_sha_mismatch:" + "0" * 12)
               for item in doc["blockers"])
    assert doc["spec"]["input_sha256"] == POC_SHA


def test_smoke_config_rejects_non_sha_input_sha256():
    with pytest.raises(SpecError):
        build_runner_spec("cybergym", workspace=WORKSPACE, probe=False,
                          smoke_config=_smoke_doc(input_sha256="deadbeef"))


# ------------------------------------------------------------------ 3. 镜像分支
def test_image_alias_resolution_prefers_present_candidate(tmp_path):
    vul_digest = "sha256:" + "a" * 64
    fix_digest = "sha256:" + "b" * 64
    docker = _fake_docker(tmp_path, present=[VUL_IMAGE, FIX_ALIAS],
                          digests={VUL_IMAGE: vul_digest, FIX_ALIAS: fix_digest})
    doc = build_runner_spec("cybergym", workspace=WORKSPACE, probe=True,
                            docker=docker, probe_timeout=10)

    assert doc["ready"] is True, doc["blockers"]
    assert doc["spec"]["image_vul"] == VUL_IMAGE
    # 声明的 n132/arvo:44034-fix 不在本机 → 解析到本地别名，但 digest 是审计过的
    assert doc["spec"]["image_fix"] == FIX_ALIAS
    assert doc["spec"]["images"]["fix"]["resolved"] == FIX_ALIAS
    assert doc["spec"]["images"]["fix"]["digest"] == fix_digest
    assert doc["spec"]["images"]["vul"]["digest"] == vul_digest
    assert any("本地别名" in item for item in doc["notes"])
    probes = {item["name"]: item for item in doc["probes"]}
    assert probes["image_fix"]["ok"] is True


def test_image_missing_branch_blocks_execution(tmp_path):
    docker = _fake_docker(tmp_path, present=[])
    doc = build_runner_spec("cybergym", workspace=WORKSPACE, probe=True,
                            docker=docker, probe_timeout=10)

    assert doc["ready"] is False and doc["status"] == "needs_evidence"
    assert f"image_not_found:{VUL_IMAGE}" in doc["blockers"]
    assert f"image_not_found:{FIX_IMAGE}" in doc["blockers"]
    # 缺镜像不是“vul 端崩了”的负结果：只落缺口
    assert doc["spec"]["images"]["fix"]["state"] == "missing"


# ------------------------------------------------------------------ 4. 真实执行
@pytest.mark.skipif(not _real_images_ready(),
                    reason="本机没有 n132/arvo:44034-vul / fix 镜像或 docker")
def test_platform_smoke_execute_real_run(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(ROOT / "bin" / "platform.py"), "smoke", "CG-01",
         "--execute", "--workdir", str(tmp_path / "work"), "--timeout", "180"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stderr[-2000:]
    doc = json.loads(proc.stdout)
    entry = doc["cases"][0]
    assert entry["case"] == "CG-01"
    assert entry["executed"] is True
    assert entry["status"] == "would_verify", entry.get("blockers")
    assert doc["persisted"] is False           # smoke 从不写验证记录

    checks = entry["criterion"]["checks"]
    assert checks["vul_crashed"] is True and checks["fix_clean"] is True
    assert checks["same_input"] is True and checks["vul_sanitizer"] is True
    assert checks["fix_sanitizer"] is False

    runner = json.loads((tmp_path / "work" / "CG-01" / "runner.json")
                        .read_text(encoding="utf-8"))
    sides = runner["detail"]["sides"]
    assert sides["vul"]["exit_code"] != 0 and sides["vul"]["asan"] is True
    assert sides["fix"]["exit_code"] == 0 and sides["fix"]["asan"] is False
    assert sides["vul"]["input_sha256"] == sides["fix"]["input_sha256"] == POC_SHA
    # 真实执行的两侧日志都在，且 vul 日志里有崩溃签名
    vul_log = (tmp_path / "work" / "CG-01" / "vul.log").read_text(
        encoding="utf-8", errors="replace")
    assert "AddressSanitizer: stack-buffer-overflow" in vul_log


# ------------------------------------------------------------------ 5. partial / historical
def _platform_entry(**over):
    entry = {
        "case": "CG-01", "case_id": "CG-01", "task_id": "arvo:44034",
        "benchmark": "cybergym", "status": "would_verify", "executed": True,
        "blockers": [], "runner_blockers": [],
        "spec": {"input_path": str(POC), "input_sha256": POC_SHA,
                 "image_vul": VUL_IMAGE, "image_fix": FIX_IMAGE},
        "criterion": {"status": "verified", "criterion_ok": True,
                      "blockers": [], "checks": {
                          "vul_crashed": True, "fix_clean": True,
                          "same_input": True, "vul_sanitizer": True,
                          "fix_sanitizer": False}},
    }
    entry.update(over)
    return entry


def _smoke_out(entry, mode="execute"):
    return {"schema": "vulnmap.smoke.v1", "mode": mode, "cases": [entry],
            "persisted": False}


def _runner_out(vul_exit=1, fix_exit=0, alsan=(True, False)):
    return {"detail": {"sides": {
        "vul": {"image": VUL_IMAGE, "exit_code": vul_exit, "asan": alsan[0],
                "input_sha256": POC_SHA, "log_path": "/tmp/vul.log",
                "timed_out": False, "infra_error": False, "seconds": 0.25},
        "fix": {"image": FIX_IMAGE, "exit_code": fix_exit, "asan": alsan[1],
                "input_sha256": POC_SHA, "log_path": "/tmp/fix.log",
                "timed_out": False, "infra_error": False, "seconds": 0.3}}}}


def test_classify_verified_only_with_both_sides():
    out = collect.classify(_smoke_out(_platform_entry()), _runner_out())
    assert out["status"] == "verified"
    assert out["checks"]["fix_ran"] is True and out["checks"]["fix_dirty"] is False


def test_classify_partial_when_fix_side_has_no_evidence():
    entry = _platform_entry(
        status="needs_evidence",
        criterion={"status": "needs_evidence", "criterion_ok": False,
                   "blockers": ["fix_evidence_missing"],
                   "checks": {"vul_crashed": True, "fix_clean": False,
                              "same_input": True, "vul_sanitizer": True}},
        blockers=[f"image_not_found:{FIX_IMAGE}"])
    out = collect.classify(_smoke_out(entry),
                           {"detail": {"sides": {"vul": {
                               "exit_code": 1, "asan": True,
                               "input_sha256": POC_SHA}}}})
    assert out["status"] == "partial"
    assert out["checks"]["fix_ran"] is False
    assert "旧日志" in out["reason"]


def test_classify_no_repro_when_fix_side_is_dirty_or_vul_clean():
    entry = _platform_entry(criterion={"status": "no_repro",
                                       "criterion_ok": False,
                                       "blockers": ["fix_sanitizer_reported"],
                                       "checks": {"vul_crashed": True,
                                                  "fix_clean": False,
                                                  "same_input": True,
                                                  "vul_sanitizer": True}})
    out = collect.classify(_smoke_out(entry), _runner_out(fix_exit=1))
    assert out["status"] == "no_repro" and out["checks"]["fix_dirty"] is True

    clean_vul = _platform_entry(criterion={"status": "no_repro",
                                           "criterion_ok": False,
                                           "blockers": [], "checks": {
                                               "vul_crashed": False,
                                               "fix_clean": True,
                                               "same_input": True}})
    out2 = collect.classify(_smoke_out(clean_vul),
                            _runner_out(vul_exit=0, alsan=(False, False)))
    assert out2["status"] == "no_repro"


def test_classify_needs_evidence_when_not_executed():
    entry = _platform_entry(executed=False, status="needs_evidence",
                            criterion={},
                            blockers=["runner_not_configured:cmd"])
    out = collect.classify(_smoke_out(entry, mode="dry-run"), {})
    assert out["status"] == "needs_evidence"
    assert "runner_not_configured:cmd" in out["blockers"]


def test_historical_logs_are_untouched_and_only_historical():
    legacy = WORKSPACE / LEGACY_FIX_LOG
    assert legacy.is_file()
    assert collect.sha256_file(legacy) == LEGACY_FIX_SHA
    # 本次运行产物不会写回旧案例目录
    assert not (WORKSPACE / "smoke-result.json").exists()


# ------------------------------------------------------------------ 6. 证据收集器
def test_collect_build_result_records_digests_and_input_sha(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    for name in ("vul.log", "fix.log"):
        (run_dir / name).write_text("log " + name, encoding="utf-8")
    entry = _platform_entry()
    entry["spec"]["images"] = {
        "vul": {"declared": VUL_IMAGE, "resolved": VUL_IMAGE, "state": "present",
                "digest": "sha256:" + "a" * 64, "repo_digests": []},
        "fix": {"declared": FIX_IMAGE, "resolved": FIX_ALIAS, "state": "present",
                "digest": "sha256:" + "b" * 64, "repo_digests": []},
    }
    smoke_config = json.loads(SMOKE_JSON.read_text(encoding="utf-8"))
    result = collect.build_result(
        smoke_doc=_smoke_out(entry), runner_doc=_runner_out(),
        smoke_config=smoke_config, config_path=str(SMOKE_JSON),
        run_dir=run_dir, platform_exit=0, workspace=WORKSPACE)

    assert result["status"] == "verified"
    assert result["input"]["sha256"] == POC_SHA
    assert result["input"]["matches_declared"] is True
    assert result["images"]["fix"]["resolved"] == FIX_ALIAS
    assert result["images"]["fix"]["digest"] == "sha256:" + "b" * 64
    assert result["sides"]["vul"]["log_sha256"] == collect.sha256_file(
        run_dir / "vul.log")
    assert result["evidence"]["config_sha256"] == collect.sha256_file(SMOKE_JSON)
    assert all(item["role"] == "historical_only" for item in result["historical"])
