"""V3 P5（V3-017）验收：补丁工作流只写实验副本、独立测试、失败回滚、不写 confirmed。

断言口径以《VULNMAP-V3 完整升级方案》§12/§13 与 `/tmp` 契约（Lead 定稿）为准，
**不**以实现为准：

1. **只写实验副本**：`propose` 之后 origin 的每个字节、整树哈希都不变；补丁只出现在
   `<patch_root>/<task>/<P1>/experiment/`；`proposal.status=proposed`、
   `applied_to_origin=false`；`baseline/` 与原件同哈希。
2. **补丁必须带原件哈希、finding/证据引用、diff、测试命令、回滚方案**：
   `proposal.origin.tree_sha256` 可复算；`root_cause.finding.candidate_id` 指向原始候选；
   `evidence[].sha256` 由工作流现场计算、可复算；`tests.trigger` / `rollback.files` 非空。
3. **独立测试**：`test` 从 `baseline` 重建独立副本（不复用 `experiment/`），跑
   「原版触发（非零）/ 补丁不触发（零）/ 回归（零）」，最后回滚 `experiment/` 并
   校验哈希回到基线；任何一项不成立就 `failed`，前置不成立就 `blocked`。
4. **工程采纳 ≠ 漏洞确认**：只有测试通过 + 回滚通过 + 原件未变 + 证据可复算 +
   finding 在，`review` 才 `accepted`；`scope` 恒为 `patch_validation`；既有 verify
   记录只在 `vulnerability` 块里**只读回显**，任何补丁工件都不得出现
   `"confirmed"` 或 `"verified": true`。
5. **拒绝**：证据缺失、候选不存在、无源码（unsupported）、改测试文件、吞异常、
   diff 过大、diff 与基线不匹配 → `PatchError` / `PatchUnsupported`，且不半写。
6. **失败回滚**：基线被删/被改 → `test` 直接 `blocked`，显式 `rollback` 拒绝执行；
   正常 `rollback` 把实验副本恢复到基线哈希。

全部测试用临时目录 + 临时 `PlatformStore`，不碰仓库 `.platform`。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.platform import PlatformStore, TaskSpec  # noqa: E402
from agent.platform.adaptive.patch import (  # noqa: E402
    DEFAULT_LIMITS, PatchError, PatchProposal, PatchReview, PatchTest,
    PatchUnsupported, PatchWorkflow, RootCause, apply_unified, build_unified,
    parse_unified, read_tree, tree_manifest, tree_sha256)
from agent.platform.verify import Verification  # noqa: E402

TASK = "task-v3-p5"
PY = sys.executable

VICTIM = (
    "import sys\n"
    "data = open(sys.argv[1], 'rb').read()\n"
    "n = int.from_bytes(data[:1], 'big')\n"
    "print([0, 1, 2][n])\n"
)
FIXED = (
    "import sys\n"
    "data = open(sys.argv[1], 'rb').read()\n"
    "n = int.from_bytes(data[:1], 'big')\n"
    "table = [0, 1, 2]\n"
    "if n >= len(table):\n"
    "    print('rejected')\n"
    "    raise SystemExit(0)\n"
    "print(table[n])\n"
)
TRIGGER = f"{PY} victim.py poc.bin"
REGRESSION = f"{PY} victim.py good.bin"


# ------------------------------------------------------------------ 夹具
class Case:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.src = tmp / "src"
        self.src.mkdir()
        (self.src / "victim.py").write_text(VICTIM, encoding="utf-8")
        (self.src / "poc.bin").write_bytes(b"\xff")
        (self.src / "good.bin").write_bytes(b"\x01")
        self.evidence = tmp / "crash.log"
        self.evidence.write_text("IndexError: list index out of range\n",
                                 encoding="utf-8")
        self.store = PlatformStore(tmp / "platform.db")
        self.store.create_task(TaskSpec(task_id=TASK, benchmark="target_yaml",
                                        target=str(self.src)))
        self.store.save_candidate({
            "id": "C1", "task_id": TASK, "input_sha256": "a" * 64,
            "crash_type": "IndexError", "stack_hash": "deadbeef",
            "evidence_sha256": "b" * 64, "state": "new",
        })
        self.root = tmp / "patch"
        self.workflow = PatchWorkflow(self.root, store=self.store, task_id=TASK)
        self.fixed = tmp / "fixed.py"
        self.fixed.write_text(FIXED, encoding="utf-8")

    @property
    def origin_manifest(self) -> dict:
        return tree_manifest(read_tree(self.src))

    def propose(self, **overrides) -> dict:
        kwargs = dict(
            candidate_id="C1", source_root=self.src, line=4,
            argument="数组下标没有边界检查，越界读触发 IndexError",
            claim="observed", file="victim.py", patched=self.fixed,
            trigger_cmd=TRIGGER, regression_cmds=[REGRESSION],
            evidence=[self.evidence],
        )
        kwargs.update(overrides)
        return self.workflow.propose(**kwargs)

    def patch_dir(self, patch_id: str = "P1") -> Path:
        return self.root / TASK / patch_id


@pytest.fixture()
def case(tmp_path: Path) -> Case:
    return Case(tmp_path)


def _all_json_text(root: Path) -> str:
    return "\n".join(path.read_text(encoding="utf-8")
                     for path in sorted(root.rglob("*.json")))


# ------------------------------------------------------------------ 1. 只写副本
def test_propose_writes_only_experiment_and_keeps_origin(case: Case) -> None:
    before_manifest = case.origin_manifest
    before_files = {path.name: path.read_bytes()
                    for path in case.src.iterdir() if path.is_file()}

    out = case.propose()

    assert out["status"] == "proposed"
    assert out["patch_id"] == "P1"
    assert out["proposal"]["status"] == "proposed"
    assert out["proposal"]["applied_to_origin"] is False
    assert out["experiment"]["applied_to_origin"] is False

    # 原件一个字节都没变（整树哈希 + 逐文件字节）
    assert case.origin_manifest == before_manifest
    assert out["origin"]["tree_sha256"] == tree_sha256(before_manifest)
    assert out["origin"]["unchanged"] is True
    for name, data in before_files.items():
        assert (case.src / name).read_bytes() == data

    pdir = case.patch_dir()
    # 补丁只出现在实验副本里
    assert (pdir / "experiment" / "victim.py").read_text(encoding="utf-8") == FIXED
    assert (pdir / "baseline" / "victim.py").read_text(encoding="utf-8") == VICTIM
    assert not (case.src / "victim.py").read_text(encoding="utf-8") == FIXED
    # 基线 = 原件
    assert tree_sha256(tree_manifest(read_tree(pdir / "baseline"))) == \
        out["origin"]["tree_sha256"]
    # 工件都在 patch_root 内
    assert pdir.is_dir() and case.root in pdir.parents


def test_proposal_carries_diff_tests_finding_and_rollback(case: Case) -> None:
    out = case.propose()
    proposal = out["proposal"]
    cause = out["root_cause"]

    assert proposal["diff"].startswith("--- a/victim.py")
    assert proposal["diff_sha256"] == __import__("hashlib").sha256(
        proposal["diff"].encode("utf-8")).hexdigest()
    assert proposal["tests"]["trigger"]["cmd"] == TRIGGER
    assert proposal["tests"]["regression"][0]["cmd"] == REGRESSION
    assert proposal["rollback"]["files"] == ["victim.py"]
    assert proposal["rollback"]["baseline_tree_sha256"] == \
        proposal["origin"]["tree_sha256"]
    assert proposal["files"][0]["path"] == "victim.py"
    assert proposal["files"][0]["added"] >= 1

    # 原始 finding / 证据引用
    assert cause["finding"]["task_id"] == TASK
    assert cause["finding"]["candidate_id"] == "C1"
    assert cause["finding"]["input_sha256"] == "a" * 64
    assert cause["evidence"], "根因必须带可复算证据"
    ref = cause["evidence"][0]
    assert Path(ref["path"]).is_file()
    assert ref["sha256"] == __import__("hashlib").sha256(
        Path(ref["path"]).read_bytes()).hexdigest()
    assert cause["snippet_sha256"]
    # 工件读回来还是同一个契约
    assert PatchProposal.from_dict(proposal).patch_id == "P1"
    assert RootCause.from_dict(cause).candidate_id == "C1"


# ------------------------------------------------------------------ 2. 拒绝
def test_propose_refuses_missing_finding_or_source(case: Case) -> None:
    with pytest.raises(PatchError):
        case.propose(candidate_id="C9")          # 候选不存在
    with pytest.raises(PatchUnsupported):
        case.propose(source_root=case.tmp / "nope")   # 无源码 → unsupported
    with pytest.raises(PatchError):
        case.propose(evidence=[case.tmp / "missing.log"])
    with pytest.raises(PatchError):
        case.propose(trigger_cmd="")             # 没有测试命令
    with pytest.raises(PatchError):
        case.propose(argument="短")              # 根因无论证
    with pytest.raises(PatchError):
        case.propose(line=99)                    # 行号越界
    assert not case.patch_dir().exists(), "被拒绝时不许半写"


def _diff_for(case: Case, after: str, path: str = "victim.py") -> str:
    before = (case.src / path).read_text(encoding="utf-8")
    return build_unified(path, before, after)


def test_propose_refuses_fake_fix_diffs(case: Case) -> None:
    # 1) 改测试文件
    (case.src / "tests").mkdir()
    target = case.src / "tests" / "test_victim.py"
    target.write_text("def test_x():\n    assert True\n", encoding="utf-8")
    diff = build_unified("tests/test_victim.py",
                         target.read_text(encoding="utf-8"),
                         "def test_x():\n    assert False\n")
    with pytest.raises(PatchError) as exc:
        case.propose(patched="", diff=_write(case.tmp / "t.diff", diff),
                     file="tests/test_victim.py", line=1)
    assert "touches_test_file" in str(exc.value)

    # 2) 吞异常
    swallow = VICTIM.replace(
        "print([0, 1, 2][n])\n",
        "try:\n    print([0, 1, 2][n])\nexcept IndexError:\n    pass\n")
    diff = _diff_for(case, swallow)
    with pytest.raises(PatchError) as exc:
        case.propose(patched="", diff=_write(case.tmp / "s.diff", diff),
                     file="victim.py", line=4)
    assert "swallows_exception" in str(exc.value)

    # 3) 删功能（只删不补）
    diff = _diff_for(case, VICTIM.replace("print([0, 1, 2][n])\n", ""))
    with pytest.raises(PatchError) as exc:
        case.propose(patched="", diff=_write(case.tmp / "d.diff", diff),
                     file="victim.py", line=4)
    assert "deletes_without_replacement" in str(exc.value)

    # 4) 规模上限
    big = VICTIM + "".join(f"x{i} = {i}\n" for i in range(400))
    diff = _diff_for(case, big)
    with pytest.raises(PatchError) as exc:
        case.propose(patched="", diff=_write(case.tmp / "big.diff", diff),
                     file="victim.py", line=4)
    assert "too_many_changed_lines" in str(exc.value)
    assert DEFAULT_LIMITS["max_changed_lines"] < 400


def test_large_diff_allowed_only_when_limits_raised(case: Case) -> None:
    big = VICTIM + "".join(f"x{i} = {i}\n" for i in range(400))
    diff = _diff_for(case, big)
    diff_file = _write(case.tmp / "big.diff", diff)
    workflow = PatchWorkflow(case.root, store=case.store, task_id=TASK,
                             limits={"max_changed_lines": 1000,
                                     "max_diff_bytes": 1 << 20})
    out = workflow.propose(
        candidate_id="C1", source_root=case.src, line=4,
        argument="大补丁在显式放宽上限后才允许", claim="model_hypothesis",
        file="victim.py", diff=diff_file,
        trigger_cmd=TRIGGER, regression_cmds=[REGRESSION],
        evidence=[case.evidence])
    assert out["patch_id"] == "P1"
    assert out["proposal"]["files"][0]["added"] >= 400


def _write(path: Path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


# ------------------------------------------------------------------ 3. 独立测试 + 复核
def test_independent_test_passes_and_review_accepts(case: Case) -> None:
    case.propose()
    test = case.workflow.test("P1")

    assert test["status"] == "passed"
    assert test["passed"] is True
    assert test["test"]["blockers"] == []
    gates = {gate["name"]: gate["ok"] for gate in test["test"]["gates"]}
    assert gates["origin_unchanged"] and gates["origin_unchanged_after_test"]
    assert gates["rollback_verified"]
    assert any(name.startswith("trigger-baseline") for name in gates)
    assert any(name.startswith("trigger-patched") for name in gates)
    assert any(name.startswith("regression-1") for name in gates)
    runs = {run["name"]: run for run in test["test"]["runs"]}
    assert runs["trigger-baseline"]["exit_code"] != 0
    assert runs["trigger-patched"]["exit_code"] == 0
    assert runs["regression-1"]["exit_code"] == 0
    # 回滚后实验副本回到基线
    assert test["test"]["rollback"]["restored_tree_sha256"] == \
        test["test"]["origin"]["tree_sha256"]

    review = case.workflow.review("P1")
    assert review["status"] == "accepted"
    assert review["review"]["scope"] == "patch_validation"
    assert review["review"]["engineering"]["accepted"] is True
    assert review["review"]["vulnerability"]["status"] == "not_evaluated"
    assert review["review"]["vulnerability"]["verification_ids"] == []

    # 补丁侧任何工件都不写 confirmed，也不写 verified=true
    text = _all_json_text(case.root)
    assert '"confirmed"' not in text
    assert '"verified": true' not in text


def test_review_accepts_only_when_test_passed(case: Case) -> None:
    case.propose()
    # 没跑测试就复核：rejected，且理由是 test_present 缺失
    review = case.workflow.review("P1")
    assert review["status"] == "rejected"
    assert "test_present" in review["reasons"]

    # 补丁“不修”的版本：测试失败 → 复核 rejected
    noop = VICTIM + "# no real fix\n"
    case.fixed.write_text(noop, encoding="utf-8")
    second = case.propose(argument="第二份提案（不修）", patched=case.fixed)
    assert second["patch_id"] == "P2"
    test = case.workflow.test("P2")
    assert test["status"] == "failed"
    review = case.workflow.review("P2")
    assert review["status"] == "rejected"
    assert "test_passed" in review["reasons"]
    assert review["review"]["engineering"]["accepted"] is False


# ------------------------------------------------------------------ 4. 回滚
def test_rollback_restores_experiment_hash(case: Case) -> None:
    out = case.propose()
    expected = out["origin"]["tree_sha256"]
    experiment = case.patch_dir() / "experiment"
    # 手改实验副本，再显式回滚
    (experiment / "victim.py").write_text("# tampered\n", encoding="utf-8")
    assert tree_sha256(tree_manifest(read_tree(experiment))) != expected
    out = case.workflow.rollback("P1")
    assert out["status"] == "reverted"
    assert out["rollback"]["restored_tree_sha256"] == expected
    assert (experiment / "victim.py").read_text(encoding="utf-8") == VICTIM


def test_failed_rollback_blocks_test_and_refuses_rollback(case: Case) -> None:
    case.propose()
    baseline = case.patch_dir() / "baseline"
    for path in sorted(baseline.rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    baseline.rmdir()

    test = case.workflow.test("P1")
    assert test["status"] == "blocked"
    assert "baseline_missing" in test["test"]["blockers"]
    assert case.workflow.review("P1")["status"] == "rejected"

    with pytest.raises(PatchError):
        case.workflow.rollback("P1")


# ------------------------------------------------------------------ 5. 证据被改
def test_review_rejects_tampered_evidence(case: Case) -> None:
    case.propose()
    assert case.workflow.test("P1")["status"] == "passed"
    case.evidence.write_text("tampered evidence\n", encoding="utf-8")
    review = case.workflow.review("P1")
    assert review["status"] == "rejected"
    assert "evidence_recomputable" in review["reasons"]


# ------------------------------------------------------------------ 6. verify 只读
def test_verified_record_is_read_only_and_never_confirmed(case: Case) -> None:
    case.store.save_verification(Verification(
        verification_id="V1", task_id=TASK, candidate_id="C1",
        benchmark="target_yaml", kind="repro", verified=True,
        status="verified", evidence_sha256="c" * 64, detail={"note": "fake"}))
    case.propose(verification_ids=["V1"])
    case.workflow.test("P1")
    review = case.workflow.review("P1")

    vuln = review["review"]["vulnerability"]
    assert vuln["status"] == "verified_in_platform"
    assert vuln["verification_ids"] == ["V1"]
    assert vuln["source"] == "agent.platform.verify"
    # 工程采纳与漏洞结论互不代签
    assert review["review"]["scope"] == "patch_validation"
    text = _all_json_text(case.root)
    assert '"confirmed"' not in text
    assert '"verified": true' not in text


# ------------------------------------------------------------------ 7. 契约自守
def test_contracts_refuse_applied_or_verdict_fields(case: Case) -> None:
    proposal = {
        "patch_id": "P1", "task_id": TASK, "candidate_id": "C1",
        "root_cause_id": "RC1", "source_root": str(case.src),
        "diff": "--- a/victim.py\n+++ b/victim.py\n@@ -1 +1 @@\n-x\n+y\n",
        "files": ({"path": "victim.py"},), "origin": {}, "tests":
        {"trigger": {"cmd": "true"}}, "rollback": {"files": ["victim.py"]},
    }
    with pytest.raises(PatchError):
        PatchProposal(**{**proposal, "status": "applied"})
    with pytest.raises(PatchError):
        PatchProposal(**{**proposal, "applied_to_origin": True})

    with pytest.raises(PatchError):
        RootCause(root_cause_id="RC1", task_id=TASK, candidate_id="C1",
                  file="victim.py", line=1, claim="observed",
                  argument="没有证据也要过？", evidence=())

    with pytest.raises(PatchError):
        PatchTest(test_id="T1", patch_id="P1", task_id=TASK,
                  status="maybe")
    with pytest.raises(PatchError):
        PatchReview(review_id="R1", patch_id="P1", task_id=TASK,
                    status="accepted", engineering={},
                    vulnerability={"note": "confirmed by patch"},
                    scope="vulnerability")


def test_diff_roundtrip_and_context_strictness(case: Case) -> None:
    before = VICTIM
    diff = build_unified("victim.py", before, FIXED)
    parsed = parse_unified(diff)
    assert parsed[0].path == "victim.py"
    assert apply_unified(diff, {"victim.py": before})["victim.py"] == FIXED
    # 上下文不匹配就拒绝，不尽力而为
    with pytest.raises(PatchError):
        apply_unified(diff, {"victim.py": "totally different\n"})


# ------------------------------------------------------------------ 8. CLI
def test_cli_propose_test_review_roundtrip(case: Case, tmp_path: Path) -> None:
    diff = build_unified("victim.py", VICTIM, FIXED)
    diff_file = tmp_path / "fix.diff"
    diff_file.write_text(diff, encoding="utf-8")
    base = [PY, str(ROOT / "bin" / "platform.py"), "--db", str(case.tmp / "platform.db")]

    propose = subprocess.run(
        base + ["patch", "propose", TASK, "--candidate", "C1",
                "--source-root", str(case.src), "--file", "victim.py",
                "--line", "4", "--claim", "observed",
                "--argument", "数组下标没有边界检查，越界读触发 IndexError",
                "--evidence", str(case.evidence), "--diff", str(diff_file),
                "--trigger-cmd", TRIGGER, "--regression-cmd", REGRESSION,
                "--patch-root", str(case.root)],
        capture_output=True, text=True, timeout=180)
    assert propose.returncode == 0, propose.stderr
    out = json.loads(propose.stdout)
    assert out["status"] == "proposed" and out["patch_id"] == "P1"

    test = subprocess.run(
        base + ["patch", "test", "P1", "--task-id", TASK,
                "--patch-root", str(case.root)],
        capture_output=True, text=True, timeout=180)
    assert test.returncode == 0, test.stderr
    assert json.loads(test.stdout)["status"] == "passed"

    review = subprocess.run(
        base + ["patch", "review", "P1", "--task-id", TASK,
                "--patch-root", str(case.root)],
        capture_output=True, text=True, timeout=180)
    assert review.returncode == 0, review.stderr
    assert json.loads(review.stdout)["status"] == "accepted"

    rollback = subprocess.run(
        base + ["patch", "rollback", "P1", "--patch-root", str(case.root)],
        capture_output=True, text=True, timeout=120)
    assert rollback.returncode == 0, rollback.stderr
    assert json.loads(rollback.stdout)["status"] == "reverted"

    # CLI 跑完原件还是原样
    assert (case.src / "victim.py").read_text(encoding="utf-8") == VICTIM
    assert tree_sha256(tree_manifest(read_tree(case.src))) == \
        out["origin"]["tree_sha256"]


def test_cli_refuses_without_source_tree(case: Case, tmp_path: Path) -> None:
    base = [PY, str(ROOT / "bin" / "platform.py"), "--db", str(case.tmp / "platform.db")]
    proc = subprocess.run(
        base + ["patch", "propose", TASK, "--candidate", "C1",
                "--source-root", str(tmp_path / "nope"),
                "--line", "1", "--argument", "没有源码不该假装能修",
                "--trigger-cmd", "true",
                "--patch-root", str(case.root)],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2
    out = json.loads(proc.stdout)
    assert out["status"] == "unsupported"
