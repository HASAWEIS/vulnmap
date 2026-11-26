"""V3-017 补丁工作流编排：提议 → 独立测试 → 复核（只判工程采纳）。

一次补丁全过程只产出**文件工件**，不写数据库、不改 origin、不写验证结论：

```
<patch_root>/<task_id>/<P1>/
    root_cause.json     # 根因 + 原始 finding/证据引用（可复算）
    proposal.json       # status=proposed + diff + 测试命令 + 回滚方案
    baseline/           # 原件字节快照（只读基线，回滚用）
    experiment/         # 唯一可写副本；补丁只落在这里，不自动应用
    run/                # 每次测试重建的独立副本（baseline / patched）
    logs/               # 每条命令的完整输出 + 哈希
    test.json           # 原版触发 / 补丁不触发 / 回归 / 回滚
    review.json         # scope=patch_validation，engineering accepted/rejected
```

`PatchReview` 的漏洞块只做**既有 verify 台账的只读回显**：补丁测试通过不等于
漏洞 `confirmed`，两者在字段上就分开（§12 / §13）。
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Iterable, Mapping

from .contracts import (CLAIM_SOURCES, EXPECT_NONZERO, EXPECT_ZERO, PATCH_VERSION,
                        PROPOSAL_SCHEMA, Gate, PatchError,
                        PatchProposal, PatchTest, FindingRef, RootCause,
                        EvidenceRef, PatchReview, PatchUnsupported, safe_relpath,
                        sha256_bytes, verdict_fields_in)
from .diff import (DEFAULT_LIMITS, apply_unified, build_unified, changed_stats,
                   diff_paths, hygiene_problems, parse_unified)
from .workspace import (file_sha256, manifest_of_tree, read_json, read_tree,
                        run_command, tree_manifest, tree_sha256, write_json,
                        write_log, write_tree)

#: 允许被测试命令引用的根目录（相对 patch 目录）；其余路径一律拒绝
RUN_ROOTS = ("run/baseline", "run/patched")


def _task_id_ok(value: str) -> str:
    text = str(value or "").strip()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$", text):
        raise PatchError(f"unsafe task_id: {value!r}")
    return text


def _expect_ok(expect, exit_code) -> bool:
    if exit_code is None:
        return False
    if expect in (EXPECT_ZERO, "0", 0):
        return exit_code == 0
    if expect in (EXPECT_NONZERO, None, ""):
        return exit_code != 0
    try:
        return exit_code == int(expect)
    except (TypeError, ValueError):
        return False


def _rel_to(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)


class PatchWorkflow:
    """补丁工件编排器；`store` 只用于**读**候选与验证记录。"""

    def __init__(self, root: Path | str, *, store=None, task_id: str = "",
                 limits: Mapping | None = None) -> None:
        self.root = Path(root)
        self.store = store
        self.task_id = _task_id_ok(task_id) if task_id else ""
        self.limits = dict(DEFAULT_LIMITS)
        self.limits.update(dict(limits or {}))

    # ------------------------------------------------------------ 目录与读取
    @property
    def task_dir(self) -> Path:
        if not self.task_id:
            raise PatchError("task_id required")
        return self.root / self.task_id

    def patch_dir(self, patch_id: str) -> Path:
        path = self.task_dir / str(patch_id or "")
        if not path.is_dir():
            raise PatchError(f"unknown patch: {patch_id!r}")
        return path

    def _next_patch_id(self, task_dir: Path) -> str:
        used = set()
        if task_dir.is_dir():
            for item in task_dir.iterdir():
                match = re.match(r"^P(\d+)$", item.name)
                if match:
                    used.add(int(match.group(1)))
        index = 1
        while index in used:
            index += 1
        return f"P{index}"

    def _load_proposal(self, patch_id: str) -> tuple[Path, dict]:
        pdir = self.patch_dir(patch_id)
        doc = read_json(pdir / "proposal.json")
        if str(doc.get("schema") or "") != PROPOSAL_SCHEMA:
            raise PatchError(f"unknown proposal schema: {doc.get('schema')!r}")
        return pdir, doc

    def load(self, patch_id: str) -> dict:
        pdir = self.patch_dir(patch_id)
        out: dict = {"patch_id": patch_id, "task_id": self.task_id,
                     "dir": str(pdir)}
        for name, key in (("root_cause.json", "root_cause"),
                          ("proposal.json", "proposal"),
                          ("test.json", "test"),
                          ("review.json", "review")):
            path = pdir / name
            out[key] = read_json(path) if path.is_file() else None
        return out

    @classmethod
    def find(cls, root: Path | str, patch_id: str) -> tuple[str, Path]:
        """在 patch_root 下按 patch_id 找任务（`--task-id` 可省略）。"""
        base = Path(root)
        hits = [item for item in sorted(base.glob(f"*/{patch_id}"))
                if item.is_dir()]
        if not hits:
            raise PatchError(f"unknown patch: {patch_id!r}")
        if len(hits) > 1:
            raise PatchError(
                f"ambiguous patch {patch_id!r}: {[str(h) for h in hits]}")
        return hits[0].parent.name, hits[0]

    # ------------------------------------------------------------ 只读 store
    def _candidate(self, candidate_id: str) -> dict:
        cid = str(candidate_id or "").strip()
        if not cid:
            raise PatchError("candidate_id required")
        if self.store is None:
            return {}
        candidate = self.store.get_candidate(self.task_id, cid)
        if candidate is None:
            raise PatchError(
                f"candidate {cid!r} not found in task {self.task_id!r}")
        return candidate

    def _verifications(self, candidate_id: str) -> list[dict]:
        if self.store is None:
            return []
        try:
            rows = self.store.list_verifications(self.task_id)
        except Exception as exc:                      # noqa: BLE001 - 只读回显
            raise PatchError(f"cannot read verifications: {exc}") from exc
        return [dict(row) for row in rows
                if str(row.get("candidate_id") or "") in ("", candidate_id)]

    # ------------------------------------------------------------ 提议
    def propose(self, *, candidate_id: str, source_root: str | Path,
                line: int, argument: str,
                claim: str = "model_hypothesis",
                file: str = "", end_line: int = 0, function: str = "",
                evidence: Iterable[str | Path] = (),
                verification_ids: Iterable[str] = (),
                diff: str | Path = "", patched: str | Path = "",
                trigger_cmd: str, regression_cmds: Iterable[str] = (),
                timeout: float = 60.0, strategy: str = "",
                allow_large: bool = False) -> dict:
        """生成补丁工件（只写 patch_root 下的实验副本，不动 origin）。"""
        if not self.task_id:
            raise PatchError("task_id required")
        if claim not in CLAIM_SOURCES:
            raise PatchError(f"claim must be one of {CLAIM_SOURCES}")

        src = Path(source_root).expanduser()
        if not src.is_dir():
            raise PatchUnsupported(
                f"unsupported: no source tree at {src}; 只有有源码的目标才做补丁")
        src = src.resolve()
        if bool(str(diff or "")) == bool(str(patched or "")):
            raise PatchError("exactly one of diff/patched is required")
        candidate = self._candidate(candidate_id)

        tree = read_tree(src)
        manifest = tree_manifest(tree)
        origin_sha = tree_sha256(manifest)

        # ---- 1) 产出 after 文本与 diff（只对已存在文件、只接受 UTF-8 源码）
        if patched:
            rel = _require_rel(file)
            if rel not in tree:
                raise PatchError(
                    f"patched file {rel!r} is not an existing file in source tree")
            after_text = _read_text(patched)
            before_text = _decode(tree[rel], rel)
            diff_text = build_unified(rel, before_text, after_text)
        else:
            diff_text = _read_text(diff)
            parsed = parse_unified(diff_text)
            if file and _require_rel(file) != parsed[0].path:
                raise PatchError(
                    f"--file {file!r} does not match diff path {parsed[0].path!r}")
        parsed = parse_unified(diff_text)
        problems = hygiene_problems(parsed, diff_text, limits=self.limits,
                                    allow_large=allow_large)
        if problems:
            raise PatchError("diff rejected: " + "; ".join(problems))

        texts = {item.path: _decode(tree[item.path], item.path)
                 for item in parsed}
        new_texts = apply_unified(diff_text, texts)
        patched_tree = dict(tree)
        changed: list[dict] = []
        for item in parsed:
            before_text = texts[item.path]
            after_text = new_texts[item.path]
            if after_text == before_text:
                raise PatchError(f"{item.path}: diff produces identical content")
            patched_tree[item.path] = after_text.encode("utf-8")
            stat = changed_stats(item)
            changed.append({
                "path": item.path,
                "before_sha256": sha256_bytes(before_text.encode("utf-8")),
                "after_sha256": sha256_bytes(after_text.encode("utf-8")),
                "added": stat["added"], "removed": stat["removed"],
                "hunks": stat["hunks"],
            })
        if tree_manifest(patched_tree) == manifest:
            raise PatchError("patch does not change the source tree")

        # ---- 2) 根因（必须落在补丁触及的文件上，line 在文件内）
        rel_cause = _require_rel(file or parsed[0].path)
        if rel_cause not in diff_paths(parsed):
            raise PatchError(
                f"root cause file {rel_cause!r} is not among patched files")
        cause_lines = _decode(tree[rel_cause], rel_cause).splitlines()
        if line < 1 or line > len(cause_lines):
            raise PatchError(
                f"root cause line {line} outside {rel_cause} "
                f"(1..{len(cause_lines)})")
        end = int(end_line or line)
        if end < line or end > len(cause_lines):
            raise PatchError(f"root cause end_line {end} invalid")
        snippet = "\n".join(cause_lines[line - 1:end])
        evidence_refs = list(EvidenceRef.from_path(item, base=src)
                             for item in (evidence or ()))
        verifications = self._verifications(str(candidate_id))
        known = {str(row.get("verification_id") or ""): row
                 for row in verifications}
        requested = [str(v) for v in (verification_ids or ())]
        for vid in requested:
            if self.store is not None and vid not in known:
                raise PatchError(
                    f"verification {vid!r} not found for task {self.task_id!r}")
        verified_ids = [vid for vid in requested
                        if str(known.get(vid, {}).get("status") or "") == "verified"
                        and bool(known.get(vid, {}).get("verified"))]
        status = "verified" if verified_ids else "not_verified"

        finding = FindingRef(
            task_id=self.task_id, candidate_id=str(candidate_id),
            evidence_sha256=str(candidate.get("evidence_sha256") or ""),
            input_sha256=str(candidate.get("input_sha256") or ""),
            crash_type=str(candidate.get("crash_type") or ""),
            verification_ids=tuple(requested),
            verification_status=status,
        )
        root_cause = RootCause(
            root_cause_id="RC1", task_id=self.task_id,
            candidate_id=str(candidate_id), file=rel_cause, line=int(line),
            end_line=end, function=str(function or ""), claim=str(claim),
            argument=str(argument or ""), snippet=snippet,
            snippet_sha256=sha256_bytes(snippet.encode("utf-8")),
            evidence=tuple(evidence_refs), finding=finding,
        )

        tests = {
            "trigger": {"name": "trigger", "cmd": str(trigger_cmd).strip(),
                        "expect_exit": EXPECT_NONZERO},
            "regression": [
                {"name": f"regression-{index}", "cmd": str(cmd).strip(),
                 "expect_exit": EXPECT_ZERO}
                for index, cmd in enumerate(regression_cmds or (), start=1)
            ],
            "timeout": float(timeout),
        }
        if not tests["trigger"]["cmd"]:
            raise PatchError("trigger command required")

        # ---- 3) 落盘：基线 + 实验副本（唯一写入点）
        task_dir = self.task_dir
        task_dir.mkdir(parents=True, exist_ok=True)
        patch_id = self._next_patch_id(task_dir)
        pdir = task_dir / patch_id
        pdir.mkdir(parents=True)
        write_tree(pdir / "baseline", tree)
        write_tree(pdir / "experiment", patched_tree)
        write_json(pdir / "baseline_manifest.json",
                   {"schema": "vulnmap.adaptive.patch.baseline_manifest.v1",
                    "tree_sha256": origin_sha, "files": manifest})

        # 写完副本后再算一次原件：证明 propose 没有动 origin
        if tree_manifest(read_tree(src)) != manifest:
            shutil.rmtree(pdir, ignore_errors=True)
            raise PatchError("origin changed while proposing; patch discarded")

        rollback = {
            "strategy": "restore_baseline_bytes",
            "baseline_tree_sha256": origin_sha,
            "files": list(diff_paths(parsed)),
            "command": f"platform patch rollback {patch_id} "
                       f"--task-id {self.task_id}",
            "integrity_checked": False,
        }
        proposal = PatchProposal(
            patch_id=patch_id, task_id=self.task_id,
            candidate_id=str(candidate_id), root_cause_id="RC1",
            source_root=str(src), diff=diff_text, files=tuple(changed),
            origin={"tree_sha256": origin_sha, "files": len(tree),
                    "touched": [{"path": item["path"],
                                 "sha256": item["before_sha256"]}
                                for item in changed]},
            tests=tests, rollback=rollback, strategy=str(strategy or ""),
        )
        write_json(pdir / "root_cause.json", root_cause.to_dict())
        proposal_bytes = write_json(pdir / "proposal.json", proposal.to_dict())
        return {
            "status": "proposed",
            "patch_id": patch_id,
            "task_id": self.task_id,
            "dir": str(pdir),
            "proposal_sha256": sha256_bytes(proposal_bytes),
            "root_cause": root_cause.to_dict(),
            "proposal": proposal.to_dict(),
            "experiment": {
                "dir": str(pdir / "experiment"),
                "tree_sha256": tree_sha256(tree_manifest(patched_tree)),
                "applied_to_origin": False,
            },
            "origin": {"tree_sha256": origin_sha, "files": len(tree),
                       "unchanged": True},
        }

    # ------------------------------------------------------------ 测试
    def test(self, patch_id: str, *, timeout: float | None = None,
             keep_run: bool = False) -> dict:
        """在**独立副本**上跑：原版触发 / 补丁不触发 / 回归 / 回滚。"""
        pdir, prop_doc = self._load_proposal(patch_id)
        proposal = PatchProposal.from_dict(prop_doc)
        proposal_sha = file_sha256(pdir / "proposal.json")
        gates: list[Gate] = []
        blockers: list[str] = []

        def block(code: str, detail: str) -> dict:
            blockers.append(code)
            gates.append(Gate(code, False, detail))
            return self._write_test(pdir, patch_id, proposal, proposal_sha,
                                    gates, [], blockers, {}, {}, {},
                                    status="blocked")

        # 基线必须完好（回了原始字节，才能谈“原版触发”）
        try:
            base_tree = read_tree(pdir / "baseline")
        except PatchError as exc:
            return block("baseline_missing", str(exc))
        base_manifest = tree_manifest(base_tree)
        base_sha = tree_sha256(base_manifest)
        if base_sha != str(proposal.origin.get("tree_sha256") or ""):
            return block("baseline_tampered",
                         f"baseline={base_sha} expected="
                         f"{proposal.origin.get('tree_sha256')}")
        gates.append(Gate("baseline_matches_proposal", True, base_sha))

        # origin 现在还必须与提案时一致（原件不能被悄悄改过）
        try:
            origin_manifest = manifest_of_tree(proposal.source_root)
        except PatchError as exc:
            return block("origin_unreadable", str(exc))
        origin_sha = tree_sha256(origin_manifest)
        origin_ok = origin_sha == str(proposal.origin.get("tree_sha256") or "")
        gates.append(Gate("origin_unchanged", origin_ok, origin_sha))
        if not origin_ok:
            return block("origin_changed",
                         f"origin={origin_sha} expected="
                         f"{proposal.origin.get('tree_sha256')}")

        # 独立副本：从 baseline 重算一遍，不复用 experiment/
        try:
            touched = diff_paths(parse_unified(proposal.diff))
            base_texts = {rel: _decode(base_tree[rel], rel) for rel in touched}
            patched_texts = apply_unified(proposal.diff, base_texts)
        except (KeyError, PatchError) as exc:
            return block("diff_does_not_apply", str(exc))
        patched_tree = dict(base_tree)
        for rel, text in patched_texts.items():
            if rel in patched_tree and text != base_texts[rel]:
                patched_tree[rel] = text.encode("utf-8")
        if tree_manifest(patched_tree) == base_manifest:
            return block("patch_is_noop", "patched tree equals baseline")

        run_root = pdir / "run"
        try:
            if run_root.exists():
                shutil.rmtree(run_root)
            write_tree(run_root / "baseline", base_tree)
            write_tree(run_root / "patched", patched_tree)
        except OSError as exc:
            return block("run_copy_failed", f"{type(exc).__name__}: {exc}")
        gates.append(Gate("independent_copy", True,
                          f"baseline={base_sha} "
                          f"patched={tree_sha256(tree_manifest(patched_tree))}"))

        limit = float(timeout if timeout is not None
                      else proposal.tests.get("timeout") or 60.0)
        runs: list[dict] = []
        runs.append(self._run_stage(pdir, "trigger-baseline", "trigger_baseline",
                                    proposal.tests["trigger"], "run/baseline",
                                    limit, gates))
        patched_trigger = dict(proposal.tests["trigger"])
        patched_trigger["expect_exit"] = EXPECT_ZERO
        runs.append(self._run_stage(pdir, "trigger-patched", "trigger_patched",
                                    patched_trigger, "run/patched",
                                    limit, gates))
        for command in proposal.tests.get("regression") or ():
            runs.append(self._run_stage(
                pdir, str(command.get("name") or "regression"), "regression",
                command, "run/patched", limit, gates))

        # 跑完再看一次原件：测试命令不许碰 origin
        try:
            origin_after = tree_sha256(manifest_of_tree(proposal.source_root))
        except PatchError as exc:
            origin_after = f"unreadable: {exc}"
        gates.append(Gate("origin_unchanged_after_test",
                          origin_after == origin_sha, origin_after))

        rollback = self._restore_experiment(pdir, base_tree, base_sha)
        gates.append(Gate("rollback_verified", bool(rollback.get("ok")),
                          str(rollback.get("detail") or rollback.get(
                              "restored_tree_sha256") or "")))

        status = "passed" if all(g.ok for g in gates) else "failed"
        if not keep_run:
            shutil.rmtree(run_root, ignore_errors=True)
        independent = {"baseline_tree_sha256": base_sha,
                       "patched_tree_sha256": tree_sha256(
                           tree_manifest(patched_tree)),
                       "from": "baseline (独立副本，不复用 experiment/)"}
        origin_doc = {"tree_sha256": origin_sha,
                      "unchanged": origin_after == origin_sha}
        return self._write_test(pdir, patch_id, proposal, proposal_sha, gates,
                                runs, blockers, origin_doc, independent,
                                rollback, status=status)

    def _run_stage(self, pdir: Path, tag: str, role: str, command: Mapping,
                   root_rel: str, timeout: float, gates: list[Gate]) -> dict:
        root = pdir / root_rel
        cmd = str(command.get("cmd") or "")
        expect = command.get("expect_exit", EXPECT_ZERO)
        result = run_command(cmd, cwd=root, timeout=timeout)
        log = write_log(pdir / "logs" / f"{tag}.log", result)
        ok = _expect_ok(expect, result.exit_code)
        gates.append(Gate(f"{tag}:{role}", ok,
                          f"cmd={cmd!r} exit={result.exit_code} "
                          f"expect={expect} timed_out={result.timed_out}"))
        return {
            "name": tag, "role": role, "cmd": cmd,
            "root": root_rel, "expect": expect,
            "exit_code": result.exit_code, "timed_out": bool(result.timed_out),
            "ok": bool(ok), "duration": round(float(result.duration), 3),
            "output_tail": log["output_tail"],
            "log": _rel_to(Path(log["log"]), pdir),
            "log_sha256": log["log_sha256"], "log_size": log["log_size"],
        }

    def _restore_experiment(self, pdir: Path, base_tree: dict[str, bytes],
                            expected_sha: str) -> dict:
        experiment = pdir / "experiment"
        try:
            write_tree(experiment, base_tree)
            restored = tree_sha256(tree_manifest(read_tree(experiment)))
        except (OSError, PatchError) as exc:
            return {"ok": False, "strategy": "restore_baseline_bytes",
                    "error": f"{type(exc).__name__}: {exc}"}
        ok = restored == expected_sha
        return {"ok": ok, "strategy": "restore_baseline_bytes",
                "restored_tree_sha256": restored,
                "expected_tree_sha256": expected_sha,
                "files": len(base_tree),
                "detail": "" if ok else f"restored={restored} expected={expected_sha}"}

    def _write_test(self, pdir: Path, patch_id: str, proposal: PatchProposal,
                    proposal_sha: str, gates: list[Gate], runs: list[dict],
                    blockers: list[str], origin: dict, independent: dict,
                    rollback: dict, *, status: str) -> dict:
        test = PatchTest(
            test_id="T1", patch_id=patch_id, task_id=self.task_id,
            status=status, gates=tuple(gates), runs=tuple(runs),
            blockers=tuple(blockers), proposal_sha256=proposal_sha,
            origin=dict(origin), independent=dict(independent),
            rollback=dict(rollback),
        )
        data = write_json(pdir / "test.json", test.to_dict())
        return {"status": status, "patch_id": patch_id,
                "task_id": self.task_id, "test": test.to_dict(),
                "test_sha256": sha256_bytes(data),
                "gates": [gate.to_dict() for gate in gates],
                "passed": test.passed,
                "note": "补丁测试通过只表示工程工件可复现；漏洞结论由 verify 决定"}

    # ------------------------------------------------------------ 回滚
    def rollback(self, patch_id: str) -> dict:
        """显式回滚实验副本并校验哈希（原件从不参与）。"""
        pdir, prop_doc = self._load_proposal(patch_id)
        proposal = PatchProposal.from_dict(prop_doc)
        base_tree = read_tree(pdir / "baseline")
        expected = str(proposal.origin.get("tree_sha256") or "")
        if tree_sha256(tree_manifest(base_tree)) != expected:
            raise PatchError("baseline tampered; rollback refused")
        result = self._restore_experiment(pdir, base_tree, expected)
        if not result.get("ok"):
            raise PatchError(f"rollback failed: {result.get('detail')}")
        return {"status": "reverted", "patch_id": patch_id, "task_id": self.task_id,
                "rollback": result}

    # ------------------------------------------------------------ 复核
    def review(self, patch_id: str) -> dict:
        """只判 `patch_validation`：独立测试通过才 engineering accepted。"""
        pdir, prop_doc = self._load_proposal(patch_id)
        proposal = PatchProposal.from_dict(prop_doc)
        proposal_sha = file_sha256(pdir / "proposal.json")
        gates: list[Gate] = []
        reasons: list[str] = []

        # 1) 根因与证据：文档在、schema 认得、证据现场可复算、snippet 对得上
        cause_doc = read_json(pdir / "root_cause.json")
        try:
            root_cause = RootCause.from_dict(cause_doc)
        except PatchError as exc:
            root_cause = None
            gates.append(Gate("root_cause_valid", False, str(exc)))
        if root_cause is not None:
            gates.append(Gate("root_cause_valid", True,
                              f"{root_cause.file}:{root_cause.line} "
                              f"claim={root_cause.claim}"))
            gates.append(Gate(
                "root_cause_matches_finding",
                root_cause.task_id == proposal.task_id
                and root_cause.candidate_id == proposal.candidate_id,
                f"{root_cause.task_id}/{root_cause.candidate_id}"))
            gates.append(Gate(
                "root_cause_in_patch",
                root_cause.file in [str(item.get("path"))
                                    for item in proposal.files],
                root_cause.file))
            evidence_ok = bool(root_cause.evidence) and all(
                ref.verify() for ref in root_cause.evidence)
            gates.append(Gate("evidence_recomputable", evidence_ok,
                              f"{len(root_cause.evidence)} ref(s)"))
            snippet_ok = False
            detail = "baseline file missing"
            try:
                base_lines = _decode(
                    (pdir / "baseline" / root_cause.file).read_bytes(),
                    root_cause.file).splitlines()
                snippet = "\n".join(
                    base_lines[root_cause.line - 1:root_cause.end_line])
                snippet_ok = (sha256_bytes(snippet.encode("utf-8"))
                              == root_cause.snippet_sha256)
                detail = f"sha256={'ok' if snippet_ok else 'mismatch'}"
            except (OSError, PatchError) as exc:
                detail = f"{type(exc).__name__}: {exc}"
            gates.append(Gate("root_cause_snippet_matches_baseline",
                              snippet_ok, detail))
            if root_cause.finding is None:
                gates.append(Gate("finding_present", False, "no finding ref"))
            else:
                finding_ok = bool(root_cause.finding.candidate_id)
                if self.store is not None:
                    finding_ok = finding_ok and self.store.get_candidate(
                        self.task_id, root_cause.finding.candidate_id) is not None
                gates.append(Gate("finding_present", finding_ok,
                                  root_cause.finding.candidate_id))

        # 2) 原件未变
        try:
            origin_sha = tree_sha256(manifest_of_tree(proposal.source_root))
        except PatchError as exc:
            origin_sha = f"unreadable: {exc}"
        gates.append(Gate("origin_unchanged",
                          origin_sha == str(proposal.origin.get("tree_sha256")),
                          origin_sha))

        # 3) 测试与回滚（测试文档必须属于这份提案，且工件留在本地）
        test_path = pdir / "test.json"
        test = None
        if not test_path.is_file():
            gates.append(Gate("test_present", False, "test.json missing"))
        else:
            try:
                test = PatchTest.from_dict(read_json(test_path))
            except PatchError as exc:
                gates.append(Gate("test_present", False, str(exc)))
        if test is not None:
            test_sha = file_sha256(test_path)
            gates.append(Gate("test_present", True, test_sha))
            gates.append(Gate("test_matches_proposal",
                              test.proposal_sha256 == proposal_sha,
                              f"test={test.proposal_sha256} "
                              f"proposal={proposal_sha}"))
            gates.append(Gate("test_passed", test.passed,
                              f"status={test.status} "
                              f"blockers={list(test.blockers)}"))
            gates.append(Gate("test_gates_all_ok",
                              bool(test.gates) and all(g.ok for g in test.gates),
                              f"{sum(1 for g in test.gates if not g.ok)} "
                              f"failed gate(s)"))
            gates.append(Gate("test_runs_consistent",
                              _runs_consistent(test.runs),
                              f"{len(test.runs)} run(s)"))
            gates.append(Gate(
                "test_baseline_matches_proposal",
                str(test.independent.get("baseline_tree_sha256") or "")
                == str(proposal.origin.get("tree_sha256") or ""),
                str(test.independent.get("baseline_tree_sha256") or "")))
            patched_ok, patched_detail = _patched_matches(proposal, pdir)
            gates.append(Gate("patched_tree_matches_diff", patched_ok,
                              patched_detail))
            gates.append(Gate("rollback_verified",
                              bool(test.rollback.get("ok")),
                              str(test.rollback.get("detail")
                                  or test.rollback.get("restored_tree_sha256")
                                  or "")))
            local_ok, local_detail = _artifacts_local(test.runs, pdir)
            gates.append(Gate("test_artifacts_local", local_ok, local_detail))

        # 4) 补丁侧不许夹带裁决字段
        docs = [prop_doc, cause_doc]
        if test is not None:
            docs.append(test.to_dict())
        found: list[str] = []
        for doc in docs:
            found.extend(verdict_fields_in(doc))
        gates.append(Gate("no_verdict_claim", not found, f"fields={found}"))
        reasons.extend(gate.name for gate in gates if not gate.ok)

        accepted = all(gate.ok for gate in gates) and bool(gates)
        vulnerability = self._vulnerability_block(proposal.candidate_id)
        review = PatchReview(
            review_id="R1", patch_id=patch_id, task_id=self.task_id,
            status="accepted" if accepted else "rejected",
            engineering={"accepted": accepted,
                         "proposal_sha256": proposal_sha,
                         "test_sha256": file_sha256(test_path)
                         if test_path.is_file() else "",
                         "checks": [gate.to_dict() for gate in gates]},
            gates=tuple(gates), reasons=tuple(dict.fromkeys(reasons)),
            vulnerability=vulnerability, proposal_sha256=proposal_sha,
            test_sha256=file_sha256(test_path) if test_path.is_file() else "",
        )
        data = write_json(pdir / "review.json", review.to_dict())
        return {"status": review.status, "accepted": review.accepted,
                "patch_id": patch_id, "task_id": self.task_id,
                "review": review.to_dict(),
                "review_sha256": sha256_bytes(data),
                "reasons": list(review.reasons)}

    def _vulnerability_block(self, candidate_id: str) -> dict:
        """既有 verify 台账的只读回显；没有记录就是 not_evaluated。"""
        block = {"status": "not_evaluated", "verification_ids": [],
                 "source": "agent.platform.verify",
                 "note": "补丁复核不改写漏洞结论；是否有漏洞由 verify 决定"}
        if self.store is None:
            return block
        try:
            rows = self.store.list_verifications(self.task_id)
        except Exception:                             # noqa: BLE001 - 只读
            return block
        ids = [str(row.get("verification_id") or "")
               for row in rows
               if str(row.get("candidate_id") or "") in ("", candidate_id)
               and bool(row.get("verified"))
               and str(row.get("status") or "") == "verified"]
        if ids:
            block["status"] = "verified_in_platform"
            block["verification_ids"] = ids
        return block


def _require_rel(value: str) -> str:
    return safe_relpath(value)


def _decode(data: bytes, rel: str) -> str:
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PatchError(f"binary/non-utf8 source file: {rel} ({exc})") from exc


def _read_text(path: str | Path) -> str:
    try:
        return Path(path).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        raise PatchError(f"cannot read file {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise PatchError(f"file is not utf-8 text: {path} ({exc})") from exc


def _runs_consistent(runs: Iterable[Mapping]) -> bool:
    """测试文档自洽：每条 run 的 ok 必须与 expect/exit_code 一致。"""
    seen = False
    for run in runs or ():
        seen = True
        expect = run.get("expect")
        exit_code = run.get("exit_code")
        if bool(run.get("ok")) != _expect_ok(expect, exit_code):
            return False
    return seen


def _patched_matches(proposal: PatchProposal, pdir: Path) -> tuple[bool, str]:
    """从 baseline + diff 重算补丁树，必须与测试记下的独立副本同哈希。"""
    try:
        touched = diff_paths(parse_unified(proposal.diff))
        base = read_tree(pdir / "baseline")
        texts = {rel: _decode(base[rel], rel) for rel in touched}
        patched = apply_unified(proposal.diff, texts)
        tree = dict(base)
        for rel, text in patched.items():
            tree[rel] = text.encode("utf-8")
        computed = tree_sha256(tree_manifest(tree))
    except (KeyError, PatchError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, computed


def _artifacts_local(runs: Iterable[Mapping], pdir: Path) -> tuple[bool, str]:
    """测试文档里的 run 根必须落在 patch 目录内（防跨目录拼证据）。"""
    allowed = {str((pdir / rel).resolve()) for rel in RUN_ROOTS}
    for run in runs or ():
        root = str(run.get("root") or "")
        if not root:
            return False, "run without root"
        if Path(root).is_absolute() or ".." in Path(root).parts:
            return False, f"non-local run root: {root}"
        if str((pdir / root).resolve()) not in allowed:
            return False, f"unexpected run root: {root}"
    return True, f"{len(list(runs or ()))} run(s)"


__all__ = ["PatchWorkflow", "RUN_ROOTS", "PATCH_VERSION", "digest_of", "now"]
