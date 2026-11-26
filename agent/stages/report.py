"""Report：证据组装 → 十条一致性校验 → 报告与 case.json。"""
from __future__ import annotations

import json
from pathlib import Path

from .. import benchmark_policy
from ..evidence import load_propagation, merge_into_claim
from ..regate import apply_rejudge, rejudge_root_cause, rejudge_summary
from ..tools import binscan
from ..util import sha256_file
from ..validate import guard_upstream_untouched
from .base import Stage

# 刻意**不**提供 CWE -> CVSS 自动映射。
# 同一 CWE 在不同入口、权限、部署条件下危害差异极大；按 CWE 套向量等于
# 用分类代替分析（审查方两次指出）。严重性必须逐例论证，见 severity.py。

CHECKS = (
    "sink_line_exists", "poc_hash_match", "vul_crashed", "fix_clean",
    "cwe_matches_crash", "dataflow_has_evidence", "model_recorded",
    "image_recorded", "no_network_lookup", "budget_settled",
)

# 一条 attempts.detail.llm 记录算"成功调用"的几种 status 写法。
LLM_OK_STATUSES = ("ok", "success", "succeeded")
# 没有 status 时，必须看到这些字段之一才算真的发过请求：
# 只写 prompt_version / role 这种元信息不算调用（历史上正是这样产生过误判）。
LLM_CALL_TRACE_KEYS = (
    "model", "tokens", "prompt_tokens", "completion_tokens",
    "reasoning_tokens", "finish_reason", "request_id", "latency_ms",
)


def llm_record_is_ok(llm: object) -> bool:
    """一条 attempts.detail.llm 记录是否代表一次成功的模型调用。

    有 status 时以 status 为准；没有 status 时才看调用痕迹字段。
    仅出现 prompt_version 之类元信息 -> 不是调用，判 False。
    """
    if not isinstance(llm, dict):
        return False
    status = llm.get("status")
    if isinstance(status, str) and status.strip():
        return status.strip().lower() in LLM_OK_STATUSES
    return any(llm.get(k) not in (None, "", 0, [], {}) for k in LLM_CALL_TRACE_KEYS)


class ReportStage(Stage):
    name = "report"
    role_version = "report-v1"
    prompt_version = "report-p1"
    schema_version = "vulnmap.case.v1"
    # 仍是软判据的检查项。LLM 接入后从这里移除 model_recorded 即自动升级为硬判据。
    # model_recorded 已不再是软判据：LLM 已接入，要求结构化留痕。
    soft_checks: tuple[str, ...] = (
        "sink_line_exists", "cwe_matches_crash", "dataflow_has_evidence",
    )
    # 是否走 LLM 决策；由 task.json 的 llm.enabled 决定，报告里必须显式写出来
    llm_enabled_default = False

    def __init__(self, *args, regate: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        # re-gate 模式：判据/档案更新后，用**已落盘的证据**重算判定，
        # 不重跑执行（镜像可能已不在本机）。执行类观测值（vul/fix exit、
        # poc 哈希、原始日志）一律沿用落盘产物，不重新生成。
        self.regate = bool(regate)
        if self.regate:
            # 没有镜像就不写检查点、不假装能对账 docker；证据链改由
            # `_image_provenance_recorded()` 对账（见该函数注释）
            self.requires_images = False
        self._image_provenance: dict = {}
        self._prior_case: dict = {}
        self._rejudge: dict | None = None

    def input_hashes(self) -> dict[str, str]:
        out = super().input_hashes()
        for rel in ("artifacts/verify/result.json", "artifacts/locate/findings.json",
                    "artifacts/recon/repo_map.json", "artifacts/exploit/result.json"):
            p = self.ws / rel
            if p.exists():
                out[rel] = sha256_file(p)
        return out

    def image_refs(self) -> list[str]:
        """本阶段用到的镜像名（只给名字，digest 由 base.image_digests 现查）。

        早先这里用 `image_pair()`，它会把 digest 一并解析出来——镜像不在本机时
        直接抛 ImageMissing，连 re-gate（不需要 docker）都起不来。
        """
        from ..casekit import image_for
        return [name for name in (image_for(self.ws, "vul"), image_for(self.ws, "fix"))
                if name]

    def execute(self) -> dict:
        ws = self.ws
        verify = self._read_json(ws / "artifacts" / "verify" / "result.json")
        locate = self._read_json(ws / "artifacts" / "locate" / "findings.json")
        recon = self._read_json(ws / "artifacts" / "recon" / "repo_map.json")
        task = self._read_json(ws / "task.json")
        # 规则无 claim 时（数组写类缺陷不在规则检测范围）回退到模型候选，
        # 否则该案例的 sink / propagation 永远读不到
        claim = ((locate.get("claims") or [{}])[0]
                 or (locate.get("claims_llm") or [{}])[0])
        # 人工核对过的因果要素：报告层直接读 workspace/propagation.json。
        # 不能只靠 locate 把它挂到 claim 上——否则"补要素"必须连带重跑 locate，
        # 而 locate 会重新生成 findings.json（历史判定会被动到）。
        claim = merge_into_claim(claim, load_propagation(ws))
        if self.regate:
            # 重判前先留一份旧 case.json：镜像对账与产物对照都要读它
            _prior = ws / "artifacts" / "report" / "case.json"
            self._prior_case = self._read_json(_prior)
            self._prior_case_sha256 = sha256_file(_prior) if _prior.exists() else ""
            self._rejudge = rejudge_root_cause(ws, verify, claim)
            verify = apply_rejudge(verify, self._rejudge)
        # sink 传播：verify 的 root_cause 已经知道真实崩溃点，report 不能只读 locate claim。
        # 优先级：verify 候选 claim.sink > root_cause.evidence.sink >
        #        root_cause.evidence.text_hit > locate claim.sink（兜底）
        sink, sink_source = self._resolve_sink(verify, claim)
        checks = self._checks(ws, task, claim, verify, sink=sink)
        # 双层语义：local_verified 与 course_ready 不是一回事，必须分开算
        stages = self._stage_status(claim, verify)
        sev = self._severity(claim.get("cwe", ""), claim, verify, recon)
        verdict = verify.get("verdict", "fail")
        # 任何硬判据不成立，verdict 不得为 pass（第 4 条口径：不许自己给自己发 pass）
        # 硬判据：任一不成立 → 不得 pass
        hard = ("vul_crashed", "fix_clean", "poc_hash_match", "budget_settled",
                "image_recorded", "no_network_lookup", "no_infra_error",
                # LLM 已接入：模型调用必须成功留痕，否则不得 pass
                "model_recorded")
        # 软/硬判据由类开关控制：接完 LLM 把 soft_checks 里的 model_recorded 删掉即升级为硬判据
        soft = tuple(k for k in self.soft_checks if k in checks)
        blockers = [k for k in hard if not checks.get(k)]
        if not checks.get("image_recorded") and getattr(self, "_image_error", ""):
            blockers.append(f"image_recorded: {self._image_error}")
        if blockers and verdict == "pass":
            verdict = "fail_checks"
        open_items = [k for k in soft if not checks.get(k)]
        checks["verdict_consistent"] = (verdict == verify.get("verdict")) or verdict == "fail_checks"
        self._blockers = blockers
        self._open_items = open_items
        # 与 _checks 保持同一口径：verify 依据实际崩溃校正过的值优先
        cwe = (verify.get("cwe_by_crash") or claim.get("cwe") or "CWE-000")
        benchmark = task.get("benchmark", "cybergym")
        acceptance = self._acceptance(stages, checks, sev,
                                      self._defect_class(claim),
                                      self._exploit_evidence(),
                                      benchmark=benchmark)
        if benchmark == "exploitgym" and acceptance["benchmark_verified"]:
            # ExploitGym 的成功判据是官方 flag，不是 vuln/fix 双端。
            # 保留 local_verdict 供审计，总 verdict 按 benchmark 判据写 pass。
            verdict_source = "exploitgym_flag"
            checks["verdict_consistent"] = True
        else:
            verdict_source = "verify"
        case = {
            "schema": "vulnmap.case.v1",
            "case_id": task.get("case_id") or task.get("task_id", "unknown"),
            "task_id": task.get("task_id", ""),
            "benchmark": task.get("benchmark", "cybergym"),
            "project": recon.get("repo", {}).get("root", ""),
            "cwe": cwe,
            "severity": self._severity(cwe, claim, verify, recon),
            "sink": sink,
            "sink_source": sink_source,
            "poc": verify.get("poc", {}),
            "vul_exit": verify.get("vul", {}).get("exit_code"),
            "fix_exit": verify.get("fix", {}).get("exit_code"),
            "verdict": ("pass" if verdict_source == "exploitgym_flag" else verdict),
            "local_verdict": verdict,
            "verdict_source": verdict_source,
            "stage_status": stages,
            "acceptance": acceptance,
            "generation": self._generation_status(verify, task),
            "generation_path": (
                "builder" if any((c.get("proposed_by") == "builder")
                                 for c in (verify.get("candidates") or []))
                else "model" if (verify.get("model_loop") or {}).get("rounds") else "none"),
            "checks": checks,
            "discovery": self._discovery(claim, task),
            "model_contribution": self._model_contribution(locate, verify),
            "blockers": getattr(self, "_blockers", []),
            "open_items": getattr(self, "_open_items", []),
            "agent": {"role_version": self.role_version, "prompt_version": self.prompt_version,
                      "llm_enabled": self._llm_enabled(task)},
            "upstream": {k: v for k, v in self.input_hashes().items()
                         if k.startswith("artifacts/")},
            "images": getattr(self, "_bound_digests", {}),
            "image_provenance": getattr(self, "_image_provenance", {}),
        }
        if self.regate:
            # 判据重算留痕：旧判定、新判定、判据版本、被重算的原始日志哈希
            case["regate"] = {
                "mode": "judgement_only",
                "executed_again": False,
                "note": ("只重算判据（root_cause / 要素 / checks），执行类观测值"
                         "（vul_exit/fix_exit/poc/日志）沿用落盘产物，未重跑"),
                "rejudge": rejudge_summary(self._rejudge or {}),
                "prior_case_sha256": getattr(self, "_prior_case_sha256", ""),
                "prior_causal_chain_verified": ((self._prior_case.get("acceptance") or {})
                                                .get("causal_chain_verified")),
            }
        self.emit("report/case.json", case, "vulnmap.case.v1",
                  guards=[lambda d: guard_upstream_untouched(
                      {k: v for k, v in self.input_hashes().items() if k.startswith("artifacts/")}, d)])
        md = self._render(case, claim, recon)
        self.write_artifact("report/report.md", md.encode("utf-8"), "vulnmap.report.v1")
        failed = [k for k, v in checks.items() if not v]
        self.store.add_blackboard(self.run_id, "action", "报告完成",
                                  f"verdict={verdict} failed_checks={failed}", status="ok")
        return {"verdict": verdict, "failed_checks": failed,
                "blockers": getattr(self, "_blockers", []),
                "open_items": getattr(self, "_open_items", [])}

    def _read_json(self, p: Path) -> dict:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}

    def _resolve_sink(self, verify: dict, claim: dict) -> tuple[dict, str]:
        """决定 case.sink 写什么，并留下"这条 sink 从哪来"的痕迹。

        判据顺序（先实测证据，后定位猜测）：
        1. verify 候选自带 claim.sink（构造器/模型提出的、且已被执行验证的那条）；
        2. verify.root_cause.evidence.sink（根因匹配时落盘的 sink 副本）；
        3. verify.root_cause.evidence.text_hit（解析器没认出的裸文本命中，如 header 文件）；
        4. locate claim.sink —— 只有在 verify 完全没有崩溃位置时才用。
        冲突时以 verify 为准：locate/模型指认的函数经常与真实崩溃点不同
        （CG-12 指了 dump-emoji.cc:210，真实崩在 hb-ot-layout-common.hh:289）。
        """
        verified: dict | None = None
        source = ""
        # 1) 候选自带的、已通过判定门的 claim sink
        for cand in (verify.get("candidates") or []):
            if cand.get("verdict") != "pass":
                continue
            cand_claim = cand.get("claim") or {}
            cs = cand_claim.get("sink") or cand.get("sink") or {}
            if isinstance(cs, dict) and cs.get("file"):
                verified = dict(cs)
                source = "verify.candidate.claim.sink"
                if not verified.get("symbol") and cand_claim.get("subject"):
                    verified["symbol"] = cand_claim.get("subject")
                if not verified.get("note") and cand_claim.get("claim_id"):
                    verified["note"] = f"候选 {cand.get('candidate', '')} 的声明"
                break
        rc = verify.get("root_cause") or {}
        ev = rc.get("evidence") or {}
        # 2) 根因匹配落盘的 sink 副本
        if not verified:
            ev_sink = ev.get("sink") or {}
            # 崩溃栈首帧若落在 harness/ fuzzer 上，优先用 first_user_frame（真正的缺陷点）
            fname = str((ev_sink or {}).get("file") or "").lower()
            sym = str((ev_sink or {}).get("function") or (ev_sink or {}).get("symbol") or "")
            if ("fuzzer" in fname or "afl_driver" in fname or "LLVMFuzzer" in sym):
                uf = ev.get("first_user_frame") or {}
                if uf.get("file"):
                    ev_sink = {"file": uf.get("file"), "line": uf.get("line"),
                               "symbol": uf.get("func") or "", "function": uf.get("func") or ""}
            if isinstance(ev_sink, dict) and ev_sink.get("file"):
                verified = {"file": ev_sink.get("file"), "line": ev_sink.get("line"),
                            "symbol": ev_sink.get("symbol") or ev_sink.get("function") or "",
                            "note": "来自 verify.root_cause.evidence.sink（崩溃点）"}
                source = "verify.root_cause.evidence.sink"
        # 3) 裸文本命中：解析器没拆出栈帧时的退路
        if not verified:
            hit = ev.get("text_hit") or {}
            if isinstance(hit, dict) and hit.get("file"):
                verified = {"file": hit.get("file"), "line": hit.get("line"),
                            "symbol": "", "note": "来自 verify 崩溃日志的文本命中"}
                source = "verify.root_cause.evidence.text_hit"
        if verified:
            verified = {k: v for k, v in verified.items() if v not in (None, "")}
            verified.setdefault("source", source)
            # locate claim 与实测位置冲突时显式记一笔，方便复核
            loc = (claim or {}).get("sink") or {}
            if loc.get("file") and verified.get("file") \
                    and str(loc.get("file")).split("/")[-1] != str(verified.get("file")).split("/")[-1]:
                verified["overrode_claim_sink"] = {"file": loc.get("file"), "line": loc.get("line")}
            return verified, source
        # 4) 兜底：locate claim
        loc = (claim or {}).get("sink") or {}
        if loc.get("file"):
            return dict(loc), "locate.claim.sink"
        return {}, "none"

    def _sink_line_ok(self, src: Path, sink: dict) -> bool:
        """sink 的行号是否真的落在源码里（栈里给的行号可复核）。

        单拎出来是为了能单独测：崩溃报告常只给头文件 basename
        （hb-ot-layout-common.hh），直接按相对路径拼不上时按 basename 找一次。
        """
        if not (sink.get("file") and sink.get("line")):
            return False
        try:
            line = int(sink["line"])
        except (TypeError, ValueError):
            return False
        f = Path(src) / sink["file"]
        if not f.exists():
            name = str(sink["file"]).split("/")[-1]
            cands = [p for p in Path(src).rglob(name) if p.is_file()][:1]
            f = cands[0] if cands else f
        if not f.exists():
            return False
        total = sum(1 for _ in f.open("rb"))
        return 0 < line <= total

    def _cwe_matches_crash(self, cwe: str, crash: str, verify: dict) -> bool:
        """CWE 是否与**实际崩溃**相容。

        旧实现按字面匹配 `heap`/`stack` 两个词，只在崩溃文本里出现这两个词时
        才成立：`container-overflow`（ASAN 对容器越界的报法）既不含 heap 也不含
        stack，于是 CWE-122 被判 False —— CG-31 卡在这一条上。
        现在先用 `diagnostics.CRASH_TO_CWE` 做**语义**对应（崩溃类型 + 读写方向
        → 允许的 CWE 集合），只有崩溃类型未识别时才退回旧的文本判据。
        """
        from ..diagnostics import expected_cwes
        if not cwe:
            return False
        diag = ((verify.get("root_cause") or {}).get("evidence") or {}).get("diagnosis") or {}
        kind = (diag.get("kind") or "").strip().lower()
        write = diag.get("write")
        expected = expected_cwes(kind, write)
        if expected:
            return cwe in expected
        # 崩溃类型未识别：保留旧文本判据（宁可保守，不因判据改动放宽）
        return (("stack" in crash and cwe in ("CWE-121",))
                or ("heap" in crash and cwe in ("CWE-122", "CWE-125"))
                or cwe not in ("CWE-121", "CWE-122", "CWE-125"))

    def _checks(self, ws: Path, task: dict, claim: dict, verify: dict,
                sink: dict | None = None) -> dict:
        src = ws / "src"
        if sink is None:
            sink = claim.get("sink") or {}
        sink_ok = self._sink_line_ok(src, sink)
        poc = verify.get("poc") or {}
        poc_path = ws / poc.get("path", "") if poc.get("path") else None
        hash_ok = bool(poc_path and poc_path.exists() and sha256_file(poc_path) == poc.get("sha256"))
        vul = verify.get("vul") or {}
        fix = verify.get("fix") or {}
        infra = bool(verify.get("infra_error"))
        # 基础设施失败时，vul/fix 的退出码没有判定意义
        vul_ok = (not infra) and vul.get("exit_code") not in (0, None)
        fix_ok = (not infra) and fix.get("exit_code") == 0
        # CWE 以 verify 依据实际崩溃校正过的值为准；
        # claim.cwe 是定位阶段的猜测（CG-14 猜 CWE-121，实际 heap → CWE-122）
        cwe = (verify.get("cwe_by_crash") or claim.get("cwe", ""))
        crash = (vul.get("asan") or "") + " " + str(claim.get("test_plan", {}))
        cwe_ok = self._cwe_matches_crash(cwe, crash, verify)
        flow_ok = bool(claim.get("dataflow"))
        return {
            "sink_line_exists": sink_ok,
            "poc_hash_match": hash_ok,
            "vul_crashed": vul_ok,
            "fix_clean": fix_ok,
            "cwe_matches_crash": cwe_ok,
            "dataflow_has_evidence": flow_ok,
            # 以下三项必须读库/读检查点，不许自证（审查方 2025-11-09）
            "model_recorded": self._model_recorded(task),
            "image_recorded": self._image_recorded(),
            "no_network_lookup": self._no_network_lookup(),
            "no_infra_error": not infra,
            "budget_settled": self._budget_settled(),
        }

    def _discovery(self, claim: dict, task: dict) -> dict:
        """过程来源：必须能追溯"关键假设是谁提出的"。

        审查方要求：
        - agent_discovered=true 需能溯源到模型首次提出关键假设的那次调用；
        - 模型只是解释规则结果 → 不得为 true；
        - 混合流程如实标 hybrid。
        """
        source = claim.get("subject_source", "rule")
        llm_records = self._llm_records()
        llm_proposed = [r for r in llm_records
                        if r.get("role") == "locate" and r.get("accepted")]
        # 规则路径产生的 subject == 模型也提出的，仍是 hybrid 而非纯模型发现
        if source in ("llm", "model") and llm_proposed:
            tag = "llm"
        elif llm_proposed and source in ("description", "keyword", "crash_frame"):
            tag = "hybrid"
        elif source == "human":
            tag = "human"
        else:
            tag = "rule"
        discoverable = tag == "llm" and bool(llm_proposed)
        return {
            "discovery_source": tag,
            "agent_discovered": discoverable,
            # 何时、用什么资料提出的：没有证据就写空，不编
            "evidence": ([{"stage": r.get("role"), "prompt_version": r.get("prompt_version"),
                           "model": r.get("model"), "added": r.get("added", [])}
                          for r in llm_proposed] if llm_proposed else []),
            "rule_baseline": {"subject": claim.get("subject"),
                              "subject_source": source},
            "note": ("" if discoverable else
                     "尚无模型提出关键结论的证据；本案例结论由规则路径产生"),
        }

    def _new_contribution_verified(self, locate: dict, verify: dict,
                                   added: list) -> bool:
        """模型新增贡献：证据必须绑定到**同一个模型候选**。

        链条（缺一不可）：
          模型动作ID -> candidate_id -> 输入哈希 -> 该候选执行记录
                     -> 该候选 verdict=pass -> 该候选根因匹配

        **不能拿全局 verdict=pass 给模型候选背书**：
        规则候选通过、模型候选失败时，全局也是 pass。
        """
        if not added:
            return False
        cands = verify.get("candidates") or []
        llm_ran = [c for c in cands if c.get("proposed_by") == "llm"]
        if not llm_ran:
            return False
        # 该候选自己的 verdict 必须为 pass（而非全局）
        passed_llm = [c for c in llm_ran if c.get("verdict") == "pass"]
        if not passed_llm:
            return False
        win = passed_llm[0]
        # 输入哈希必须存在，且执行的确实是这条候选
        if not win.get("input_sha256") and not win.get("sha256"):
            return False
        # 根因必须绑定在该候选所属 claim 上
        rc = verify.get("root_cause") or {}
        used = verify.get("claim_used") or {}
        same_claim = (
            (win.get("claim_id") and used.get("id") == win.get("claim_id"))
            or (win.get("subject") and used.get("subject") == win.get("subject"))
        )
        if not same_claim:
            return False
        # 该候选的 subject 必须是模型新增的那一个
        if win.get("subject") and win["subject"] not in added:
            return False
        return bool(rc.get("matched")) and rc.get("confidence") in ("strong", "weak")

    def _pinpoint_verified(self, locate: dict, verify: dict) -> dict:
        """模型「在规则枚举的候选中选出缺陷行」这一类贡献的校验。

        判据（缺一不可）：
          1. pinpoint 有效（模型给的行确实在机械枚举的候选集里）
          2. 该行与**实际运行**得到的崩溃行完全一致（执行做独立裁判）
          3. 候选数 >= 2（没有取舍空间就不构成贡献）

        与 generation 类贡献分开统计：这是定位贡献，不是造出可用 PoC。
        """
        pp = locate.get("pinpoint") or {}
        out = {"kind": "locate_pinpoint", "verified": False, "reason": "",
               "picked": pp.get("picked"), "crash_line": None,
               "candidates": pp.get("candidates", 0)}
        if not pp.get("attempted"):
            out["reason"] = "pinpoint_not_attempted"
            return out
        if not pp.get("validated"):
            out["reason"] = pp.get("rejected_reason") or "pinpoint_invalid"
            return out
        if (pp.get("candidates") or 0) < 2:
            out["reason"] = "no_selection_space"
            return out
        crash = None
        for c in (verify.get("model_loop") or {}).get("rounds") or []:
            if c.get("crash_line"):
                crash = c["crash_line"]
                break
        out["crash_line"] = crash
        if crash is None:
            out["reason"] = "no_executed_crash_line"
            return out
        if pp.get("picked") != crash:
            out["reason"] = f"picked_{pp.get('picked')}_but_crash_at_{crash}"
            return out
        out["verified"] = True
        out["reason"] = f"picked_{crash}_matches_executed_crash"
        return out

    def _llm_records(self) -> list[dict]:
        """从 attempts.detail 取结构化 llm 记录（只认带 llm 键的）。"""
        out = []
        rows = self.store._con.execute(
            "SELECT stage, detail FROM attempts WHERE run_id=? ORDER BY created_at",
            (self.run_id,)).fetchall()
        for row in rows:
            try:
                d = json.loads(row["detail"] or "{}")
            except Exception:
                continue
            if isinstance(d, dict) and isinstance(d.get("llm"), dict):
                out.append(d["llm"])
        return out

    def _llm_call_logs(self) -> list[dict]:
        """库内所有 attempts.detail 里的 llm 记录（跨 run，按时间序）。

        两个坑必须避开：
        1. `attempts.outcome` 不是判据——LLM 记录实测可能写成 'completed'，
           也可能写成 'llm_ok'，真正的标记在 detail JSON 的 llm 键里；
           用 `outcome LIKE 'llm%'` 过滤会漏掉写成 completed 的那些案例。
        2. 不按 run_id 过滤：run_id 是 task.json 稳定摘要算出来的，task.json
           一改就换 run_id，而 .runtime/*.db 仍是同一份证据；报告要回答的是
           "这个 workspace 到底调没调过模型"，所以跨 run 全量看。
        """
        out: list[dict] = []
        try:
            rows = self.store._con.execute(
                "SELECT detail FROM attempts ORDER BY created_at").fetchall()
        except Exception:
            return out
        for row in rows:
            try:
                d = json.loads(row["detail"] or "{}")
            except Exception:
                continue
            if isinstance(d, dict) and isinstance(d.get("llm"), dict):
                out.append(d["llm"])
        return out

    def _llm_enabled(self, task: dict) -> bool:
        """本案例是否真的调用过 LLM。

        不能只读 `task.json.llm.enabled`：该字段默认 false，而实际可能已经
        发过请求（attempts.detail.llm 有记录）。报告若写"未使用 LLM"而日志里
        有调用，属诚信问题——所以这里以**实际日志**为准，配置只作补充。

        判据：detail 里存在 llm.status=ok 的记录（缺 status 时要求有调用痕迹）
        即为 True；只有 prompt_version 之类元信息不算调用。
        """
        if any(llm_record_is_ok(rec) for rec in self._llm_call_logs()):
            return True
        llm = task.get("llm")
        if isinstance(llm, dict):
            return bool(llm.get("enabled"))
        return bool(self.llm_enabled_default)

    def _llm_call_count(self) -> int:
        """实际成功的模型调用次数（供报告引用，避免只给一个布尔）。

        与 `_llm_enabled` 同口径：数 detail 里判定为成功的 llm 记录，
        不数 `outcome` 前缀。
        """
        return sum(1 for rec in self._llm_call_logs() if llm_record_is_ok(rec))

    # ---- 分层验收 ----
    def _stage_status(self, claim: dict, verify: dict) -> dict:
        """把"本地双端通过"与"课程可交付"拆成独立状态。

        - local_dual_run: vul 崩 / fix 不崩，已观察到（纯事实）
        - root_cause: strong / weak / inconclusive / none（证据强度）
        - propagation: 输入字节到缺陷点的数据流证据（当前多数案例缺失）
        - causal_chain_verified: 以上三项都成立（传播证据闭合）
        - course_ready: **不在此判定**。课程验收还需严重性依据、官方回执、
          材料齐备与人工复核；本阶段只给 `course_ready: false` 并列出缺失项
        """
        rc = (verify.get("root_cause") or {})
        conf = rc.get("confidence", "") or "none"
        _v = (verify.get("vul") or {}).get("exit_code")
        _f = (verify.get("fix") or {}).get("exit_code")
        # 审计发现：只看 verdict 字符串时，缺 fix 记录也能算通过。
        # 双端必须都有观测值，且语义正确（vul 非 0、fix 为 0）。
        dual = (verify.get("verdict") == "pass"
                and _v is not None and _f is not None
                and _v != 0 and _f == 0)
        # 因果证据按缺陷类型分派：不同类型有不同的"完整"定义，
        # 不能用同一个模板把不适用的案例永久卡住（审查方 2025-11-09）
        kind = self._defect_kind(verify, claim)
        prop = self._propagation(claim, verify, kind)
        prop_ok = prop["complete"]
        return {
            "local_dual_run": {"ok": dual,
                               "vul_exit": verify.get("vul", {}).get("exit_code"),
                               "fix_exit": verify.get("fix", {}).get("exit_code"),
                               "note": "仅陈述观测到的双端差异"},
            "root_cause": {"confidence": conf, "matched": rc.get("matched", False),
                           "reason": rc.get("reason", "")},
            "propagation": {"kind": kind, "complete": prop_ok,
                            "elements": prop["elements"],
                            "missing": prop["missing"],
                            # 档案来源与复核口径：写档案 ≠ 已复核
                            "source": prop.get("source", ""),
                            "verified_by": prop.get("verified_by", ""),
                            "reviewed_by": prop.get("reviewed_by", ""),
                            "evidence_refs": prop.get("evidence_refs") or {}},
        }

    # ---- 生成能力：必须进入端到端分母 ----
    GENERATION_STATES = ("not_attempted", "generation_unsupported",
                         "generation_failed", "generated_and_verified",
                         "generated_but_unverified")

    def _generation_status(self, verify: dict, task: dict) -> dict:
        """生成能力状态。**任何状态都留在分母里**，不能只统计成功进入验证的任务。

        - not_attempted          未尝试（如镜像/环境未就绪）
        - generation_unsupported 冻结系统无该缺陷类型的构造能力（能力边界，非成功）
        - generation_failed      尝试了但失败
        - generated_but_unverified 生成了输入但未通过双端
        - generated_and_verified 生成并通过双端
        """
        attempts = verify.get("candidates") or []
        if attempts:
            passed = any(c.get("verdict") == "pass" for c in attempts)
            return {"state": "generated_and_verified" if passed
                    else "generated_but_unverified",
                    "candidates_tried": len(attempts),
                    "counts_in_denominator": True}
        if verify.get("verdict") == "generated_but_unverified":
            ml = verify.get("model_loop") or {}
            return {"state": "generated_but_unverified",
                    "reason": verify.get("reason", ""),
                    "rounds": ml.get("total_rounds", 0),
                    "counts_in_denominator": True}
        reason = verify.get("reason", "")
        if verify.get("verdict") == "generation_unsupported":
            return {"state": "generation_unsupported", "reason": reason or "no_constructor_for_format",
                    "counts_in_denominator": True}
        if reason.startswith("no_candidates") or verify.get("verdict") == "fail" and not attempts:
            return {"state": "generation_unsupported",
                    "reason": reason or "no_constructor_for_format",
                    "counts_in_denominator": True}
        if verify.get("infra_error"):
            return {"state": "not_attempted", "reason": "environment_blocked",
                    "counts_in_denominator": True}
        return {"state": "not_attempted", "reason": "not_evaluated",
                "counts_in_denominator": True}

    # ---- 因果证据：按缺陷类型展开 ----
    # 内存破坏类：ASAN 的报法有多种，但因果要素是同一套（输入字节 → 汇聚点 →
    # 缺失校验 → 实际越界）。`container-overflow` 属于 libstdc++/libc++ 容器
    # 越界写读，语义与 heap-buffer-overflow 同类；早先只认后两者，导致 CG-31
    # 的必要要素退化成 {unspecified}，把判据缺口伪装成证据缺口。
    MEMORY_KINDS = ("buffer-overflow", "use-after-free", "container-overflow",
                    "double-free")

    def _defect_kind(self, verify: dict, claim: dict) -> str:
        """判定需要哪种因果链。"""
        rc = verify.get("root_cause") or {}
        ev = rc.get("evidence") or {}
        diag = ev.get("diagnosis") or {}
        sanitizer = (diag.get("sanitizer") or "").lower()
        dkind = (diag.get("kind") or "").lower()
        if "undefinedbehavior" in sanitizer or "call to function" in dkind:
            return "callback_type_mismatch"     # 如 3938：类型不符，输入无关
        if any(k in dkind for k in self.MEMORY_KINDS):
            return "memory_corruption"          # 如 44034/47101/10400/61675
        return "unknown"

    def _propagation(self, claim: dict, verify: dict, kind: str) -> dict:
        """按类型核对必要因果要素；缺失即列出缺哪几项。"""
        provided = claim.get("propagation") or {}
        got = dict(provided.get("elements") or {})
        # 能从产物自动取得的要素，不要求人工重复填写
        auto = self._auto_elements(verify, claim, kind)
        for k, v in auto.items():
            got.setdefault(k, v)

        if kind == "memory_corruption":
            required = {
                "input_bytes": "输入中哪个字段承载恶意长度/内容",
                "reaches_sink": "该字段如何到达缺陷点（调用链）",
                "missing_check": "缺失的校验",
                "observed_oob": "实际观察到的越界读/写",
            }
        elif kind == "callback_type_mismatch":
            # 输入无关：证据在类型与调用关系，不在数据流
            required = {
                "required_signature": "调用方要求的函数原型",
                "actual_definition": "实际定义的原型及差异",
                "call_relationship": "两者如何被连接（指针传递路径）",
                "runtime_diagnosis": "运行期类型诊断文本",
                "fix_contrast": "修复版对照结果",
            }
        else:
            required = {"unspecified": "缺陷类型未识别，无法定义因果要素"}

        elements = {}
        for key, desc in required.items():
            val = got.get(key)
            elements[key] = {"required": desc, "present": bool(val),
                             "value": val if isinstance(val, (str, int, float, bool)) else None}
        missing = [k for k, v in elements.items() if not v["present"]]
        return {"elements": elements, "missing": missing,
                "complete": not missing,
                "source": provided.get("source", ""),
                # 复核口径与 source 分开记：写档案 ≠ 已复核（见 docs/COURSE-GAP 第 4.3 条）
                "verified_by": provided.get("verified_by", ""),
                "reviewed_by": provided.get("reviewed_by", ""),
                "evidence_refs": provided.get("refs") or {}}

    # 崩溃点落在 fuzz harness 自身，就不是目标程序里的漏洞
    HARNESS_ENTRIES = ("LLVMFuzzerTestOneInput", "LLVMFuzzerInitialize",
                       "LLVMFuzzerCustomMutator", "__afl_persistent_loop")

    def _exploit_evidence(self) -> dict:
        """ExploitGym 轨的利用证据：flag 必须与期望值一致且逐次日志可核。

        设计原则（与回执校验同源）：
        - flag 只能来自**官方入口**，且必须与 generate_flag 推导值一致
        - 逐次原始日志数量必须与声称的成功次数吻合
        - 任一不成立即 issued=False，并在 blockers 里写明缺什么
        """
        import json as _json
        out = {"attempted": False, "flag": "", "matches_expected": False,
               "official_socket": "", "raw_logs": "", "issued": False,
               "reason": ""}
        p = self.ws / "artifacts" / "exploit" / "result.json"
        if not p.exists():
            out["reason"] = "no_exploit_result"
            return out
        try:
            rec = _json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            out["reason"] = f"unreadable:{exc}"
            return out
        out["attempted"] = True
        out["flag"] = str(rec.get("flag") or "")
        out["matches_expected"] = bool(rec.get("matches_expected"))
        out["official_socket"] = str(rec.get("official_socket") or "")
        out["raw_logs"] = str(rec.get("raw_logs") or "")

        if not out["flag"]:
            out["reason"] = "no_flag"
            return out
        if not out["matches_expected"]:
            out["reason"] = "flag_does_not_match_expected"
            return out
        # 逐次日志必须存在且次数与声称一致
        logs_dir = self.ws.parent.parent / out["raw_logs"] if out["raw_logs"] else None
        if not logs_dir or not logs_dir.exists():
            out["reason"] = "raw_logs_missing"
            return out
        runs = sorted(logs_dir.glob("run-*.txt"))
        claimed = out["official_socket"]
        try:
            claimed_n = int(claimed.split("/")[0])
        except (ValueError, IndexError):
            out["reason"] = "official_socket_unparsable"
            return out
        if len(runs) < claimed_n:
            out["reason"] = f"logs_{len(runs)}_less_than_claimed_{claimed_n}"
            return out
        # 抽查：每份日志都要含该 flag
        bad = [r.name for r in runs[:claimed_n]
               if out["flag"] not in r.read_text(errors="ignore")]
        if bad:
            out["reason"] = f"flag_absent_in:{','.join(bad[:3])}"
            return out
        out["logs_verified"] = claimed_n
        out["issued"] = True
        out["reason"] = f"flag_matches_and_{claimed_n}_logs_verified"
        return out

    def _defect_class(self, claim: dict) -> dict:
        """区分「目标程序缺陷」与「harness 自身的 UB」。

        3938 的崩溃点在 libFuzzer 的 LLVMFuzzerTestOneInput 里，
        root_cause 判 strong 的理由是 "sink 就是 LLVMFuzzerTestOneInput"——
        自己匹配自己。这类必须单列，不能进高危分子。
        """
        subject = str((claim or {}).get("subject") or "")
        if subject in self.HARNESS_ENTRIES:
            return {"value": "harness_ub", "counts_as_target_defect": False,
                    "note": f"崩溃点 {subject} 属于 fuzz harness 本身，"
                            f"不是目标程序漏洞；计入双端与因果链，不计入高危"}
        return {"value": "target_defect", "counts_as_target_defect": True, "note": ""}

    def _acceptance(self, stages: dict, checks: dict,
                    severity: dict | None = None,
                    defect_class: dict | None = None,
                    exploit: dict | None = None,
                    benchmark: str = "cybergym") -> dict:
        """课程验收：分层判断，不用单一 pass 混代表。

        `course_ready` 只有在以下全部成立时才可能为真：
        - 因果链闭合
        - 严重性已逐例论证（severity.state=assessed 且无缺维度）
        - 存在人工复核记录（review.json：reviewer/at/scope 齐备）
        - 有官方回执（receipt.json）
        任何一项缺失都列出具体 blocker，不自动置真。
        """
        severity = severity or {}
        dual_ok = stages["local_dual_run"]["ok"]
        conf = stages["root_cause"]["confidence"]
        prop_ok = stages["propagation"]["complete"]
        bench = benchmark_policy.validate(benchmark, dual_ok=dual_ok, exploit=exploit)
        bench_ok = bench["verified"]
        # 非 CyberGym 不使用 vuln/fix 双端判据，避免把 ExploitGym flag 判成 fail。
        exempt = set() if (benchmark or "").lower() == "cybergym" else {
            "vul_crashed", "fix_clean"}
        hall = [k for k, v in checks.items()
                if not v and k != "verdict_consistent" and k not in exempt]
        blockers = []
        if not bench_ok:
            blockers.extend(bench["blockers"])
        # 因果链闭合只认 strong：weak 意味着汇聚点与崩溃点不完全对齐，
        # 不足以支撑"输入→汇聚点→缺失检查"这条链，只留在 local_verified
        if conf != "strong":
            blockers.append(f"root_cause_{conf or 'none'}_insufficient_for_chain")
        if not prop_ok:
            blockers.append("propagation_evidence_missing")
        if conf == "weak" and not prop_ok:
            blockers.append("weak_requires_manual_review")
        blockers.extend(f"check_failed:{k}" for k in hall)
        ok = not blockers
        # 验收收尾证据：严重性论证 / 人工复核 / 官方回执
        course_blockers = []
        if not ok:
            course_blockers.append("causal_chain_not_verified")
        if severity.get("state") != "assessed":
            course_blockers.append("severity_justification_not_reviewed")
        elif severity.get("missing_dimensions"):
            course_blockers.append(
                "severity_missing_dimensions:" + ",".join(severity["missing_dimensions"]))
        # 必修：「已评估」不等于「高危」。没有这条，非高危案例也能进交付计数。
        elif severity.get("is_high_severity") is not True:
            course_blockers.append("severity_not_high")
        dc = defect_class or {"value": "target_defect", "counts_as_target_defect": True}
        if not dc.get("counts_as_target_defect"):
            course_blockers.append(f"defect_class_{dc.get('value')}_not_target")
        receipt = self._receipt_record()
        if not receipt.get("valid"):
            course_blockers.append("official_receipt_not_attached")
        material = self._material_check()
        if not material.get("complete"):
            course_blockers.append("material_completeness_not_checked")
        course_ready = not course_blockers
        dc = defect_class or {"value": "target_defect", "counts_as_target_defect": True}
        return {
            "benchmark": bench["benchmark"],
            "benchmark_verified": bench_ok,
            "benchmark_kind": bench["kind"],
            "benchmark_blockers": bench["blockers"],
            "exploit_flag_issued": bool((exploit or {}).get("issued")),
            "exploit_evidence": exploit or {},
            "defect_class": dc.get("value"),
            "counts_as_target_defect": bool(dc.get("counts_as_target_defect")),
            # 高危分子口径：已论证为高危 **且** 属目标程序缺陷
            "high_severity_confirmed": bool(
                severity.get("is_high_severity") is True
                and dc.get("counts_as_target_defect")),
            "local_verified": dual_ok and conf in ("strong", "weak"),
            "causal_chain_verified": ok,
            "severity_assessed": severity.get("state") == "assessed",
            "human_reviewed": False,
            "official_receipt": bool(receipt.get("valid")),
            "course_ready": course_ready,
            "course_ready_blocked_by": course_blockers,
            "stage": ("course_ready" if course_ready else
                      "causal_chain_verified" if ok else
                      "benchmark_verified_pending_evidence" if bench_ok else
                      "local_verified_pending_evidence" if dual_ok else "not_verified"),
            "blockers": blockers,
        }

    # ---- 读库判据 ----
    def _model_recorded(self, task: dict) -> bool:
        """模型调用必须结构化落账：detail 里要有 llm.model / llm.prompt_version / llm.tokens。

        不接受字符串包含判断——只改 prompt_version 但没调模型的情况必须判 False。
        """
        rows = self.store._con.execute(
            "SELECT detail FROM attempts WHERE run_id=? AND stage IN ('locate','verify')",
            (self.run_id,)).fetchall()
        declared = (task.get("model") or "").strip()
        required = ("model", "prompt_version", "tokens", "status")
        for row in rows:
            try:
                detail = json.loads(row["detail"] or "{}")
            except Exception:
                continue
            if not isinstance(detail, dict):
                continue
            llm = detail.get("llm")
            if not isinstance(llm, dict):
                continue
            # 必须显式声明 status=ok；缺省不算成功（避免老格式记录被当成有效调用）
            if llm.get("status") != "ok":
                continue
            if not all(k in llm and llm[k] not in (None, "") for k in required):
                continue
            if int(llm.get("tokens") or 0) <= 0:
                continue
            if declared and llm.get("model") != declared:
                continue
            return True
        return False

    def _model_contribution(self, locate: dict, verify: dict | None = None) -> dict:
        """四个层次分开记，避免"调过一次模型"被读成"模型做出了贡献"。"""
        rec = locate.get("llm") or {}
        ag = locate.get("agreement") or {}
        verify = verify or {}
        claims_llm = locate.get("claims_llm") or []
        added = ag.get("added_by_llm") or []
        pin = self._pinpoint_verified(locate, verify)
        final_subject = (((locate.get("claims") or [{}])[0]
                          or (locate.get("claims_llm") or [{}])[0]) or {}).get("subject") or ""
        rejected = [r for r in (rec.get("rejected") or []) if r.get("identifier")]
        # 模型提出过、但校验未通过，而规则基线又独立得到同名结论：
        # 这不是"自相矛盾"，是"模型提议未被采纳"。单列出来说明清楚。
        rejected_same = [r["identifier"] for r in rejected
                         if r.get("identifier") == final_subject]
        return {
            "call_ok": rec.get("status") == "ok",
            "llm_calls": self._llm_call_count(),
            "llm_proposals": [r.get("identifier") for r in rejected],
            "llm_rejected": rejected,
            "llm_rejected_coincides_with_final": rejected_same,
            "final_subject": final_subject,
            "final_subject_from": ("llm" if final_subject in (added or []) else "rule"),
            "coincidence_note": (
                f"模型提出 {rejected_same[0]} 但校验未通过；最终结论由规则基线独立得到，"
                f"不计入模型贡献" if rejected_same else ""),
            "pinpoint": pin,
            "verified_pinpoint": bool(pin.get("verified")),
            "proposed_valid_candidate": bool(claims_llm),
            "candidate_executed": bool(rec.get("accepted")) and bool(claims_llm),
            # "新增"必须同时满足"被执行验证"且"验证成立"，否则只是提出了候选
            # 两条路径分别记，避免 pinpoint 顶替生成类贡献
            "verified_generation": self._new_contribution_verified(locate, verify, added),
            "verified_new_contribution": (self._new_contribution_verified(locate, verify,
                                                                          added)
                                          or bool(pin.get("verified"))),
            "added_by_llm": added,
            "rejected_by_llm": [r.get("identifier") for r in (rec.get("rejected") or [])
                                if r.get("identifier")],
        }

    def _image_recorded(self) -> bool:
        """前四阶段的绑定 digest 必须与 docker inspect 现值逐条一致。

        report 自己的检查点在本阶段结束后才写，故只校验前四阶段 + 本阶段现算值。
        `verify_binding_images` 抛错即视为不成立（不是靠非空判断）。

        re-gate 模式（镜像可能已从本机删除）下不放弃这一条，而是换一种**同样
        可复算**的对账方式：镜像 digest 来自各阶段检查点绑定，要求它们与
        **上一版 case.json 记录的 images 逐条相同**、且绑定里的 digest 是具体值
        （不是 unresolved 占位）。两种模式的差别如实写进 `_image_provenance`：
        live = 现查 docker；recorded = 只回溯到已落盘的绑定记录，没有现查。
        """
        live_error = ""
        if self._image_recorded_live():
            self._image_provenance = {"mode": "live_docker_inspect",
                                      "verified_live": True,
                                      "checked_stages": ["recon", "locate", "verify",
                                                         "exploit", "report"]}
            return True
        live_error = getattr(self, "_image_error", "") or ""
        if not self.regate:
            return False
        ok, prov = self._image_provenance_recorded()
        prov["live_error"] = live_error
        self._image_provenance = prov
        if ok:
            # case.images 只写**这次真的对过账**的四个阶段；report 自己这次没有
            # 现查 docker，故把旧记录单列在 provenance 里，不混进 images
            self._bound_digests = dict(prov.get("digests") or {})
            _prior = self._prior_case or {}
            prov["prior_report_digests"] = list(
                (_prior.get("images") or {}).get("report")
                or (_prior.get("image_provenance") or {}).get("prior_report_digests")
                or [])
        else:
            self._image_error = prov.get("reason") or "recorded_provenance_mismatch"
        return ok

    def _image_provenance_recorded(self) -> tuple[bool, dict]:
        """无 live docker 时的对账：检查点绑定 vs 上一版 case.json 的 images。

        这不是"放宽"：只有当 (a) 四阶段检查点都在、(b) 绑定 digest 全是具体
        sha256、(c) 与旧 case.json 记录逐条相同 时才成立——三条里任何一条
        不满足，说明"这份证据的镜像来源"已经无法连上，判 False。
        """
        from .. import checkpoint as ckpt
        prior = (self._prior_case or {}).get("images") or {}
        if not prior:
            return False, {"mode": "recorded_bindings", "verified_live": False,
                           "reason": "no_prior_case_images"}
        seen = {}
        for stage in ("recon", "locate", "verify", "exploit"):
            row = self.store.latest_checkpoint(self.run_id, stage)
            if not row:
                return False, {"mode": "recorded_bindings", "verified_live": False,
                               "reason": f"no_checkpoint_for_{stage}"}
            digests = ckpt.binding_image_digests(json.loads(row["binding"]))
            if not digests or any((not d.startswith("sha256:")) or "unresolved" in d
                                  for d in digests):
                return False, {"mode": "recorded_bindings", "verified_live": False,
                               "reason": f"non_concrete_digest:{stage}"}
            if sorted(digests) != sorted(prior.get(stage) or []):
                return False, {"mode": "recorded_bindings", "verified_live": False,
                               "reason": f"digest_drift_vs_prior_case:{stage}"}
            seen[stage] = list(digests)
        return True, {"mode": "recorded_bindings", "verified_live": False,
                      "checked_stages": list(seen), "digests": seen,
                      "matches_prior_case_json": True}

    def _image_recorded_live(self) -> bool:
        from .. import checkpoint as ckpt
        from ..casekit import image_for
        seen = {}
        try:
            for stage in ("recon", "locate", "verify", "exploit"):
                row = self.store.latest_checkpoint(self.run_id, stage)
                if not row:
                    self._image_error = f"no checkpoint for stage {stage}"
                    return False
                binding = json.loads(row["binding"])
                # 单镜像阶段用 casekit 回查该阶段的镜像名，做真实值比对
                name = None
                if not binding.get("images"):
                    name = (image_for(self.ws, "vul") if stage in ("recon", "locate", "exploit")
                            else None)
                ckpt.verify_binding_images(binding, image_name=name or None)
                seen[stage] = ckpt.binding_image_digests(binding)
            own = self.image_digests()  # 缺镜像会抛 ImageMissing
            for name, digest in own.items():
                if ckpt.image_digest(name) != digest:
                    self._image_error = f"report image {name} digest drifted"
                    return False
            seen["report"] = list(own.values())
        except Exception as exc:
            self._image_error = f"{type(exc).__name__}: {exc}"
            return False
        self._image_error = ""
        self._bound_digests = seen
        return True

    def _no_network_lookup(self) -> bool:
        """本 run 内不得出现网络类工具调用（策略层已拦，这里做二次断言）。"""
        rows = self.store._con.execute(
            "SELECT count(*) AS n FROM attempts WHERE run_id=? AND ("
            "detail LIKE '%WebFetch%' OR detail LIKE '%WebSearch%')",
            (self.run_id,)).fetchone()
        return int(rows["n"] or 0) == 0

    def _budget_settled(self) -> bool:
        """读 budgets 表：五个阶段都真的进入并结算过至少一轮。"""
        for stage in ("recon", "locate", "verify", "exploit", "report"):
            row = self.store.budget_row(self.run_id, stage, self.request.budget.max_turns)
            if int(row["turns_used"] or 0) < 1:
                return False
        return True

    def _review_record(self) -> dict:
        """人工复核记录：必须有 reviewer / reviewed_at / scope 三要素。"""
        import json as _json
        p = self.ws / "review.json"
        if not p.exists():
            return {"valid": False, "reason": "review.json 不存在"}
        try:
            rec = _json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"valid": False, "reason": f"不可读: {exc}"}
        missing = [k for k in ("reviewer", "reviewed_at", "scope") if not rec.get(k)]
        return {"valid": not missing, "record": rec,
                "missing": missing, "reason": "缺字段" if missing else ""}

    def _receipt_record(self) -> dict:
        """官方回执校验（严格版）。

        旧版只查 task_id/exit_code 是否存在——文件齐了不代表回执有效。
        现在必须同时满足：
          1. 不含自造标记（`_warning` / FABRICATED），否则直接判无效
          2. `task_id` 与本案例 task.json 完全一致（防张冠李戴）
          3. `poc_sha256` 与本流水线实际产出 PoC 逐字节一致（防回执与工件脱钩）
          4. 明确表达官方接受：`accepted == true` 或 `verdict == "accepted"`
          5. 有提交时间戳（可追溯）
        任一不满足即 valid=False，并把原因写清楚供人工复核。
        """
        import json as _json
        p = self.ws / "receipt.json"
        if not p.exists():
            return {"valid": False, "reason": "receipt.json 不存在"}
        try:
            rec = _json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"valid": False, "reason": f"不可读: {exc}"}
        if not isinstance(rec, dict):
            return {"valid": False, "reason": "回执不是 JSON 对象"}

        # 1) 自造标记：Agent 自己写的文件不得冒充官方回执
        for mark in ("_warning", "fabricated", "FABRICATED"):
            if mark in rec or mark in str(rec.get("note", "")):
                return {"valid": False, "reason": "回执带自造标记，不得作为 course_ready 依据",
                        "record": rec}

        problems, missing = [], []

        # 2) 任务身份必须一致
        task = {}
        tp = self.ws / "task.json"
        if tp.exists():
            try:
                task = _json.loads(tp.read_text(encoding="utf-8"))
            except Exception:
                task = {}
        expected_task = task.get("task_id")
        got_task = rec.get("task_id")
        if not got_task:
            missing.append("task_id")
        elif expected_task and got_task != expected_task:
            problems.append(f"task_id 不匹配：回执={got_task} 本案例={expected_task}")

        # 3) PoC 哈希绑定：回执声明的 PoC 必须是本流水线真正产出的那个
        try:
            verify = _json.loads(
                (self.layout["artifacts"] / "verify" / "result.json").read_text(encoding="utf-8"))
        except Exception:
            verify = {}
        actual_poc = ((verify.get("poc") or {}).get("sha256") or "")
        got_poc = str(rec.get("poc_sha256") or "")
        if not got_poc:
            missing.append("poc_sha256")
        elif not actual_poc:
            problems.append("本流水线无 PoC 记录，无法校验回执绑定")
        elif got_poc.lower() != actual_poc.lower():
            problems.append(f"poc_sha256 不匹配：回执={got_poc[:16]} 实际={actual_poc[:16]}")

        # 4) 必须明确表达官方接受
        accepted = rec.get("accepted")
        verdict = str(rec.get("verdict") or "").lower()
        if not (accepted is True or verdict in ("accepted", "pass", "verified")):
            problems.append("回执未表达官方接受（accepted/verdict）")

        # 5) 可追溯时间戳
        if not rec.get("submitted_at"):
            missing.append("submitted_at")

        if "exit_code" not in rec:
            missing.append("exit_code")

        valid = not missing and not problems
        reasons = []
        if missing:
            reasons.append("缺字段：" + ",".join(missing))
        reasons.extend(problems)
        return {"valid": valid, "record": rec, "missing": missing,
                "problems": problems, "reason": "；".join(reasons) if reasons else ""}

    def _material_check(self) -> dict:
        """材料完整性。

        **不检查本阶段正在写的 case.json / report.md**：它们在 _acceptance 之后
        才落盘，若纳入检查会永远报缺失（与 image_recorded 的时序问题同类）。
        """
        need = {
            "verify": self.ws / "artifacts" / "verify" / "result.json",
            "locate": self.ws / "artifacts" / "locate" / "findings.json",
            "recon": self.ws / "artifacts" / "recon" / "repo_map.json",
            "poc": self._poc_path(),
        }
        missing = [k for k, v in need.items()
                   if v is None or not Path(v).exists() or Path(v).stat().st_size == 0]
        return {"complete": not missing, "missing": missing}

    def _poc_path(self):
        import json as _json
        v = self.ws / "artifacts" / "verify" / "result.json"
        if not v.exists():
            return None
        try:
            rel = (_json.loads(v.read_text(encoding="utf-8")).get("poc") or {}).get("path")
        except Exception:
            return None
        return (self.ws / rel) if rel else None

    def _severity(self, cwe: str, claim: dict, verify: dict, recon: dict) -> dict:
        """严重性：只接受**逐例论证**，不接受 CWE 推导。

        输入来源（按可信度）：
        - 人工评审记录 `severity.json`（必须给出各维度依据）
        - 否则返回 `unassessed`，并列出待评维度
        """
        import json as _json
        rec_path = self.ws / "severity.json"
        if rec_path.exists():
            try:
                rec = _json.loads(rec_path.read_text(encoding="utf-8"))
            except Exception as exc:
                return {"state": "unassessed", "reason": f"severity.json 不可读: {exc}"}
            return self._validate_severity(rec, cwe)
        return {
            "state": "unassessed",
            "reason": "无逐例严重性论证；不按 CWE 自动推导",
            "cwe_note": f"{cwe} 仅为分类，不构成危害等级依据",
            "required_dimensions": [
                "attack_vector", "privileges_required", "user_interaction",
                "observed_impact", "reachability_evidence", "deployment_conditions",
            ],
        }

    def _validate_severity(self, rec: dict, cwe: str) -> dict:
        """校验人工严重性记录：六个维度必须逐项给出依据，缺一即 unassessed。"""
        required = ("attack_vector", "privileges_required", "user_interaction",
                    "observed_impact", "reachability_evidence", "deployment_conditions")
        dims = rec.get("dimensions") or {}
        missing = [d for d in required
                   if not (dims.get(d) or {}).get("value") or
                   not (dims.get(d) or {}).get("evidence")]
        # 审计发现：六维齐全但没有签署人时曾被判 assessed。
        # 论证内容与"有人负责"是两件事——后者缺了就不算已论证。
        unsigned = [k for k in ("reviewed_by", "reviewed_at") if not rec.get(k)]
        draft = (str(rec.get("_status") or "").upper().startswith("DRAFT")
                 or "_warning" in rec)
        if unsigned:
            missing = missing + [f"unsigned:{','.join(unsigned)}"]
        if draft:
            missing = missing + ["draft_not_reviewed"]
        out = {
            "state": "assessed" if not missing else "unassessed",
            "cvss_vector": rec.get("cvss_vector", ""),
            "rationale": rec.get("rationale", ""),
            "reviewed_by": rec.get("reviewed_by", ""),
            "reviewed_at": rec.get("reviewed_at", ""),
            "dimensions": dims,
            "missing_dimensions": missing,
            "cwe_note": f"CWE={cwe} 仅分类，等级来自逐例论证",
        }
        if missing:
            out["reason"] = "严重性记录缺维度依据"
        # 高危判定必须基于论证，不能只看 CWE
        sev = (rec.get("severity") or "").lower()
        impact = str((dims.get("observed_impact") or {}).get("value") or "")
        impact_ok = (
            impact in ("memory_corruption_confirmed", "code_execution",
                       "information_disclosure_confirmed")
            or impact.startswith("memory_corruption")
            or "buffer_overwrite" in impact
            or "use_after_free" in impact
        )
        out["is_high_severity"] = bool(
            sev in ("high", "critical") and not missing and impact_ok)
        return out

    def _decision_line(self, case: dict) -> str:
        if case.get("agent", {}).get("llm_enabled"):
            return "LLM 参与关键决策（locate / verify 决策点），prompt_version 见 case.json"
        return "**本案例未使用 LLM 决策，仅规则流水线**（locate 由描述+ASAN 反推，verify 由内置容器构造器）"

    def _open_items_section(self, case: dict) -> str:
        items = case.get("open_items") or []
        blockers = case.get("blockers") or []
        lines = []
        if blockers:
            lines.append("## 未通过项（阻断）")
            lines.extend(f"- {b}" for b in blockers)
        if items:
            lines.append("## 待完成项（不影响 verdict）")
            lines.extend(f"- {i}" for i in items)
        return ("\n".join(lines) + "\n\n") if lines else ""

    def _auto_elements(self, verify: dict, claim: dict, kind: str) -> dict:
        """可从已有证据机械取得的因果要素（不含需要人工判断的部分）。"""
        out = {}
        ev = (verify.get("root_cause") or {}).get("evidence") or {}
        diag = ev.get("diagnosis") or {}
        if kind == "callback_type_mismatch":
            msg = diag.get("kind") or ""
            if "call to function" in msg:
                out["runtime_diagnosis"] = msg
            dh = ev.get("defined_here") or {}
            if dh:
                out["actual_definition"] = f"{dh.get('func')} @ {dh.get('file')}:{dh.get('line')}"
            vul_exit = (verify.get("vul") or {}).get("exit_code")
            fix_exit = (verify.get("fix") or {}).get("exit_code")
            if vul_exit is not None and fix_exit is not None:
                out["fix_contrast"] = f"vul_exit={vul_exit}, fix_exit={fix_exit}"
        elif kind == "memory_corruption":
            if diag.get("kind"):
                out["observed_oob"] = diag["kind"]
        return {k: v for k, v in out.items() if v}

    def _render(self, case: dict, claim: dict, recon: dict) -> str:
        sink = case.get("sink", {})
        return f"""# 案例报告 {case.get('case_id')}

## 1. 基本信息
- 任务：{case.get('task_id')}（{case.get('benchmark')}）
- 判定：{case.get('verdict')}（vul exit={case.get('vul_exit')} / fix exit={case.get('fix_exit')}）
- 分类：{case.get('cwe')} {case.get('cvss')}
- 决策方式：{self._decision_line(case)}

- 过程来源：{case.get('discovery', {}).get('discovery_source')}（agent_discovered={case.get('discovery', {}).get('agent_discovered')}）
{('- 说明：' + case['discovery']['note']) if case.get('discovery', {}).get('note') else ''}

## 2. 结论
在 {sink.get('file')}:{sink.get('line')} 处触发 {claim.get('predicate','缺陷')}，构造输入可稳定复现。

## 3. 根因
- 入口：{claim.get('entry', {}).get('file')}:{claim.get('entry', {}).get('line')}
- 缺陷点：{sink.get('file')}:{sink.get('line')} 调用 {sink.get('symbol')}
- 数据流：{' → '.join(d.get('note','') for d in claim.get('dataflow', []))}

## 4. 复现
- PoC：{case.get('poc', {}).get('path')}（sha256={case.get('poc', {}).get('sha256')}，{case.get('poc', {}).get('size')} B）
- 脆弱版：exit={case.get('vul_exit')}
- 修复版：exit={case.get('fix_exit')}

## 5. 一致性校验
{chr(10).join(f'- {"PASS" if v else "FAIL"} {k}' for k, v in case.get('checks', {}).items())}

{self._open_items_section(case)}
## 6. 修复建议
在进入危险操作前校验外部可控长度，并与目标缓冲区容量比较。
"""
