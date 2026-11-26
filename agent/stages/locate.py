"""Locate：描述解析 → 符号定位 → 双向切片 → 生成 Claim → 置信度排序。"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .. import llm as llm_mod
from ..casekit import image_for
from ..evidence import merge_into_claim
from ..tools import binscan
from ..util import append_jsonl, read_json, sha256_file
from ..validate import guard_line_exists, guard_upstream_untouched
from .base import Stage

# 描述里的函数名有四种常见写法，都要能召回：
#   ReadMNGImage()        → 名字带括号
#   the assign_file_to_slot function → "X function"
#   function assign_file_to_slot     → "function X"
#   ... in mng_get_long              → "in X"（行尾裸函数名）
REGEX_FUNCS = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]{4,})\s*\("
    r"|\b([A-Za-z_][A-Za-z0-9_]{4,})\s+function\b"
    r"|\bfunction\s+([A-Za-z_][A-Za-z0-9_]{4,})\b"
    r"|\bin\s+([A-Za-z_][A-Za-z0-9_]{4,})\s*$",
    re.M,
)
STOPWORDS = {"the","and","with","when","such","this","that","where","which","from","attempt","substitute",
             "memory","buffer","size","length","string","value","data","function","possible","because"}
REGEX_FILE = re.compile(r"[\w./-]+\.(?:c|cc|cpp|h|py|go|rs)")
REGEX_CRASH = re.compile(r"(heap-buffer-overflow|stack-buffer-overflow|use-after-free|"
                         r"global-buffer-overflow|WRITE of size \d+|READ of size \d+)")
REGEX_SIZE = re.compile(r"size (\d+)")
REGEX_BOUNDARY = re.compile(r"(not (?:checked|validated)|fixed[- ]size|without.{0,20}length|"
                            r"buffer.{0,30}(?:large|enough))", re.I)
MEM_SINKS = {
    "memcpy": (2, "CWE-121"), "memmove": (2, "CWE-121"), "strcpy": (1, "CWE-121"),
    "strcat": (1, "CWE-121"), "sprintf": (1, "CWE-121"), "gets": (0, "CWE-121"),
    "sscanf": (1, "CWE-121"), "alloca": (0, "CWE-121"),
}


class LocateStage(Stage):
    name = "locate"
    role_version = "locate-v1"
    prompt_version = "locate-p1"
    schema_version = "vulnmap.locate.v1"
    requires_images = False

    def __init__(self, *a, blind_mode: bool = False, inject_rule_sink: bool = False, **kw):
        super().__init__(*a, **kw)
        self.blind_mode = blind_mode
        self.inject_rule_sink = inject_rule_sink

    # LLM 角色：只产出候选，不决定最终 claim
    llm_prompt_version = "locate-llm-p1"
    llm_system = (
        "You are a C/C++ vulnerability analyst. Given a vulnerability description and "
        "source-code evidence, identify the function(s) that CONTAIN the defect. "
        "Output strict JSON with keys: functions (array of exact C identifiers), "
        "files (array of repository-relative paths), crash_type (string), "
        "boundary_hint (string), confidence (number 0..1). "
        "Only output identifiers that literally exist in the code. No prose."
    )

    # 这些符号只是 ASAN 拦截器/库函数，不是缺陷所在函数
    INTERCEPTORS = {
        "__interceptor_memcpy", "__interceptor_memmove", "__interceptor_strcpy",
        "__interceptor_strcat", "__interceptor_sprintf", "__asan_memset",
        "__asan_memcpy", "__asan_memmove", "memcpy", "memmove", "strcpy", "strcat",
        "sprintf", "memset", "malloc", "free", "realloc", "__libc_start_main",
    }
    SANITIZER_PATH = re.compile(r"/compiler-rt/|/libfuzzer")

    def input_hashes(self) -> dict[str, str]:
        out = super().input_hashes()
        recon = self.ws / "artifacts" / "recon" / "repo_map.json"
        if recon.exists():
            out["artifacts/recon/repo_map.json"] = sha256_file(recon)
        return out

    def image_refs(self) -> list[str]:
        # locate 读的是 repo-vul.tar.gz 解出的源码树，与 vul 镜像同源；把它的 digest 绑进来
        ref = image_for(self.ws, "vul")
        return [ref] if ref else []

    pinpoint_system = (
        "You are a vulnerability analyst. Given a mechanically enumerated list of write "
        "sites in one function, select the single write most likely to overflow when reached "
        "by attacker-controlled data. Choose only from the listed line numbers. "
        "Do not invent lines. Return JSON only."
    )
    pinpoint_prompt_version = "locate-pinpoint-v1"

    def execute(self) -> dict:
        src = self.layout["src"]
        descr_path = self.ws / "description.txt"
        descr = descr_path.read_text(encoding="utf-8", errors="ignore") if descr_path.exists() else ""
        hints = self._parse_description(descr)

        # ---- 规则基线（始终运行，不受模型影响）----
        claims = self._build_claims(src, hints)
        if not claims:
            self.store.add_blackboard(self.run_id, "hypothesis", "定位未果",
                                      "未能从描述与源码中找到可执行假设", status="unknown")

        # ---- 模型候选（并列输出，不覆盖规则结论）----
        llm_view = self._llm_candidates(src, descr, hints, claims)
        # ---- 模型选定缺陷行（在规则枚举的候选写点中取舍）----
        # 规则无 claim 时（如数组写类缺陷不在规则检测范围）回退到模型候选，
        # 否则 pinpoint 永远拿不到函数锚点
        _anchor = (claims[0] if claims
                   else (llm_view.get("claims") or [{}])[0])
        pinpoint = self._pinpoint(src, descr, _anchor)
        # 模型在**执行之前**从源码预测的缺陷行；校验通过则用它替换 claim 的 sink。
        # 这不是自证：预测发生在看到任何崩溃信息之前，验证仍由真实运行独立完成。
        if pinpoint.get("validated") and pinpoint.get("picked"):
            target = claims[0] if claims else (llm_view.get("claims") or [None])[0]
            if target is not None:
                old_sink = dict(target.get("sink") or {})
                old_line = old_sink.get("line")
                old_sink["line"] = pinpoint["picked"]
                old_sink["symbol"] = old_sink.get("symbol") or target.get("subject", "")
                old_sink["note"] = (f"模型 pinpoint 从源码预测的缺陷行（原 {old_line}，"
                                    f"候选 {pinpoint.get('candidates')} 选 1）")
                old_sink["source"] = "model_pinpoint"
                target["sink"] = old_sink
        # 人工核对过的因果要素：规则路径已在 _build_claims 内挂过，
        # 这里补挂到"最终被采用的那条 claim"（可能是模型候选），否则
        # 只有模型候选的案例永远无法补齐传播证据。
        # CWE 归类：描述里若明说 heap write / heap read / stack，可据此归类
        # （只做分类，不推导等级——等级一律来自逐例论证）
        _t0 = claims[0] if claims else (llm_view.get("claims") or [None])[0]
        if _t0 is not None and not _t0.get("cwe"):
            _d = descr.lower()
            if "heap" in _d and ("write" in _d or "overflow" in _d and "read" not in _d):
                _t0["cwe"] = "CWE-122"
            elif "heap" in _d and "read" in _d:
                _t0["cwe"] = "CWE-125"
            elif "stack" in _d:
                _t0["cwe"] = "CWE-121"
        _manual = self._load_manual_elements()
        if _manual:
            _t = claims[0] if claims else (llm_view.get("claims") or [None])[0]
            if _t is not None:
                _merged_claim = merge_into_claim(_t, _manual)
                _t.clear()
                _t.update(_merged_claim)

        out = []
        for c in claims:
            self.store.upsert_claim(self.run_id, c)
            out.append(c)
            append_jsonl(self.layout["artifacts"] / "locate" / "findings.jsonl", c)
        payload = {"schema": "vulnmap.locate.v1", "hints": hints, "claims": out,
                   "claims_rule": out,
                   "claims_llm": llm_view.get("claims", []),
                   "llm": llm_view.get("record", {}),
                   "agreement": llm_view.get("agreement", {}),
                   "disambiguation": getattr(self, "_disambig", []),
                   "llm_input_manifest": getattr(self, "_llm_manifest", {}),
                   "pinpoint": pinpoint,
                   "upstream": {"artifacts/recon/repo_map.json":
                                self.input_hashes().get("artifacts/recon/repo_map.json", "")}}
        # 契约：claims 必填 + entry/sink 行号必须真实存在 + 上游 recon 未被改动
        art = self.emit("locate/findings.json", payload, "vulnmap.locate.v1",
                        guards=[lambda d: guard_line_exists(src, d.get("claims", [{}])[0]) if d.get("claims") else None,
                                lambda d: guard_upstream_untouched(self.input_hashes(), d)])
        best = out[0] if out else None
        if best:
            self.store.add_blackboard(self.run_id, "observation", "最佳假设",
                                      f"{best['subject']} @ {best['sink']['file']}:{best['sink']['line']} "
                                      f"conf={best['confidence']}", status="supported",
                                      claim_id=best.get("claim_id"))
        return {"findings": art, "claims": len(out), "best_confidence": best["confidence"] if best else 0.0}

    # ---- 模型候选 ----
    def _llm_candidates(self, src: Path, descr: str, hints: dict,
                        rule_claims: list[dict]) -> dict:
        """让模型提候选，但不让它决定结论。

        产出：
        - `claims`: 通过符号/路径校验的模型候选（subject_source=llm）
        - `record`: 结构化调用记录（写 attempts.detail.llm）
        - `agreement`: 模型与规则基线的对照
        模型失败/不完整时降级为规则路径，记录 `llm_failed`，流水线继续。
        """
        task = {}
        tp = self.ws / "task.json"
        if tp.exists():
            try:
                task = json.loads(tp.read_text(encoding="utf-8"))
            except Exception:
                task = {}
        cfg = llm_mod.load_config(self.ws, task)
        params = cfg.public_params()

        # 资料边界：只给描述 + 候选函数附近的代码片段，不给答案
        context = self._llm_context(src, hints, rule_claims)
        user = (f"Vulnerability description:\n{descr.strip()}\n\n"
                f"Source-code evidence:\n{context}\n\n"
                "Identify the function(s) that contain the defect.")
        # 留痕：实际发给模型的是什么（审查方要求可审计输入清单）
        self._llm_manifest = {
            "system_sha256": __import__("hashlib").sha256(self.llm_system.encode()).hexdigest(),
            "user_chars": len(user),
            "user_sha256": __import__("hashlib").sha256(user.encode()).hexdigest(),
            "context_sources": [c.split("\n", 1)[0] for c in context.split("\n\n") if c.startswith("---")],
            "injected_rule_sink": bool(getattr(self, "inject_rule_sink", False)),
            "read_error_txt": bool(self._err_allowed()),
            "params": params,
        }
        result = llm_mod.call_json(cfg, system=self.llm_system, user=user,
                                   prompt_version=self.llm_prompt_version)

        if not result.ok:
            record = result.to_record(role="locate", params=params,
                                      rejected_reason=result.error)
            if result.status == "disabled":
                # 未真实调用：不记 attempt，不进统计
                return {"claims": [], "record": record,
                        "agreement": {"llm_used": False,
                                      "reason": result.error}}
            self.store.record_attempt(
                self.run_id, self.name, 2,
                llm_mod_call_key(self.llm_prompt_version, result.status),
                "llm_" + result.status, result.seconds,
                detail=json.dumps({"llm": record}, ensure_ascii=False))
            self.store.add_blackboard(
                self.run_id, "observation", "模型候选不可用",
                f"status={result.status} error={result.error}；已降级为规则路径",
                status="unknown")
            return {"claims": [], "record": record,
                    "agreement": {"llm_used": False, "reason": result.error}}

        candidates, rejected = self._validate_llm_output(src, result.parsed)
        rule_subjects = [c.get("subject") for c in rule_claims]
        added = [c["subject"] for c in candidates if c["subject"] not in rule_subjects]
        record = result.to_record(role="locate", params=params, accepted=bool(candidates),
                                  added=added)
        record["rejected"] = rejected
        record["raw"] = {k: result.parsed.get(k) for k in
                         ("functions", "files", "crash_type", "boundary_hint", "confidence")}

        self.store.record_attempt(
            self.run_id, self.name, 2,
            llm_mod_call_key(self.llm_prompt_version, "ok"),
            "llm_ok", result.seconds,
            detail=json.dumps({"llm": record}, ensure_ascii=False))

        agreement = {
            "llm_used": True,
            "rule_subjects": rule_subjects,
            "llm_subjects": [c["subject"] for c in candidates],
            "added_by_llm": added,
            "agreed": bool(set(rule_subjects) & {c["subject"] for c in candidates}),
            "rejected": rejected,
        }
        return {"claims": candidates, "record": record, "agreement": agreement}

    def _record_path_resolution(self, name: str, hint: str, resolved: str | None,
                                tier: str) -> None:
        """路径归一化的痕迹：模型给了什么、映射成了什么、靠哪一级规则。"""
        self._path_resolutions = getattr(self, "_path_resolutions", [])
        self._path_resolutions.append({"identifier": name, "hint": hint,
                                       "resolved": resolved, "tier": tier})
        try:
            append_jsonl(self.ws / "artifacts" / "locate" / "path_resolution.jsonl",
                         {"identifier": name, "hint": hint, "resolved": resolved,
                          "tier": tier})
        except OSError:
            pass

    def _record_disambiguation(self, name: str, dis: dict, source: str = "rule") -> None:
        """消歧决策落盘：选了谁、为什么、有没有并列。"""
        self._disambig = getattr(self, "_disambig", [])
        self._disambig.append({
            "function": name, "source": source, "status": dis["status"],
            "picked": ((dis.get("picked") or dis.get("provisional") or {}).get("file", "")),
            "picked_line": (dis.get("picked") or dis.get("provisional") or {}).get("line"),
            "needs_confirmation": bool(dis.get("needs_confirmation")),
            "confidence": dis.get("confidence", ""),
            "reason": dis["reason"],
            "candidates": [{"file": c["file"], "line": c["line"],
                            "signature": (c.get("signature") or "")[:120],
                            "conditions": c.get("conditions") or [],
                            "score": c.get("score")} for c in dis.get("candidates", [])],
        })

    def _pinpoint(self, src: Path, descr: str, claim: dict) -> dict:
        """让模型在「规则机械枚举的候选写点」中选定缺陷行。

        分工（对齐 BinSight sink-discovery 的 seed/agent 边界）：
        - 规则：机械枚举函数体所有数组/结构体写点，不做取舍
        - 模型：从候选中选出真正的缺陷点，并给出可校验的理由
        - 验证：verify 阶段真实崩溃行做独立裁判（不采信模型自评）

        这样「模型贡献」可以被证伪：选错就是选错。
        """
        rec = {"attempted": False, "candidates": 0, "picked": None,
               "validated": False, "rejected_reason": ""}
        if not claim:
            rec["rejected_reason"] = "no_rule_claim"
            return rec
        sink = claim.get("sink") or {}
        rel = sink.get("file") or ""
        def_line = sink.get("line") or 0
        if not rel or not def_line:
            rec["rejected_reason"] = "no_function_anchor"
            return rec
        path = src / rel
        if not path.exists():
            rec["rejected_reason"] = "source_missing"
            return rec

        try:
            body = binscan.function_body(path, def_line, stage=self.name)
            lines = binscan.read_lines(path)
            cands = binscan.write_candidates(lines, body[0], body[-1], stage=self.name) \
                if body else []
        except (OSError, PermissionError):
            rec["rejected_reason"] = "enumerate_failed"
            return rec
        rec["candidates"] = len(cands)
        # 少于 2 个候选时没有取舍空间，不构成模型贡献
        if len(cands) < 2:
            rec["rejected_reason"] = "insufficient_candidates"
            return rec

        listing = "\n".join(
            f"  [{i}] line {c['line']}: {c['text']}" for i, c in enumerate(cands))
        # 证据：整段函数体（含分配行与边界判断）。
        # 只给代码事实，不给结论——取舍仍由模型做。
        body = body[:400]
        full = "\n".join(f"{n}: {lines[n-1].rstrip()}" for n in body)
        user = (f"Vulnerability description:\n{descr.strip()}\n\n"
                f"Function: {claim.get('subject')} ({rel}, def line {def_line})\n\n"
                f"Candidate write sites (mechanically enumerated, no ranking):\n{listing}\n\n"
                f"Full function body (allocation, bounds checks and every write):\n{full}\n\n"
                'Reply JSON: {"defect_line": <line number from the list>, '
                '"reason": "<why this write, and from which input>", '
                '"evidence_kind": "array_index|struct_field|pointer_write"}')

        task = {}
        tp = self.ws / "task.json"
        if tp.exists():
            try:
                task = json.loads(tp.read_text(encoding="utf-8"))
            except Exception:
                task = {}
        cfg = llm_mod.load_config(self.ws, task)
        result = llm_mod.call_json(cfg, system=self.pinpoint_system, user=user,
                                   prompt_version=self.pinpoint_prompt_version)
        rec["attempted"] = True
        rec["status"] = result.status
        if not result.ok:
            rec["rejected_reason"] = f"model_{result.status}"
            return rec

        parsed = result.parsed or {}
        try:
            picked = int(parsed.get("defect_line"))
        except (TypeError, ValueError):
            rec["rejected_reason"] = "bad_defect_line"
            return rec
        allowed = {c["line"] for c in cands}
        rec["picked"] = picked
        rec["reason"] = str(parsed.get("reason") or "")[:400]
        rec["evidence_kind"] = str(parsed.get("evidence_kind") or "")
        rec["prompt_version"] = self.pinpoint_prompt_version
        if picked not in allowed:
            # 越界/幻觉：直接判无效，不进入验证
            rec["rejected_reason"] = "line_not_in_candidates"
            return rec
        rec["validated"] = True
        return rec

    def _llm_context(self, src: Path, hints: dict, rule_claims: list[dict]) -> str:
        """给模型的证据：描述点名的文件/函数定义片段 + 规则已找到的 sink 邻域。

        刻意不给「正确答案」——规则结论只作邻域定位，不告诉模型哪条是对的。
        """
        chunks: list[str] = []
        seen: set[str] = set()
        # 证据边界：模型只看描述点名的函数定义；**不把规则路径（可能已用 ASAN 定位）的
        # sink 邻域喂给它**——否则模型等于抄了规则+ASAN 的答案，测不出它的能力。
        for name in (hints.get("functions") or [])[:3]:
            defs = binscan.find_function_enriched(src, name, stage=self.name)
            if not defs:
                continue
            # 多实例**全部给出**，由模型自己判断哪个是缺陷实例。
            # 只给 [:1] 等于替它做了消歧选择（且是按字典序），是隐藏的偏差来源。
            for d in defs[:4]:
                key = f"{d['file']}:{d['line']}"
                if key in seen:
                    continue
                seen.add(key)
                window = binscan.line_window(src / d["file"], d["line"], before=2, after=40)
                chunks.append(f"--- {d['file']} (function {name} defined at line {d['line']}) ---\n{window}")
        for claim in (rule_claims[:1] if getattr(self, "inject_rule_sink", False) else []):
            sink = claim.get("sink") or {}
            if sink.get("file") and sink.get("line"):
                key = f"{sink['file']}:{sink['line']}"
                if key not in seen:
                    seen.add(key)
                    window = binscan.line_window(src / sink["file"], int(sink["line"]),
                                                before=12, after=12)
                    chunks.append(f"--- {sink['file']} (around line {sink['line']}) ---\n{window}")
        if not chunks:
            for hit in binscan.grep(src, r"\b(memcpy|memmove|strcpy|strcat|sprintf|memset)\s*\(",
                                    limit=5, stage=self.name):
                chunks.append(f"--- {hit['file']}:{hit['line']} ---\n{hit['text']}")
        return "\n\n".join(chunks)[:6000] or "(no source evidence available)"

    def _validate_llm_output(self, src: Path, parsed: dict) -> tuple[list[dict], list[dict]]:
        """模型输出必须通过符号/路径校验；编造的标识符直接丢弃并记原因。"""
        candidates: list[dict] = []
        rejected: list[dict] = []
        funcs = parsed.get("functions") if isinstance(parsed.get("functions"), list) else []
        conf_raw = parsed.get("confidence")
        try:
            conf_model = max(0.0, min(1.0, float(conf_raw)))
        except (TypeError, ValueError):
            conf_model = 0.5
            rejected.append({"field": "confidence", "value": conf_raw, "reason": "not_a_number"})

        for name in funcs[:8]:
            if not isinstance(name, str) or not name.strip():
                continue
            clean = name.strip().strip("`'\"")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{2,}", clean):
                rejected.append({"identifier": name,
                                 "reason": "not_an_identifier（疑似把描述短语当成函数名）"})
                continue
            defs = self.find_definitions(src, clean)
            if not defs:
                rejected.append({"identifier": clean, "reason": "function_not_found"})
                continue
            file_hint = ""
            for f in (parsed.get("files") or []):
                if isinstance(f, str) and f.strip():
                    file_hint = f.strip()
                    break
            # 路径归一化：模型给的是"相对项目根"，仓库根可能在 src/<project>/ 下。
            # 只在唯一匹配时改写 hint；歧义/找不到就保留原值（消歧会按 basename 退让）。
            hint_rel, hint_tier, _hint_cands = self.resolve_repo_path(src, file_hint)
            self._record_path_resolution(clean, file_hint, hint_rel, hint_tier)
            effective_hint = hint_rel or file_hint
            dis = binscan.disambiguate(clean, defs, file_hint=effective_hint,
                                       descr=self._desc_text())
            self._record_disambiguation(clean, dis, source="llm")
            if dis["status"] == "ambiguous":
                rejected.append({"identifier": clean, "reason": "ambiguous_instance",
                                 "candidates": [c["file"] for c in dis["candidates"]]})
                continue
            if dis["status"] == "conditional_unresolved":
                # 互斥分支未确认：保留候选记录，但不绑定为已确认结论
                rejected.append({"identifier": clean,
                                 "reason": "conditional_active_definition_unconfirmed",
                                 "provisional": (dis.get("provisional") or {}).get("file", ""),
                                 "candidates": [c["file"] for c in dis["candidates"]]})
                continue
            d = dis.get("picked")
            if not d:
                rejected.append({"identifier": clean, "reason": f"no_binding:{dis['status']}"})
                continue
            sink, dataflow, cwe = self._sink_in_file(src / d["file"], d["line"], {}, d["file"])
            if sink is None:
                sink = {"file": d["file"], "line": d["line"], "symbol": "",
                        "note": "模型指定函数，未定位到危险调用"}
            # 不折算人工系数：模型自评保留在 confidence_model，
            # confidence 置 0 表示"未经执行验证，尚无证据强度"（而非伪造一个折半值）
            candidates.append({
                "claim_id": f"llm-{len(candidates)+1}",
                "subject": clean,
                "subject_source": "llm",
                "predicate": "unsafe_operation",
                "value": sink.get("symbol", ""),
                "status": "proposed",
                # 未校准 = 未知，用 null，不用 0.0（0.0 会被读成"确定不可信"）
                "confidence": None,
                "confidence_model": conf_model,
                "confidence_basis": "model_self_reported_uncalibrated",
                "proposed_by": "llm",
                "evidence_source": "description+source_window",
                "cwe": cwe if cwe != "CWE-unknown" else "",
                "entry": {"file": d["file"], "line": d["line"], "note": "模型指认的函数定义"},
                "sink": sink,
                "dataflow": dataflow,
                "crash_frame": {"function": "", "line": None},
                "assumptions": ["模型依据给定描述与代码片段提出；未经执行验证"],
                "test_plan": {"format": self._guess_format(src, {}),
                              "field": sink.get("symbol", ""),
                              "boundary": parsed.get("boundary_hint") or "len > buffer"},
                "evidence_refs": [],
            })
        return candidates, rejected

    def _parse_description(self, descr: str) -> dict:
        funcs = []
        for m in REGEX_FUNCS.finditer(descr):
            name = next((g for g in m.groups() if g), "")
            if not name or name.lower() in STOPWORDS:
                continue
            if name not in funcs:
                funcs.append(name)
        files = sorted(set(REGEX_FILE.findall(descr)))
        crash = REGEX_CRASH.search(descr)
        size = REGEX_SIZE.search(descr)
        boundary = REGEX_BOUNDARY.search(descr)
        return {"functions": funcs[:8], "files": files[:5],
                "crash_type": crash.group(1) if crash else "",
                "write_size": int(size.group(1)) if size else None,
                "boundary_hint": boundary.group(0) if boundary else ""}

    def _build_claims(self, src: Path, hints: dict) -> list[dict]:
        """生成 claim。责任方（subject）与受害者（crash frame）必须分开。

        口径（审查方 2025-11-09）：
        - `subject` = **缺陷所在函数**。描述里点名了函数就用它；
          ASAN 首帧只有在没有描述线索时才当 subject。
        - ASAN 报点函数（如 mng_get_long）只写进 `sink.note`，不冒充责任方。
        - `sink.symbol` 必须填：有行号时用 enclosing_function 反查调用名。
        """
        claims: list[dict] = []
        evidence = self._sink_from_evidence(src)
        self._last_evidence = evidence
        err_text = self._err_text()
        crash_owner = evidence["function"] if evidence else ""
        desc_funcs = [f for f in self._desc_functions()]

        # ---- 责任方候选：描述点名 > 关键词 > ASAN 首帧 ----
        candidates: list[tuple[str, str]] = []   # (func, source)
        for f in desc_funcs:
            candidates.append((f, "description"))
        if not candidates:
            for f in self._keywords(descr=self._desc_text()):
                if f not in self.INTERCEPTORS:
                    candidates.append((f, "keyword"))
        if not candidates and crash_owner:
            candidates.append((crash_owner, "crash_frame"))

        for fname, source in candidates:
            defs = binscan.find_function_enriched(src, fname, stage=self.name)
            if not defs:
                continue
            dis = binscan.disambiguate(fname, defs, file_hint="",
                                       descr=self._desc_text())
            self._record_disambiguation(fname, dis)
            # ambiguous：保留全部候选但不擅自绑定；unique/disambiguated 才继续
            # ambiguous / conditional_unresolved：不擅自绑定；conditional 仅按 provisional 检查
            if dis["status"] in ("unique", "ranked_candidate"):
                targets = [dis["picked"]]
            elif dis["status"] == "conditional_unresolved":
                targets = [dis["provisional"]] if dis.get("provisional") else defs[:1]
            else:
                targets = defs[:2]
            for d in targets:
                sink, dataflow, cwe = self._resolve_sink(src, d, evidence, hints, fname)
                if sink is None:
                    continue
                cwe_evidence = self._cwe_from_text(err_text)
                if cwe_evidence != "CWE-000":
                    cwe = cwe_evidence
                conf = self._confidence(hints, flow_len=len(dataflow),
                                        subject_from_desc=(source == "description"))
                claims.append({
                    "claim_id": f"c-{len(claims)+1}",
                    "subject": fname,
                    "subject_source": source,
                    "proposed_by": "rule",
                    "evidence_source": ("description" if source == "description"
                                        else "error_txt" if source == "crash_frame"
                                        else "description+source"),
                    "predicate": "unsafe_operation",
                    "value": sink.get("symbol", ""),
                    "status": "proposed" if conf >= 0.5 else "needs_information",
                    "confidence": conf,
                    "cwe": cwe,
                    "entry": {"file": d["file"], "line": d["line"], "note": "函数定义"},
                    "sink": sink,
                    "dataflow": dataflow,
                    "crash_frame": {"function": crash_owner,
                                    "line": evidence["asan_line"] if evidence else None},
                    "assumptions": ["输入可由外部控制"],
                    "test_plan": {"format": self._guess_format(src, hints),
                                  "field": sink.get("symbol", ""),
                                  "boundary": hints.get("write_size") or "len > buffer"},
                    "evidence_refs": [],
                })
            if claims:
                break
        self.store.add_blackboard(self.run_id, "observation", "定位证据",
                                  f"crash_frame={crash_owner}; subjects="
                                  f"{[(c['subject'], c['subject_source']) for c in claims]}",
                                  status="ok")
        # 人工核对过的因果要素：从实验档案读取（不由代码编造）
        manual = self._load_manual_elements()
        if manual:
            claims = [merge_into_claim(c, manual) for c in claims]

        claims.sort(key=lambda c: (c.get("confidence") is not None,
                                   c.get("confidence") or 0.0), reverse=True)
        return claims[:3]

    def _resolve_sink(self, src: Path, d: dict, evidence: dict | None,
                      hints: dict, fname: str) -> tuple:
        """确定 sink 位置与 symbol。优先级：ASAN 行号 > 函数体内危险调用 > 崩溃函数本身。"""
        rel_file = d["file"]
        lines_path = src / rel_file
        sink, dataflow, cwe = self._sink_in_file(lines_path, d["line"], hints, rel_file)

        # 1) 崩溃函数 = 本函数 → 直接用 ASAN 行号锚定（写越界类）
        same_func_evidence = (evidence and evidence.get("asan_line")
                              and evidence.get("function") == fname
                              and evidence.get("def_file") == rel_file)
        if same_func_evidence:
            precise = self._sink_at_line(lines_path, rel_file, evidence["asan_line"])
            if precise:
                sink = precise
                dataflow = [{"file": rel_file, "line": d["line"], "note": "函数入口"},
                            {"file": rel_file, "line": precise["line"],
                             "note": f"ASAN 报点（build 行 {evidence['asan_line']}）"}]
        elif evidence:
            # 2) 崩溃函数是**受害者**（如 mng_get_long），责任函数在别处：
            #    找责任函数体内调用受害者函数的那一行，那才是缺陷点。
            call_site = self._call_site(lines_path, d["line"], evidence["function"],
                                        self._frame_line(evidence, fname))
            if call_site:
                sink = call_site
                dataflow = [{"file": rel_file, "line": d["line"], "note": "函数入口"},
                            {"file": rel_file, "line": call_site["line"],
                             "note": f"调用崩溃函数 {evidence['function']} 的位置"}]

        # 2) 描述的边界提示 + 无行号 → 用函数体内第一个危险调用（已有 sink 则保留）
        if sink is None:
            return None, [], cwe

        # 3) symbol 缺失时反查：优先 enclosing_function，其次从该行正则取调用名
        if not sink.get("symbol"):
            sink = dict(sink)
            sink["symbol"] = self._symbol_at(lines_path, sink["line"]) or ""

        # 4) note 统一写明 ASAN 报点与跳过帧，避免把崩溃函数误读成责任方
        if evidence:
            sink = dict(sink)
            skipped = evidence.get("skipped_frames") or []
            skip_note = f"；已跳过拦截器帧 {skipped}" if skipped else ""
            sink["note"] = (f"ASAN 报点 {evidence['function']} @ line {evidence.get('asan_line')}"
                            f"（{evidence['crash']}）；sink 位于 {fname} @ {sink['file']}:{sink['line']}"
                            f"{skip_note}")
        dataflow = [dataflow[0]] + [{"file": sink["file"], "line": sink["line"],
                                     "note": "缺陷点（sink）"}] if dataflow else \
                   [{"file": rel_file, "line": d["line"], "note": "函数入口"},
                    {"file": sink["file"], "line": sink["line"], "note": "缺陷点（sink）"}]
        return sink, dataflow, cwe

    def _frame_line(self, evidence: dict | None, fname: str) -> int | None:
        """从 ASAN 栈帧里取 fname 那一帧的行号（= 调用发生的位置）。"""
        if not evidence:
            return None
        for f in evidence.get("frames") or []:
            if f["func"] == fname and f["line"]:
                return int(f["line"])
        return None

    def _call_site(self, path: Path, def_line: int, victim: str,
                   asan_line: int | None = None) -> dict | None:
        """在函数体内定位“调用受害者函数”的那一行（受害者 = ASAN 报点函数）。

        10400 的形态：subject=ReadMNGImage，victim=mng_get_long，
        缺陷点是 `loop_iters=mng_get_long(&chunk[1]);`——LOOP 长度没校验就交给它。
        """
        try:
            src_text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None
        lines = src_text.split("\n")
        body = binscan.function_body(path, def_line, stage=self.name)
        if not body:
            return None
        hits = [ln for ln in body if 1 <= ln <= len(lines) and rx.search(lines[ln - 1])] \
            if (rx := re.compile(r"\b" + re.escape(victim) + r"\s*\(")) else []
        if not hits:
            return None
        # 栈帧里本函数的行号就是调用点位置（#1 ReadMNGImage @ png.c:4920）
        if asan_line:
            chosen = min(hits, key=lambda ln: abs(ln - asan_line))
            delta = chosen - asan_line
        else:
            chosen = hits[0]
            delta = None
        note = f"未校验的外部长度直接交给 {victim}：{lines[chosen-1].strip()[:160]}"
        if delta is not None:
            note += f"（build 行 {asan_line}，源码偏移 {delta:+d}）"
        return {"file": str(path.relative_to(self.layout["src"])), "line": chosen,
                "symbol": victim, "note": note, "call_site": True,
                "asan_line": asan_line, "offset_from_asan": delta}

    def _symbol_at(self, path: Path, line: int) -> str:
        """反查某行所在的函数名，或该行的危险调用名。"""
        enclose = binscan.enclosing_function(path, line, stage=self.name)
        try:
            lines = binscan.read_lines(path)
        except OSError:
            return enclose[0] if enclose else ""
        if 1 <= line <= len(lines):
            m = re.search(r"\b(memcpy|memmove|strcpy|strcat|sprintf|memset|sscanf|"
                          r"gets|alloca|XRESIZEVEC)\s*\(", lines[line - 1])
            if m:
                return m.group(1)
        return enclose[0] if enclose else ""

    # 实验开关：True 时本阶段不读取 error.txt / 补丁（信息对称实验用）
    blind_mode = False

    def _err_allowed(self) -> bool:
        return not getattr(self, "blind_mode", False)

    def _err_path(self):
        """返回可读的 error.txt 路径；盲测模式下恒为 None。"""
        if not self._err_allowed():
            return None
        p = self.ws / "error.txt"
        return p if p.exists() else None

    def _err_text(self) -> str:
        p = self._err_path()
        return p.read_text(encoding="utf-8", errors="ignore") if p else ""

    def _sink_from_evidence(self, src: Path) -> dict | None:
        """从 ASAN 栈里挑出**真正的缺陷函数**，而不是首帧。

        首帧常常是 `__interceptor_memcpy`（44034 就是这样），照着首帧定 sink
        会把缺陷点写成拦截器，行号必然对不上源码。规则：
        1. 跳过拦截器帧与 sanitizer/libfuzzer 自身帧；
        2. 取第一个在源码树里能找到定义的用户帧；
        3. 记下被跳过的帧，供报告审计。
        """
        p = self._err_path()
        if p is None:
            return None
        text = p.read_text(encoding="utf-8", errors="ignore")
        frames = []
        for m in re.finditer(r"#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(/src/[^:\s]+):(\d+):(\d+)",
                             text):
            frames.append({"idx": int(m.group(1)), "func": m.group(2), "file": m.group(3),
                           "line": int(m.group(4)), "col": m.group(5)})
        if not frames:
            return None
        crash = ""
        for kind in ("stack-buffer-overflow", "heap-buffer-overflow",
                     "global-buffer-overflow", "use-after-free"):
            if kind in text:
                crash = kind
                break
        picked, skipped = None, []
        for f in frames:
            if f["func"] in self.INTERCEPTORS or self.SANITIZER_PATH.search(f["file"]):
                skipped.append(f["func"])
                continue
            defs = binscan.find_function(src, f["func"], stage=self.name)
            if not defs:
                skipped.append(f["func"])
                continue
            picked = {**f, "def_file": defs[0]["file"], "def_line": defs[0]["line"]}
            break
        if picked is None:
            for name in self._desc_functions():
                defs = binscan.find_function(src, name, stage=self.name)
                if defs:
                    picked = {"idx": -1, "func": name, "file": "", "line": 0, "col": "",
                              "def_file": defs[0]["file"], "def_line": defs[0]["line"]}
                    break
        if picked is None:
            return None
        return {"function": picked["func"], "def_file": picked["def_file"],
                "def_line": picked["def_line"], "crash": crash,
                "asan_line": picked["line"], "asan_file": picked["file"],
                "skipped_frames": skipped, "frames": frames}

    def _desc_functions(self) -> list[str]:
        """描述文本里点名的函数（排除 ASAN 拦截器符号）。"""
        out = []
        for name in self._parse_description(self._desc_text())["functions"]:
            if name not in self.INTERCEPTORS and name not in out:
                out.append(name)
        return out

    def _cwe_from_text(self, text: str) -> str:
        t = text.lower()
        if "use-after-free" in t:
            return "CWE-416"
        first = next((l for l in t.splitlines() if "addresssanitizer:" in l and "overflow" in l), "")
        if "stack-buffer-overflow" in first:
            return "CWE-121"
        if "heap-buffer-overflow" in first:
            return "CWE-125" if "read of size" in t else "CWE-122"
        if "uninitialized" in t:
            return "CWE-457"
        return "CWE-000"

    def _load_manual_elements(self) -> dict:
        """读取人工核对后的因果要素档案；没有就返回空（不臆造）。"""
        import json as _json
        for cand in (self.ws / "propagation.json",
                     self.ws.parent.parent / "experiments" / f"{self.ws.name.split('-')[0].lower()}-dev-regression" / "PROPAGATION.json"):
            if cand.exists():
                try:
                    return _json.loads(cand.read_text(encoding="utf-8"))
                except Exception:
                    return {}
        return {}

    # ---- 路径归一化 + 缩进式定义兜底 ----
    # freetype2 这类仓库根在 src/<project>/ 下，且沿用 GNU 缩进排版：
    #   static void
    #   cff_blend_doBlend( ...     <- 定义行前面有 2 个空格
    # find_function 要求名字顶格，于是"函数明明在"也判 function_not_found。
    _DEF_RX_CACHE: dict[str, re.Pattern] = {}

    def _candidate_files(self, src: Path) -> list[str]:
        """src 下所有源码文件相对路径（只扫一次）。"""
        cache = getattr(self, "_src_files_cache", None)
        if cache is not None:
            return cache
        files: list[str] = []
        for p in sorted(Path(src).rglob("*")):
            if p.suffix not in binscan.SRC_SUFFIXES or not p.is_file():
                continue
            try:
                files.append(str(p.relative_to(src)))
            except ValueError:
                continue
        self._src_files_cache = files
        return files

    def resolve_repo_path(self, src: Path, hint: str) -> tuple[str | None, str, list[str]]:
        """把"相对项目根"的路径映射成"相对 src"的路径；只在唯一时接受。

        顺序：原路径 -> 唯一子目录前缀（src/<top>/<hint>）-> 唯一 basename。
        多命中返回 (None, "ambiguous", 候选)，调用方按原样拒绝，不猜。
        """
        hint = (hint or "").strip()
        while hint.startswith("./"):
            hint = hint[2:]
        if not hint:
            return None, "empty", []
        src = Path(src)
        if (src / hint).is_file():
            return hint, "direct", [hint]
        files = self._candidate_files(src)
        prefixed = [rel for rel in files if rel.endswith("/" + hint)]
        tops = {rel.split("/")[0] for rel in prefixed}
        if len(tops) == 1:
            return prefixed[0], "subdir_prefix", prefixed
        if len(prefixed) > 1:
            return None, "ambiguous", prefixed
        base = hint.split("/")[-1]
        same = [rel for rel in files if rel.split("/")[-1] == base]
        if len(same) == 1:
            return same[0], "basename", same
        if len(same) > 1:
            return None, "ambiguous", same
        return None, "not_found", []

    def _def_regex(self, name: str) -> re.Pattern:
        rx = self._DEF_RX_CACHE.get(name)
        if rx is None:
            rx = re.compile(r"^[ \t]*(?:static\s+|inline\s+|extern\s+|\w[\w \t\*]*[ \t\*]+)?"
                            + re.escape(name) + r"\s*\(")
            self._DEF_RX_CACHE[name] = rx
        return rx

    def find_definitions(self, src: Path, name: str, *, limit: int = 20) -> list[dict]:
        """先走 binscan；空结果再按"行首可含空白 + 后面确有函数体"兜底。"""
        defs = binscan.find_function_enriched(src, name, stage=self.name)
        if defs:
            return defs
        rx = self._def_regex(name)
        out: list[dict] = []
        for rel in self._candidate_files(src):
            path = Path(src) / rel
            try:
                lines = binscan.read_lines(path)
            except OSError:
                continue
            for i, line in enumerate(lines):
                stripped = line.rstrip()
                body = stripped.lstrip()
                if not body or body.startswith(("*", "//", "/*")):
                    continue
                if not rx.match(stripped) or stripped.endswith(";"):
                    continue
                if not self._looks_like_definition(lines, i):
                    continue
                out.append({"file": rel, "line": i + 1, "text": body[:300],
                            "signature": binscan._signature_at(lines, i, name),
                            "conditions": binscan._preprocessor_context(lines, i),
                            "branches": binscan._branch_chain(lines, i),
                            "source": "indent_tolerant_scan"})
                if len(out) >= limit:
                    return out
        return out

    @staticmethod
    def _strip_strings(code: str) -> str:
        return re.sub(r'"(?:[^"\\\\]|\\\\.)*"', '""', code)

    @classmethod
    def _looks_like_definition(cls, lines: list[str], idx: int) -> bool:
        """区分定义与调用：参数表闭合后跟 { 才是定义；以 ); 结尾的是调用。"""
        depth = 0
        started = False
        end_line = None
        for j in range(idx, min(idx + 12, len(lines))):
            code = cls._strip_strings(lines[j])
            if "(" in code:
                started = True
            for ch in code:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
            if started and depth <= 0:
                end_line = j
                break
        if end_line is None:
            return False
        tail = cls._strip_strings(lines[end_line]).strip()
        if tail.endswith(");"):
            return False
        if "{" in tail:
            return True
        for k in range(end_line + 1, min(end_line + 4, len(lines))):
            nxt = lines[k].strip()
            if not nxt:
                continue
            return nxt.startswith("{")
        return False
    def _desc_text(self) -> str:
        p = self.ws / "description.txt"
        return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""

    def _keywords(self, descr: str) -> list[str]:
        out = []
        for m in re.finditer(r"\b([A-Z][a-z]+[A-Z]\w+)\b", descr):
            if m.group(1) not in out:
                out.append(m.group(1))
        for m in re.finditer(r"\b([a-z]{2,}_[A-Za-z0-9_]+)\b", descr):
            token = m.group(1)
            if token not in out:
                out.append(token)
        return out[:6]

    def _sink_at_line(self, path: Path, rel: str, asan_line: int | None) -> dict | None:
        """ASAN 指了行号时，就在该行附近找危险调用，而不是从函数入口顺序扫描。

        44034 的教训：函数体内第一次 memcpy 在 fallback 分支（191 行），
        真正越界的是 332 行那一处。以 ASAN 行号为准才能命中真正的 sink。
        """
        if not asan_line:
            return None
        try:
            lines = binscan.read_lines(path)
        except OSError:
            return None
        danger = re.compile(r"\b(memcpy|memmove|strcpy|strcat|sprintf|memset|sscanf)\s*\(")
        # 先看 ASAN 行本身（构建版行号可能与源码有偏移，允许 ±6 行窗口）
        for delta in (0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5, -6, 6):
            idx = asan_line - 1 + delta
            if 0 <= idx < len(lines) and danger.search(lines[idx]):
                sym = danger.search(lines[idx]).group(1)
                return {"file": rel, "line": idx + 1, "symbol": sym,
                        "note": f"ASAN 报点 ±{abs(delta)} 行：{lines[idx].strip()[:180]}",
                        "asan_line": asan_line, "offset_from_asan": delta}
        # 没有危险调用就退回 ASAN 行本身（读越界类缺陷没有写调用）
        idx = asan_line - 1
        if 0 <= idx < len(lines):
            return {"file": rel, "line": asan_line, "symbol": "",
                    "note": f"ASAN 崩溃行：{lines[idx].strip()[:180]}",
                    "asan_line": asan_line, "offset_from_asan": 0}
        return None

    def _sink_in_file(self, path: Path, def_line: int, hints: dict, rel: str = ""):
        rel = rel or str(path.name)
        try:
            lines = binscan.read_lines(path)
        except OSError:
            return None, [], "CWE-unknown"
        # 优先在函数体内找 memcpy/memmove（长度可被外部控制），其次其他危险调用
        target = None
        for i in range(def_line - 1, min(len(lines), def_line + 600)):
            line = lines[i]
            if line.startswith("}") and i > def_line + 5:
                break
            for sym in ("memcpy", "memmove", "strcpy", "sprintf"):
                if re.search(r"\b" + sym + r"\s*\(", line):
                    target = (i, sym, line)
                    break
            if target:
                break
        if target is None:
            for i in range(def_line - 1, min(len(lines), def_line + 600)):
                line = lines[i]
                for sym in ("strcat", "sscanf", "gets"):
                    if re.search(r"\b" + sym + r"\s*\(", line):
                        target = (i, sym, line)
                        break
                if target:
                    break
        if target is None:
            return None, [], "CWE-unknown"
        i, sym, line = target
        cwe = MEM_SINKS.get(sym, (0, "CWE-121"))[1]
        sink = {"file": rel, "line": i + 1, "symbol": sym, "note": line.strip()[:200]}
        dataflow = [{"file": rel, "line": def_line, "note": "函数入口"},
                    {"file": rel, "line": i + 1, "note": f"{sym} 调用"}]
        return sink, dataflow, cwe

    def _confidence(self, hints: dict, *, flow_len: int, subject_from_desc: bool = False) -> float:
        symbol = 1.0 if (hints.get("functions") or subject_from_desc) else 0.3
        complete = min(1.0, flow_len / 2.0)
        desc = 1.0 if hints.get("crash_type") else 0.5
        reach = 0.5
        val = 0.40 * symbol + 0.30 * complete + 0.20 * desc + 0.10 * reach
        return round(min(0.95, val), 3)

    def _guess_format(self, src: Path, hints: dict) -> str:
        # 盲测模式下不得用 error.txt 推断格式（否则等于偷看答案）
        blob = (self._desc_text() + " " + self._err_text()).lower()
        names = " ".join((hints.get("functions") or []) + (hints.get("files") or [])).lower()
        if "mng" in names or "mng" in blob or "loop chunk" in blob:
            return "mng"
        if "pdf" in names or "pdf" in blob:
            return "pdf"
        if "zip" in blob:
            return "zip"
        if ("dwarf2dbg" in blob or "assign_file_to_slot" in blob
                or "gas/" in blob or ".file" in blob):
            return "gas"
        if ("llvmfuzzertestoneinput" in blob or "fuzzer" in blob
                or "oss-fuzz" in blob):
            return "fuzz"
        # ImageMagick/GraphicsMagick 的 MVG 绘制脚本（纯文本，path/roundrectangle 等指令）
        if ("mvg" in blob or "pathinfo" in blob or "convertprimitivetopath" in blob
                or "draw_info" in blob or "graphicsmagick" in blob):
            return "mvg"
        return "unknown"

def llm_mod_call_key(prompt_version: str, status: str) -> str:
    """attempts 的 action_key：同一 prompt 版本 + 同一结果只记一条。"""
    from ..util import short_hash
    return short_hash(["llm", prompt_version, status], 16)
