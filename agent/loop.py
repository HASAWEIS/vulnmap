"""模型驱动的输入生成闭环。

流程（每一轮都留痕）：
1. 把「源码片段 + 缺陷假设 + 上一轮的执行反馈」交给模型；
2. 模型输出**输入内容**（base64 或可打印文本）+ 修改理由；
3. 用固定执行器跑双端（vul / fix），拿到真实诊断；
4. 把诊断回灌给模型，进入下一轮；
5. 最多 `max_rounds` 轮，全部动作、候选哈希、双端日志落盘。

设计原则：
- 模型只负责**提出输入**，判定权在固定验收器（vul 崩 / fix 不崩 / 根因匹配）；
- 每轮失败原因原样回灌，不美化、不跳过；
- 不人为制造第一次失败，第一次就成功也照实记录。
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field

from . import llm as llm_mod


@dataclass
class LoopRound:
    round_id: int
    rationale: str = ""
    encoding: str = "text"
    data: bytes = b""
    sha256: str = ""
    mlm_tokens: int = 0
    mlm_status: str = ""
    verdict: str = ""
    vul_exit: int | None = None
    fix_exit: int | None = None
    feedback: str = ""
    crash_line: int | None = None

    def to_record(self) -> dict:
        return {
            "round": self.round_id,
            "rationale": self.rationale[:800],
            "encoding": self.encoding,
            "size": len(self.data),
            "sha256": self.sha256,
            "llm_status": self.mlm_status,
            "llm_tokens": self.mlm_tokens,
            "verdict": self.verdict,
            "vul_exit": self.vul_exit,
            "fix_exit": self.fix_exit,
            "feedback": self.feedback[:1200],
            "crash_line": self.crash_line,
        }


LOOP_SYSTEM = (
    "You are a vulnerability researcher. You must produce a concrete input file that "
    "triggers the described defect in the target program. "
    "Reply with STRICT JSON only, keys: "
    "encoding ('base64' or 'text'), content (the input bytes; if base64, valid base64), "
    "rationale (why this input should reach the defect), "
    "predicted_field (which field/length you are abusing). "
    "IMPORTANT: keep total content under 4000 characters; prefer a compact input. "
    "No prose outside JSON."
)


def build_prompt(claim: dict, context: str, history: list[LoopRound],
                 fmt: str) -> str:
    from .builders import FIELD_SPECS, supported_formats
    parts = [
        f"Target input format: {fmt}" + (" — BINARY format: you MUST use encoding=hex; text output is invalid" if (fmt or "").lower() in ("pdf","tiff","bmp","font","cff_pdf","png","mng","rar5","dwg","av1") else ""),
        f"Available builders: {supported_formats()}",
        f"Builder field spec for '{fmt}': {FIELD_SPECS.get(fmt, 'none')}",
        ("If you know the exact fields, MODE A (recipe) is convenient; otherwise you MAY "
         'return raw bytes via {"encoding":"hex","data":"..."} (<=512KB). '
         'Old builder field sets only describe known bugs; do not assume they fit this task. '
         '(legacy note) If the format above has a builder, MODE A used to be mandatory: '
         "fields. Only fall back to MODE B if no builder applies."),
        f"Defect hypothesis: {json.dumps({k: claim.get(k) for k in ('subject','cwe','sink','test_plan')}, ensure_ascii=False)}",
        f"Source evidence:\n{context}",
    ]
    if history:
        fails = [r for r in history if r.verdict == "not_triggered"]
        if len(fails) >= 2:
            parts.append(
                "IMPORTANT: the previous attempts were NOT triggered. "
                "Repeating a similar input will fail again. "
                "You must CHANGE THE HYPOTHESIS: pick a different defect field, "
                "a different length class (e.g. 0 / 1 / max / wrap-around), "
                "or a different part of the format that reaches the same sink.")
        parts.append("Previous attempts and their REAL observed results:")
        for r in history:
            parts.append(
                f"- round {r.round_id}: size={len(r.data)} sha={r.sha256[:12]} "
                f"vul_exit={r.vul_exit} fix_exit={r.fix_exit} verdict={r.verdict}\n"
                f"  rationale={r.rationale[:200]}\n"
                f"  observed={r.feedback[:300]}")
        parts.append("Adjust the input based on what actually happened. Do not repeat an "
                     "identical input.")
    else:
        parts.append("This is the first attempt.")
    return "\n\n".join(parts)


def parse_response(content: str, fmt: str = "", *,
                   require_recipe: bool = False) -> tuple[bytes, str, str]:
    """解析模型输出 → (data, rationale, predicted_field)。失败抛 ValueError。

    支持两种模式：
    - recipe: 模型给字段，由 builders 组装容器（推荐，不受输出体积限制）
    - text / base64: 模型直接给字节（仅在无构造器时使用）
    """
    from .builders import build as assemble
    obj = json.loads(content)
    if not isinstance(obj, dict):
        raise ValueError("not_an_object")
    enc = (obj.get("encoding") or "text").lower()
    if enc == "recipe":
        target_fmt = (obj.get("format") or fmt or "").lower()
        fields = obj.get("fields") or {}
        res = assemble(target_fmt, fields)
        if not res.ok:
            raise ValueError(f"recipe_failed:{res.reason}")
        return (res.data, str(obj.get("rationale") or ""),
                str(obj.get("predicted_field") or ""))
    if require_recipe:
        # 有构造器时强制 recipe：让模型吐完整二进制必然超预算
        raise ValueError(
            "must_use_recipe:format_has_builder; reply with "
            '{"encoding":"recipe","format":"%s","fields":{...}}' % fmt)
    raw = obj.get("content")
    if not isinstance(raw, str) or not raw:
        raise ValueError("missing_content")
    if enc == "base64":
        try:
            data = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise ValueError(f"bad_base64:{exc}") from exc
    else:
        data = raw.encode("utf-8", errors="surrogateescape")
    return data, str(obj.get("rationale") or ""), str(obj.get("predicted_field") or "")


def run_loop(*, config: llm_mod.LlmConfig, claim: dict, context: str, fmt: str,
             execute, max_rounds: int = 3, prompt_version: str = "verify-llm-loop-p1",
             max_tokens: int = 8000, log=None) -> dict:
    """执行闭环。`execute(data) -> dict` 由调用方注入（固定验收器）。"""
    # 闭环要产出完整输入内容，需要比单次抽取更大的输出预算。
    # 必须用 replace 保留全部字段（直接重建 dict 会丢掉 disable_thinking）
    import dataclasses
    config = dataclasses.replace(config, max_tokens=max_tokens)
    history: list[LoopRound] = []
    transcript = []
    for i in range(1, max_rounds + 1):
        prompt = build_prompt(claim, context, history, fmt)
        res = llm_mod.call_json(config, system=LOOP_SYSTEM, user=prompt,
                                prompt_version=prompt_version)
        rnd = LoopRound(round_id=i, mlm_status=res.status, mlm_tokens=res.tokens)
        transcript.append({"round": i, "stage": "llm", "status": res.status,
                           "tokens": res.tokens, "error": res.error})
        if not res.ok:
            rnd.verdict = f"llm_{res.status}"
            rnd.feedback = res.error
            history.append(rnd)
            if log:
                log(f"round {i}: llm {res.status} {res.error}")
            continue
        from .builders import BUILDERS
        require_recipe = (fmt or "").lower() in BUILDERS
        try:
            data, rationale, field = parse_response(res.content, fmt,
                                                   require_recipe=require_recipe)
        except ValueError as exc:
            rnd.verdict = "invalid_model_output"
            _msg = str(exc)
            if "binary_format_requires_hex" in _msg:
                _msg += ('; reply exactly with {"encoding":"hex","content":"<hex bytes>"} '
                         'e.g. {"encoding":"hex","content":"414243"} — text is rejected')
            rnd.feedback = _msg
            rnd.rationale = res.content[:300]
            history.append(rnd)
            if log:
                log(f"round {i}: invalid output {exc}")
            continue

        import hashlib
        rnd.sha256 = hashlib.sha256(data).hexdigest()
        rnd.rationale = rationale
        # 去重：与历史任一候选相同 → duplicate_input，不执行、不计有效轮次
        seen = {r.sha256 for r in history if r.sha256}
        if rnd.sha256 in seen:
            rnd.data = b""
            rnd.verdict = "duplicate_input"
            rnd.feedback = (f"该输入与之前某轮完全相同 (sha256={rnd.sha256[:16]})，已拒绝。"
                            "必须改变输入内容或改变假设。")
            history.append(rnd)
            transcript.append({"round": i, "stage": "dedup", **rnd.to_record()})
            if log:
                log(f"round {i}: duplicate_input {rnd.sha256[:12]} 已拒绝，未执行")
            continue
        rnd.data = data
        rnd.encoding = "base64" if data != data.decode("utf-8", "ignore").encode() else "text"

        # 固定验收器执行（真实双端）
        outcome = execute(data) or {}
        rnd.vul_exit = outcome.get("vul_exit")
        rnd.fix_exit = outcome.get("fix_exit")
        rnd.verdict = outcome.get("verdict", "")
        rnd.feedback = (outcome.get("feedback") or "")[:1500]
        rnd.crash_line = outcome.get("crash_line")
        history.append(rnd)
        transcript.append({"round": i, "stage": "execute", **rnd.to_record()})
        if log:
            log(f"round {i}: sha={rnd.sha256[:12]} vul={rnd.vul_exit} "
                f"fix={rnd.fix_exit} verdict={rnd.verdict}")
        # 只要该轮自身通过就停止
        if rnd.verdict == "pass":
            break

    best = next((r for r in history if r.verdict == "pass"), None)
    effective = [r for r in history if r.verdict not in ("duplicate_input",)
                 and r.vul_exit is not None]
    return {
        "rounds": [r.to_record() for r in history],
        "transcript": transcript,
        "total_rounds": len(history),
        "effective_rounds": len(effective),
        "duplicates_rejected": sum(1 for r in history if r.verdict == "duplicate_input"),
        "succeeded": best is not None,
        "winner_sha256": best.sha256 if best else "",
        "winner_round": best.round_id if best else None,
        # 字节不落 record（避免把二进制塞进 JSON），但要让 verify 能拿到并作为正式候选落盘
        "winner_data": best.data if best else b"",
        "total_tokens": sum(r.mlm_tokens for r in history),
    }
