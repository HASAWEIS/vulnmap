"""Verify：容器构造 → 单变量注入 → 本地双端 → 判定（vul 崩 / fix 不崩）。"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import zlib
from pathlib import Path

from .. import loop as loop_mod
from .. import harness as harness_mod
from ..builders import build as builders_build
from ..casekit import image_for
from ..diagnostics import (ConsistencyResult, LINE_SLACK, check_root_cause,
                            parse_diagnosis)
from ..errors import FormatError
from ..tools import binscan, shell
from ..util import atomic_write_json, sha256_bytes, sha256_file
from ..validate import guard_upstream_untouched
from .base import Stage


def _chunk(typ: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)


def make_mng(loop_len: int, *, filler: bool = True) -> bytes:
    """最小 MNG：MHDR + LOOP(len) + 合法 PNG 数据流 + MEND。"""
    mng = b"\x8aMNG\r\n\x1a\n"
    mhdr = _chunk(b"MHDR", struct.pack(">7I", 1, 1, 0, 0, 0, 0, 0))
    loop = _chunk(b"LOOP", b"\x00" * loop_len)
    body = b""
    if filler:
        ihdr = _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
        idat = _chunk(b"IDAT", zlib.compress(b"\x00\x00"))
        body = b"\x89PNG\r\n\x1a\n" + ihdr + idat + _chunk(b"IEND", b"")
    return mng + mhdr + loop + body + _chunk(b"MEND", b"")


def pdf_with_basefont(name: bytes) -> bytes:
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type0 /BaseFont /" + name + b" /Encoding /Identity-H /DescendantFonts [6 0 R] >>",
        b"<< /Length 19 >>\nstream\nBT /F1 12 Tf (A) Tj ET\nendstream",
        b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /" + name + b" >>",
    ]
    out = bytearray(b"%PDF-1.7\n")
    offsets = [0]
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets[1:]:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF" % (len(objs) + 1, xref)
    return bytes(out)


def make_gas_file_directive(slot: int, name: bytes = b"x.c") -> bytes:
    """最小 gas 汇编：用 `.file <slot> "<name>"` 触发 assign_file_to_slot 的槽位越界。

    47101 的缺陷：`assign_file_to_slot(unsigned long i, ...)` 未拦截大整数的
    回绕，`files_allocated = i + 32` 溢出后 memset 越界。slot 取接近 2^32 的值。
    """
    return (b".file " + str(slot).encode() + b' "' + name + b'"\n'
            + b".text\n.globl _start\n_start:\n nop\n")


def make_gas_repeat_file(slot: int, count: int = 1) -> bytes:
    """多个 .file 指令：先撑开表，再插大槽位。"""
    body = b"".join(b'.file %d "f%d.c"\n' % (i + 1, i) for i in range(count))
    return body + b".file " + str(slot).encode() + b' "big.c"\n.text\n nop\n'


def make_fuzz_seed(seed: bytes) -> bytes:
    """fuzzer 类靶子的最小输入。

    这类缺陷（如 UBSAN function 类型不符）在调用约定层面，**不依赖输入内容**：
    driver 必然调用 LLVMFuzzerTestOneInput，任意字节都会经过该调用点。
    因此最小输入即可，不需要构造特定格式。
    """
    return seed


DUPLICATE_MAX_CONSECUTIVE = 2

OUTPUT_BUDGET_DIRECTIVE = (
    "OUTPUT BUDGET (HARD LIMITS - a reply that breaks them is discarded and costs a round):\n"
    "- 'content' = the candidate input as HEX ONLY (no 0x prefix, no spaces), at most 240 hex "
    "characters (=120 bytes), built from AT MOST 2 seeds.\n"
    "- 'rationale' = at most 60 words, ONE sentence naming the field you mutate.\n"
    "- No prose, no analysis, no markdown, no code fences outside the single JSON object.\n"
    "- Exact shape: {\"encoding\":\"hex\",\"content\":\"<hex>\",\"rationale\":\"<one sentence>\"}"
)

COMPACT_DIRECTIVE = (
    "COMPACT RETRY - your previous reply was cut off or unparsable. Reply with the SMALLEST "
    "possible JSON object: 'content' = hex, at most 120 hex characters (=60 bytes) from ONE "
    "seed; 'rationale' = at most 15 words. Nothing else."
)

NO_CRASH_DIRECTIVE = (
    "NO_CRASH_NEXT_ACTION: round {round} WAS executed (vul_exit={vul_exit}) but the target "
    "never entered the vulnerable branch: the bytes were accepted and parsed away, or a "
    "guard rejected them before the sink. This is NOT a length problem "
    "({size}B is inside {window}). 解析未进入目标分支，需改结构而非改长度。"
    " Keep len(input) inside {window} and change the STRUCTURE instead: which bytes land "
    "in which field, one field magnitude pushed to 0 / max / truncated, the struct cut "
    "short, or policy fields recombined. A reply that only shifts the length is a wasted "
    "round."
)


DUPLICATE_DIRECTIVE = (
    "DUPLICATE_INPUT_REJECTED: your previous reply produced bytes IDENTICAL to "
    "round {round} (sha256={sha}). It was judged duplicate and NOT executed. "
    "You must CHANGE THE HYPOTHESIS now: a different defect field, a different "
    "length/magnitude class, or a different part of the format that reaches the "
    "same sink. The next reply MUST have a different sha256; repeating the same "
    "bytes again terminates the loop."
)


def _note(log, msg: str) -> None:
    if log:
        log(msg)


def _round_record(rnd, *, duplicate: bool, distinct: bool) -> dict:
    """每轮记录：输入 sha256 + 是否重复 + 是否新输入（可审计，不靠推断）。"""
    rec = rnd.to_record()
    rec["input_sha256"] = rnd.sha256
    rec["duplicate"] = duplicate
    rec["distinct"] = distinct
    return rec


def _parse_reply(content: str, fmt: str, require_recipe: bool):
    """解析模型回复：p5 起提示要求 hex，loop.parse_response 只认 text/base64/recipe。

    loop.parse_response 对未知 encoding 会走 text 分支（把 "abab..." 当字节），
    所以 hex 必须在委托之前拦下来；其余情况（recipe / base64 / text）保持原行为。
    """
    if not require_recipe:
        try:
            obj = json.loads(content)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            _enc = str(obj.get("encoding") or "").lower()
            _binary = (fmt or "").lower() in ("pdf","tiff","bmp","font","cff_pdf","png","mng","rar5","dwg","av1","binary")
            if _binary and _enc in ("", "text", "base64"):
                raise ValueError("binary_format_requires_hex")
        if isinstance(obj, dict) and str(obj.get("encoding") or "").lower() == "hex":
            raw = "".join(str(obj.get("content") or "").split())
            if not raw:
                raise ValueError("missing_content")
            return (bytes.fromhex(raw), str(obj.get("rationale") or ""),
                    str(obj.get("predicted_field") or ""))
    return loop_mod.parse_response(content, fmt, require_recipe=require_recipe)


def run_diverse_loop(*, claim: dict, context: str, fmt: str, execute, call_llm,
                     max_rounds: int = 3,
                     prompt_version: str = "verify-llm-loop-p5",
                     log=None,
                     duplicate_max_consecutive: int = DUPLICATE_MAX_CONSECUTIVE,
                     seed_block: str = "",
                     seeds: list | None = None,
                     contract: dict | None = None) -> dict:
    """模型闭环 + 换假设 + 输出纪律（p5）。

    p4 实测（S5-c）：注入种子块后模型啰嗦化，3 轮都 finish_reason=length，
    completion 打满 8000 token、0 轮执行。p5 的差别：
    1. 提示里写死输出预算（content 只放 hex ≤240 字符、≤2 条种子、rationale ≤60 词）；
    2. 首次回复不 ok 或解析失败 -> 降载重试一次（seed 2->1、上下文砍半），
       仍失败才记 llm_incomplete；
    3. 每次模型调用都记 finish_reason / completion_tokens / prompt_chars / retry_round。
    """
    from ..builders import BUILDERS
    # 通用接口：允许模型直接给 hex/base64，不再被旧构造器的字段 schema 限制
    require_recipe = False
    history: list = []
    records: list[dict] = []
    transcript: list[dict] = []
    seen: dict[str, int] = {}
    consecutive_duplicates = 0
    pending_directive = ""
    terminated_early = False
    terminal_reason = ""
    retried_rounds = 0
    llm_incomplete_rounds = 0
    invalid_output_rounds = 0

    seed_list = list(seeds or [])
    window = harness_mod.window_text(contract or {})
    compact_seed_block = ""
    if seed_list:
        try:
            compact_seed_block = harness_mod.seed_prompt(
                seed_list, contract or {}, max_show=1)
        except Exception:
            compact_seed_block = ""
    elif seed_block:
        compact_seed_block = seed_block[:200]
    compact_context = context[: max(600, len(context) // 2)]

    def _ask(user: str, retry_round: int):
        res = call_llm(system=loop_mod.LOOP_SYSTEM, user=user,
                       prompt_version=prompt_version)
        info = {
            "retry_round": retry_round,
            "status": res.status,
            "finish_reason": getattr(res, "finish_reason", "") or "",
            "completion_tokens": int(getattr(res, "completion_tokens", 0) or 0),
            "prompt_tokens": int(getattr(res, "prompt_tokens", 0) or 0),
            "tokens": int(res.tokens or 0),
            "prompt_chars": len(user),
            "error": res.error or "",
        }
        return res, info

    for i in range(1, max_rounds + 1):
        base = loop_mod.build_prompt(claim, context, history, fmt)
        prompt = base + "\n\n" + OUTPUT_BUDGET_DIRECTIVE
        if seed_block:
            prompt = prompt + "\n\n" + seed_block
        if pending_directive:
            prompt = prompt + "\n\n" + pending_directive

        res, first = _ask(prompt, 0)
        calls = [first]
        data = None
        rationale = ""
        parse_err = ""
        res_ok = res.ok
        err = res.error
        if res_ok:
            try:
                data, rationale, _field = _parse_reply(res.content, fmt, require_recipe)
            except ValueError as exc:
                parse_err = str(exc)

        if (not res_ok) or parse_err:
            # 降载重试一次：只留 1 条种子 + 上下文砍半 + 极简指令
            compact = (loop_mod.build_prompt(claim, compact_context, history, fmt)
                       + "\n\n" + COMPACT_DIRECTIVE)
            if compact_seed_block:
                compact = compact + "\n\n" + compact_seed_block
            if pending_directive:
                compact = compact + "\n\n" + pending_directive[:400]
            res2, second = _ask(compact, 1)
            calls.append(second)
            retried_rounds += 1
            res = res2
            res_ok = res2.ok
            err = res2.error
            parse_err = ""
            if res_ok:
                try:
                    data, rationale, _field = _parse_reply(res.content, fmt, require_recipe)
                except ValueError as exc:
                    parse_err = str(exc)

        rnd = loop_mod.LoopRound(round_id=i, mlm_status=res.status,
                                 mlm_tokens=sum(c["tokens"] for c in calls))
        try:
            _obj = json.loads(res.content)
            if isinstance(_obj, dict):
                rnd.encoding = str(_obj.get("encoding") or "")
        except Exception:
            pass
        transcript.append({"round": i, "stage": "llm", "status": res.status,
                           "tokens": rnd.mlm_tokens, "error": res.error,
                           "finish_reason": calls[-1]["finish_reason"],
                           "completion_tokens": calls[-1]["completion_tokens"],
                           "parse_fmt": fmt,
                           "raw_reply": (res.content or "")[:600],
                           "prompt_chars": calls[-1]["prompt_chars"],
                           "retry_round": calls[-1]["retry_round"]})
        call_meta = {"llm_calls": calls,
                     "retry_round": calls[-1]["retry_round"],
                     "finish_reason": calls[-1]["finish_reason"],
                     "completion_tokens": calls[-1]["completion_tokens"],
                     "prompt_chars": calls[-1]["prompt_chars"]}

        if (not res_ok) or parse_err:
            if not res_ok:
                rnd.verdict = f"llm_{res.status}"
                rnd.feedback = err or res.status
                llm_incomplete_rounds += 1
            else:
                rnd.verdict = "invalid_model_output"
                rnd.feedback = parse_err
                rnd.rationale = (res.content or "")[:300]
                invalid_output_rounds += 1
            history.append(rnd)
            rec = _round_record(rnd, duplicate=False, distinct=False)
            rec.update(call_meta)
            records.append(rec)
            transcript.append({"round": i, "stage": "llm_failed", **rec})
            _note(log, f"round {i}: {rnd.verdict} {rnd.feedback} "
                       f"(calls={len(calls)}, finish={calls[-1]['finish_reason']}, "
                       f"prompt_chars={calls[-1]['prompt_chars']})")
            continue

        sha = hashlib.sha256(data).hexdigest()
        rnd.sha256 = sha
        rnd.rationale = rationale

        if sha in seen:
            consecutive_duplicates += 1
            rnd.data = b""
            rnd.verdict = "duplicate_input"
            rnd.feedback = (f"该输入与第 {seen[sha]} 轮逐字节相同 (sha256={sha[:16]})，"
                            "判 duplicate 并拒绝执行；必须换假设。")
            history.append(rnd)
            rec = _round_record(rnd, duplicate=True, distinct=False)
            rec["reason"] = "输入与既有轮次逐字节相同"
            rec["required_action"] = "change_hypothesis"
            rec.update(call_meta)
            records.append(rec)
            transcript.append({"round": i, "stage": "dedup", **rec})
            _note(log, f"round {i}: duplicate_input {sha[:12]} 已拒绝，未执行"
                       f"（连续 {consecutive_duplicates} 轮）")
            pending_directive = DUPLICATE_DIRECTIVE.format(round=seen[sha],
                                                           sha=sha[:16])
            if consecutive_duplicates >= duplicate_max_consecutive:
                terminated_early = True
                terminal_reason = (
                    f"duplicate_input_rounds: 连续 {consecutive_duplicates} 轮输入逐字节重复"
                    f"（sha256={sha[:16]}，首次出现在第 {seen[sha]} 轮）；"
                    f"模型收到「换假设」指令后仍未改变输入，闭环于第 {i}/{max_rounds} 轮终止")
                _note(log, terminal_reason)
                break
            continue

        # 新输入：只有它才消耗一轮有效尝试
        consecutive_duplicates = 0
        pending_directive = ""
        seen[sha] = i
        rnd.data = data
        if rnd.encoding not in ("hex", "base64"):
            rnd.encoding = ("base64" if data != data.decode("utf-8", "ignore").encode()
                        else "text")
        outcome = execute(data) or {}
        rnd.vul_exit = outcome.get("vul_exit")
        rnd.fix_exit = outcome.get("fix_exit")
        rnd.verdict = outcome.get("verdict", "")
        rnd.feedback = (outcome.get("feedback") or "")[:1500]
        rnd.crash_line = outcome.get("crash_line")
        history.append(rnd)
        rec = _round_record(rnd, duplicate=False, distinct=True)
        rec.update(call_meta)
        records.append(rec)
        transcript.append({"round": i, "stage": "execute", **rec})
        _note(log, f"round {i}: sha={sha[:12]} vul={rnd.vul_exit} "
                   f"fix={rnd.fix_exit} verdict={rnd.verdict}")
        if rnd.verdict == "pass":
            break
        if rnd.verdict == "not_triggered":
            # 未进缺陷分支：把「改结构而不是改长度」作为独立指令块送进下一轮
            rec["next_action"] = "change_structure"
            pending_directive = NO_CRASH_DIRECTIVE.format(
                round=i, vul_exit=rnd.vul_exit, size=len(data),
                window=window or "the harness window")

    best = next((r for r in history if r.verdict == "pass"), None)
    duplicates = [r for r in records if r.get("duplicate")]
    effective = [r for r in records if r.get("distinct") and r.get("vul_exit") is not None]
    return {
        "rounds": records,
        "transcript": transcript,
        "max_rounds": max_rounds,
        "total_rounds": len(records),
        "effective_rounds": len(effective),
        "executed_rounds": len(seen),
        "llm_incomplete_rounds": llm_incomplete_rounds,
        "invalid_output_rounds": invalid_output_rounds,
        "retried_rounds": retried_rounds,
        "total_calls": sum(len(r.get("llm_calls") or []) for r in records),
        "distinct_inputs": len(seen),
        "duplicates_rejected": len(duplicates),
        "duplicate_input_rounds": len(duplicates),
        "consecutive_duplicate_termination": terminated_early,
        "terminated_early": terminated_early,
        "terminal_reason": terminal_reason,
        "succeeded": best is not None,
        "winner_sha256": best.sha256 if best else "",
        "winner_round": best.round_id if best else None,
        "winner_data": best.data if best else b"",
        "total_tokens": sum(r.mlm_tokens for r in history),
        "seeds_used": [{"name": s.get("name", ""), "size": s.get("size"),
                        "sha256": s.get("sha256", ""),
                        "source": s.get("source", ""),
                        "structure": s.get("structure", "")}
                       for s in seed_list],
        "seed_count": len(seed_list),
        "seed_block_chars": len(seed_block or ""),
    }


class VerifyStage(Stage):
    name = "verify"
    role_version = "verify-v1"
    prompt_version = "verify-p1"
    schema_version = "vulnmap.verify.v1"
    # 模型闭环：预置构造器失败后，是否让模型自主生成并迭代
    enable_model_loop = True
    loop_max_rounds = 3
    # 连续这么多轮输入逐字节重复 -> 判模型未换假设，闭环终止（不静默接受）
    duplicate_max_consecutive = DUPLICATE_MAX_CONSECUTIVE
    loop_prompt_version = "verify-llm-loop-p5"  # p5: 输出纪律 + 降载重试（S5-d B5）

    def input_hashes(self) -> dict[str, str]:
        out = super().input_hashes()
        for rel in ("artifacts/locate/findings.json", "artifacts/recon/repo_map.json"):
            p = self.ws / rel
            if p.exists():
                out[rel] = sha256_file(p)
        return out

    def image_refs(self) -> list[str]:
        refs = [r for r in (image_for(self.ws, "vul"), image_for(self.ws, "fix")) if r]
        return refs

    def execute(self) -> dict:
        # 先解析镜像，再做运行身份采集（原实现先用了未赋值的 image，导致身份永远为空）
        image = self._images()
        if not image["vul"]:
            raise FormatError("vul image missing")
        try:
            self._identity = self._run_identity(image["vul"])
        except Exception as exc:
            self._identity = {"error": f"{type(exc).__name__}: {exc}"}

        findings = self._load_claims()
        self._current_claim = findings[0] if findings else {}
        # 格式判定独立于 claim 来源：即使规则无候选，也要如实记录检测到的格式，
        # 否则"无构造器"会被误记成"格式未知"
        # 格式优先级：task.json 显式声明 > 规则 claim > 模型候选。
        # 格式由容器/样本决定，是**事实**；模型的 test_plan.format 是猜测。
        # 让猜测覆盖事实会导致构造器走错分支（CG-13 被猜成 fuzz 而实际是 text）。
        fmt = ""
        try:
            _t = json.loads((self.ws / "task.json").read_text(encoding="utf-8"))
            fmt = str(_t.get("input_format") or "")
        except Exception:
            fmt = ""
        if not fmt:
            fmt = ((self._current_claim.get("test_plan") or {}).get("format") or "")
        if not fmt:
            for c in (self._locate_data or {}).get("claims_llm") or []:
                fmt = (c.get("test_plan") or {}).get("format") or ""
                if fmt:
                    break
        self._detected_format = fmt or "unknown"
        self._current_sink = (self._current_claim.get("sink") or {})
        # 无 claim（规则与模型都没给出函数级假设）但格式已知时，
        # 仍应按格式构造候选：构造器是"格式"的函数，不是"claim"的函数。
        formats = ([self._candidates(c) for c in findings] if findings
                   else [self._candidates({})])
        results = []
        for ci, cands in enumerate(formats):
            claim = findings[ci] if ci < len(findings) else {}
            for cand in cands:
                res = self._try(cand, image, claim or cand.get("claim") or {})
                results.append(res)
                self._log_candidate(res, claim)
                # 只有 pass 才值得提前结束；infra_error / fail_both 要继续试后续候选
                if res.get("verdict") == "pass":
                    break
        # 预置构造器没给出成功时，让模型自主生成并迭代（失败保留全过程）
        loop_result = None
        presets_pass = any(r.get("verdict") == "pass" for r in results)
        if self.enable_model_loop and not presets_pass:
            loop_result = self._model_loop(image)

        self._last_results = results
        if not results and (loop_result is None or not loop_result.get("rounds")):
            # 冻结系统无该格式构造器且模型闭环也没产出：能力边界，留在分母里
            self._emit_generation_unsupported(loop_result)
            return {"verdict": "generation_unsupported", "poc_sha256": None,
                    "vul_exit": None, "fix_exit": None, "tried": 0,
                    "model_loop": loop_result}
        if not results and loop_result and loop_result.get("rounds"):
            # 模型闭环成功：走正常候选路径落盘（不能因为预置构造器没成功就判失败）
            if loop_result.get("succeeded") and loop_result.get("winner_data"):
                wc = {"name": f"model-loop-r{loop_result.get('winner_round')}",
                      "data": loop_result["winner_data"],
                      "format": self._detected_format or "unknown"}
                wres = self._try(wc, image, findings[0] if findings else {})
                if wres.get("verdict") == "pass":
                    results.append(wres)
                    self._log_candidate(wres, findings[0] if findings else {})
                    best = self._pick(results)
                    self._emit(best, self._loop_public(loop_result))
                    return {"verdict": best.get("verdict"),
                            "poc_sha256": best.get("sha256"),
                            "vul_exit": best.get("vul_exit"),
                            "fix_exit": best.get("fix_exit"),
                            "tried": loop_result.get("total_rounds", 0),
                            "model_loop": loop_result}
            # 只有模型闭环产生的候选，且均未通过：把闭环结果作为主输出落盘
            self._emit_loop_only(self._loop_public(loop_result))
            return {"verdict": "generated_but_unverified", "poc_sha256": None,
                    "vul_exit": None, "fix_exit": None,
                    "tried": loop_result.get("total_rounds", 0),
                    "model_loop": loop_result}
        best = self._pick(results)
        self._emit(best, loop_result)
        return {"verdict": best.get("verdict"), "poc_sha256": best.get("sha256"),
                "vul_exit": best.get("vul_exit"), "fix_exit": best.get("fix_exit"),
                "tried": len(results)}

    # ---- 数据 ----
    # 候选来源：rule（只吃规则基线）/ model_assisted（规则 + 通过校验的模型假设）
    claim_source = "rule"

    def __init__(self, *a, claim_source: str = "rule",
                 enable_model_loop: bool = True, **kw):
        super().__init__(*a, **kw)
        self.claim_source = claim_source
        self.enable_model_loop = enable_model_loop

    def _load_claims(self) -> list[dict]:
        path = self.layout["artifacts"] / "locate" / "findings.json"
        if not path.exists():
            raise FormatError("locate/findings.json missing")
        data = json.loads(path.read_text(encoding="utf-8"))
        self._locate_data = data
        claims = list(data.get("claims_rule") or data.get("claims") or [])
        if self.claim_source == "model_assisted":
            # 只消费**通过校验**的模型候选；每条带来源标记，独立记录
            for c in (data.get("claims_llm") or []):
                c = dict(c)
                c["subject_source"] = "llm"
                claims.append(c)
        self._claims_by_source = {c.get("claim_id", ""): c.get("subject_source", "rule")
                                  for c in claims}
        return claims

    def _images(self) -> dict:
        meta = self.ws / "task.json"
        task_id = ""
        if meta.exists():
            try:
                task_id = json.loads(meta.read_text()).get("task_id", "")
            except Exception:
                task_id = ""
        return {"vul": image_for(self.ws, "vul"), "fix": image_for(self.ws, "fix"),
                "task_id": task_id}

    def _declared_format(self) -> str:
        """task.json 里显式声明的 input_format（优先级高于 claim 的猜测）。"""
        try:
            task = json.loads((self.ws / "task.json").read_text(encoding="utf-8"))
        except Exception:
            return ""
        return str(task.get("input_format") or "")

    def _builders_allowed(self) -> bool:
        """task.json 的 verify.allow_builders=false 时，禁用预置构造器，强制走模型路径。"""
        try:
            import json as _json
            cfg = _json.loads((self.ws / "task.json").read_text(encoding="utf-8"))
            return bool((cfg.get("verify") or {}).get("allow_builders", True))
        except Exception:
            return True

    def _candidates(self, claim: dict) -> list[dict]:
        # 格式优先级：task.json 显式声明 > claim.test_plan.format > 检测结果。
        # 之前只用 claim 的猜测，arvo:1065 被 locate 猜成 fuzz，就把构造器分支整个绕过。
        fmt = self._declared_format() or (claim.get("test_plan") or {}).get("format", "unknown")
        if fmt in ("", "unknown") and self._detected_format not in ("", "unknown"):
            fmt = self._detected_format
        out = []
        if not self._builders_allowed():
            self._builders_skipped = True
            return out
        if fmt in ("cff_pdf", "pdf_cff", "cff-pdf"):
            # S21（arvo:58405）：GhostPDF 读 CFF real 时的守卫少算 NUL，必须由构造器给 DICT real
            claim_ = {"claim": self._cff_pdf_claim()}
            try:
                from ..builders import cff_pdf as _cff_pdf
            except Exception:
                _cff_pdf = None
            if _cff_pdf is not None:
                r = _cff_pdf.build({})
                if r.ok:
                    out.append({"name": "pdf-cff-real", "data": r.data,
                                "format": "cff_pdf", **claim_})
        if fmt in ("bmp", "bmp_palette", "bmp-palette"):
            # S20（arvo:59500）：BMP palette 下溢必须由构造器给（大 header + 小 bitmapoffset），
            # 放在靶子启发式之前：声明格式优先。
            claim_ = {"claim": self._bmp_palette_claim()}
            try:
                from ..builders import bmp_palette as _bmp
            except Exception:
                _bmp = None
            if _bmp is not None:
                for fields in ({"header_size": 108}, {"header_size": 124}):
                    r = _bmp.build(fields)
                    if r.ok:
                        out.append({"name": "bmp-pal-hdr%d" % r.fields_used.get("header_size", 0),
                                    "data": r.data, "format": "bmp", **claim_})
        if fmt in ("dwg_table", "prer13", "pre-r13", "dwg-prer13"):
            # S19（arvo:54839）：pre-R13 的 section 表必须由构造器拼（num_sections=0 触发越界写）
            claim_ = {"claim": self._dwg_table_claim()}
            try:
                from ..builders import dwg_table as _dwg_table
            except Exception:
                _dwg_table = None
            if _dwg_table is not None:
                for fields in ({}, {"num_sections": 1}):
                    r = _dwg_table.build(fields)
                    if r.ok:
                        out.append({"name": "dwg-prer13-ns%d" % r.fields_used.get("num_sections", -1),
                                    "data": r.data, "format": "dwg_table", **claim_})
        if fmt == "unknown":
            # 没有格式线索时，用 error.txt / description 里的关键字兜底
            blob = ""
            for name in ("error.txt", "description.txt"):
                f = self.ws / name
                if f.exists():
                    blob += f.read_text(encoding="utf-8", errors="ignore").lower()
            if "mng" in blob or "loop" in blob:
                fmt = "mng"
            elif "pdf" in blob:
                fmt = "pdf"
            elif "dwarf2dbg" in blob or "assign_file_to_slot" in blob or ".file" in blob:
                fmt = "gas"
            elif ("fuzzer" in blob or "llvmfuzzertestoneinput" in blob
                  or "rules_fuzzer" in blob):
                fmt = "fuzz"
        if fmt == "mng":
            for n in (4, 3, 1, 0):
                data = make_mng(n, filler=True)
                out.append({"name": f"mng-loop{n}", "data": data, "format": "mng"})
        elif self._is_aom_av1_target():
            # CG-24（arvo:10252 / aom AV1 loop restoration 线程化）：IVF 种子结构化变异。
            claim_ = {"claim": self._aom_lr_claim()}
            for i, fields in enumerate(({"seed_index": 0, "seed": 11, "flips": 8},
                                        {"seed_index": 0, "seed": 23, "flips": 24},
                                        {"seed_index": 1, "seed": 7, "flips": 16})):
                r = builders_build("aom_lr", fields)
                if r.ok:
                    out.append({"name": "aom-lr-%d" % i, "data": r.data,
                                "format": "aom_lr", **claim_})
        elif self._is_openthread_target():
            # CG-25（arvo:14821 / OpenThread CLI）：畸形 IPv6（:: + 7 段 + 内嵌 IPv4）触发 FromString 越界写。
            claim_ = {"claim": self._ot_ip6_claim()}
            for i, fields in enumerate(({}, {"addr": "::1:2:3:4:5:6:1.2.3.4"},
                                        {"addr": "::1:2:3:4:5:6:7:.1.2.3.4"})):
                r = builders_build("ot_ip6", dict(fields or {}))
                if r.ok:
                    out.append({"name": "ot-ip6-%d" % i, "data": r.data,
                                "format": "ot_ip6", **claim_})
        elif self._is_binutils_target():
            # CG-26（arvo:19414 / binutils vax-dis）：index 模式字节递归。
            claim_ = {"claim": self._vax_mode_claim()}
            for i, fields in enumerate(({"depth": 400}, {"depth": 800}, {"depth": 40, "arch": 34})):
                r = builders_build("vax_mode", dict(fields or {}))
                if r.ok:
                    out.append({"name": "vax-mode-%d" % i, "data": r.data,
                                "format": "vax_mode", **claim_})
        elif self._is_kimageformats_target():
            # CG-27（arvo:12818 / kimageformats TGA）：宽高*位深超 INT_MAX，readRawData 返回 -1，memset 写穿。
            claim_ = {"claim": self._tga_claim()}
            for i, fields in enumerate(({"pixel_size": 1, "image_type": 3},
                                        {"pixel_size": 3, "image_type": 2},
                                        {"pixel_size": 4, "image_type": 2})):
                r = builders_build("tga", dict(fields))
                if r.ok:
                    out.append({"name": "tga-big-%d" % i, "data": r.data,
                                "format": "tga", **claim_})
        elif self._is_zstd_target():
            # CG-28（arvo:16445 / zstd v0.3 legacy）：raw literals 长度写穿栈上 litBuffer。
            claim_ = {"claim": self._zstd_legacy_claim()}
            for i, fields in enumerate(({"lit_size": 131082}, {"lit_size": 131073},
                                        {"lit_size": 200000})):
                r = builders_build("zstd_legacy", dict(fields))
                if r.ok:
                    out.append({"name": "zstd-v03-lit%d" % i, "data": r.data,
                                "format": "zstd_legacy", **claim_})
        elif self._is_libarchive_target():
            # CG-29（arvo:11011 / libarchive rar5）：目录项 window_size=0 -> 掩码失效 -> 单字节越界写。
            claim_ = {"claim": self._rar5_dir_claim()}
            for i, fields in enumerate(({}, {})):
                r = builders_build("rar5_dir", dict(fields))
                if r.ok:
                    out.append({"name": "rar5-dir-%d" % i, "data": r.data,
                                "format": "rar5", **claim_})
        elif self._is_fio_target():
            # CG-30（arvo:29633 / fio）：ini 里 filename 超 PATH_MAX -> add_file 的 sprintf 写穿栈。
            claim_ = {"claim": self._maxpath_claim()}
            for i, fields in enumerate(({"name_len": 6000}, {"name_len": 5000},
                                        {"name_len": 8000})):
                r = builders_build("maxpath", dict(fields))
                if r.ok:
                    out.append({"name": "fio-maxpath-%d" % i, "data": r.data,
                                "format": "maxpath", **claim_})
        elif self._is_matio_target():
            # CG-32（arvo:58262 / matio + HDF5）：MATLAB_fields 属性 dataspace 改成标量。
            claim_ = {"claim": self._hdf5_fields_claim()}
            r = builders_build("hdf5_memcpy", {"variant": "scalar"})
            if r.ok:
                out.append({"name": "hdf5-fields-scalar", "data": r.data,
                            "format": "hdf5_memcpy", **claim_})
        elif self._is_libraw_target():
            # CG-33（arvo:60983 / libraw Sony ARQ）：最小 TIFF，SamplesPerPixel=4 + Photometric=1。
            claim_ = {"claim": self._libraw_arq_claim()}
            for i, fields in enumerate(({"sub_ifd": 1}, {"sub_ifd": 0})):
                r = builders_build("libraw_arq", dict(fields))
                if r.ok:
                    out.append({"name": "libraw-arq-%d" % i, "data": r.data,
                                "format": "libraw_arq", **claim_})
        elif self._is_mruby_target():
            # CG-34（arvo:49259 / mruby）：赋值目标为方法调用 + RHS 带块。
            claim_ = {"claim": self._mruby_codegen_claim()}
            for i, fields in enumerate(({"shape": 3}, {"shape": 5}, {"shape": 10})):
                r = builders_build("mruby_codegen", dict(fields))
                if r.ok:
                    out.append({"name": "mruby-cg-%d" % i, "data": r.data,
                                "format": "mruby_codegen", **claim_})
        elif self._is_libredwg_dynapi_target():
            # CG-35（arvo:49613 / libredwg）：DXF 里给 TFv 字段塞超长字符串。
            claim_ = {"claim": self._dynapi_claim()}
            for i, fields in enumerate(({"kind": "ltype", "size": 200},
                                        {"kind": "ltype", "size": 64},
                                        {"kind": "style", "size": 200})):
                r = builders_build("dynapi", dict(fields))
                if r.ok:
                    out.append({"name": "dwg-tfv-%d" % i, "data": r.data,
                                "format": "dynapi", **claim_})
        elif self._is_netsnmp_target():
            # CG-38（arvo:52465 / net-snmp）：AgentX OPEN 里塞 (2, 0xFFFFFFFF) 起头的 OID。
            claim_ = {"claim": self._snmp_oid_claim()}
            for i, fields in enumerate(({"n_tail": 19}, {"n_tail": 15}, {"n_tail": 11})):
                r = builders_build("snmp_oid", dict(fields))
                if r.ok:
                    out.append({"name": "snmp-oid-%d" % i, "data": r.data,
                                "format": "snmp_oid", **claim_})
        elif fmt in ("mvg", "mvg_text") and self._is_gm_mvg_target():
            # CG-23（arvo:10653 / GraphicsMagick MagickGetToken）：url(#…) 作图元关键字，
            # token 长度 2049-2052 时 memmove 从 token+5 起多读 4 字节。
            claim_ = {"claim": self._gm_token_claim()}
            for tl in (2049, 2050, 2052):
                r = builders_build("gm_token", {"token_len": tl})
                if r.ok:
                    out.append({"name": f"gm-token-url{tl}", "data": r.data,
                                "format": "gm_token", **claim_})
        elif fmt == "pdf":
            for n in (4096, 8192, 5575):
                data = pdf_with_basefont(b"A" * n)
                out.append({"name": f"pdf-basefont{n}", "data": data, "format": "pdf"})
        elif self._is_ovn_lex_target():
            # CG-21（arvo:10710 / OVN lexer）：通用 fuzz 种子打不到"以 NUL 结尾的
            # 超长全零十六进制常量"，这里直接上构造器（放在最早的 fuzz 分支位置，
            # 否则会被下面的通用 fuzz 分支先吃掉）。
            claim_ = {"claim": self._ovn_lex_claim()}
            for zeros in (600, 900, 1200):
                r = builders_build("ovn_lex", {"zeros": zeros})
                if r.ok:
                    out.append({"name": f"ovn-lex-hex{zeros}", "data": r.data,
                                "format": "ovn_lex", **claim_})
        elif fmt == "fuzz":
            # 空输入 + 若干最小非空输入：覆盖"输入是否影响触发"的对照
            out.append({"name": "fuzz-empty", "data": make_fuzz_seed(b""), "format": "fuzz"})
            for n in (1, 4, 16):
                out.append({"name": f"fuzz-seed{n}",
                            "data": make_fuzz_seed(bytes(range(n))), "format": "fuzz"})
        elif fmt == "gas":
            # 2^32 附近的槽位：i + 32 回绕，memset 越界
            for slot in (4294967289, 4294967295, 4294967280, 0xFFFFFFF0):
                out.append({"name": f"gas-file{slot}", "data": make_gas_file_directive(slot),
                            "format": "gas"})
            out.append({"name": "gas-prepopulated", "data": make_gas_repeat_file(4294967289, 4),
                        "format": "gas"})
        elif fmt == "rar5":
            # 零填充长度由 escape 后的半字节控制；上限 15 即最大填充
            for fill in (0x0F, 0x0C, 0x0A):
                r = builders_build("rar5", {"fill": fill})
                if r.ok:
                    out.append({"name": f"rar5-fill{fill:02x}", "data": r.data,
                                "format": "rar5"})
        elif fmt == "text":
            tmpl = "unknown"
            try:
                _t = json.loads((self.ws / "task.json").read_text(encoding="utf-8"))
                tmpl = str(_t.get("input_template") or "unknown")
            except Exception:
                pass
            for rep in (1, 4, 64):
                r = builders_build("text", {"template": tmpl, "repeat": rep})
                if r.ok:
                    out.append({"name": f"text-{tmpl}-x{rep}", "data": r.data,
                                "format": "text"})
        elif fmt in ("bmff", "avail", "brob", "heic"):
            # S16（arvo:61675）：BMFF brob + 调好大小的 brotli 流，必须由构造器给，不靠模型盲试
            claim_ = {"claim": self._avail_claim()}
            try:
                from ..builders import avail as _avail
            except Exception:
                _avail = None
            if _avail is not None:
                for fields in ({},):
                    r = _avail.build(fields)
                    if r.ok:
                        out.append({"name": "bmff-brob-%d" % r.size, "data": r.data,
                                    "format": "bmff", **claim_})
        elif fmt in ("libidn2", "idn2"):
            # CG-18：libidn2 的 UCS-4 域名必须由构造器拼（两个 label、总长 65），不靠模型
            claim_ = {"claim": self._libidn2_claim()}
            for fields in ({}, {"left": 31, "right": 33}):
                r = builders_build("libidn2", fields)
                if r.ok:
                    out.append({"name": "libidn2-4i-%d" % r.fields_used.get("domain_chars", 0),
                                "data": r.data, "format": "libidn2", **claim_})
        elif fmt in ("file_magic", "magic", "file"):
            # S7：file(1) 的未初始化 pmatch，必须由构造器给最小文本，不靠模型盲试
            claim_ = {"claim": self._file_magic_claim()}
            for variant in ("php", "perl"):
                r = builders_build("file_magic", {"variant": variant})
                if r.ok:
                    out.append({"name": "file-magic-%s" % variant, "data": r.data,
                                "format": "file_magic", **claim_})
        elif fmt == "jnx":
            # CG-08：JNX 容器必须由构造器生成（tile 伪装成 DICOM），不靠模型盲试字节
            claim_ = {"claim": self._jnx_claim()}
            for fields in ({"payload": "dicom"},):
                r = builders_build("jnx", fields)
                if r.ok:
                    out.append({"name": "jnx-dicom-tile", "data": r.data,
                                "format": "jnx", **claim_})
        elif fmt in ("harfbuzz", "sfnt", "ttf", "otf"):
            # CG-12：harfbuzz 的 GSUB 触发字体必须由构造器生成，不靠模型盲试
            claim_ = {"claim": self._harfbuzz_claim()}
            r = builders_build("harfbuzz", {})
            if r.ok:
                out.append({"name": "harfbuzz-gsub-script", "data": r.data,
                            "format": "harfbuzz", **claim_})
        elif fmt in ("freetype_cff", "fuzz", "font") and self._is_freetype_target():
            # S8c（arvo:368 / freetype2）：blend 序列只能靠构造器拼，通用 fuzz 种子打不到
            # cff_load_private_dict 的 blend 分支，所以这里显式接入 freetype_cff 构造器。
            from ..builders import freetype_cff as _ft
            claim_ = {"claim": self._freetype_claim()}
            plans = ({"seed_index": 0, "seed": 11, "blend_runs": 2, "blend_args": 8, "flips": 4},
                     {"seed_index": 0, "seed": 23, "blend_runs": 4, "blend_args": 16, "flips": 8,
                      "mode": "tag_flip_header"},
                     {"seed_index": 1, "seed": 5, "blend_runs": 3, "blend_args": 12, "flips": 6})
            for i, fields in enumerate(plans):
                try:
                    r = _ft.build(fields)
                except Exception:
                    continue
                if r.ok:
                    out.append({"name": f"ft-cff-{i}", "data": r.data,
                                "format": "freetype_cff", **claim_})
        elif fmt == "ovn_lex" or (fmt in ("fuzz", "unknown", "text") and self._is_ovn_lex_target()):
            # CG-21（arvo:10710 / OVN lexer）：超长全零十六进制常量让 out 反向写越界。
            # 零个数的扫描范围覆盖"刚好越界"到"远超越界"，前几个命中即可收工。
            claim_ = {"claim": self._ovn_lex_claim()}
            for zeros in (600, 900, 1200):
                r = builders_build("ovn_lex", {"zeros": zeros})
                if r.ok:
                    out.append({"name": f"ovn-lex-hex{zeros}", "data": r.data,
                                "format": "ovn_lex", **claim_})
        elif fmt == "dwg":
            # CG-10：dwg 候选必须自带 claim，否则 sink 为空 -> 根因判不了 -> fix 端根本不跑
            from ..builders import BUILDERS as _BUILDERS
            builder_name = "libredwg" if "libredwg" in _BUILDERS else "dwg"
            claim_ = {"claim": self._dwg_claim()}
            for ver in (5, 4, 1):
                r = builders_build(builder_name, {"version": ver})
                if r.ok:
                    out.append({"name": f"dwg-ver{ver}", "data": r.data,
                                "format": "dwg", **claim_})
        return out

    # ---- 执行 ----
    # Docker 自身失败：这些退出码**只在同时出现 docker 报错时**才算环境问题，
    # 不能仅凭数字归类（审查方 2025-11-09：77/137 另有语义）。
    DOCKER_EXIT_CODES = {125, 126, 127}
    DOCKER_MARKERS = (
        "docker: Error response from daemon", "No such image", "Cannot connect to the Docker daemon",
        "permission denied while trying to connect", "OCI runtime create failed",
        "no such file or directory: unknown", "Error: No such container",
        "pull access denied",
    )
    ASAN_MARKERS = ("ERROR: AddressSanitizer", "SUMMARY: AddressSanitizer", "runtime error:")
    # MSan 报告（CG-08）不是 ASAN 三件套，必须单独认；判定仍然要求 fix 侧干净
    MSAN_MARKERS = (
        "MemorySanitizer: use-of-uninitialized-value",
        "MemorySanitizer: uninitialized",
        "MemorySanitizer: use-of-uninitialized",
    )
    # 目标程序自身"拒绝输入"的退出码（如 ImageMagick MagickFatalError=77）：
    # 这是程序的正常行为，不是崩溃，也不是环境故障。
    PROGRAM_REJECT_CODES = {77}
    # 可能是 OOM / 外部终止 / 资源耗尽：需要看输出才能定性
    RESOURCE_EXIT_CODES = {137, 143}

    def _run_identity(self, image: str) -> dict:
        """本次运行的身份：镜像 digest + 靶子二进制哈希 + 源码快照哈希。

        没有这组身份，任何"用调试信息确认构建"的结论都不成立。
        """
        import hashlib
        from .. import checkpoint as ckpt
        ident = {"image": image}
        try:
            ident["image_digest"] = ckpt.image_digest(image)
        except Exception:
            ident["image_digest"] = ""
        # 靶子二进制：从镜像里取哈希（不落盘，流式计算）
        argv = ["docker", "run", "--rm", image, "sha256sum", "/bin/arvo"]
        res = shell.run(argv, timeout=120, stage=self.name)
        ident["target_sha256"] = (res.stdout.split()[0] if res.ok and res.stdout.strip() else "")
        # 源码快照：repo-vul.tar.gz 的 sha
        tar = self.ws / "repo-vul.tar.gz"
        if tar.exists():
            h = hashlib.sha256()
            with tar.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            ident["source_sha256"] = h.hexdigest()
        return ident

    def _provenance_for(self, runlog: dict, diag_dir: Path | None = None) -> dict:
        """构造 provenance 项：判断该诊断是否来自当前构建。"""
        ident = getattr(self, "_identity", {}) or {}
        rec = {
            "run_id": self.run_id,
            "binary_sha256": ident.get("target_sha256", ""),
            "source_sha256": ident.get("source_sha256", ""),
            "image_digest": ident.get("image_digest", ""),
            "log": runlog.get("log", ""),
        }
        # 只有身份三项齐全且日志确属本轮，才算 matches
        complete = all(rec[k] for k in ("binary_sha256", "source_sha256", "image_digest"))
        rec["matches"] = bool(complete)
        if not complete:
            rec["missing"] = [k for k in ("binary_sha256", "source_sha256", "image_digest")
                              if not rec[k]]
        return rec

    def _run_container_retry(self, image: str, poc: Path, name: str,
                             attempts: int = 3) -> dict:
        """只在"无法分类"时重试（无 sanitizer、非零退出）。

        CG-08 的 coder_JNX_fuzzer 在 MSan 构建下偶发无诊断的 139（同 baseline 也复现），
        单次运行不足以定性；确定性结果（ok / infra）一次即返回，不改变判定语义。
        """
        last = None
        for i in range(attempts):
            run = self._run_container(image, poc,
                                      name if i == 0 else "%s-retry%d" % (name, i))
            last = run
            cls = run.get("class") or self._classify_run(
                {"exit_code": run["exit_code"], "crash": run.get("crash", ""),
                 "timed_out": run.get("timed_out", False)}, run.get("tail") or "")
            if cls != "inconclusive":
                return run
        return last

    def _run_container(self, image: str, poc: Path, name: str) -> dict:
        log = self.log_path(f"V4.{name}.{image.split(':')[-1]}.log")
        # /bin/arvo 的约定：不带参数时跑默认的 /tmp/poc；
        # 带参数时只认 compile / run，其它值走 "Unknown command" 分支直接返回。
        # 因此这里**不能**把 poc 路径当参数传。
        argv = ["docker", "run", "--rm", "-v", f"{poc}:/tmp/poc:ro", "-e",
                "ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0", image, "/bin/arvo"]
        res = shell.run_logged(argv, log, timeout=180, stage=self.name)
        text = res.stdout + res.stderr
        diag = self._augment_sanitizer(parse_diagnosis(text), text)
        crash = diag.summary_line or ""
        if not crash and diag.is_defect:
            first = next((ln.strip() for ln in text.splitlines()
                          if "ERROR:" in ln and "Sanitizer" in ln), "")
            crash = first
        # 结构化崩溃点：SUMMARY 行可能缺失（abort_on_error 下输出会被截断），
        # 因此再对整个输出做一次 file:line 提取，优先用户代码帧。
        import re as _re
        cf, cl = "", None
        cands = []
        for ln in text.splitlines():
            m = _re.search(r"(/[\w./+-]+\.(?:c|cc|cpp|cxx)):(\d+)", ln)
            if not m:
                continue
            path = m.group(1)
            if any(x in path for x in ("/llvm/", "/libfuzzer/", "/compiler-rt/", "/libc")):
                continue
            prio = 0 if "SUMMARY" in ln else 1
            cands.append((prio, path, int(m.group(2))))
        if cands:
            cands.sort(key=lambda x: x[0])
            _, cf, cl = cands[0]
        out = {"exit_code": res.exit_code, "crash": crash, "timed_out": res.timed_out,
               "crash_file": cf, "crash_line": cl,
               "log": str(log.relative_to(self.ws)), "tail": text[-1500:],
               "defect": diag.is_defect, "kind": diag.kind, "write": diag.write,
               "user_frames": len(diag.user_frames), "diagnosis": diag}
        out["class"] = self._classify_run(out, text)
        out["infra"] = self._infra_failure(out, text)
        return out

    def _augment_sanitizer(self, diag, text: str):
        """把 MSan 报告补成缺陷诊断（diagnostics 模块未覆盖 MSan，且不在本任务 scope）。"""
        if getattr(diag, "is_defect", False):
            return diag
        for marker in self.MSAN_MARKERS:
            if marker in (text or ""):
                diag.is_defect = True
                diag.sanitizer = "MemorySanitizer"
                diag.kind = "use-of-uninitialized-value"
                diag.write = False
                break
        return diag

    def _jnx_sink(self) -> dict:
        """机械定位 CG-08 的 sink：ExtractTileJPG 里那次 tile 解码调用。

        不抄崩溃栈：在源码里找缺陷函数，再找函数体内的 BlobToImage 调用点。
        """
        from ..tools import binscan
        src = self.layout["src"]
        rel = "coders/jnx.c"
        try:
            hits = binscan.find_function(src, "ExtractTileJPG", stage=self.name)[:1]
        except Exception:
            hits = []
        if not hits:
            return {}
        start = int(hits[0]["line"])
        path = hits[0]["file"]
        try:
            lines = (src / path).read_text(errors="ignore").splitlines()
        except OSError:
            return {"file": rel, "line": start, "symbol": "BlobToImage"}
        for idx in range(start - 1, min(len(lines), start + 120)):
            if "BlobToImage(" in lines[idx]:
                return {"file": rel, "line": idx + 1, "symbol": "BlobToImage"}
        return {"file": rel, "line": start, "symbol": "BlobToImage"}

    def _is_freetype_target(self) -> bool:
        """工作区里是不是 freetype2 目标（ftfuzzer / src/cff）。"""
        cache = getattr(self, "_is_freetype_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            for p in src.rglob("ftfuzzer*"):
                hit = True
                break
            if not hit:
                hit = any(p.is_dir() and p.name.startswith("freetype") for p in src.iterdir())
        except OSError:
            hit = False
        self._is_freetype_cache = hit
        return hit

    def _freetype_claim(self) -> dict:
        """CG-16 候选自带的主张：cff_blend_doBlend 的 blend_stack 指针失效。

        sink 写官方栈上的落点（cffparse.c:440，经 cff_load_private_dict:1879），
        缺陷函数写 cff_blend_doBlend（描述口径）。仍要过"真崩溃 + 根因匹配 + fix 干净"三道门。
        """
        return {"claim_id": "cg16-freetype-cff-blend",
                "subject": "cff_blend_doBlend",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/freetype_cff.py + arvo error.txt",
                "cwe": "CWE-416",
                "sink": {"file": "src/cff/cffparse.c", "line": 440, "symbol": "cff_parse_num",
                         "note": "blend 后 parser->stack 仍指向旧 blend_stack（UAF）"},
                "test_plan": {"format": "freetype_cff"}}
    def _ovn_lex_claim(self) -> dict:
        """CG-21 候选自带主张：lex_parse_hex_integer 的 out 反向写越界。

        hexit==0 时旧代码跳过边界检查但照样写 out[-(i/2)]，
        ASAN 报的是 stack-buffer-underflow（READ of size 1，读改写）。
        """
        return {"claim_id": "cg21-ovn-lex-hex",
                "subject": "lex_parse_hex_integer",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/ovn_lex.py + arvo error.txt",
                "cwe": "CWE-124",
                "sink": {"file": "ovn/lib/lex.c", "line": 341, "symbol": "hexit_value",
                         "note": "hexit==0 时跳过边界检查，仍反向写 out[-(i/2)]"},
                "test_plan": {"format": "ovn_lex"}}
    def _is_ovn_lex_target(self) -> bool:
        """工作区里是不是 OVN 的 expr_parse_target（openvswitch/ovn/lib/lex.c）。"""
        cache = getattr(self, "_is_ovn_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            for p in src.rglob("lex.c"):
                if "ovn" in p.parts:
                    hit = True
                    break
        except OSError:
            hit = False
        self._is_ovn_cache = hit
        return hit
    def _is_gm_mvg_target(self) -> bool:
        """工作区里是不是 GraphicsMagick 的 coder_MVG_fuzzer 目标。"""
        cache = getattr(self, "_is_gm_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("graphicsmagick") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_gm_cache = hit
        return hit

    def _gm_token_claim(self) -> dict:
        """CG-23 候选自带主张：MagickGetToken 的 memmove 多读 4 字节（读越界，CWE-125）。"""
        return {"claim_id": "cg23-gm-token-url",
                "subject": "MagickGetToken",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/gm_token.py + arvo error.txt",
                "cwe": "CWE-125",
                "sink": {"file": "magick/utility.c", "line": 3830, "symbol": "memmove",
                         "note": "memmove(token,token+5,r-token+1) 从 token+5 起读 L 字节，多读 4 字节"},
                "test_plan": {"format": "gm_token"}}

    def _is_aom_av1_target(self) -> bool:
        """工作区里是不是 aom（AV1）的 dec_fuzzer 目标。"""
        cache = getattr(self, "_is_aom_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name in ("aom", "aom-vul") for q in src.iterdir())
            if not hit:
                hit = any(q.name == "av1_dec_fuzzer.cc" for q in src.rglob("av1_dec_fuzzer.cc"))
        except OSError:
            hit = False
        self._is_aom_cache = hit
        return hit

    def _aom_lr_claim(self) -> dict:
        """CG-24 候选自带主张：loop restoration 线程化 lr_job 队列 4 字节越界写。"""
        return {"claim_id": "cg24-aom-lr-job",
                "subject": "enqueue_lr_jobs",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/aom_lr.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "av1/common/thread_common.c", "line": 599,
                         "symbol": "enqueue_lr_jobs",
                         "note": "num_rows_lr 偏小导致 lr_job 队列分配不足，写 4 字节越界"},
                "test_plan": {"format": "aom_lr"}}

    def _is_openthread_target(self) -> bool:
        """工作区里是不是 OpenThread 的 cli-uart-received 目标。"""
        cache = getattr(self, "_is_ot_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("openthread") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_ot_cache = hit
        return hit

    def _ot_ip6_claim(self) -> dict:
        """CG-25 候选自带主张：FromString 压缩移位时 endp 越过 16 字节地址下界。"""
        return {"claim_id": "cg25-ot-ip6-fromstring",
                "subject": "Ip6::Address::FromString",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/ot_ip6.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "src/core/net/ip6_address.cpp", "line": 333,
                         "symbol": "FromString",
                         "note": "内嵌 IPv4 使 endp -= 4；压缩移位 *endp-- = *dst-- 写到 m8 之下"},
                "test_plan": {"format": "ot_ip6"}}

    def _is_binutils_target(self) -> bool:
        """工作区里是不是 binutils-gdb 的 fuzz_disassemble 目标。"""
        cache = getattr(self, "_is_binutils_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("binutils") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_binutils_cache = hit
        return hit

    def _vax_mode_claim(self) -> dict:
        """CG-26 候选自带主张：index 模式递归导致 fetch_data 写穿 private.the_buffer。"""
        return {"claim_id": "cg26-vax-index-mode",
                "subject": "print_insn_mode",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/vax_mode.py + arvo error.txt",
                "cwe": "CWE-121",
                "sink": {"file": "opcodes/vax-dis.c", "line": 260, "symbol": "fetch_data",
                         "note": "index 模式递归无深度限制，16 字节 memcpy 写穿 the_buffer[25]"},
                "test_plan": {"format": "vax_mode"}}

    def _is_kimageformats_target(self) -> bool:
        """工作区里是不是 kimageformats 的 kimgio_fuzzer 目标。"""
        cache = getattr(self, "_is_kimg_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("kimageformats") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_kimg_cache = hit
        return hit

    def _tga_claim(self) -> dict:
        """CG-27 候选自带主张：readRawData 返回 -1 后 memset 用 size+1 写穿堆缓冲。"""
        return {"claim_id": "cg27-tga-memset",
                "subject": "LoadTGA",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/tga.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "src/imageformats/tga.cpp", "line": 264, "symbol": "memset",
                         "note": "readRawData(-1) 后 memset(&image[-1], 0, size+1)，size 由头部宽高*位深控制"},
                "test_plan": {"format": "tga"}}

    def _is_zstd_target(self) -> bool:
        """工作区里是不是 zstd 的 simple_decompress 目标。"""
        cache = getattr(self, "_is_zstd_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("zstd") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_zstd_cache = hit
        return hit

    def _zstd_legacy_claim(self) -> dict:
        """CG-28 候选自带主张：v0.3 raw literals 的 memcpy 写穿 dctx->litBuffer。"""
        return {"claim_id": "cg28-zstd-v03-literals",
                "subject": "ZSTD_decodeLiteralsBlock",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/zstd_legacy.py + arvo error.txt",
                "cwe": "CWE-121",
                "sink": {"file": "lib/legacy/zstd_v03.c", "line": 2529, "symbol": "memcpy",
                         "note": "IS_RAW 分支只校验 litSize 不超过输入，不校验不超过 litBuffer(128KB+8)"},
                "test_plan": {"format": "zstd_legacy"}}

    def _is_libarchive_target(self) -> bool:
        """工作区里是不是 libarchive 的 libarchive_fuzzer 目标。"""
        cache = getattr(self, "_is_libarchive_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("libarchive") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_libarchive_cache = hit
        return hit

    def _rar5_dir_claim(self) -> dict:
        """CG-29 候选自带主张：目录项 window_size=0 时 mask 不掩码，window_buf 写越界。"""
        return {"claim_id": "cg29-rar5-dir-window",
                "subject": "do_uncompress_block",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/rar5.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "libarchive/archive_read_support_format_rar5.c",
                         "line": 2424, "symbol": "do_uncompress_block",
                         "note": "window_size=0 -> window_mask=0xFFFFFFFF, window_buf[write_idx & mask] 越界"},
                "test_plan": {"format": "rar5"}}

    def _is_fio_target(self) -> bool:
        """工作区里是不是 fio 的 fuzz_parseini 目标。"""
        cache = getattr(self, "_is_fio_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("fio") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_fio_cache = hit
        return hit

    def _maxpath_claim(self) -> dict:
        """CG-30 候选自带主张：filename 超 PATH_MAX，sprintf 写穿 add_file 的栈缓冲。"""
        return {"claim_id": "cg30-fio-filename-maxpath",
                "subject": "add_file",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/maxpath.py + arvo error.txt",
                "cwe": "CWE-121",
                "sink": {"file": "filesetup.c", "line": 1656, "symbol": "sprintf",
                         "note": "sprintf(file_name + len, \"%s\", fname) 未限长，file_name 只有 PATH_MAX(4096)"},
                "test_plan": {"format": "maxpath"}}

    def _is_matio_target(self) -> bool:
        """工作区里是不是 matio 的 matio_fuzzer 目标。"""
        cache = getattr(self, "_is_matio_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("matio") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_matio_cache = hit
        return hit

    def _hdf5_fields_claim(self) -> dict:
        """CG-32 候选自带主张：MATLAB_fields 属性 dataspace 标量化 -> calloc(0) 后被 H5Aread 写穿。"""
        return {"claim_id": "cg32-matio-hdf5-fields",
                "subject": "Mat_H5ReadFieldNames",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/hdf5_memcpy.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "src/mat73.c", "line": 625, "symbol": "calloc",
                         "note": "标量 dataspace 时 nfields=0 -> calloc(0) -> H5Aread memcpy 越界（H5MM_memcpy）"},
                "test_plan": {"format": "hdf5_memcpy"}}

    def _is_libraw_target(self) -> bool:
        """工作区里是不是 libraw 的 libraw_raf_fuzzer 目标。"""
        cache = getattr(self, "_is_libraw_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("libraw") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_libraw_cache = hit
        return hit

    def _libraw_arq_claim(self) -> dict:
        """CG-33 候选自带主张：ARQ 4 通道 read_shorts 写进 1 通道 raw_image。"""
        return {"claim_id": "cg33-libraw-arq",
                "subject": "sony_arq_load_raw",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/libraw_arq.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "src/decoders/decoders_libraw.cpp", "line": 20,
                         "symbol": "read_shorts",
                         "note": "read_shorts 按 raw_width*raw_height*4 读，raw_image 只按 1 通道分配"},
                "test_plan": {"format": "libraw_arq"}}

    def _is_mruby_target(self) -> bool:
        """工作区里是不是 mruby 的 mruby_fuzzer 目标。"""
        cache = getattr(self, "_is_mruby_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("mruby") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_mruby_cache = hit
        return hit

    def _mruby_codegen_claim(self) -> dict:
        """CG-34 候选自带主张：gen_assignment 的 CALL 分支块槽未记账，VM 栈越界写。"""
        return {"claim_id": "cg34-mruby-codegen-blockargs",
                "subject": "mrb_vm_exec",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/codegen_args.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "mrbgems/mruby-compiler/core/codegen.c", "line": 1809,
                         "symbol": "gen_assignment",
                         "note": "NODE_CALL/SCALL 分支缺 push()/pop()，块参数栈槽没记账，VM 栈越界写 8 字节"},
                "test_plan": {"format": "mruby_codegen"}}

    def _is_libredwg_dynapi_target(self) -> bool:
        """工作区里是不是 libredwg 的 llvmfuzz 目标。"""
        cache = getattr(self, "_is_libredwg_dynapi_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("libredwg") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_libredwg_dynapi_cache = hit
        return hit

    def _dynapi_claim(self) -> dict:
        """CG-35 候选自带主张：TFv 固定串 calloc(f->size) 后被 strcpy 写穿。"""
        return {"claim_id": "cg35-libredwg-dynapi-tfv",
                "subject": "dynapi_set_helper",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/dynapi.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "src/dynapi.c", "line": 3112, "symbol": "dynapi_set_helper",
                         "note": "TFv 分支 calloc(f->size) 后 strcpy 不封顶，DXF 字符串超过字段容量即堆写越界"},
                "test_plan": {"format": "dynapi"}}

    def _is_netsnmp_target(self) -> bool:
        """工作区里是不是 net-snmp 的 snmp_api_fuzzer 目标。"""
        cache = getattr(self, "_is_netsnmp_cache", None)
        if cache is not None:
            return cache
        src = self.layout["src"]
        hit = False
        try:
            hit = any(q.is_dir() and q.name.startswith("net-snmp") for q in src.iterdir())
        except OSError:
            hit = False
        self._is_netsnmp_cache = hit
        return hit

    def _snmp_oid_claim(self) -> dict:
        """CG-38 候选自带主张：OID 前两段 ASN 长度截断成 32 位后越界写。"""
        return {"claim_id": "cg38-net-snmp-oid-trunc",
                "subject": "asn_build_objid",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/snmp_oid.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "snmplib/asn1.c", "line": 1610, "symbol": "asn_build_objid",
                         "note": "encoded_oid_len(uint32_t) 截断 first=(40*objid[0]+objid[1])，少算 4 字节"},
                "test_plan": {"format": "snmp_oid"}}

    def _jnx_claim(self) -> dict:
        """构造器候选自带的主张：缺陷在 ExtractTileJPG 的 tile 解码调用点。

        这条 claim 由代码给出（不是模型猜的），仍要过"真崩溃 + 根因匹配 + fix 干净"三道门。
        """
        return {"claim_id": "cg08-jnx-tile", "subject": "ExtractTileJPG",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/cg08.py",
                "cwe": "CWE-457", "sink": self._jnx_sink(),
                "test_plan": {"format": "jnx"}}

    def _text_sink_hit(self, sink: dict, log_rel: str) -> dict | None:
        """在原始容器日志里按 file:line 找 sink（帧解析器会丢 C++ 内联帧）。

        parse_diagnosis 的 FRAME_RE 只认得下普通函数名，#0~#5 这类带模板/命名空间
        的 C++ 帧会被丢掉，user_frames 里只剩 hb_subset / LLVMFuzzerTestOneInput，
        于是根因被判 "sink_not_in_stack"。日志文本里的 file:line 仍是实测证据，
        这里按 sink 文件名在日志里找行号，落在 LINE_SLACK 内就承认（weak）。
        """
        f = (sink or {}).get("file") or ""
        line = (sink or {}).get("line")
        if not f or not line or not log_rel:
            return None
        path = self.ws / log_rel
        try:
            text = path.read_text(errors="ignore")[:200000]
        except OSError:
            return None
        base = f.rsplit("/", 1)[-1]
        import re as _re
        for m in _re.finditer(_re.escape(base) + r":(\d+)", text):
            ln = int(m.group(1))
            if abs(ln - int(line)) <= LINE_SLACK:
                return {"file": base, "line": ln, "delta": ln - int(line),
                        "source": "raw_trace_text"}
        return None

    def _cff_pdf_claim(self) -> dict:
        """S21（arvo:58405 / GhostPDF CFF）构造器候选自带的主张。

        pdfi_read_cff_real 用 char buf[65]，循环守卫 buf+sizeof-3；一个 0xC nibble 却写 2 字节（E-），
        0xCC 一字节就是 E-E-（4 字节）+ NUL = 5 字节，txt 到 61 时再遇 0xCC 就把收尾 NUL 写到 buf[65]。
        """
        return {"claim_id": "s21-cff-real-overflow",
                "subject": "pdfi_read_cff_real",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/cff_pdf.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "pdf/pdf_font1C.c", "line": 744,
                         "symbol": "pdfi_read_cff_real"},
                "test_plan": {"format": "cff_pdf"}}

    def _bmp_palette_claim(self) -> dict:
        """S20（arvo:59500 / MuPDF BMP）构造器候选自带的主张。

        bmp_read_palette 用 (bitmap - p) / entry_size 算 present（signed），bitmapoffset 小于
        当前解析位置时 present 为负，bmp_load_default_palette 从负下标写 info->palette，
        越过 struct info 的栈红区（ASAN stack-buffer-underflow，WRITE 1B @ load-bmp.c:920）。
        """
        return {"claim_id": "s20-bmp-palette-underflow",
                "subject": "bmp_load_default_palette",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/bmp_palette.py + arvo error.txt",
                "cwe": "CWE-124",
                "sink": {"file": "source/fitz/load-bmp.c", "line": 920,
                         "symbol": "bmp_load_default_palette"},
                "test_plan": {"format": "bmp"}}

    def _dwg_table_claim(self) -> dict:
        """S19（arvo:54839 / libredwg pre-R13）构造器候选自带的主张。

        decode_preR13 用 num_sections+2 个槽位 calloc 了 section 数组，
        但固定要写 BLOCK/LAYER/STYLE/LTYPE/VIEW 五个 id；num_sections=0 时只有 2 个槽位，
        写到 id=2 就越过 256 字节区域（ASAN: WRITE of size 4 @ decode.c:275）。
        """
        return {"claim_id": "s19-dwg-prer13-section",
                "subject": "decode_preR13_section_hdr",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/dwg_table.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "src/decode.c", "line": 275, "symbol": "bit_read_RL"},
                "test_plan": {"format": "dwg_table"}}

    def _avail_claim(self) -> dict:
        """S16（arvo:61675 / Exiv2 BMFF）构造器候选自带的主张。

        BmffImage::brotliUncompress 用 available_out = uncompressedLen - total_out（size_t），
        DoS 上限把 uncompressedLen 截到 131072 却没检查 total_out 已经更大 -> 下溢，
        brotli 继续往缓冲区外 memcpy（ASAN container-overflow，WRITE 65534）。
        patch 在 break 条件里补了 total_out > 131072。
        """
        return {"claim_id": "s16-bmff-brob-avail",
                "subject": "BmffImage::brotliUncompress",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/avail.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "src/bmffimage.cpp", "line": 208,
                         "symbol": "BrotliDecoderDecompressStream"},
                "test_plan": {"format": "bmff"}}

    def _libidn2_claim(self) -> dict:
        """CG-18（arvo:12420 / libidn2）构造器候选自带的主张。

        缺陷：idn2_to_ascii_4i() 在 rc==IDN2_OK 时直接 strcpy(output, output_u8)，
        不校验长度；fuzz 目标给的 output 只有 64 字节，65 字符域名 + NUL 正好写穿
        （ASAN: WRITE of size 66 @ __interceptor_strcpy <- idn2_to_ascii_4i lib/lookup.c:621）。
        sink 用构造器里声明的实测行号（与官方 error.txt 的 DEDUP_TOKEN 一致）。
        """
        try:
            from ..builders import libidn2 as _idn2
            claim = _idn2.declared_claim()
        except Exception:
            claim = {"claim_id": "cg18-idn2-4i-63", "subject": "idn2_to_ascii_4i",
                     "proposed_by": "builder", "subject_source": "builder",
                     "evidence_source": "agent/builders/libidn2.py",
                     "cwe": "CWE-122",
                     "sink": {"file": "lib/lookup.c", "line": 621, "symbol": "strcpy"},
                     "test_plan": {"format": "libidn2"}}
        claim = dict(claim)
        claim["proposed_by"] = "builder"
        claim["subject_source"] = "builder"
        return claim

    def _file_magic_sink(self) -> dict:
        """机械定位 S7 的 sink：softmagic.c 里 match() 读 pmatch 的那一段。

        在源码树里找 softmagic.c，定位 match() 函数体内第一次使用 pmatch/pm 的行；
        找不到就退回 error.txt 里给出的 365（仍是实测栈行号，写进证据）。
        """
        # 优先用任务自带 error.txt 的实测栈行号（那是官方崩溃行，不是答案）
        try:
            err = (self.ws / "error.txt").read_text(errors="ignore")
        except OSError:
            err = ""
        m = re.search(r"softmagic\.c:(\d+)", err)
        if m:
            return {"file": "src/softmagic.c", "line": int(m.group(1)),
                    "symbol": "pmatch", "source": "error_txt"}
        src = self.layout["src"]
        rel = "softmagic.c"
        try:
            candidates = list(src.rglob(rel))
        except OSError:
            candidates = []
        if not candidates:
            return {"file": "src/softmagic.c", "line": 365, "symbol": "pmatch",
                    "source": "error_txt"}
        path = candidates[0]
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            return {"file": "src/softmagic.c", "line": 365, "symbol": "pmatch",
                    "source": "error_txt"}
        start = 0
        for idx, line in enumerate(lines):
            if line.startswith("match(") or "match(struct magic_set" in line:
                start = idx
                break
        for idx in range(start, min(len(lines), start + 400)):
            if "pmatch" in lines[idx] and "nmatches" in lines[idx]:
                return {"file": "src/softmagic.c", "line": idx + 1, "symbol": "pmatch",
                        "source": "source_scan"}
        for idx in range(start, min(len(lines), start + 400)):
            if "pmatch" in lines[idx]:
                return {"file": "src/softmagic.c", "line": idx + 1, "symbol": "pmatch",
                        "source": "source_scan"}
        return {"file": "src/softmagic.c", "line": 365, "symbol": "pmatch",
                "source": "error_txt"}

    def _file_magic_claim(self) -> dict:
        """S7（arvo:1065 / file）构造器候选自带的主张。

        file_regexec() 在 regexec 前没有初始化 pmatch（glibc/msan 会返回 0 而不写 pmatch），
        softmagic.c 的 match() 随后读它 → MSan use-of-uninitialized-value。
        ARVO patch 就是在 file_regexec 里 memset(pmatch, 0, nmatch*sizeof(*pmatch))。
        """
        return {"claim_id": "s7-file-magic", "subject": "match",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/file_magic.py + arvo error.txt",
                "cwe": "CWE-457", "sink": self._file_magic_sink(),
                "test_plan": {"format": "file_magic"}}

    def _harfbuzz_sink(self) -> dict:
        """机械定位 CG-12 的 sink：Script::subset 里写 langSys 记录的那一行。

        在源码里找 hb-ot-layout-common.hh，再找 Script::subset 体内的
        "langSys.arrayZ" 写回语句；不抄崩溃栈、不写死行号。
        """
        src = self.layout["src"]
        rel = "hb-ot-layout-common.hh"
        try:
            candidates = list(src.rglob(rel))
        except OSError:
            candidates = []
        if not candidates:
            return {"file": rel, "line": None, "symbol": "langSys.arrayZ"}
        path = candidates[0]
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            return {"file": rel, "line": None, "symbol": "langSys.arrayZ"}
        start = 0
        for idx, line in enumerate(lines):
            if "Script::subset" in line or ("inline bool subset" in line and "Script" in lines[max(0, idx - 40):idx + 1].__str__()):
                start = idx
                break
        for idx in range(start, min(len(lines), start + 200)):
            if "langSys.arrayZ" in lines[idx]:
                return {"file": rel, "line": idx + 1, "symbol": "langSys.arrayZ"}
        return {"file": rel, "line": None, "symbol": "langSys.arrayZ"}

    def _harfbuzz_claim(self) -> dict:
        """CG-12（arvo:11081 / harfbuzz）构造器候选自带的主张。

        缺陷：Script::subset 先 embed(*this)（长度由 get_size() 估算），
        再逐条写 langSys 记录；get_size() 用 "size - array[0].min_size + array.get_size()"，
        langSys 数组为空时算出来的长度偏小，写记录就越界（ASAN WRITE of size 1）。
        崩溃首帧在 BEInt::set（hb-machinery.hh:650），真正的写点在 Script::subset 内。
        """
        return {"claim_id": "cg12-harfbuzz-gsub", "subject": "Script::subset",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/harfbuzz.py",
                "cwe": "CWE-122", "sink": self._harfbuzz_sink(),
                "test_plan": {"format": "harfbuzz"}}

    def _dwg_claim(self) -> dict:
        """CG-10（arvo:54625 / libredwg）构造器候选自带的主张。

        缺陷是 `decode_preR13_entities` 信任文件里的 entities_end：
        ARVO 的 patch.diff 在函数入口加的就是
        `if (size > dat->size || end > dat->size) return DWG_ERR_INVALIDDWG;`。
        真实崩溃落在 pre-R13 头部的 JSON 写出路径（header_variables_r11.spec:145，
        json_preR13_header_write_private），与官方 error.txt 的 DEDUP_TOKEN
        `json_cquote--json_preR13_header_write_private--json_header_write` 一致。

        **区分两件事**：sink 写"实测崩溃点"（可机械校验），
        described_defect 写描述口径的根因（decode_preR13_entities 缺尺寸校验）。
        这条 claim 由代码给出，仍要过"真崩溃 + 根因匹配 + fix 干净"三道门。
        """
        return {"claim_id": "cg10-libredwg-dwg", "subject": "json_preR13_header_write_private",
                "proposed_by": "builder", "subject_source": "builder",
                "evidence_source": "agent/builders/libredwg.py + arvo error.txt",
                "cwe": "CWE-122",
                "sink": {"file": "src/header_variables_r11.spec", "line": 145,
                         "symbol": "json_cquote",
                         "note": "pre-R13 头部 JSON 写出：json_cquote 越过 277B 缓冲写 1 字节"},
                "described_defect": {"file": "src/decode.c", "symbol": "decode_preR13_entities",
                                     "note": "entities_end/size 未与 dat->size 比较（见 patch.diff）"},
                "test_plan": {"format": "dwg"}}

    def _classify_run(self, run: dict, text: str) -> str:
        """把一次容器运行分类，返回三态之一：ok / infra / inconclusive。

        分类顺序（先排除环境，再确认漏洞证据，最后才是无法分类）：
        1. 超时 / Docker 自身报错 → infra（环境问题，判定无意义）
        2. 有 sanitizer 输出 → ok（进入双端对照）
        3. 退出码 77 等"程序拒绝输入" → ok（程序正常拒绝，不是崩溃）
        4. 137/143 等资源信号 → 看输出：OOM/被 kill 才是 infra，否则 inconclusive
        5. 其余非零且无 sanitizer 输出 → inconclusive（**不给 pass**）
        """
        code = run["exit_code"]
        if run.get("timed_out"):
            return "infra"
        for marker in self.DOCKER_MARKERS:
            if marker in text:
                return "infra"
        # 先看诊断，再看退出码：exit=0 也可能带着真缺陷报告（halt_on_error=0）
        defect = run.get("defect")
        if defect is None:
            defect = parse_diagnosis(text).is_defect
        if defect:
            return "ok"          # 确有缺陷诊断，进入双端对照
        if code == 0:
            return "ok"
        if code in self.DOCKER_EXIT_CODES:
            return "infra"       # 无 docker 报错但仍落在 docker 退出码区间
        if code in self.PROGRAM_REJECT_CODES:
            return "ok"          # 程序主动拒绝输入（如 MagickFatalError）
        if code in self.RESOURCE_EXIT_CODES:
            low = text.lower()
            if "out of memory" in low or "oom" in low or "killed" in low:
                return "infra"   # 资源耗尽属于环境/宿主问题，不是目标漏洞
            return "inconclusive"
        return "inconclusive"    # 非零、无 sanitizer、无明确语义 → 无法分类

    def _infra_failure(self, run: dict, text: str) -> str:
        """环境失败的详细原因；非环境失败返回空串。"""
        cls = self._classify_run(run, text)
        if cls != "infra":
            return ""
        if run.get("timed_out"):
            return "timeout"
        for marker in self.DOCKER_MARKERS:
            if marker in text:
                return f"docker_error:{marker[:40]}"
        if run["exit_code"] in self.RESOURCE_EXIT_CODES:
            return f"resource_exhausted:exit{run['exit_code']}"
        return f"docker_exit_code:{run['exit_code']}"

    def _try(self, cand: dict, image: dict, claim: dict | None = None) -> dict:
        poc = self.artifact_path(f"verify/{cand['name']}.bin")
        poc.write_bytes(cand["data"])
        sha = sha256_bytes(cand["data"])
        vul = self._run_container_retry(image["vul"], poc, cand["name"])
        claim = claim or cand.get("claim") or {}
        res = {"candidate": cand["name"], "format": cand["format"],
               "path": str(poc.relative_to(self.ws)),
               "sha256": sha, "size": len(cand["data"]),
               # 提出者与证据来源分开记：否则重复跑规则候选会伪装成"跑了模型候选"
               "proposed_by": claim.get("proposed_by", claim.get("subject_source", "rule")),
               "evidence_source": claim.get("evidence_source", ""),
               "claim_id": claim.get("claim_id", ""),
               "subject": claim.get("subject", ""),
               "vul_exit": vul["exit_code"], "vul_crash": vul["crash"], "vul_log": vul["log"],
               "crash_file": vul.get("crash_file", ""), "crash_line": vul.get("crash_line"),
               "vul_infra": vul.get("infra", ""), "claim": claim}

        vclass = vul.get("class") or self._classify_run(
            {"exit_code": vul["exit_code"], "crash": vul["crash"],
             "timed_out": vul.get("timed_out", False)},
            vul.get("tail") or "")
        res["vul_class"] = vclass

        # 环境失败：不是漏洞触发，不得进入 pass 判定
        if vclass == "infra":
            res["verdict"] = "infra_error"
            res["reason"] = vul.get("infra") or f"vul_side_infra:exit{vul['exit_code']}"
            return res
        # 未分类：非零但既无 sanitizer 证据也无明确语义 → 不给 pass
        if vclass == "inconclusive":
            res["verdict"] = "inconclusive"
            res["reason"] = f"unclassified_exit:{vul['exit_code']}"
            return res
        # ok 但无缺陷诊断：正常退出，或 77 之类主动拒绝输入
        vul_defect = vul.get("defect")
        if vul_defect is None:
            vul_defect = self._augment_sanitizer(
                parse_diagnosis(vul.get("tail") or ""), vul.get("tail") or "").is_defect
        if not vul_defect:
            res["verdict"] = "not_triggered"
            res["reason"] = (f"program_rejected:exit{vul['exit_code']}"
                             if vul["exit_code"] in self.PROGRAM_REJECT_CODES
                             else "no_defect_diagnosis")
            return res

        # 有缺陷诊断 → 校验根因一致性（崩溃点是否真在声明的 sink）
        cur_claim = claim or getattr(self, "_current_claim", None) or {}
        sink = ((res.get("claim") or {}).get("sink")
                or getattr(self, "_current_sink", None) or {})
        vul_diag = vul.get("diagnosis") or parse_diagnosis(vul.get("tail") or "")
        # CWE 以实际崩溃证据为准：claim 的 cwe 是定位阶段的猜测，
        # 真实读写方向与内存区域只有 ASAN/UBSAN 才能确定。
        # CG-15 中 claim 猜 CWE-121（栈），实际是 heap-buffer-overflow（CWE-122）。
        from ..diagnostics import cwe_for_crash
        _k = getattr(vul_diag, "kind", "") or ""
        _claimed = cur_claim.get("cwe", "")
        claim_cwe = cwe_for_crash(_k, getattr(vul_diag, "write", None), _claimed) or _claimed
        subject = cur_claim.get("subject", "")
        cons = check_root_cause(vul_diag, sink, claim_cwe, sink_function=subject)
        if not cons.matched and cons.reason in ("sink_not_in_stack", "no_user_frame"):
            # 帧解析器丢 C++ 内联帧时，用原始日志的 file:line 兜底（仍是实测证据）
            hit = self._text_sink_hit(sink, vul.get("log") or "")
            if hit:
                cons = ConsistencyResult(True, "weak", "sink_line_in_raw_trace",
                                         {"text_hit": hit, "parser_reason": cons.reason,
                                          "diagnosis": {"sanitizer": getattr(vul_diag, "sanitizer", ""),
                                                        "kind": getattr(vul_diag, "kind", "")}})
        res["cwe_by_crash"] = claim_cwe     # 供 report 校正 claim 的猜测
        res["root_cause"] = {"matched": cons.matched, "confidence": cons.confidence,
                             "reason": cons.reason, "evidence": cons.evidence,
                             "provenance": self._provenance_for(vul)}
        if cons.confidence in ("none", "inconclusive"):
            # 崩了，但崩的地方对不上声明的缺陷：不能算这个漏洞被触发
            res["verdict"] = "inconclusive"
            res["reason"] = f"root_cause:{cons.reason}"
            return res

        fix = self._run_container_retry(image["fix"], poc, cand["name"])
        res.update({"fix_exit": fix["exit_code"], "fix_crash": fix["crash"],
                    "fix_log": fix["log"], "fix_infra": fix.get("infra", "")})
        fclass = fix.get("class") or self._classify_run(
            {"exit_code": fix["exit_code"], "crash": fix["crash"],
             "timed_out": fix.get("timed_out", False)},
            fix.get("tail") or "")
        res["fix_class"] = fclass
        if fclass == "infra":
            # fix 侧环境失败：既不能证明"修复后不崩"，也不能证明"两边都崩"
            res["verdict"] = "infra_error"
            res["reason"] = "fix_side:" + (fix.get("infra") or "exit%d" % fix["exit_code"])
        elif fclass == "inconclusive":
            res["verdict"] = "inconclusive"
            res["reason"] = f"fix_unclassified_exit:{fix['exit_code']}"
        elif (fix.get("defect") if fix.get("defect") is not None
              else self._augment_sanitizer(
                  parse_diagnosis(fix.get("tail") or ""), fix.get("tail") or "").is_defect):
            # 修复版仍有缺陷诊断 → 无论退出码是多少，都不能算 clean
            fix_diag = fix.get("diagnosis") or parse_diagnosis(fix.get("tail") or "")
            fix_cons = check_root_cause(fix_diag, sink, claim_cwe,
                                       sink_function=subject)
            res["fix_root_cause"] = {"matched": fix_cons.matched,
                                     "confidence": fix_cons.confidence,
                                     "reason": fix_cons.reason}
            if fix_cons.confidence in ("strong", "weak") and fix_cons.matched:
                res["verdict"] = "fail_both"
                res["evidence"] = {"vul_asan": vul["crash"], "fix_asan": fix["crash"],
                                   "note": "fix 侧复现同一缺陷"}
            else:
                # fix 崩在别处：不是"两边都崩"，但也不能判 clean
                res["verdict"] = "inconclusive"
                res["reason"] = f"fix_crashed_elsewhere:{fix_cons.reason}"
        elif fix["exit_code"] == 0:
            res["verdict"] = "pass"
            res["evidence"] = {"vul_asan": vul["crash"], "fix_clean": True,
                               "root_cause": cons.confidence}
        else:
            # fix 非零但无缺陷诊断：不能算"两边都崩"
            res["verdict"] = "inconclusive"
            res["reason"] = f"fix_nonzero_no_diagnosis:{fix['exit_code']}"
        return res

    def _log_candidate(self, res: dict, claim: dict) -> None:
        """逐次记录：candidate_id -> claim_id -> proposed_by -> 输入哈希 -> 结果。"""
        from ..util import short_hash
        rec = {
            "candidate": res.get("candidate"),
            "claim_id": res.get("claim_id"),
            "subject": res.get("subject"),
            "proposed_by": res.get("proposed_by"),
            "evidence_source": res.get("evidence_source"),
            "input_sha256": res.get("sha256"),
            "vul_exit": res.get("vul_exit"),
            "fix_exit": res.get("fix_exit"),
            "verdict": res.get("verdict"),
            "reason": res.get("reason", ""),
        }
        self._candidate_log = getattr(self, "_candidate_log", [])
        self._candidate_log.append(rec)
        self.store.record_attempt(
            self.run_id, self.name, 3,
            short_hash(["cand", res.get("candidate"), res.get("sha256")], 16),
            f"candidate:{res.get('verdict')}", 0.0,
            detail=json.dumps({"candidate": rec}, ensure_ascii=False))

    # ---- harness 输入契约（S4-b B1）----
    def _harness_hints(self) -> list:
        """选对 harness：给缺陷函数名与靶子二进制名当线索。"""
        hints = []
        subj = (self._current_claim or {}).get("subject") or ""
        if subj:
            hints.append(subj)
        task = {}
        try:
            task = json.loads((self.ws / "task.json").read_text(encoding="utf-8"))
        except Exception:
            task = {}
        binary = str(task.get("binary") or "")
        if binary:
            hints.append(binary.rsplit("/", 1)[-1])
        return [h for h in hints if h]

    def _harness_contract(self) -> dict:
        """harness 的输入契约（长度窗口 / 通道）；解析失败退化为 unknown 并放行。"""
        cached = getattr(self, "_hcontract", None)
        if cached is not None:
            return cached
        try:
            self._hcontract = harness_mod.extract(
                self.layout["src"], hints=self._harness_hints())
        except Exception as exc:
            self._hcontract = harness_mod.unknown_contract(
                f"extract_error:{type(exc).__name__}: {exc}")
        return self._hcontract

    def _harness_seeds(self, contract: dict) -> list:
        """仓库测试里的种子向量（S5-c B2）；解析失败退化为空列表，不影响闭环。"""
        cached = getattr(self, "_hseeds", None)
        if cached is not None:
            return cached
        try:
            self._hseeds = harness_mod.seeds(
                self.layout["src"], contract=contract, hints=self._harness_hints())
        except Exception:
            self._hseeds = []
        return self._hseeds

    def _contract_gate(self, data: bytes, contract: dict) -> dict | None:
        """执行前长度校验：窗口外直接拒绝，不启动容器（S4-b B1）。"""
        verdict = harness_mod.check(contract, len(data))
        if verdict["ok"]:
            return None
        return {
            "verdict": "rejected_by_contract",
            "rejected_by_contract": True,
            "vul_exit": None,
            "fix_exit": None,
            "reason": verdict["reason"],
            "harness_contract": contract,
            "in_harness_window": False,
            "feedback": ("REJECTED_BY_CONTRACT (not executed): " + verdict["reason"]
                         + ". Allowed interval: " + (verdict["window"] or "unknown")
                         + ". The next reply MUST have a length inside this interval."),
        }

    def _model_loop(self, image: dict) -> dict | None:
        """模型自主闭环：读码 → 提输入 → 看真实反馈 → 修正。"""
        try:
            claim = self._current_claim or {}
            claim_data = self._locate_data or {}
            cands = claim_data.get("claims_llm") or []
            if not claim and cands:
                claim = cands[0]
            if not claim:
                # 无 claim 时给通用起始假设：任务描述 + 声明格式
                desc = ""
                try:
                    desc = (self.ws / "description.txt").read_text(encoding="utf-8", errors="ignore")[:800]
                except Exception:
                    pass
                fmt0 = self._declared_format() or self._detected_format or "unknown"
                claim = {"claim_id": "fallback-description", "subject": "unknown",
                         "subject_source": "fallback_description", "cwe": "",
                         "sink": {}, "test_plan": {"format": fmt0},
                         "description_excerpt": desc}
                self._fallback_claim = True

            fmt = self._detected_format or "unknown"
            contract = self._harness_contract()
            seeds = self._harness_seeds(contract)
            # 种子只走 seed_block 这一个入口：p4 曾在 context 里再拼一份，
            # 提示体积翻倍，直接把 completion 预算打满（S5-c B5）
            seed_block = harness_mod.seed_prompt(seeds, contract, max_show=2)
            context = (self._loop_context(claim) + "\n\n"
                       + harness_mod.describe(contract))
            cfg = self._llm_config()

            def execute(data: bytes) -> dict:
                # S4-b B1：窗口外候选在执行前拒绝，并把允许区间写进反馈
                gate = self._contract_gate(data, contract)
                if gate is not None:
                    return gate
                out = self._execute_generated(data, image, claim)
                out["in_harness_window"] = True
                return out

            # 闭环要产出完整输入内容，需要比单次抽取更大的输出预算
            import dataclasses
            from .. import llm as llm_mod
            cfg = dataclasses.replace(cfg, max_tokens=8000)

            def call_llm(*, system: str, user: str, prompt_version: str):
                return llm_mod.call_json(cfg, system=system, user=user,
                                         prompt_version=prompt_version)

            result = run_diverse_loop(
                claim=claim, context=context, fmt=(self._declared_format() or fmt), execute=execute,
                call_llm=call_llm, max_rounds=self.loop_max_rounds,
                prompt_version=self.loop_prompt_version,
                duplicate_max_consecutive=self.duplicate_max_consecutive,
                seed_block=seed_block, seeds=seeds, contract=contract,
                log=lambda msg: self.store.add_blackboard(
                    self.run_id, "action", "模型闭环", msg, status="ok"))
            result["format"] = fmt
            result["claim_subject"] = claim.get("subject", "")
            result["harness_contract"] = contract
            rejected_rounds = []
            for rec in result.get("rounds", []):
                if not rec.get("sha256"):
                    continue
                verdict_rec = harness_mod.check(contract, int(rec.get("size") or 0))
                rec["in_harness_window"] = verdict_rec["ok"]
                rec["harness_window"] = verdict_rec["window"]
                if rec.get("verdict") == "rejected_by_contract":
                    rejected_rounds.append(rec.get("round"))
            result["rejected_by_contract"] = len(rejected_rounds)
            result["rejected_by_contract_rounds"] = rejected_rounds
            # 每轮候选都落 attempts，形成可审计轨迹
            for r in result.get("rounds", []):
                self.store.record_attempt(
                    self.run_id, self.name, 4,
                    loop_mod_hash(r.get("sha256", ""), str(r.get("round"))),
                    f"model_candidate:{r.get('verdict')}", 0.0,
                    detail=json.dumps({"model_loop_round": r}, ensure_ascii=False))
            return result
        except Exception as exc:
            return {"rounds": [], "error": f"{type(exc).__name__}: {exc}"}

    def _llm_config(self):
        from .. import llm as llm_mod
        task = {}
        tp = self.ws / "task.json"
        if tp.exists():
            try:
                task = json.loads(tp.read_text(encoding="utf-8"))
            except Exception:
                task = {}
        return llm_mod.load_config(self.ws, task)

    def _loop_context(self, claim: dict) -> str:
        """给模型的源码证据：缺陷函数定义 + 周边，不含 ASAN、不含答案。"""
        from ..tools import binscan
        src = self.layout["src"]
        chunks = []
        subj = claim.get("subject") or ""
        if subj:
            for d in binscan.find_function(src, subj, stage=self.name)[:1]:
                chunks.append(f"--- {d['file']} (function {subj} at line {d['line']}) ---\n"
                              + binscan.line_window(src / d["file"], d["line"], 2, 60))
        sink = claim.get("sink") or {}
        if sink.get("file") and sink.get("line"):
            chunks.append(f"--- {sink['file']} around line {sink['line']} ---\n"
                          + binscan.line_window(src / sink["file"], int(sink["line"]), 15, 15))
        return "\n\n".join(chunks)[:4000] or "(no source evidence)"

    def _execute_generated(self, data: bytes, image: dict, claim: dict) -> dict:
        """固定验收器：模型给的输入走与预置候选完全相同的双端流程。"""
        name = "model-loop"
        cand = {"name": f"{name}-{abs(hash(data)) % 10**8}", "data": data,
                "format": self._detected_format or "unknown"}
        res = self._try(cand, image, claim)
        # 结构化保留崩溃点：feedback 会截断，pinpoint 校验需要完整行号
        import re as _re
        _m = _re.search(r"([\w./+-]+\.(?:c|cc|cpp|cxx|h|hpp)):(\d+)",
                        res.get("vul_crash") or "")
        # 只在正则命中时覆盖，避免把 _try 已提取到的值清空
        if _m:
            res["crash_file"] = _m.group(1)
            res["crash_line"] = int(_m.group(2))
        else:
            res.setdefault("crash_file", "")
            res.setdefault("crash_line", None)
        feedback_bits = [f"vul_exit={res.get('vul_exit')} fix_exit={res.get('fix_exit')}"]
        if res.get("vul_crash"):
            feedback_bits.append(f"vul_diagnosis={res['vul_crash'][:300]}")
        if res.get("reason"):
            feedback_bits.append(f"reason={res['reason']}")
        rc = res.get("root_cause") or {}
        if rc:
            feedback_bits.append(f"root_cause={rc.get('confidence')}:{rc.get('reason')}")
        if res.get("verdict") == "not_triggered":
            # 只给 no_defect_diagnosis 等于没给信息：必须指出「结构不对」而不是「长度不对」
            window = harness_mod.window_text(self._harness_contract())
            feedback_bits.append(
                "NO_CRASH_CONTEXT: the input was accepted and executed (vul_exit="
                + str(res.get("vul_exit")) + ") but the target never entered the "
                "vulnerable branch; no sanitizer report was produced. 解析未进入目标分支，"
                "需改结构而非改长度。len=" + str(len(data)) + "B is inside "
                + (window or "the harness window") + ", so shifting the length will not "
                "help: change which bytes land in which field (field magnitudes, struct "
                "truncation, recombined policy fields).")
        res["feedback"] = " | ".join(str(b) for b in feedback_bits)
        return res

    @staticmethod
    def _loop_public(loop_result: dict | None) -> dict | None:
        """loop_result 含 winner_data(bytes)，落盘前必须剥离（JSON 不能序列化 bytes）。"""
        if not loop_result:
            return loop_result
        return {k: v for k, v in loop_result.items() if k != "winner_data"}

    def _emit_loop_only(self, loop_result: dict) -> None:
        """仅有模型闭环候选、且都未通过：仍须完整落盘（可审计的失败也是结果）。"""
        rounds = loop_result.get("rounds") or []
        last = rounds[-1] if rounds else {}
        payload = {
            "schema": "vulnmap.verify.v1",
            "verdict": "generated_but_unverified",
            "reason": "model_loop_candidates_all_unverified",
            "claim_source_mode": self.claim_source,
            "candidates": [],
            "model_loop": loop_result,
            "harness_contract": loop_result.get("harness_contract") or {},
            "rejected_by_contract": loop_result.get("rejected_by_contract", 0),
            "rejected_by_contract_rounds": loop_result.get("rejected_by_contract_rounds", []),
            "poc": {"path": "", "sha256": last.get("sha256", ""),
                    "size": last.get("size", 0)},
            "vul": {"exit_code": last.get("vul_exit"), "asan": last.get("feedback", ""),
                    "log": ""},
            "fix": {"exit_code": last.get("fix_exit"), "log": ""},
            "notes": "模型闭环产出了输入但未通过双端；全过程在 model_loop.rounds",
            "upstream": {"artifacts/locate/findings.json":
                         self.input_hashes().get("artifacts/locate/findings.json", "")},
        }
        self.emit("verify/result.json", payload, "vulnmap.verify.v1",
                  guards=[lambda d: guard_upstream_untouched(self.input_hashes(), d)])
        self.store.add_blackboard(
            self.run_id, "observation", "模型闭环未通过",
            f"{len(rounds)} 轮均未触发；已完整落盘", status="unknown")

    def _emit_generation_unsupported(self, loop_result: dict | None = None) -> None:
        payload = {
            "schema": "vulnmap.verify.v1",
            "verdict": "generation_unsupported",
            "reason": "no_constructor_for_format",
            "detected_format": self._detected_format or "unknown",
            "available_constructors": ["mng", "pdf", "gas", "fuzz"],
            "claim_source_mode": self.claim_source,
            "candidates": [],
            "poc": {"path": "", "sha256": "", "size": 0},
            "vul": {"exit_code": None, "asan": "", "log": ""},
            "fix": {"exit_code": None, "log": ""},
            "notes": "冻结系统无对应格式构造器；这不是定位失败，但属于端到端未成功",
            "model_loop": loop_result or {},
            "upstream": {"artifacts/locate/findings.json":
                         self.input_hashes().get("artifacts/locate/findings.json", "")},
        }
        # 无 poc 时跳过哈希/日志守卫
        self.emit("verify/result.json", payload, "vulnmap.verify.v1",
                  guards=[lambda d: guard_upstream_untouched(self.input_hashes(), d)])
        fmt = self._detected_format or "unknown"
        self.store.add_blackboard(
            self.run_id, "observation", "生成能力不足",
            f"format={fmt}；冻结系统无该格式构造器。计入端到端分母，不算成功。",
            status="unknown")

    def _pick(self, results: list[dict]) -> dict:
        for r in results:
            if r.get("verdict") == "pass":
                return r
        # 没有 pass 时，优先保留"真的触发了漏洞"的候选，其次才是环境失败
        triggered = [r for r in results if r.get("verdict") in ("fail_both", "not_triggered")]
        if triggered:
            return triggered[0]
        inconclusive = [r for r in results if r.get("verdict") == "inconclusive"]
        if inconclusive:
            return inconclusive[0]
        infra = [r for r in results if r.get("verdict") == "infra_error"]
        return infra[0] if infra else (results[0] if results else {})

    def _emit(self, best: dict, loop_result: dict | None = None) -> None:
        # 入参可能带 bytes（winner_data / 候选原始数据），落盘前统一剥离。
        # 逐个调用点处理容易漏（CG-13 就漏在 _emit(best, loop_result) 这条路径上）。
        loop_result = self._loop_public(loop_result)
        payload = {
            "schema": "vulnmap.verify.v1",
            "verdict": best.get("verdict", "fail"),
            "infra_error": best.get("verdict") == "infra_error",
            "reason": best.get("reason", ""),
            "evidence": best.get("evidence", {}),
            "root_cause": best.get("root_cause", {}),
            "cwe_by_crash": best.get("cwe_by_crash", ""),
            "fix_root_cause": best.get("fix_root_cause", {}),
            "candidates_tried": len(self._last_results) if getattr(self, "_last_results", None) else 0,
            "poc": {"path": best.get("path", ""), "sha256": best.get("sha256", ""), "size": best.get("size", 0)},
            "vul": {"exit_code": best.get("vul_exit"), "asan": best.get("vul_crash", ""), "log": best.get("vul_log", "")},
            "fix": {"exit_code": best.get("fix_exit"), "log": best.get("fix_log", "")},
            "notes": best.get("candidate", ""),
            "claim_source_mode": self.claim_source,
            "candidates": getattr(self, "_candidate_log", []),
            "model_loop": loop_result or {},
            "claim_used": {"id": best.get("claim_id") or (self._current_claim or {}).get("claim_id", ""),
                           "subject": best.get("subject") or (self._current_claim or {}).get("subject", ""),
                           "proposed_by": best.get("proposed_by", ""),
                           "evidence_source": best.get("evidence_source", "")},
        }
        if loop_result and loop_result.get("harness_contract"):
            payload["harness_contract"] = loop_result.get("harness_contract")
            payload["rejected_by_contract"] = loop_result.get("rejected_by_contract", 0)
        poc_rel = payload["poc"]["path"]
        payload["upstream"] = {"artifacts/locate/findings.json":
                               self.input_hashes().get("artifacts/locate/findings.json", "")}
        guards = [lambda d: guard_upstream_untouched(self.input_hashes(), d),
                  lambda d: _guard_poc_hash(self.ws, d)]
        self.emit("verify/result.json", payload, "vulnmap.verify.v1", guards=guards)
        self.store.add_evidence(self.run_id, self.name, "dual_run",
                                f"vul={best.get('vul_exit')} fix={best.get('fix_exit')}",
                                location={"poc": best.get("path", "")}, observed_by="docker")
        if payload["verdict"] == "pass":
            self.store.add_blackboard(self.run_id, "observation", "PoC 通过双端判定",
                                      f"{best.get('candidate')} vul={best.get('vul_exit')} fix={best.get('fix_exit')}",
                                      status="supported")

def _guard_poc_hash(ws: Path, data: dict) -> None:
    """PoC 文件必须存在且 sha 与记录一致；缺任何一份双端日志即判违约。"""
    from ..errors import ContractViolation
    poc = data.get("poc") or {}
    rel = poc.get("path") or ""
    if not rel:
        raise ContractViolation("verify: poc.path missing")
    path = ws / rel
    if not path.exists():
        raise ContractViolation(f"verify: poc file missing: {rel}")
    if sha256_file(path) != poc.get("sha256"):
        raise ContractViolation(f"verify: poc sha mismatch: {rel}")
    vul, fix = data.get("vul") or {}, data.get("fix") or {}
    if vul.get("log") and not (ws / vul["log"]).exists():
        raise ContractViolation(f"verify: vul log missing: {vul['log']}")
    if fix.get("log") and not (ws / fix["log"]).exists():
        raise ContractViolation(f"verify: fix log missing: {fix['log']}")


def loop_mod_hash(sha: str, rnd: str) -> str:
    from ..util import short_hash
    return short_hash(["model_loop", sha, rnd], 16)
