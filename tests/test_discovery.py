"""Discovery v1.0 冒烟测试（受控 fixture，不依赖网络/LLM）。"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from agent.discovery import (agents, callsites, campaign, covfuzz, coverage_map,
                             isolation, profile, report, targetspec, triage)

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "discovery"


def test_d0_profile():
    p = profile.scan(FIX)
    assert p["source_count"] >= 1
    assert any(b["path"].endswith("vuln_parser") for b in p["binaries"])
    assert p["entries"], "must find main"
    assert p["formats"]


def test_d0_elf_meta():
    p = profile.scan(FIX)
    assert p["binaries"]
    meta = profile.elf_meta(FIX / p["binaries"][0]["path"])
    assert meta["bits"] in (32, 64)
    assert meta["endian"] in ("little", "big")


def test_d1_callsites_and_coverage_fields():
    led = callsites.scan(FIX)
    assert led["planned"] >= 3
    assert led["uncovered"] == led["planned"]
    assert led["status"] == "partial"
    assert all("score" in s for s in led["sites"])
    assert {"planned", "covered", "uncovered", "status"} <= set(led)


def test_d1_score_formula():
    led = callsites.scan(FIX)
    for s in led["sites"]:
        weight = callsites.DANGEROUS[s["callee"]][1]
        assert s["score"] == weight * (2 if s["reachable"] else 1) * (2 if s["controlled"] else 1)


def test_agents_pool_isolated(tmp_path):
    tasks = [agents.Task("a", "t", {}), agents.Task("b", "t", {})]

    def handler(task, work):
        if task.task_id == "b":
            raise RuntimeError("boom")
        (work / "x").write_text("ok")
        return {"task": task.task_id}

    results = agents.run_pool(tasks, handler, workers=2)
    assert {r.task_id for r in results} == {"a", "b"}
    assert any(r.ok for r in results) and any(not r.ok for r in results)


def test_agents_seeds_shapes():
    json_seeds = agents.propose_seeds({"function": "cJSON_Parse", "file": "cJSON.c"},
                                      FIX, "json")
    png_seeds = agents.propose_seeds({"function": "png_read_info", "file": "png.c"},
                                     FIX, "png")
    generic = agents.propose_seeds({"function": "parse", "file": "a.c"}, FIX, "unknown")
    assert any(b"\x00" in s or b"\\u0000" in s for s in json_seeds)
    assert png_seeds[0].startswith(b"\x89PNG\r\n\x1a\n")
    assert generic and generic[0].startswith(b"FUZZ")


def test_targetspec_loads_fixture_yaml():
    spec = targetspec.load(FIX / "target.yaml")
    assert spec["name"] == "discovery-fixture"
    assert spec["build"]["mode"] == "main"
    assert spec["sources"] and Path(spec["sources"][0]).is_file()
    build_spec = targetspec.to_build_spec(spec, FIX.parent / "_yaml_build")
    assert build_spec["mode"] == "main"
    assert build_spec["includes"]



def test_targetspec_autodetect_fixture():
    spec = targetspec.autodetect(FIX)
    assert spec["build"]["mode"] == "main"
    assert any(p.endswith("vuln_parser.c") for p in spec["sources"])
    assert "mode: main" in targetspec.dump(spec)


def test_targetspec_autodetect_cjson(tmp_path):
    d = tmp_path / "cjson"
    d.mkdir()
    (d / "cJSON.c").write_text("int placeholder;\n")
    spec = targetspec.autodetect(d)
    assert spec["build"] == {"mode": "api", "harness": "cjson"}


def test_targetspec_autodetect_configure(tmp_path):
    d = tmp_path / "lib"
    d.mkdir()
    (d / "configure").write_text("#!/bin/sh\n")
    spec = targetspec.autodetect(d)
    assert spec["needs_review"] is True
    assert spec["build"]["harness_path"] == "harness.c"



def test_targetspec_autodetect_format_from_sources(tmp_path):
    d = tmp_path / "libtiff-like"
    d.mkdir()
    (d / "configure").write_text("#!/bin/sh\n")
    (d / "tif_dummy.c").write_text("int dummy;\n")
    spec = targetspec.autodetect(d)
    assert spec["format"] == "tiff"



def test_isolation_detect_and_limits():
    info = isolation.detect()
    assert info["mode"] in {"unshare", "bwrap", "none"}
    assert isinstance(info["prefix"], list)
    isolation.limits(2.0)  # 仅确认可构造


def test_run_input_isolated(tmp_path):
    if isolation.detect()["mode"] == "none":
        pytest.skip("no OS isolation available")
    fix = FIX
    build = covfuzz.build(tmp_path / "b", [fix / "vuln_parser.c"], mode="main",
                          includes=[fix])
    seed = (fix / "vuln_parser").read_bytes() if False else (
        b"FUZZ" + (64).to_bytes(2, "little") + b"\x01" + b"A" * 64)
    result = covfuzz.run_input(build["binary"], seed, tmp_path / "run")
    assert result["isolation"] != "none"
    assert result["network"] == "none"
    assert result["crash"]


def test_require_isolation_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(isolation, "detect",
                        lambda: {"mode": "none", "prefix": [], "network": "host"})
    with pytest.raises(RuntimeError):
        covfuzz.run_input("/bin/true", b"x", tmp_path / "run",
                          require_isolation=True)


def test_covfuzz_build_and_run(tmp_path):
    build = covfuzz.build(tmp_path / "build",
                          [FIX / "vuln_parser.c"], mode="main",
                          includes=[FIX])
    binary = Path(build["binary"])
    assert binary.exists()
    result = covfuzz.run_input(binary, b"FUZZ" + (64).to_bytes(2, "little") + b"\x01" + b"A" * 64,
                               tmp_path / "run")
    assert result["crash"]
    assert "AddressSanitizer" in result["log"]


def test_d2_d3_fixture_campaign(tmp_path):
    out = tmp_path / "out"
    summary = campaign.run(FIX, out, seconds=2, max_sites=3, workers=2,
                           use_llm=False, db_path=tmp_path / "c.db")
    assert summary["target_yaml"].endswith("target.yaml")
    assert summary["risk_stats"]["crashes"] >= 1
    assert summary["risk_stats"]["confirmed"] >= 1
    assert summary["coverage"]["planned"] >= 3
    hypotheses = json.loads((out / "hypotheses.json").read_text())
    assert hypotheses and any(h.get("seed_count", 0) > 0 for h in hypotheses)
    assert summary["execution_isolation"]["mode"] in {"unshare", "bwrap", "none"}
    assert summary["analysis"]["mode"] == "heuristic"
    records = json.loads((out / "triage.json").read_text())
    assert records and records[0]["verdict"] == "confirmed"
    assert records[0]["access"] == "WRITE"
    assert records[0]["build_clean"] is True
    assert (out / "report.md").exists()


def test_report_structure():
    p = profile.scan(FIX)
    led = callsites.scan(FIX)
    led["covered"] = 1
    led["uncovered"] = led["planned"] - 1
    rep = report.build(p, led, [{"verdict": "confirmed", "function": "f",
                                 "file": "a.c", "line": 1, "stack_hash": "h",
                                 "reproduced": 3, "crash_type": "heap-buffer-overflow",
                                 "access": "WRITE", "access_size": 1}])
    assert [row["stage"] for row in rep["analysis_completeness"]] == [
        "静态档案", "调用点", "输入构造/执行"]
    assert {"planned", "covered", "confirmed", "weakened", "excluded"} <= set(rep["risk_stats"])


def test_png_structured_mutation_keeps_chunks():
    seed = agents._png_seed(1, 1)
    rng = __import__("random").Random(3)
    for _ in range(40):
        out = covfuzz.mutate_png(rng, seed, [seed])
        chunks = covfuzz.png_chunks(out)
        assert chunks and chunks[0]["type"] == b"IHDR"


def test_tiff_structured_mutation_parses():
    tiff = (b"II*\x00\x08\x00\x00\x00" + b"\x01\x00"
            + b"\x00\x01\x03\x00\x01\x00\x00\x00\x08\x00\x00\x00"
            + b"\x00\x00\x00\x00")
    info = covfuzz.tiff_entries(tiff)
    assert info and info["count"] == 1
    rng = __import__("random").Random(5)
    out = covfuzz.mutate_tiff(rng, tiff, [tiff])
    assert isinstance(out, bytes) and out




def test_analysis_llm_is_default(monkeypatch):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "test-key")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.delenv("VULNMAP_DISABLE_LLM", raising=False)

    def fake_llm(prompt: str, timeout: float = 0, **kwargs):
        return {"hypothesis": "length from input reaches memcpy",
                "confidence": 0.8,
                "citations": ["vuln_parser.c:16"]}

    monkeypatch.setattr(agents, "_llm_json", fake_llm)
    site = {"id": "s1", "function": "parse_record", "file": "vuln_parser.c",
            "line": 16, "callee": "memcpy", "category": "copy",
            "args": "buf, data + 8, len", "controlled": True, "reachable": True}
    result = agents.analyze_site(site, FIX)
    assert result["llm"] is True
    assert result["llm_status"] == "ok"
    assert result["citations"] == ["vuln_parser.c:16"]


def test_analysis_falls_back_without_key(monkeypatch):
    for name in ("DISCOVERY_LLM_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY",
                 "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DISCOVERY_LLM_DISABLED", "1")
    result = agents.analyze_site(
        {"id": "s1", "function": "parse_record", "file": "vuln_parser.c",
         "line": 16, "callee": "memcpy", "category": "copy",
         "args": "buf, len", "controlled": True, "reachable": True}, FIX)
    assert result["llm"] is False
    assert result["llm_status"] in {"disabled", "no_key"}


def test_hypothesis_drives_seed_choice():
    site = {"function": "parse", "file": "a.c", "line": 1,
            "callee": "memcpy", "args": "buf,len"}
    base = agents.propose_seeds(site, None, "json")
    hyp = {"hypothesis": "length field drives copy",
           "window": "int len = 2642; /* comment */"}
    adapted = agents.propose_seeds(site, None, "json", hypothesis=hyp)
    assert len(adapted) > len(base)
    assert any(b"2642" in s for s in adapted)
    assert "length" in agents.seed_basis(hyp)
    png = agents.propose_seeds({"function": "png", "file": "a.c"}, None, "png",
                               hypothesis={"hypothesis": "interlace path"})
    assert any(s.startswith(b"\x89PNG") and s[28] == 1 for s in png)


def test_png_fixture_structured_write_confirmed(tmp_path):
    from agent.discovery import covfuzz as cf
    fix = ROOT / "fixtures" / "discovery_png"
    build = cf.build(tmp_path / "b", [fix / "png_parser.c"], mode="main",
                     includes=[fix])
    seed = (fix / "seed.png").read_bytes()
    rng = __import__("random").Random(7)
    result = None
    for i in range(300):
        data = cf.mutate_png(rng, seed, [seed])
        result = cf.run_input(build["binary"], data, tmp_path / "run")
        if result["crash"]:
            break
    assert result and result["crash"]
    assert "heap-buffer-overflow" in result["log"]
    assert "WRITE of size" in result["log"]


def test_triage_clean_rebuild(tmp_path):
    build = covfuzz.build(tmp_path / "b", [FIX / "vuln_parser.c"], mode="main",
                          includes=[FIX])
    data = b"FUZZ" + (64).to_bytes(2, "little") + b"\x01" + b"A" * 64
    (tmp_path / "crashes").mkdir()
    digest = __import__("hashlib").sha256(data).hexdigest()[:16]
    (tmp_path / "crashes" / f"crash-{digest}.bin").write_bytes(data)
    res = covfuzz.run_input(build["binary"], data, tmp_path / "run")
    (tmp_path / "crashes" / f"crash-{digest}.log").write_text(res["log"])
    def rebuild():
        again = covfuzz.build(tmp_path / "clean", [FIX / "vuln_parser.c"],
                              mode="main", includes=[FIX])
        return again["binary"]

    rec = triage.triage({"input_sha256": digest,
                         "log_path": str(tmp_path / "crashes" / f"crash-{digest}.log")},
                        tmp_path / "crashes", binary=Path(build["binary"]),
                        rebuilder=rebuild)
    assert rec["verdict"] == "confirmed"
    assert rec["reproduced"] == 3
    assert rec["build_clean"] is True


def test_triage_rejects_invalid_diagnostic(tmp_path):
    (tmp_path / "crashes").mkdir()
    rec = triage.triage({"log": "", "input": b"x"},
                        tmp_path / "crashes", binary=Path("/bin/true"),
                        rebuilder=lambda: "/bin/true")
    assert rec["verdict"] == "needs_human"
    assert rec["reason"] == "invalid_diagnostic"
    assert rec["reproduced"] == 0
    assert rec["diagnostic_valid"] is False


def test_triage_clean_build_failure_never_confirmed(tmp_path):
    fix = FIX
    build = covfuzz.build(tmp_path / "b", [fix / "vuln_parser.c"], mode="main",
                          includes=[fix])
    data = b"FUZZ" + (64).to_bytes(2, "little") + b"\x01" + b"A" * 64
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    digest = __import__("hashlib").sha256(data).hexdigest()[:16]
    (crashes / f"crash-{digest}.bin").write_bytes(data)
    res = covfuzz.run_input(build["binary"], data, tmp_path / "run")
    (crashes / f"crash-{digest}.log").write_text(res["log"])

    def broken_rebuild():
        raise RuntimeError("compiler exploded")

    rec = triage.triage({"input_sha256": digest,
                         "log_path": str(crashes / f"crash-{digest}.log")},
                        crashes, binary=Path(build["binary"]),
                        rebuilder=broken_rebuild)
    assert rec["verdict"] == "needs_human"
    assert rec["reason"] == "clean_build_failed"
    assert rec["build_clean"] is False


def test_triage_reused_build_not_confirmed(tmp_path):
    fix = FIX
    build = covfuzz.build(tmp_path / "b", [fix / "vuln_parser.c"], mode="main",
                          includes=[fix])
    data = b"FUZZ" + (64).to_bytes(2, "little") + b"\x01" + b"A" * 64
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    digest = __import__("hashlib").sha256(data).hexdigest()[:16]
    (crashes / f"crash-{digest}.bin").write_bytes(data)
    res = covfuzz.run_input(build["binary"], data, tmp_path / "run")
    (crashes / f"crash-{digest}.log").write_text(res["log"])
    rec = triage.triage({"input_sha256": digest,
                         "log_path": str(crashes / f"crash-{digest}.log")},
                        crashes, binary=Path(build["binary"]))
    assert rec["verdict"] == "needs_human"
    assert rec["reason"] == "clean_build_unavailable"
    assert rec["reproduced"] == 3 and rec["build_clean"] is False


# ============================================================ P2/P3 硬化新增
# 隔离硬化：bwrap 只读根/PID ns/cap-drop/die-with-parent，unshare 补 no_new_privs
def test_isolation_detect_exposes_hardening_flags():
    info = isolation.detect()
    assert info["mode"] in {"unshare", "bwrap", "none"}
    assert {"mode", "prefix", "network", "no_new_privs", "cap_drop",
            "ro_root", "pidns"} <= set(info)
    if info["mode"] == "none":
        assert info["network"] == "host" and info["no_new_privs"] is False
    else:
        assert info["network"] == "none" and info["no_new_privs"] is True


def test_isolation_bwrap_prefix_is_hardened():
    if not isolation._bwrap_available():
        pytest.skip("bwrap unavailable")
    info = isolation.resolve("bwrap")
    prefix = info["prefix"]
    assert prefix[0] == "bwrap"
    for flag in ("--unshare-net", "--die-with-parent", "--ro-bind",
                 "--dev", "--proc"):
        assert flag in prefix, flag
    assert "--unshare-pid" in prefix
    assert prefix[prefix.index("--cap-drop") + 1] == "ALL"
    assert prefix[prefix.index("--ro-bind") + 1:][:2] == ["/", "/"]
    assert info["cap_drop"] and info["ro_root"] and info["pidns"]
    assert info["no_new_privs"] is True


def test_isolation_unshare_prefix_sets_no_new_privs():
    if not isolation._unshare_available():
        pytest.skip("unshare unavailable")
    info = isolation.resolve("unshare")
    assert info["prefix"] == ["unshare", "-rn"]
    assert info["network"] == "none"
    # unshare 自身没有 no_new_privs 开关，必须由 preexec 补
    assert info["no_new_privs"] is True
    assert isolation.preexec(info, 2.0) is not None


def test_isolation_single_hardened_execution(tmp_path):
    """一次真实隔离执行：子进程 no_new_privs=1 且断网。"""
    import subprocess as sp
    info = isolation.detect()
    if info["mode"] == "none":
        pytest.skip("no OS isolation available")
    probe = "cat /proc/self/status; cat /proc/net/dev | wc -l"
    proc = sp.run(info["prefix"] + ["sh", "-c", probe], capture_output=True,
                  text=True, timeout=20,
                  preexec_fn=isolation.preexec(info, 5.0))
    assert proc.returncode == 0, proc.stderr
    assert "NoNewPrivs:\t1" in proc.stdout
    if info["mode"] == "bwrap":
        caps = [ln for ln in proc.stdout.splitlines() if ln.startswith("CapEff:")]
        assert caps and caps[0].split()[1] == "0" * 16, caps


def test_require_isolation_still_fails_closed(monkeypatch):
    monkeypatch.setattr(isolation, "detect",
                        lambda: {"mode": "none", "prefix": [], "network": "host",
                                 "no_new_privs": False, "cap_drop": False,
                                 "ro_root": False, "pidns": False})
    with pytest.raises(RuntimeError):
        isolation.resolve("auto", require=True)
    with pytest.raises(RuntimeError):
        triage._run_once(FIX / "vuln_parser", b"FUZZ", isolation="auto",
                         require_isolation=True)


# ---------------------------------------------------------------- T2 fuzz 深度
def test_cov_rt_defines_all_cmp_callbacks():
    src = covfuzz.COV_RT_C
    for name in ("cmp1", "cmp2", "cmp4", "cmp8",
                 "const_cmp1", "const_cmp2", "const_cmp4", "const_cmp8"):
        sym = f"__sanitizer_cov_trace_{name}"
        assert sym in src, sym
    # GCC 对 switch 单独发射 trace_switch，缺了会直接链接失败
    assert "__sanitizer_cov_trace_switch(uint64_t" in src
    assert "cases[0]" in src and "cases[1]" in src
    # 回调必须免 ASAN 插桩，否则比较回调自身会递归/报错
    assert src.count("no_sanitize_address") >= 11
    assert "COV_CMP" in src


def test_trace_cmp_is_enabled_in_build(tmp_path):
    build = covfuzz.build(tmp_path / "b", [FIX / "vuln_parser.c"], mode="main",
                          includes=[FIX])
    assert any("trace-cmp" in str(part) for part in build["cmd"])


def test_run_input_records_cmp_operands(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    (d / "cmp.c").write_text(
        "#include <stdio.h>\n#include <stdint.h>\n"
        "int main(int argc, char **argv){\n"
        "  FILE *f = fopen(argv[1], \"rb\"); if (!f) return 2;\n"
        "  uint32_t v = 0; uint8_t b[4] = {0};\n"
        "  size_t n = fread(b, 1, 4, f); fclose(f);\n"
        "  if (n >= 4) v = (uint32_t)b[0] | ((uint32_t)b[1] << 8);\n"
        "  if (v == 0x1234u) puts(\"magic\");\n"
        "  if (v > 70000u) puts(\"big\");\n"
        "  return 0;\n}\n")
    build = covfuzz.build(tmp_path / "b", [d / "cmp.c"], mode="main", includes=[d])
    res = covfuzz.run_input(build["binary"], b"\x01\x02\x03\x04", tmp_path / "run")
    assert res["cmp_operands"], "const_cmp 回调应记录操作数"
    seen = {(op["a"], op["b"]) for op in res["cmp_operands"]}
    assert any(0x1234 in pair for pair in seen), seen
    assert any(op["is_const"] for op in res["cmp_operands"])


def test_dictionary_from_source_extracts_strings_and_numbers():
    tokens = covfuzz.dictionary_from_source(
        'memcpy(buf, "FUZZMAGIC", 9); if (len == 2642) return; '
        'x = 0xDEADBEEF;')
    assert b"FUZZMAGIC" in tokens
    assert b"2642" in tokens
    assert (2642).to_bytes(2, "little") in tokens
    assert b"0xdeadbeef" in tokens or b"0xDEADBEEF" in tokens
    # 0/1/2 这类常量不进字典
    assert b"0" not in tokens and b"1" not in tokens


def test_dictionary_from_operands_skips_trivial():
    ops = [{"size": 4, "is_const": True, "a": 2642, "b": 0},
           {"size": 1, "is_const": True, "a": 1, "b": 1}]
    tokens = covfuzz.dictionary_from_operands(ops)
    assert b"2642" in tokens and (2642).to_bytes(4, "little") in tokens
    assert b"0" not in tokens and b"1" not in tokens


class _ScriptedRng:
    """按脚本返回 randrange/choice 的确定性 rng，用来钉死某一条变异算子。"""

    def __init__(self, ops: list[int]):
        self.ops = list(ops)
        self.i = 0

    def randrange(self, *args):
        value = self.ops[self.i] if self.i < len(self.ops) else 0
        self.i += 1
        if len(args) == 1:
            return value % max(1, args[0])
        low, high = args
        return low + (value % max(1, high - low))

    def choice(self, seq):
        return seq[0]

    def random(self):
        return 0.0


def test_dictionary_feeds_mutator():
    """必须证明"字典变异算子"本身存在：删掉 op==9 分支这条断言就得红。"""
    seed = b"FUZZ" + (64).to_bytes(2, "little") + b"\x01" + b"A" * 64
    token = b"DEADBEEF"
    # op=9 → 取第一个字典 token → 插到位置 0
    out = covfuzz.mutate(_ScriptedRng([9, 0, 0]), seed, [seed],
                         dict_tokens=[token])
    assert out[:len(token)] == token, out[:16]
    assert out[len(token):] == seed
    # 无字典时 op==9 退化为异或，不应插入任何东西
    plain = covfuzz.mutate(_ScriptedRng([9, 0, 0]), seed, [seed])
    assert len(plain) == len(seed) and plain != out
    merged = covfuzz.merge_dictionary([b"a"], [b"b", b"a"], [b"c"])
    assert merged == [b"a", b"b", b"c"]


def test_worker_learns_dictionary_from_operands(tmp_path):
    d = tmp_path / "src"
    d.mkdir()
    (d / "cmp.c").write_text(
        "#include <stdio.h>\n#include <stdint.h>\n"
        "int main(int argc, char **argv){\n"
        "  FILE *f = fopen(argv[1], \"rb\"); if (!f) return 2;\n"
        "  uint8_t b[4] = {0}; size_t n = fread(b, 1, 4, f); fclose(f);\n"
        "  uint32_t v = (uint32_t)b[0] | ((uint32_t)b[1] << 8);\n"
        "  if (n >= 2 && v == 0x2a17u) puts(\"hit\");\n"
        "  return 0;\n}\n")
    build = covfuzz.build(tmp_path / "b", [d / "cmp.c"], mode="main", includes=[d])
    stats = tmp_path / "stats" / "w1.json"
    stats.parent.mkdir()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "seed-1").write_bytes(b"\x00\x00\x00\x00")
    covfuzz.worker(build["binary"], 1, 0.4, str(corpus), str(tmp_path / "crash"),
                   str(stats), timeout=1.0, fmt="unknown")
    data = json.loads(stats.read_text())
    assert data["execs"] > 0
    assert data["cmp_operands_seen"] > 0
    assert data["dict_tokens"] > 0


# ---------------------------------------------------------------- T1 可选 LLM 复核
def _open_crash(**over):
    crash = {"verdict": "confirmed", "access": "WRITE", "reproduced": 3,
             "repeats": 3, "build_clean": True, "diagnostic_valid": True,
             "crash_type": "heap-buffer-overflow", "function": "parse_record",
             "file": "vuln_parser.c", "line": 16, "stack_hash": "abc123"}
    crash.update(over)
    return crash


def test_review_defaults_to_heuristic(monkeypatch):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "test-key")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.delenv("VULNMAP_DISABLE_LLM", raising=False)
    called = []
    monkeypatch.setattr(agents, "_llm_json",
                        lambda *a, **k: called.append(1) or {"verdict": "excluded"})
    out = agents.review_crash(_open_crash(), use_llm=False)
    assert out.get("llm") is not True and out["llm_status"] == "disabled"
    assert out["verdict"] == "confirmed"
    assert not called, "默认关闭时不得调用 LLM"
    res = agents.run_reviews([_open_crash()], workers=1)
    assert res[0].ok and res[0].data["verdict"] == "confirmed"
    assert not called


def test_llm_review_cannot_confirm_without_clean_build(monkeypatch):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "test-key")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.setattr(agents, "_llm_json",
                        lambda *a, **k: {"verdict": "confirmed", "reason": "looks bad",
                                         "_usage": {"prompt_tokens": 3}})
    out = agents.review_crash(_open_crash(build_clean=False, verdict="needs_human"),
                              use_llm=True)
    assert out["verdict"] == "needs_human"
    assert out["llm_downgraded"] is True
    assert out["llm_verdict"] == "confirmed"
    assert out["llm_gate"] == "clean_build_unavailable"


def test_llm_review_cannot_confirm_invalid_diagnostic(monkeypatch):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "test-key")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.setattr(agents, "_llm_json",
                        lambda *a, **k: {"verdict": "confirmed", "reason": "x"})
    out = agents.review_crash(_open_crash(diagnostic_valid=False,
                                          verdict="needs_human"), use_llm=True)
    assert out["verdict"] == "needs_human"
    assert out["llm_downgraded"] is True
    assert "confirmed" not in out["verdict"]


def test_review_gate_requires_explicit_diagnostic_valid(monkeypatch):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "test-key")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.setattr(agents, "_llm_json",
                        lambda *a, **k: {"verdict": "confirmed", "reason": "x"})
    base = _open_crash()
    for value in (None, "missing"):
        crash = dict(base)
        if value == "missing":
            crash.pop("diagnostic_valid")
        else:
            crash["diagnostic_valid"] = value
        gate_ok, why = agents.review_gate(crash)
        assert not gate_ok and why == "invalid_diagnostic"
        out = agents.review_crash(crash, use_llm=True)
        assert out["verdict"] == "needs_human"
        assert out["llm_downgraded"] is True


def test_llm_review_clamped_to_evidence_ceiling(monkeypatch):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "test-key")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.setattr(agents, "_llm_json",
                        lambda *a, **k: {"verdict": "confirmed", "reason": "x"})
    # 读型问题 3/3：规则上限是 weakened，LLM 不得提成 confirmed
    out = agents.review_crash(_open_crash(access="READ"), use_llm=True)
    assert out["verdict"] == "weakened"
    assert out["llm_downgraded"] is True


def test_llm_review_confirm_allowed_when_gate_open(monkeypatch):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "test-key")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.setattr(agents, "_llm_json",
                        lambda *a, **k: {"verdict": "confirmed",
                                         "reason": "写越界 3/3",
                                         "_usage": {"prompt_tokens": 12,
                                                    "completion_tokens": 4}})
    out = agents.review_crash(_open_crash(), use_llm=True)
    assert out["verdict"] == "confirmed"
    assert out["llm_downgraded"] is False
    assert out["llm_gate"] == "gate_open"
    assert out["llm_usage"]["prompt_tokens"] == 12


def test_llm_review_falls_back_on_invalid_output(monkeypatch):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "test-key")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.setattr(agents, "_llm_json",
                        lambda *a, **k: {"verdict": "totally-bogus"})
    out = agents.review_crash(_open_crash(), use_llm=True)
    assert out["verdict"] == "confirmed"      # 回退规则复核的结果
    assert out.get("llm_review_failed") is True
    assert out["llm_status"] == "invalid_or_timeout"


def test_campaign_llm_review_off_by_default(tmp_path):
    out = tmp_path / "o"
    summary = campaign.run(FIX, out, seconds=1, max_sites=2, workers=1,
                           use_llm=False, db_path=tmp_path / "c.db")
    review = summary["analysis"]["review"]
    assert review["use_llm_review"] is False
    assert review["mode"] == "heuristic"
    assert review["llm_reviews"] == 0
    assert review["confirmed"] >= 1
    assert summary["dictionary_tokens"] > 0
    assert (out / "dictionary.json").exists()


def test_campaign_llm_review_on_records_usage(tmp_path, monkeypatch):
    """开启 use_llm_review 的接线：只复核 triage 结果，且 usage 落 reviews.json。"""
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "test-key")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.delenv("VULNMAP_DISABLE_LLM", raising=False)
    calls = []

    def fake_review(prompt, timeout=None, **kwargs):
        calls.append(prompt)
        return {"verdict": "confirmed", "reason": "独立判断：写越界可确认",
                "_usage": {"prompt_tokens": 41, "completion_tokens": 9},
                "_attempts": 1}

    monkeypatch.setattr(agents, "_llm_json", fake_review)
    out = tmp_path / "o"
    summary = campaign.run(FIX, out, seconds=1, max_sites=2, workers=1,
                           use_llm=False, use_llm_review=True,
                           db_path=tmp_path / "c.db")
    review = summary["analysis"]["review"]
    assert review["use_llm_review"] is True
    assert review["mode"] == "llm"
    assert review["llm_reviews"] >= 1
    assert calls, "开启后必须真的调 LLM"
    reviews = json.loads((out / "reviews.json").read_text())
    assert reviews and all(r.get("llm") for r in reviews)
    assert reviews[0]["llm_usage"]["prompt_tokens"] == 41
    # 复核只能在门禁内确认：写型 3/3 + 干净构建才允许 confirmed
    assert all(r["verdict"] != "confirmed" or r["build_clean"] is True
               for r in reviews)
    # 台账与 reviews.json 的 verdict 必须一致（不得各说各话）
    db = json.loads(json.dumps(summary["db"]))
    assert db["review"] == len(reviews)


def test_cli_exposes_llm_review_flag():
    import subprocess as sp
    proc = sp.run([__import__("sys").executable, str(ROOT / "bin" / "discover.py"),
                   "--help"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0
    assert "--llm-review" in proc.stdout


# ---------------------------------------------------------------- T4 LLM 运营化
class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _llm_env(monkeypatch, **env):
    monkeypatch.setenv("DISCOVERY_LLM_API_KEY", "sk-SECRET-rot13")
    monkeypatch.delenv("DISCOVERY_LLM_DISABLED", raising=False)
    monkeypatch.delenv("VULNMAP_DISABLE_LLM", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, str(value))


def test_llm_json_retries_and_records_usage(monkeypatch):
    _llm_env(monkeypatch, DISCOVERY_LLM_RETRIES=1)
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(timeout)
        if len(calls) == 1:
            raise OSError("connection reset")
        return _Resp({"choices": [{"message": {"content": json.dumps(
            {"hypothesis": "h", "confidence": 0.5,
             "citations": ["vuln_parser.c:16"]})}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7,
                      "total_tokens": 18}})

    monkeypatch.setattr(agents.urllib.request, "urlopen", fake_urlopen)
    data = agents._llm_json("prompt")
    assert data is not None
    assert data["_attempts"] == 2
    assert data["_usage"] == {"prompt_tokens": 11, "completion_tokens": 7,
                              "total_tokens": 18}
    assert len(calls) == 2


def test_llm_json_honours_timeout_and_gives_up(monkeypatch):
    _llm_env(monkeypatch, DISCOVERY_LLM_RETRIES=2, DISCOVERY_LLM_TIMEOUT=1.5)
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append(timeout)
        raise TimeoutError("slow")

    monkeypatch.setattr(agents.urllib.request, "urlopen", fake_urlopen)
    assert agents._llm_json("prompt") is None
    assert seen == [1.5, 1.5, 1.5]      # 1 + retries 次尝试，每次都带配置的超时


def test_llm_usage_recorded_in_hypothesis_without_key(monkeypatch):
    _llm_env(monkeypatch)
    monkeypatch.setattr(agents, "_llm_json", lambda *a, **k: {
        "hypothesis": "len from input reaches memcpy",
        "confidence": 0.7, "citations": ["vuln_parser.c:16"],
        "_usage": {"prompt_tokens": 21, "completion_tokens": 5},
        "_attempts": 1})
    site = {"id": "s1", "function": "parse_record", "file": "vuln_parser.c",
            "line": 16, "callee": "memcpy", "category": "copy",
            "args": "buf, data + 8, len", "controlled": True, "reachable": True}
    hyp = agents.analyze_site(site, FIX)
    assert hyp["llm_usage"]["prompt_tokens"] == 21
    blob = json.dumps(hyp, ensure_ascii=False)
    assert "sk-SECRET-rot13" not in blob
    assert "SECRET" not in blob
    assert "key" not in hyp


def test_llm_rate_limit_enforces_gap(monkeypatch):
    _llm_env(monkeypatch, DISCOVERY_LLM_RATE_LIMIT=0.05)
    monkeypatch.setattr(agents, "_RATE_STATE", {"last": 0.0})
    first = agents._rate_limit_wait()
    second = agents._rate_limit_wait()
    assert first == 0.0
    assert second >= 0.03, second
    monkeypatch.setenv("DISCOVERY_LLM_RATE_LIMIT", "0")
    assert agents._rate_limit_wait() == 0.0


# ---------------------------------------------------------------- T6 init-target
def test_targetspec_prebuilt_archives_and_reasons(tmp_path):
    d = tmp_path / "lib"
    (d / ".libs").mkdir(parents=True)
    (d / "configure").write_text("#!/bin/sh\n")
    (d / ".libs" / "libfoo.a").write_bytes(b"!<arch>\n")
    spec = targetspec.autodetect(d)
    assert spec["needs_review"] is True
    assert any(p.endswith(".libs/libfoo.a") for p in spec["build"]["extra_objs"])
    assert spec["build"]["extra_objs_glob"] == "**/.libs/*.a"
    reasons = targetspec.needs_review_reasons(spec)
    assert len(reasons) >= 2
    assert any("configure" in r for r in reasons)
    assert "needs_review_reasons" in targetspec.dump(spec)


def test_targetspec_never_executes_build_system(tmp_path, monkeypatch):
    """init-target 只做静态识别：任何 configure/Makefile 都不执行。"""
    import subprocess as sp

    def boom(*a, **k):
        raise AssertionError("autodetect must not execute anything")

    monkeypatch.setattr(sp, "run", boom)
    monkeypatch.setattr(sp, "Popen", boom)
    monkeypatch.setattr(sp, "check_output", boom)
    monkeypatch.setattr(sp, "call", boom)
    monkeypatch.setattr(sp, "check_call", boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(os, "popen", boom)
    d = tmp_path / "proj"
    d.mkdir()
    (d / "configure").write_text("#!/bin/sh\nexit 0\n")
    (d / "Makefile").write_text("all:\n\ttrue\n")
    (d / "src.c").write_text("int main(void){return 0;}\n")
    spec = targetspec.autodetect(d)
    assert spec["build"]["mode"] in {"main", "api"}
    assert spec["needs_review"] is True
    assert targetspec.needs_review_reasons(spec)


def test_bwrap_readonly_root_still_writes_coverage(tmp_path):
    """只读根下必须为工作目录开可写绑定，否则覆盖率静默丢失（盲 fuzz）。"""
    if not isolation._bwrap_available():
        pytest.skip("bwrap unavailable")
    build = covfuzz.build(tmp_path / "b", [FIX / "vuln_parser.c"], mode="main",
                          includes=[FIX])
    seed = b"FUZZ" + (64).to_bytes(2, "little") + b"\x01" + b"A" * 64
    res = covfuzz.run_input(build["binary"], seed, tmp_path / "run-bwrap",
                            isolation="bwrap")
    assert res["isolation"] == "bwrap" and res["ro_root"] is True
    assert res["crash"] is True              # 只读根不影响检测崩溃
    assert len(res["bitmap"]) == covfuzz.BITMAP_BYTES, "覆盖位图必须落盘"
    assert Path(res["pcs_path"]).exists(), "PC 数组必须落盘"
    assert res["cmp_operands"], "比较操作数必须落盘"
    prefix = isolation.prefix_for(isolation.resolve("bwrap"), tmp_path)
    assert "--bind" in prefix


def test_prefix_for_adds_separator_and_guards_binds():
    if not isolation._unshare_available():
        pytest.skip("unshare unavailable")
    info = isolation.resolve("unshare")
    prefix = isolation.prefix_for(info, "/tmp")
    # unshare 不需要可写绑定，但必须以 "--" 结尾，避免目标参数被当成隔离器选项
    assert prefix == info["prefix"] + ["--"]
    assert "--bind" not in prefix
    if isolation._bwrap_available():
        bwrap = isolation.resolve("bwrap")
        with pytest.raises(ValueError):
            isolation.prefix_for(bwrap, "/")          # 只读根不能被自己改成可写
        good = isolation.prefix_for(bwrap, Path("/tmp"))
        assert good[-1] == "--" and "--bind" in good


# ============================================================ P4 构建自动化
# configure/cmake 解析 + 隔离构建（bwrap 只读源码 + 可写 build 目录 + 日志落盘）
def _fake_autotools_project(tmp_path, *, exit_code: int = 0, tag: str = "ok"):
    """最小 autotools 风格项目：configure 在 CWD 生成 Makefile，make 出 libfoo.a。"""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "foo.c").write_text("int foo(void) { return 42; }\n")
    (proj / "configure").write_text(f"""#!/bin/sh
set -e
srcdir=$(cd "$(dirname "$0")" && pwd)
echo "configure: srcdir=$srcdir CFLAGS=$CFLAGS" > config.log
if [ "{exit_code}" != "0" ]; then
  echo "deliberate configure failure ({tag})" >&2
  exit {exit_code}
fi
{{
  printf 'CC = %s\\n' "${{CC:-gcc}}"
  printf 'CFLAGS = %s\\n' "$CFLAGS"
  printf 'all: libfoo.a\\n'
  printf 'foo.o: %s/foo.c\\n' "$srcdir"
  printf '\\t$(CC) $(CFLAGS) -c %s/foo.c -o foo.o\\n' "$srcdir"
  printf 'libfoo.a: foo.o\\n'
  printf '\\tar rcs libfoo.a foo.o\\n'
}} > Makefile
echo "configure: wrote Makefile"
""")
    (proj / "configure").chmod(0o755)
    return proj


def _iso_mode_for_build():
    return "bwrap" if isolation._bwrap_available() else None


def test_targetspec_build_system_yaml_parsing(tmp_path):
    """build.system 的取值解析：显式值保留，非法值报错，auto 落到布局探测。"""
    d = tmp_path / "t"
    d.mkdir()
    (d / "configure").write_text("#!/bin/sh\n")
    (d / "target.yaml").write_text(
        "name: t\nroot: .\nsources: []\nincludes: []\n"
        "build:\n  mode: api\n  system: cmake\n")
    spec = targetspec.load(d / "target.yaml")
    assert spec["build"]["system"] == "cmake"
    assert targetspec.resolve_build_system(spec) == "cmake"

    (d / "target.yaml").write_text("build:\n  mode: api\n  system: meson\n")
    with pytest.raises(ValueError):
        targetspec.load(d / "target.yaml")

    (d / "target.yaml").write_text("build:\n  mode: api\n")
    spec = targetspec.load(d / "target.yaml")
    assert spec["build"]["system"] == "auto"
    # auto 优先跟随布局（configure 存在），没有构建系统时按 mode 兜底
    assert targetspec.resolve_build_system(spec) == "configure"
    spec["root"] = str(tmp_path / "empty")
    Path(spec["root"]).mkdir()
    spec["build"]["mode"] = "main"
    assert targetspec.resolve_build_system(spec) == "main"


def test_targetspec_detect_build_system_layouts(tmp_path):
    """configure/cmake 探测：configure 优先，只有 CMakeLists 时判 cmake。"""
    a = tmp_path / "a"
    a.mkdir()
    assert targetspec.detect_build_system(a) is None
    (a / "CMakeLists.txt").write_text("project(x)\n")
    assert targetspec.detect_build_system(a) == "cmake"
    assert targetspec.autodetect(a)["build"]["system"] == "cmake"
    (a / "configure").write_text("#!/bin/sh\n")
    assert targetspec.detect_build_system(a) == "configure"
    assert targetspec.autodetect(a)["build"]["system"] == "configure"


def test_build_library_configure_isolated_and_logged(tmp_path):
    """真实跑一遍隔离构建：日志落盘、归档被收集、源码树保持干净。"""
    if _iso_mode_for_build() is None:
        pytest.skip("bwrap unavailable")
    proj = _fake_autotools_project(tmp_path)
    before = {p.name for p in proj.iterdir()}
    out = tmp_path / "work"
    res = targetspec.build_library(
        {"root": str(proj), "sources": [], "includes": [],
         "build": {"system": "configure"}}, out, isolation="bwrap")
    assert res["ok"] and res["built"] and res["system"] == "configure"
    assert res["isolation"] == "bwrap"
    assert res["source_copied"] is False
    assert Path(res["builddir"]).is_dir() and Path(res["builddir"]) != proj
    archives = [Path(p) for p in res["archives"]]
    assert archives and archives[0].name == "libfoo.a"
    assert Path(res["log"]).is_file()
    log = Path(res["log"]).read_text()
    assert "=== step:" in log and "rc=0" in log
    # CFLAGS 必须带 ASAN/coverage（库代码也要被判崩溃并纳入覆盖）
    assert "-fsanitize=address" in log and "-fsanitize-coverage=trace-pc" in log
    # 源码树只读：构建不往项目里写文件
    assert {p.name for p in proj.iterdir()} == before


def test_build_library_failure_is_loud(tmp_path):
    """configure 非零退出 → BuildError，日志落盘且不返回空归档。"""
    if _iso_mode_for_build() is None:
        pytest.skip("bwrap unavailable")
    proj = _fake_autotools_project(tmp_path, exit_code=7, tag="broken")
    out = tmp_path / "work"
    with pytest.raises(targetspec.BuildError) as exc:
        targetspec.build_library({"root": str(proj), "sources": [], "includes": [],
                                  "build": {"system": "configure"}}, out,
                                 isolation="bwrap")
    err = exc.value
    assert err.log_path and Path(err.log_path).is_file()
    assert "rc=7" in Path(err.log_path).read_text()
    assert "deliberate configure failure" in str(err)
    assert err.result["archives"] == [] and err.result["built"] is False


def test_build_library_fails_closed_without_bwrap(tmp_path, monkeypatch):
    """bwrap 不可用 → 直接失败，绝不静默落到宿主执行构建脚本。"""
    proj = _fake_autotools_project(tmp_path)
    marker = tmp_path / "EXECUTED"
    (proj / "configure").write_text(
        "#!/bin/sh\ntouch %s\nexit 0\n" % marker)
    (proj / "configure").chmod(0o755)
    monkeypatch.setattr(isolation, "_bwrap_available", lambda: False)
    with pytest.raises(targetspec.BuildError) as exc:
        targetspec.build_library({"root": str(proj), "sources": [], "includes": [],
                                  "build": {"system": "configure"}},
                                 tmp_path / "work", isolation="bwrap")
    assert "isolation" in str(exc.value).lower()
    assert not marker.exists(), "隔离不可用时不得执行目标构建脚本"


def test_build_library_copies_configured_tree(tmp_path):
    """源树已 in-tree 配置（config.status）→ 复制到隔离目录再 out-of-tree 构建。"""
    if _iso_mode_for_build() is None:
        pytest.skip("bwrap unavailable")
    proj = _fake_autotools_project(tmp_path)
    (proj / "config.status").write_text("# already configured\n")
    res = targetspec.build_library(
        {"root": str(proj), "sources": [], "includes": [],
         "build": {"system": "configure"}}, tmp_path / "work", isolation="bwrap")
    assert res["source_copied"] is True
    assert res["source_dir"] != str(proj)
    assert Path(res["source_dir"]).is_dir()
    assert not (Path(res["source_dir"]) / "config.status").exists()
    assert res["archives"] and Path(res["archives"][0]).is_file()
    assert (proj / "config.status").exists(), "原树不得被修改"


def test_build_library_cmake_command_shape(tmp_path, monkeypatch):
    """cmake 分支：-S/-B、ASAN+coverage CFLAGS、静态库开关与归档收集。

    用假 cmake 只验证命令形状（本机无 cmake；真实 cmake 需要工具链镜像）。
    """
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "CMakeLists.txt").write_text("project(foo C)\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "cmake"
    fake.write_text("""#!/bin/sh
prev=""
build=""
for a in "$@"; do
  if [ "$prev" = "-B" ]; then build="$a"; fi
  prev="$a"
done
[ -n "$build" ] || build="."
echo "ARGS: $*" >> "$build/cmake-args.txt"
case "$1" in
  -S) mkdir -p "$build"; printf '!<arch>\\n' > "$build/libfoo.a" ;;
  --build) printf 'built\\n' >> "$build/build.txt" ;;
esac
exit 0
""")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    iso = _iso_mode_for_build() or "none"
    res = targetspec.build_library(
        {"root": str(proj), "sources": [], "includes": [],
         "build": {"system": "cmake"}}, tmp_path / "work", isolation=iso,
        require_isolation=(iso != "none"))
    assert res["system"] == "cmake" and res["built"]
    calls = (tmp_path / "work" / "build-cmake" / "cmake-args.txt").read_text()
    assert f"-S {proj}" in calls and "-B" in calls
    assert "-DCMAKE_C_FLAGS=-g -O1 -fno-omit-frame-pointer -fsanitize=address" in calls
    assert "-fsanitize-coverage=trace-pc,trace-cmp" in calls
    assert "-DBUILD_SHARED_LIBS=OFF" in calls
    assert any(Path(p).name == "libfoo.a" for p in res["archives"])


def test_build_library_direct_modes_skip_build(tmp_path):
    """mode=main/api 不需要外部构建系统：不执行任何东西，只返回预构建静态库。"""
    proj = tmp_path / "proj"
    (proj / ".libs").mkdir(parents=True)
    (proj / ".libs" / "libx.a").write_bytes(b"!<arch>\n")
    res = targetspec.build_library(
        {"root": str(proj), "sources": [], "includes": [], "build": {"mode": "main"}},
        tmp_path / "work")
    assert res["system"] == "main" and res["built"] is False and res["ok"] is True
    assert [Path(p).name for p in res["archives"]] == ["libx.a"]
    assert res["commands"] == []


def test_build_cflags_and_build_spec_override(tmp_path):
    """CFLAGS 组成 + 隔离构建产物替换 yaml 里的 extra_objs。"""
    flags = targetspec.build_cflags({"cflags": ["-DFOO=1"], "shared": True})
    assert "-fsanitize=address" in flags and "-DFOO=1" in flags
    assert any(f.startswith("-fsanitize-coverage=") for f in flags)
    lean = targetspec.build_cflags({"asan": False, "coverage": False})
    assert not any("sanitize" in f for f in lean)
    spec = {"root": str(tmp_path), "sources": ["a.c"], "includes": ["."],
            "build": {"mode": "main", "extra_objs": ["old.a"], "libs": ["-lz"]}}
    assert targetspec.to_build_spec(spec, tmp_path / "w")["extra_objs"] == ["old.a"]
    over = targetspec.to_build_spec(spec, tmp_path / "w", extra_objs=["new/libfoo.a"])
    assert over["extra_objs"] == ["new/libfoo.a"] and over["libs"] == ["-lz"]


# ============================================================ container 隔离
# 容器模式：显式选择，不可用时明确报错；bwrap 仍是默认
def test_isolation_container_mode_is_explicit_not_auto():
    assert "container" in isolation.MODES
    assert isolation.resolve("auto")["mode"] in {"bwrap", "unshare", "none"}
    assert isolation.detect()["mode"] != "container"


def test_isolation_container_unavailable_engine_is_explicit(monkeypatch):
    monkeypatch.setattr(isolation, "container_engine", lambda: None)
    problem = isolation.container_problem()
    assert problem and "container engine" in problem
    with pytest.raises(RuntimeError, match="container"):
        isolation.resolve("container")
    with pytest.raises(RuntimeError):
        isolation._fixed("container")


def test_isolation_container_unavailable_image_is_explicit(monkeypatch):
    monkeypatch.setattr(isolation, "container_engine", lambda: "docker")
    monkeypatch.setenv(isolation.CONTAINER_IMAGE_ENV, "vulnmap/missing:test")
    monkeypatch.setattr(isolation, "_image_present", lambda engine, image: False)
    problem = isolation.container_problem()
    assert problem and "image" in problem and "vulnmap/missing:test" in problem
    with pytest.raises(RuntimeError, match="image"):
        isolation.resolve("container")


def test_isolation_container_prefix_is_hardened(monkeypatch):
    monkeypatch.setattr(isolation, "container_engine", lambda: "docker")
    monkeypatch.setattr(isolation, "_image_present", lambda engine, image: True)
    monkeypatch.setenv(isolation.CONTAINER_IMAGE_ENV, "vulnmap/base:test")
    info = isolation.resolve("container")
    assert info["mode"] == "container" and info["engine"] == "docker"
    assert info["image"] == "vulnmap/base:test"
    assert info["network"] == "none"
    assert info["cap_drop"] and info["ro_root"] and info["pidns"]
    assert info["no_new_privs"] is True
    prefix = info["prefix"]
    assert prefix[0] == "docker"
    assert prefix[prefix.index("--network") + 1] == "none"
    assert "--read-only" in prefix
    assert prefix[prefix.index("--cap-drop") + 1] == "ALL"
    assert prefix[prefix.index("--security-opt") + 1] == "no-new-privileges"
    assert "--pids-limit" in prefix and "--tmpfs" in prefix
    assert "--rm" in prefix


def test_isolation_container_prefix_binds_and_env(tmp_path, monkeypatch):
    """容器前缀：可写 workdir/只读目标绑定、-w 固定 cwd、-e 透传、镜像在末尾。"""
    monkeypatch.setattr(isolation, "container_engine", lambda: "docker")
    monkeypatch.setattr(isolation, "_image_present", lambda engine, image: True)
    monkeypatch.setenv(isolation.CONTAINER_IMAGE_ENV, "vulnmap/base:test")
    info = isolation.resolve("container")
    work = tmp_path / "work"
    work.mkdir()
    ro = tmp_path / "src"
    ro.mkdir()
    (ro / "a.c").write_text("int main(void){return 0;}\n")
    prefix = isolation.prefix_for(info, work, read_only=[ro],
                                  workdir=str(work), env=["ASAN_OPTIONS"])
    assert f"{work.resolve()}:{work.resolve()}:rw" in prefix
    assert f"{ro.resolve()}:{ro.resolve()}:ro" in prefix
    assert prefix[prefix.index("-w") + 1] == str(work.resolve())
    assert prefix[prefix.index("-e") + 1] == "ASAN_OPTIONS"
    assert prefix[-1] == "vulnmap/base:test"
    assert "--" not in prefix, "docker run 不需要 -- 分隔符"
    # 已可写绑定的目录不再重复只读挂载
    dup = isolation.prefix_for(info, work, read_only=[work])
    assert dup.count(f"{work.resolve()}:{work.resolve()}:rw") == 1
    assert f"{work.resolve()}:{work.resolve()}:ro" not in dup
    for bad in ("/", str(tmp_path / "missing")):
        with pytest.raises(ValueError):
            isolation.prefix_for(info, bad)
    # 容器模式不改 RLIMIT_CPU/NOFILE（只 setsid + core=0）
    assert isolation.preexec(info, 3.0) is not None


def test_isolation_container_real_probe(tmp_path):
    """真实容器探测：断网 + 只读根 + cap-drop + no-new-privileges。"""
    import subprocess as sp
    problem = isolation.container_problem()
    if problem:
        pytest.skip(problem)
    info = isolation.resolve("container")
    work = tmp_path / "work"
    work.mkdir()
    script = ("cat /proc/self/status; ls /sys/class/net; "
              "touch /vulnmap-root-probe 2>&1 || echo ROOT_READONLY; "
              "touch /tmp/vulnmap-probe && echo TMPFS_WRITABLE")
    cmd = (isolation.prefix_for(info, work, workdir=str(work))
           + ["sh", "-c", script])
    proc = sp.run(cmd, capture_output=True, text=True, timeout=180,
                  preexec_fn=isolation.preexec(info, 60))
    assert proc.returncode == 0, proc.stderr
    status = proc.stdout
    assert "NoNewPrivs:\t1" in status
    caps = [ln for ln in status.splitlines() if ln.startswith("CapEff:")]
    assert caps and caps[0].split()[1] == "0" * 16, caps
    assert "ROOT_READONLY" in status, "根文件系统必须只读"
    assert "TMPFS_WRITABLE" in status, "/tmp 必须可写（只读根下的落盘点）"
    assert "eth0" not in status, "容器内不应有外网设备"
    assert "lo" in status


def test_cli_isolation_choices_include_container():
    """CLI 必须能选 container（不可用时由 resolve 明确报错，不是 argparse 拒绝）。"""
    import subprocess as sp
    import sys
    for script in ("discover.py", "covfuzz.py"):
        proc = sp.run([sys.executable, str(ROOT / "bin" / script), "--help"],
                      capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0
        assert "container" in proc.stdout, script


# ---------------------------------------------------------------- setup_error
def test_run_setup_error_marks_broken_isolation_run():
    """隔离里目标没起来（缺动态库/绑定路径错）→ 显式 setup_error，不是崩溃、不是 0 覆盖。"""
    assert covfuzz.run_setup_error(127, "x: error while loading shared libraries: "
                                        "libasan.so.6: cannot open shared object file",
                                   False, False)
    assert covfuzz.run_setup_error(126, "sh: 1: ./t: Permission denied", False, False)
    assert covfuzz.run_setup_error(127, "", False, False)
    # 正常执行 / 崩溃 / 超时都不算 setup_error
    assert covfuzz.run_setup_error(0, "", False, False) is None
    assert covfuzz.run_setup_error(1, "AddressSanitizer: heap-buffer-overflow",
                                   True, False) is None
    assert covfuzz.run_setup_error(None, "", False, True) is None


def test_run_input_records_setup_error(tmp_path):
    """真跑一次：伪二进制报缺库 → run_input 给出 setup_error，且 crash 仍为 False。"""
    fake = tmp_path / "broken-runtime"
    fake.write_text("#!/bin/sh\necho 'error while loading shared libraries: "
                    "libasan.so.6' >&2\nexit 127\n")
    fake.chmod(0o755)
    res = covfuzz.run_input(fake, b"x", tmp_path / "run")
    assert res["crash"] is False
    assert res["setup_error"] and "shared libraries" in res["setup_error"]
    assert res["returncode"] == 127


def test_aggregate_sums_setup_errors(tmp_path):
    stats_dir = tmp_path / "stats"
    stats_dir.mkdir()
    (stats_dir / "w0.json").write_text(json.dumps(
        {"execs": 3, "crashes": 0, "timeouts": 0, "new_coverage": 0,
         "setup_errors": 3, "setup_error": "run_setup_failed (rc=127): x"}))
    (stats_dir / "w1.json").write_text(json.dumps(
        {"execs": 5, "crashes": 0, "timeouts": 0, "new_coverage": 1,
         "setup_errors": 0}))
    agg = covfuzz.aggregate(stats_dir, tmp_path / "crashes", tmp_path / "corpus")
    assert agg["setup_errors"] == 3
    assert agg["setup_error"].startswith("run_setup_failed")
    assert agg["execs"] == 8
