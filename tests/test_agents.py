from pathlib import Path
from agent.discovery import agents

ROOT = Path(__file__).resolve().parent.parent

def test_parallel_analysis():
    sites = [{"function":"f","file":"fixtures/discovery/vuln_parser.c","line":13,
              "callee":"memcpy","controlled":True,"reachable":True} for _ in range(8)]
    res = agents.run_analysis(sites, ROOT, workers=4, timeout=10)
    assert len(res) == 8
    assert all(r.ok for r in res)
    assert all(r.data["citations"] for r in res)

def test_review_classification():
    base = {"access":"WRITE","reproduced":3,"verdict":"confirmed",
            "stack_hash":"x","build_clean":True}
    assert agents.heuristic_review(base, ROOT)["verdict"] == "confirmed"
    read = {"access":"READ","reproduced":3,"verdict":"confirmed",
            "build_clean":True}
    assert agents.heuristic_review(read, ROOT)["verdict"] == "weakened"
    none = {"access":None,"reproduced":0,"verdict":"excluded"}
    assert agents.heuristic_review(none, ROOT)["verdict"] == "excluded"
    dirty = dict(base, build_clean=False)
    assert agents.heuristic_review(dirty, ROOT)["verdict"] == "needs_human"
    invalid = dict(base, diagnostic_valid=False)
    assert agents.heuristic_review(invalid, ROOT)["verdict"] == "needs_human"
