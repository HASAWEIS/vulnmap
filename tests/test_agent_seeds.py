from pathlib import Path
from agent.discovery import agents

def test_propose_seeds_json():
    seeds = agents.propose_seeds({"function":"cJSON_Minify","file":"cJSON.c","line":1}, Path("/tmp"))
    assert seeds and all(isinstance(s, bytes) for s in seeds)
    assert any(b":" in s for s in seeds)
