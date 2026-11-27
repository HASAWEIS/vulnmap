"""自主闭环运行包：冻结输入、留痕干预、工件溯源、预算。

三类结果的定义（与 COURSE 判据分离，只描述"谁做了什么"）：

- manual_baseline : 关键输入由人准备，脚本执行并留档
- agent_assisted  : 人有介入（提供输入/提示/中途修正），Agent 完成部分步骤
- agent_autonomous: 人只给任务、权限、预算、验收条件，无关键决策介入

本模块只写/读事实，不做判定；判定在 classify.py 与 verify.py。
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time

SCHEMA = "vulnmap.autonomy.runpack.v1"


def sha_file(p) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _dump(p, obj) -> None:
    p = pathlib.Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def _load(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))


class RunPack:
    """一个运行包 = 一个目录。

    目录结构：
      run.json            身份、预算、状态
      frozen_inputs.json  开始时给定/可见材料的哈希（冻结）
      interventions.jsonl 人工介入流水（append-only）
      artifacts.jsonl     工件流水（append-only，含哈希与产生时刻）
      result.json         Agent 提交的结果（只读校验，不参与判定）
    """

    def __init__(self, root):
        self.root = pathlib.Path(root)

    # ---------------------------------------------------------------- 创建
    def init(self, *, run_id, task_id, budget, agent_visible, base_dir=None):
        self.root.mkdir(parents=True, exist_ok=True)
        started = time.time()
        _dump(self.root / "run.json", {
            "schema": SCHEMA, "run_id": run_id, "task_id": task_id,
            "started_at": started, "budget": budget,
            "state": "running", "agent_visible": list(agent_visible),
            "base_dir": str(pathlib.Path(base_dir) if base_dir else self.root.parent),
        })
        frozen = {"schema": SCHEMA + ".frozen", "run_id": run_id, "files": {}}
        base = pathlib.Path(base_dir) if base_dir else self.root.parent
        for rel in agent_visible:
            p = base / rel
            frozen["files"][rel] = {"sha256": sha_file(p), "size": p.stat().st_size}
        _dump(self.root / "frozen_inputs.json", frozen)
        (self.root / "interventions.jsonl").write_text("", encoding="utf-8")
        (self.root / "artifacts.jsonl").write_text("", encoding="utf-8")
        (self.root / "observations.jsonl").write_text("", encoding="utf-8")
        return self

    # ---------------------------------------------------------------- 留痕
    def intervention(self, *, kind, detail, at=None):
        rec = {"ts": at if at is not None else time.time(), "kind": kind,
               "detail": detail}
        with open(self.root / "interventions.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def observe(self, *, kind, detail):
        """记录一次观测（执行解析器、读日志等），用于预算核验。"""
        rec = {"ts": time.time(), "kind": kind, "detail": detail}
        with open(self.root / "observations.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + chr(10))
        return rec

    def observations(self):
        p = self.root / "observations.jsonl"
        if not p.is_file():
            return []
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]

    def artifact(self, *, name, path, producer):
        p = pathlib.Path(path)
        try:
            rel = p.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            rel = str(p)
        rec = {"ts": time.time(), "name": name, "path": rel, "producer": producer,
               "sha256": sha_file(p), "size": p.stat().st_size}
        with open(self.root / "artifacts.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def result(self, payload):
        _dump(self.root / "result.json", payload)

    def finish(self, state="finished"):
        run = _load(self.root / "run.json")
        run["state"] = state
        run["finished_at"] = time.time()
        _dump(self.root / "run.json", run)

    # ---------------------------------------------------------------- 读取
    def run(self):
        return _load(self.root / "run.json")

    def frozen(self):
        return _load(self.root / "frozen_inputs.json")

    def interventions(self):
        p = self.root / "interventions.jsonl"
        if not p.is_file():
            return []
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]

    def artifacts(self):
        p = self.root / "artifacts.jsonl"
        if not p.is_file():
            return []
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]

    def result_or_none(self):
        p = self.root / "result.json"
        return _load(p) if p.is_file() else None
