"""预算：进入即消耗一轮，退出结算耗时；收尾轮次不可被探索吃掉。

裁定口径（审查方 2025-11-09）：
- `__enter__` 成功后立即 `turns_used += 1`：进入即消耗，这样“最后一轮正好用尽”
  能正确记录，也能拦住第 max+1 次进入。
- `check_time()` 抛错的那轮**照常计入**（本轮确实被用掉了）。
- `__enter__` 因耗尽而抛错的那次不计数（没有进入，也没有消耗）。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .contracts import Budget
from .errors import BudgetExhausted
from .store import Store


@dataclass
class BudgetLease:
    store: Store
    run_id: str
    stage: str
    budget: Budget
    _started: float = 0.0
    _entered: bool = False
    turns: int = field(default=0)

    def __enter__(self) -> "BudgetLease":
        row = self.store.budget_row(self.run_id, self.stage, self.budget.max_turns)
        used = int(row["turns_used"] or 0)
        if used >= self.budget.max_turns:
            raise BudgetExhausted(f"stage {self.stage} turns exhausted ({used}/{self.budget.max_turns})")
        # 进入即消耗：先记账再执行
        self.turns = used + 1
        self.store.set_turns_used(self.run_id, self.stage, self.turns,
                                  float(row["seconds_used"] or 0.0))
        self._started = time.monotonic()
        self._entered = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self._entered:
            return None
        # 无论正常返回、超时抛错还是阶段异常，本轮耗时都结算
        elapsed = time.monotonic() - self._started
        row = self.store.budget_row(self.run_id, self.stage, self.budget.max_turns)
        self.store.set_turns_used(self.run_id, self.stage, int(row["turns_used"] or self.turns),
                                  float(row["seconds_used"] or 0.0) + elapsed)
        return None

    def check_time(self) -> None:
        if time.monotonic() - self._started > self.budget.timeout_seconds:
            raise BudgetExhausted(f"stage {self.stage} timeout")

    def remaining(self) -> int:
        row = self.store.budget_row(self.run_id, self.stage, self.budget.max_turns)
        return max(0, self.budget.max_turns - int(row["turns_used"] or 0))


@dataclass
class GlobalModelBudget:
    """全局模型预算：跨阶段累计请求数、token 与墙钟。

    与 `BudgetLease` 的区别：那个按阶段记轮次，管不住"每阶段都不超、合起来超支"。
    这里统计整条 run 的模型用量，超限即抛错终止，而不是只在报告里写一句。
    """

    max_requests: int = 200
    max_tokens: int = 2_000_000
    max_seconds: int = 7200
    _started: float = field(default_factory=time.monotonic)
    _requests: int = 0
    _tokens: int = 0
    _store: object = None
    _run_id: str = ""

    def bind(self, store, run_id: str) -> "GlobalModelBudget":
        self._store, self._run_id = store, run_id
        # 从库里继承已用量：同一 run 断点续跑时不能重新从 0 开始
        hist = self._history_usage()
        self._requests, self._tokens = hist["requests"], hist["tokens"]
        return self

    def _history_usage(self) -> dict:
        import json as _json
        if not self._store or not self._run_id:
            return {"requests": 0, "tokens": 0}
        try:
            rows = self._store._con.execute(
                "SELECT detail FROM attempts WHERE run_id=? AND outcome LIKE 'llm%'",
                (self._run_id,)).fetchall()
        except Exception:
            return {"requests": 0, "tokens": 0}
        reqs, toks = 0, 0
        for r in rows:
            reqs += 1
            try:
                d = _json.loads(r["detail"] or "{}")
                toks += int((d.get("llm") or {}).get("tokens") or 0)
            except Exception:
                continue
        return {"requests": reqs, "tokens": toks}

    def note_call(self, tokens: int = 0, requests: int = 1) -> None:
        """累加真实用量。

        `requests` 必须是**实际传输次数**（含内部重试），不是调用客户端次数：
        否则 max_retries>0 时预算会被少算，实测 2 次传输只记 1 次。
        """
        try:
            n = max(1, int(requests or 1))
        except (TypeError, ValueError):
            n = 1
        self._requests += n
        try:
            self._tokens += max(0, int(tokens or 0))
        except (TypeError, ValueError):
            pass

    def usage(self) -> dict:
        """当前已用量：进程内计数（bind 时已从 attempts 表继承历史）。"""
        return {"requests": self._requests, "tokens": self._tokens}
        import json as _json
        try:
            rows = self._store._con.execute(
                "SELECT detail FROM attempts WHERE run_id=? AND outcome LIKE 'llm%'",
                (self._run_id,)).fetchall()
        except Exception:
            return {"requests": self._requests, "tokens": self._tokens}
        reqs, toks = 0, 0
        for r in rows:
            reqs += 1
            try:
                d = _json.loads(r["detail"] or "{}")
                toks += int((d.get("llm") or {}).get("tokens") or 0)
            except Exception:
                continue
        return {"requests": reqs, "tokens": toks}

    def snapshot(self) -> dict:
        elapsed = time.monotonic() - self._started
        u = self.usage()
        return {"requests": u["requests"], "max_requests": self.max_requests,
                "tokens": u["tokens"], "max_tokens": self.max_tokens,
                "seconds": round(elapsed, 1), "max_seconds": self.max_seconds,
                "exhausted": (u["requests"] >= self.max_requests
                              or u["tokens"] >= self.max_tokens
                              or elapsed >= self.max_seconds)}

    def precheck(self) -> None:
        """模型调用前强制检查：超限直接抛错，不再发请求。"""
        elapsed = time.monotonic() - self._started
        if elapsed >= self.max_seconds:
            raise BudgetExhausted(
                f"global wall-clock exhausted ({elapsed:.0f}s/{self.max_seconds}s)")
        u = self.usage()
        if u["requests"] >= self.max_requests:
            raise BudgetExhausted(
                f"global model requests exhausted ({u['requests']}/{self.max_requests})")
        if u["tokens"] >= self.max_tokens:
            raise BudgetExhausted(
                f"global tokens exhausted ({u['tokens']}/{self.max_tokens})")
