"""V3-010：层级预算账本（run / task / finding / action）与价格口径。

口径（《V3 完整升级方案》§11「预算与进展控制」、§9「统一数据契约与存储」）：

- **层级**：`run ⊃ task ⊃ finding ⊃ action`。任一层声明了限额就按该层裁定，
  子层的花费同时计入所有祖先（`used`/`reserved` 逐层汇总），所以“子调用”
  不可能绕过上层预算：`LLMGateway.child()` / 子 job 都挂在 action 层，
  祖先链一起被扣。
- **原子预留**：`reserve()` 在一个 `BEGIN IMMEDIATE` 事务里读祖先链 →
  校验 → 写 `budget_reservations` + 各层 `reserved`。并发预留只有拿到写锁的
  那个能成功，不会出现“两个 worker 都看到剩余 1 个回合”。
- **结算三态**：`settle()` 按真实 usage 扣；**usage 缺失按预留保守扣账**
  （`usage_missing=true`，绝不填 0 把失败成本抹掉）；`release()` 退还
  （动作被拒绝、根本没发出去时才用）。
- **失败也收费**：provider 超时/异常/协议错误时调用方仍然 `settle(None)`，
  成本落在账上；`release()` 只用于“证明没有产生调用”的情形。
- **钱**：只认固定价格表（`PriceTable`：版本 + 币种 + 每模型单价）。没有价格表
  且设了 `usd` 硬上限 → 付费调用拒绝或转规则模式，**不谎称成本受控**；
  `usd` 只是账本里的一个键，不代替 provider 的 token 计量。
- **预算终止不改结果真假**：`exhausted()` 只给出 `BudgetStop`（
  `affects_result_truth=False`），调用方据此停止；它不把 `failed` 改写成
  `no_repro`，也不把 `unknown` 改写成 0。
- **幂等**：`reserve(..., idempotency_key=...)` 同一 key 重复预留返回同一条
  记录（重试不重复扣）；`settle/release` 对已结算的预留是只读幂等。

本模块只记账，不调模型、不跑目标、不写任何裁决字段。
"""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .contracts import BUDGET_LIMIT_KEYS, BudgetPort

SCHEMA = "vulnmap.adaptive.budget.v1"
SCHEMA_VERSION = 1

#: 层级（从外到内）；祖先链必须按这个顺序，不能跳级挂反
LEVELS = ("run", "task", "finding", "action")

#: 账本键 = 平台 Budget 的 max_* 去掉 max_ 前缀（seconds/execs/tokens/turns，
#: 外加金额 `usd`）。不要另起名字：同一个动作在旧 Budget 与新账本里必须是同一把尺。
BUDGET_KEYS = tuple(BUDGET_LIMIT_KEYS)

#: 金额键（只有它能走价格表；其余是计数/秒）
MONEY_KEYS = frozenset({"usd"})

#: 预留生命周期
RESERVATION_STATES = ("reserved", "settled", "released")

MAX_CHAIN = 8
_EPS = 1e-9

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS budget_scopes(
  scope_id TEXT PRIMARY KEY,
  level TEXT NOT NULL,
  parent_id TEXT NOT NULL DEFAULT '',
  limits_json TEXT NOT NULL DEFAULT '{}',
  used_json TEXT NOT NULL DEFAULT '{}',
  reserved_json TEXT NOT NULL DEFAULT '{}',
  currency TEXT NOT NULL DEFAULT '',
  price_version TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_budget_scopes_parent
  ON budget_scopes(parent_id);
CREATE TABLE IF NOT EXISTS budget_reservations(
  reservation_id TEXT PRIMARY KEY,
  scope_id TEXT NOT NULL,
  chain_json TEXT NOT NULL DEFAULT '[]',
  level TEXT NOT NULL DEFAULT '',
  action_id TEXT NOT NULL DEFAULT '',
  tool TEXT NOT NULL DEFAULT '',
  amount_json TEXT NOT NULL DEFAULT '{}',
  charged_json TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL DEFAULT 'reserved',
  usage_missing INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  settled_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_budget_res_scope
  ON budget_reservations(scope_id, state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_budget_res_idem
  ON budget_reservations(scope_id, idempotency_key)
  WHERE idempotency_key <> '';
"""


# ====================================================================== 工具
def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _amount(want: Mapping | None, *, what: str = "want") -> dict[str, float]:
    """规范化一次预留/结算的键值：只认 BUDGET_KEYS，负数与 NaN 一律拒绝。"""
    out: dict[str, float] = {}
    for key, value in dict(want or {}).items():
        name = str(key)
        if name not in BUDGET_KEYS:
            raise BudgetError(
                "unknown_budget_key",
                f"{what}[{name!r}] 不在 {list(BUDGET_KEYS)} 内",
                hint="预算键必须与平台 Budget 同名：seconds/execs/tokens/turns/usd")
        if value is None:
            continue
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise BudgetError("invalid_amount",
                              f"{what}[{name}]={value!r} 不是数字") from exc
        if number != number or number in (float("inf"), float("-inf")):
            raise BudgetError("invalid_amount", f"{what}[{name}] 不是有限数")
        if number < 0:
            raise BudgetError("invalid_amount",
                              f"{what}[{name}]={number} 不能为负")
        out[name] = number
    return out


def _loads(text: str | None) -> dict:
    try:
        doc = json.loads(text or "{}")
    except ValueError:
        return {}
    return dict(doc) if isinstance(doc, Mapping) else {}


def _dumps(doc: Mapping) -> str:
    return json.dumps(dict(doc), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


# ====================================================================== 错误
class BudgetError(ValueError):
    """账本层错误：非法键、未知预留、链条断/反、重复结算之外的契约错误。"""

    def __init__(self, code: str, reason: str, *, hint: str = "") -> None:
        self.code = str(code)
        self.reason = str(reason)
        self.hint = str(hint)
        super().__init__(f"{self.code}: {self.reason}")

    def to_dict(self) -> dict:
        return {"code": self.code, "reason": self.reason, "hint": self.hint}


class BudgetRefused(BudgetError):
    """预留被拒：预算不够（唯一会让动作停下的原因；不是结果真假）。"""

    def __init__(self, code: str, reason: str, *, key: str = "",
                 level: str = "", scope: str = "", limit: float | None = None,
                 used: float | None = None, reserved: float | None = None,
                 want: float | None = None) -> None:
        super().__init__(code, reason,
                         hint="要更多预算必须重新授权（不能由调用方放大）")
        self.key = str(key)
        self.level = str(level)
        self.scope = str(scope)
        self.limit = limit
        self.used = used
        self.reserved = reserved
        self.want = want

    def to_dict(self) -> dict:
        return {**super().to_dict(), "key": self.key, "level": self.level,
                "scope": self.scope, "limit": self.limit, "used": self.used,
                "reserved": self.reserved, "want": self.want}


# ====================================================================== 价格
@dataclass(frozen=True)
class PriceTable:
    """固定价格表：版本 + 币种 + 每模型（输入/输出 每 1k token）单价。

    **空表就是“没有价格表”**：`cost()` 返回 `None`，调用方不许把未知成本写成 0。
    """

    version: str
    currency: str = "USD"
    models: Mapping = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not str(self.version or "").strip():
            raise BudgetError("invalid_price_table", "价格表必须有版本号")
        table = {}
        for name, row in dict(self.models or {}).items():
            entry = dict(row or {})
            table[str(name)] = {
                "input_per_1k": float(entry.get("input_per_1k") or 0.0),
                "output_per_1k": float(entry.get("output_per_1k") or 0.0),
            }
        object.__setattr__(self, "models", table)
        object.__setattr__(self, "currency", str(self.currency or "USD"))

    @property
    def configured(self) -> bool:
        return bool(self.models)

    def known(self, model: str) -> bool:
        return str(model or "") in self.models

    def cost(self, model: str, *, prompt_tokens: float,
             completion_tokens: float) -> float | None:
        """本次调用的金额；模型不在表里 → `None`（未知，不是 0）。"""
        row = self.models.get(str(model or ""))
        if row is None:
            return None
        return (max(0.0, float(prompt_tokens)) / 1000.0
                * float(row["input_per_1k"])
                + max(0.0, float(completion_tokens)) / 1000.0
                * float(row["output_per_1k"]))

    def to_dict(self) -> dict:
        return {"version": self.version, "currency": self.currency,
                "configured": self.configured,
                "models": {k: dict(v) for k, v in self.models.items()}}


#: 默认**没有**价格表：不编造单价。设了 usd 硬上限又想付费调用 → 拒绝/规则模式。
EMPTY_PRICES = PriceTable(version="unconfigured", models={})


# ====================================================================== 预留
@dataclass(frozen=True)
class Reservation:
    """一条预留的只读视图：金额、状态、是否缺 usage、落在哪个 scope。"""

    reservation_id: str
    scope_id: str
    level: str = ""
    action_id: str = ""
    tool: str = ""
    amount: Mapping = field(default_factory=dict)
    charged: Mapping = field(default_factory=dict)
    state: str = "reserved"
    usage_missing: bool = False
    note: str = ""
    created_at: str = ""
    settled_at: str = ""

    @property
    def open(self) -> bool:
        return self.state == "reserved"

    def to_dict(self) -> dict:
        return {
            "reservation_id": self.reservation_id,
            "scope_id": self.scope_id,
            "level": self.level,
            "action_id": self.action_id,
            "tool": self.tool,
            "amount": dict(self.amount),
            "charged": dict(self.charged),
            "state": self.state,
            "usage_missing": bool(self.usage_missing),
            "note": self.note,
            "created_at": self.created_at,
            "settled_at": self.settled_at,
        }


def _reservation(row: Mapping) -> Reservation:
    return Reservation(
        reservation_id=str(row["reservation_id"]),
        scope_id=str(row["scope_id"]),
        level=str(row["level"] or ""),
        action_id=str(row["action_id"] or ""),
        tool=str(row["tool"] or ""),
        amount=_loads(row["amount_json"]),
        charged=_loads(row["charged_json"]),
        state=str(row["state"]),
        usage_missing=bool(row["usage_missing"]),
        note=str(row["note"] or ""),
        created_at=str(row["created_at"] or ""),
        settled_at=str(row["settled_at"] or ""),
    )


@dataclass(frozen=True)
class BudgetStop:
    """预算终止判定：只回答“还能不能继续”，不改任何结果的真假。"""

    reason: str
    level: str = ""
    scope: str = ""
    remaining: Mapping = field(default_factory=dict)
    violations: tuple[str, ...] = ()
    affects_result_truth: bool = False        # 恒 False：预算不是负结果

    def to_dict(self) -> dict:
        return {"reason": self.reason, "level": self.level, "scope": self.scope,
                "remaining": dict(self.remaining),
                "violations": list(self.violations),
                "affects_result_truth": self.affects_result_truth}


# ====================================================================== 账本
class BudgetLedger:
    """SQLite 单文件账本：原子预留、逐层汇总、幂等结算。"""

    def __init__(self, path: Path | str, *,
                 clock=time.time) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self._local = threading.local()
        self._init_schema()

    # ---- 连接 ----
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.path), timeout=30,
                                   isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=30000")
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.Error:            # pragma: no cover - 只读盘忽略
                pass
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        conn = sqlite3.connect(str(self.path), timeout=30)
        try:
            conn.executescript(SCHEMA_SQL)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            conn.commit()
        finally:
            conn.close()

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    @contextlib.contextmanager
    def _tx(self):
        """`BEGIN IMMEDIATE`：读-改-写期间持有写锁，并发预留不会双花。"""
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    # ---- scope ----
    def ensure_scope(self, scope_id: str, *, level: str, parent: str = "",
                     limits: Mapping | None = None, currency: str = "",
                     price_version: str = "") -> dict:
        """幂等建 scope；已存在只补默认值，不改已声明的限额（限额只能加不能缩）。"""
        sid = str(scope_id or "")
        if not sid:
            raise BudgetError("invalid_scope", "scope_id 不能为空")
        lvl = str(level or "")
        if lvl not in LEVELS:
            raise BudgetError("invalid_scope",
                              f"level 必须是 {list(LEVELS)}，实际 {lvl!r}")
        declared = _amount(limits, what="limits")
        ts = now()
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM budget_scopes WHERE scope_id=?",
                               (sid,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO budget_scopes(scope_id,level,parent_id,"
                    "limits_json,used_json,reserved_json,currency,price_version,"
                    "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (sid, lvl, str(parent or ""), _dumps(declared), "{}", "{}",
                     str(currency or ""), str(price_version or ""), ts, ts))
                return self.get_scope(sid)
            current = _loads(row["limits_json"])
            merged = {**declared, **current}      # 已声明的优先级更高（不静默放宽）
            conn.execute(
                "UPDATE budget_scopes SET limits_json=?,currency=?,"
                "price_version=?,updated_at=? WHERE scope_id=?",
                (_dumps(merged), str(currency or row["currency"]),
                 str(price_version or row["price_version"]), ts, sid))
        return self.get_scope(sid)

    def ensure_chain(self, *, run: str, task: str = "", finding: str = "",
                     action: str = "",
                     limits_by_level: Mapping | None = None) -> dict[str, str]:
        """按 run→task→finding→action 建链，返回 {level: scope_id}。"""
        caps = dict(limits_by_level or {})
        ids: dict[str, str] = {}
        parent = ""
        plan = (("run", run), ("task", task), ("finding", finding),
                ("action", action))
        for level, name in plan:
            if not name:
                if level in ("run",):
                    raise BudgetError("invalid_scope", "run 不能为空")
                continue
            scope_id = f"{level}:{name}"
            self.ensure_scope(scope_id, level=level, parent=parent,
                              limits=caps.get(level) or {})
            ids[level] = scope_id
            parent = scope_id
        return ids

    def get_scope(self, scope_id: str) -> dict:
        row = self._conn().execute(
            "SELECT * FROM budget_scopes WHERE scope_id=?",
            (str(scope_id),)).fetchone()
        if row is None:
            raise BudgetError("unknown_scope", f"没有预算 scope {scope_id!r}")
        return {
            "scope_id": row["scope_id"], "level": row["level"],
            "parent_id": row["parent_id"],
            "limits": _loads(row["limits_json"]),
            "used": _loads(row["used_json"]),
            "reserved": _loads(row["reserved_json"]),
            "currency": row["currency"], "price_version": row["price_version"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def chain(self, scope_id: str) -> list[dict]:
        out: list[dict] = []
        current = str(scope_id)
        seen: set[str] = set()
        while current:
            if current in seen or len(out) >= MAX_CHAIN:
                raise BudgetError("scope_cycle",
                                  f"预算链异常（重复或超过 {MAX_CHAIN} 层）：{out}")
            seen.add(current)
            scope = self.get_scope(current)
            out.append(scope)
            current = str(scope["parent_id"] or "")
        # 从内到外：子层 level 必须比祖先深，防止把 action 挂成 run 的子层
        for inner, outer in zip(out, out[1:]):
            if LEVELS.index(inner["level"]) <= LEVELS.index(outer["level"]):
                raise BudgetError(
                    "scope_order",
                    f"{inner['level']} 挂在 {outer['level']} 下面（层级倒挂）")
        return out

    # ---- 预留 ----
    def reserve(self, scope_id: str, want: Mapping | None, *,
                action_id: str = "", tool: str = "", note: str = "",
                idempotency_key: str = "") -> Reservation:
        """按祖先链原子预留；任一已声明限额不够 → `BudgetRefused`（不留半条记录）。

        没有声明限额的键放行但记 `unbounded:<key>` 提示（不谎称受控）。
        """
        amount = _amount(want, what="want")
        if not amount:
            raise BudgetError("invalid_amount", "预留金额不能为空")
        key = str(idempotency_key or "")
        ts = now()
        try:
            with self._tx() as conn:
                if key:
                    row = conn.execute(
                        "SELECT * FROM budget_reservations WHERE scope_id=? "
                        "AND idempotency_key=?", (str(scope_id), key)).fetchone()
                    if row is not None:
                        if row["state"] == "reserved":
                            # 同一个幂等键的另一条预留还开着：说明**同一个逻辑动作
                            # 正在被另一次调用执行**。把这条 open 预留交回去，调用方
                            # 就会拿它去发第二次真实请求而不花钱（漏扣）。并发下
                            # 只允许一个执行者，其余在这里被拒（可修正：等它结束）。
                            raise BudgetRefused(
                                "reservation_in_flight",
                                f"幂等键 {key!r} 的预留 {row['reservation_id']} "
                                "仍处于 reserved（另一个执行者正在用）",
                                scope=str(scope_id), key="idempotency_key")
                        return _reservation(row)
                scopes = self._chain_in_tx(conn, str(scope_id))
                for scope in scopes:
                    limits = _loads(scope["limits_json"])
                    used = _loads(scope["used_json"])
                    reserved = _loads(scope["reserved_json"])
                    for name, value in amount.items():
                        limit = limits.get(name)
                        if limit is None:
                            continue
                        committed = float(used.get(name, 0.0)) \
                            + float(reserved.get(name, 0.0))
                        if committed + value > float(limit) + _EPS:
                            raise BudgetRefused(
                                "budget_exceeded",
                                f"{scope['level']} 层 {scope['scope_id']} 的 "
                                f"{name} 不够：已用 {committed:g} + 本次 "
                                f"{value:g} > 上限 {float(limit):g}",
                                key=name, level=scope["level"],
                                scope=scope["scope_id"], limit=float(limit),
                                used=float(used.get(name, 0.0)),
                                reserved=float(reserved.get(name, 0.0)),
                                want=value)
                # 不用 `uuid`：它 import 的是标准库 `platform`，而仓库里 `bin/platform.py`
                # 会把 `platform` 解析成自己（CLI 子进程里直接变成循环 import）。
                rid = "rsv-" + os.urandom(8).hex()
                ids = [scope["scope_id"] for scope in scopes]
                conn.execute(
                    "INSERT INTO budget_reservations(reservation_id,scope_id,"
                    "chain_json,level,action_id,tool,amount_json,charged_json,"
                    "state,usage_missing,idempotency_key,note,created_at,"
                    "updated_at,settled_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid, str(scope_id), _dumps({"chain": ids}),
                     str(scopes[0]["level"]), str(action_id or ""),
                     str(tool or ""), _dumps(amount), "{}", "reserved", 0, key,
                     str(note or ""), ts, ts, ""))
                for scope in scopes:
                    self._bump(conn, scope["scope_id"], reserved=amount, used={})
                return self._get_reservation(conn, rid)
        except BudgetRefused:
            raise
        except sqlite3.OperationalError as exc:
            raise BudgetError(
                "ledger_locked",
                f"预算账本写锁不可用：{exc}",
                hint="并发预留重试；不接受“先跑后补账”") from exc

    # ---- 结算 / 退还 ----
    def settle(self, reservation_id: str, used: Mapping | None = None, *,
               note: str = "") -> dict:
        """按真实 usage 结算；缺 usage 的键按**预留额**保守扣账。

        返回 `{state, charged, missing, usage, usage_missing, overage, ...}`；
        已结算的预留再次 settle 是只读幂等（`already=True`，不重复扣）。
        """
        real = _amount(used, what="used") if used is not None else {}
        ts = now()
        with self._tx() as conn:
            row = conn.execute(
                "SELECT * FROM budget_reservations WHERE reservation_id=?",
                (str(reservation_id),)).fetchone()
            if row is None:
                raise BudgetError("unknown_reservation",
                                  f"没有预留 {reservation_id!r}")
            amount = _loads(row["amount_json"])
            if row["state"] != "reserved":
                return {"reservation_id": row["reservation_id"],
                        "state": row["state"],
                        "charged": _loads(row["charged_json"]),
                        "missing": [], "usage": "settled", "usage_missing":
                        bool(row["usage_missing"]), "already": True,
                        "overage": {}}
            charged: dict[str, float] = {}
            missing: list[str] = []
            overage: dict[str, float] = {}
            for name, reserved_amount in amount.items():
                if name in real and real[name] is not None:
                    value = float(real[name])
                else:
                    value = float(reserved_amount)
                    missing.append(name)
                charged[name] = value
                if value > float(reserved_amount) + _EPS:
                    overage[name] = value - float(reserved_amount)
            # 用了但**预留时没声明**的键：照样扣（账要真实），并记进 overage。
            # 这些键没有走过限额校验，所以不能假装它们“在预算内”。
            extra = sorted(set(real) - set(amount))
            for name in extra:
                charged[name] = float(real[name])
                overage[name] = float(real[name])   # 完全在预留之外：全额算 overage
            chain_ids = list(_loads(row["chain_json"]).get("chain") or [])
            for scope_id in chain_ids:
                self._bump(conn, scope_id, reserved={k: -v for k, v in
                                                     amount.items()},
                           used=charged)
            usage_missing = bool(missing)
            note_text = str(note or row["note"] or "")
            if missing:
                note_text = (note_text + ";usage_missing:" + ",".join(missing))
                note_text = note_text.lstrip(";")
            if extra:
                note_text = (note_text + ";unexpected_usage:" + ",".join(extra)
                             ).lstrip(";")
            conn.execute(
                "UPDATE budget_reservations SET state='settled',charged_json=?,"
                "usage_missing=?,note=?,updated_at=?,settled_at=? "
                "WHERE reservation_id=?",
                (_dumps(charged), 1 if usage_missing else 0, note_text, ts, ts,
                 str(reservation_id)))
        return {"reservation_id": str(reservation_id), "state": "settled",
                "charged": charged, "missing": missing,
                "usage": "unknown" if missing else "reported",
                "usage_missing": usage_missing, "already": False,
                "overage": overage}

    def release(self, reservation_id: str, *, reason: str = "") -> dict:
        """退还预留（只在“证明没有产生花费”时用：闸门拒绝、动作没发出去）。"""
        ts = now()
        with self._tx() as conn:
            row = conn.execute(
                "SELECT * FROM budget_reservations WHERE reservation_id=?",
                (str(reservation_id),)).fetchone()
            if row is None:
                raise BudgetError("unknown_reservation",
                                  f"没有预留 {reservation_id!r}")
            amount = _loads(row["amount_json"])
            if row["state"] != "reserved":
                return {"reservation_id": row["reservation_id"],
                        "state": row["state"], "released": {}, "already": True}
            chain_ids = list(_loads(row["chain_json"]).get("chain") or [])
            for scope_id in chain_ids:
                self._bump(conn, scope_id,
                           reserved={k: -v for k, v in amount.items()}, used={})
            note = (str(row["note"] or "") + (";release:" + str(reason or "")
                                              if reason else "")).strip(";")
            conn.execute(
                "UPDATE budget_reservations SET state='released',note=?,"
                "updated_at=?,settled_at=? WHERE reservation_id=?",
                (note, ts, ts, str(reservation_id)))
        return {"reservation_id": str(reservation_id), "state": "released",
                "released": amount, "already": False}

    def expire_open_reservations(self, *, max_age_seconds: float) -> list[dict]:
        """把陈旧未结算的预留退还（worker 崩溃后不永久占额），返回被释放的清单。"""
        cutoff = float(self.clock()) - max(0.0, float(max_age_seconds))
        rows = self._conn().execute(
            "SELECT reservation_id,created_at FROM budget_reservations "
            "WHERE state='reserved'").fetchall()
        released: list[dict] = []
        for row in rows:
            created = str(row["created_at"] or "")
            try:
                stamp = datetime.fromisoformat(created).timestamp()
            except ValueError:
                continue
            if stamp > cutoff:
                continue
            released.append(self.release(
                str(row["reservation_id"]),
                reason=f"lease_expired:{max_age_seconds:g}s"))
        return released

    # ---- 查询 ----
    def _get_reservation(self, conn: sqlite3.Connection,
                         reservation_id: str) -> Reservation:
        row = conn.execute(
            "SELECT * FROM budget_reservations WHERE reservation_id=?",
            (str(reservation_id),)).fetchone()
        if row is None:
            raise BudgetError("unknown_reservation",
                              f"没有预留 {reservation_id!r}")
        return _reservation(row)

    def get_reservation(self, reservation_id: str) -> Reservation:
        return self._get_reservation(self._conn(), reservation_id)

    def open_reservations(self, scope_id: str = "") -> list[Reservation]:
        sql = "SELECT * FROM budget_reservations WHERE state='reserved'"
        args: list = []
        if scope_id:
            sql += " AND scope_id=?"
            args.append(str(scope_id))
        rows = self._conn().execute(sql + " ORDER BY created_at", args).fetchall()
        return [_reservation(row) for row in rows]

    def snapshot(self, scope_id: str) -> dict:
        """该 scope 的账本视图；`bottleneck` 取祖先链上最紧的剩余额。"""
        scope = self.get_scope(scope_id)
        scopes = self.chain(scope_id)
        remaining: dict[str, float] = {}
        for key, limit in dict(scope["limits"]).items():
            remaining[key] = float(limit) - float(scope["used"].get(key, 0.0)) \
                - float(scope["reserved"].get(key, 0.0))
        bottleneck: dict[str, dict] = {}
        violations: list[str] = []
        levels: list[dict] = []
        for item in scopes:
            limits = dict(item["limits"])
            used = dict(item["used"])
            reserved = dict(item["reserved"])
            levels.append({"scope_id": item["scope_id"], "level": item["level"],
                           "limits": limits, "used": used,
                           "reserved": reserved})
            for key, limit in limits.items():
                left = float(limit) - float(used.get(key, 0.0)) \
                    - float(reserved.get(key, 0.0))
                current = bottleneck.get(key)
                if current is None or left < float(current["remaining"]):
                    bottleneck[key] = {"remaining": left, "level": item["level"],
                                       "scope": item["scope_id"]}
                if float(used.get(key, 0.0)) > float(limit) + _EPS:
                    violations.append(
                        f"budget_overspent:{item['level']}:{key}")
        return {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "scope": scope["scope_id"], "level": scope["level"],
            "limits": dict(scope["limits"]), "used": dict(scope["used"]),
            "reserved": dict(scope["reserved"]), "remaining": remaining,
            "bottleneck": bottleneck, "levels": levels,
            "violations": violations,
            "currency": scope["currency"],
            "price_version": scope["price_version"],
            "open_reservations": len(self.open_reservations(scope["scope_id"])),
        }

    def usage(self, scope_id: str) -> dict:
        return dict(self.get_scope(scope_id)["used"])

    def seed_usage(self, scope_id: str, used: Mapping | None) -> dict:
        """把**历史事件**里已经花掉的量作为起点（只抬不降，重复调用不翻倍）。

        旧口径的 `DeclaredBudget(used=usage_from_events(...))` 就是这么起账的；
        换成本账本后不能把历史用量丢掉——否则一旦切到 P3，预算会“凭空回血”。
        """
        start = _amount(used, what="seed_usage")
        if not start:
            return dict(self.get_scope(scope_id)["used"])
        with self._tx() as conn:
            row = conn.execute(
                "SELECT used_json FROM budget_scopes WHERE scope_id=?",
                (str(scope_id),)).fetchone()
            if row is None:
                raise BudgetError("unknown_scope", f"没有预算 scope {scope_id!r}")
            current = _loads(row["used_json"])
            merged = dict(current)
            for key, value in start.items():
                merged[key] = max(float(current.get(key, 0.0)), float(value))
            conn.execute(
                "UPDATE budget_scopes SET used_json=?,updated_at=? "
                "WHERE scope_id=?",
                (_dumps(merged), now(), str(scope_id)))
        return dict(self.get_scope(scope_id)["used"])

    def exhausted(self, scope_id: str) -> BudgetStop | None:
        """预算终止判定；返回 `BudgetStop`（不改结果真假）或 None。"""
        snap = self.snapshot(scope_id)
        for key, item in dict(snap.get("bottleneck") or {}).items():
            if float(item["remaining"]) <= _EPS:
                return BudgetStop(
                    reason=f"budget:{key}@{item['level']}",
                    level=str(item["level"]), scope=str(item["scope"]),
                    remaining={k: float(v["remaining"])
                               for k, v in dict(snap["bottleneck"]).items()},
                    violations=tuple(snap.get("violations") or ()))
        violations = tuple(snap.get("violations") or ())
        if violations:
            return BudgetStop(reason=f"violations:{violations[0]}",
                              scope=scope_id, violations=violations,
                              remaining={k: float(v["remaining"])
                                         for k, v in
                                         dict(snap["bottleneck"]).items()})
        return None

    # ---- 内部 ----
    def _chain_in_tx(self, conn: sqlite3.Connection,
                     scope_id: str) -> list[dict]:
        out: list[dict] = []
        current = str(scope_id)
        seen: set[str] = set()
        while current:
            if current in seen or len(out) >= MAX_CHAIN:
                raise BudgetError("scope_cycle",
                                  f"预算链异常：{out} -> {current}")
            seen.add(current)
            row = conn.execute(
                "SELECT * FROM budget_scopes WHERE scope_id=?",
                (current,)).fetchone()
            if row is None:
                raise BudgetError("unknown_scope",
                                  f"没有预算 scope {current!r}（先 ensure_scope）")
            out.append(dict(row))
            current = str(row["parent_id"] or "")
        for inner, outer in zip(out, out[1:]):
            if LEVELS.index(inner["level"]) <= LEVELS.index(outer["level"]):
                raise BudgetError(
                    "scope_order",
                    f"{inner['level']} 挂在 {outer['level']} 下面（层级倒挂）")
        return out

    @staticmethod
    def _bump(conn: sqlite3.Connection, scope_id: str, *,
              reserved: Mapping, used: Mapping) -> None:
        row = conn.execute(
            "SELECT reserved_json,used_json FROM budget_scopes "
            "WHERE scope_id=?", (scope_id,)).fetchone()
        if row is None:
            raise BudgetError("unknown_scope", f"没有预算 scope {scope_id!r}")
        new_reserved = _loads(row["reserved_json"])
        new_used = _loads(row["used_json"])
        for key, delta in dict(reserved or {}).items():
            value = float(new_reserved.get(key, 0.0)) + float(delta)
            new_reserved[key] = 0.0 if abs(value) < _EPS else value
        for key, delta in dict(used or {}).items():
            value = float(new_used.get(key, 0.0)) + float(delta)
            new_used[key] = 0.0 if abs(value) < _EPS else value
        conn.execute(
            "UPDATE budget_scopes SET reserved_json=?,used_json=?,updated_at=? "
            "WHERE scope_id=?",
            (_dumps(new_reserved), _dumps(new_used), now(), scope_id))


# ====================================================================== 端口
class LedgerBudget(BudgetPort):
    """`contracts.BudgetPort` 适配：`check()` 原子预留，`settle()` 结算。

    `Registry` 的协议是「先 check 再 settle」，中间夹着 handler；本类把这条
    预留按线程记在 `_pending` 里，`settle()` 找到同一条结算——所以一次动作
    只可能扣一次，handler 抛异常时仍然按预留保守扣账（§11「失败也计费」）。
    """

    def __init__(self, ledger: BudgetLedger, scope_id: str, *,
                 action_id: str = "", tool: str = "") -> None:
        self.ledger = ledger
        self.scope_id = str(scope_id)
        self.action_id = str(action_id or "")
        self.tool = str(tool or "")
        self._pending: dict[int, str] = {}
        self._all: list[str] = []
        self._last: Reservation | None = None

    def bind(self, *, action_id: str = "", tool: str = "") -> "LedgerBudget":
        """同一条链上的下一次动作换 id（控制器每轮复用预算端口时用）。"""
        if action_id:
            self.action_id = str(action_id)
        if tool:
            self.tool = str(tool)
        return self

    def check(self, want: Mapping | None) -> dict:
        amount = _amount(want, what="want")
        if not amount:
            return {"ok": True, "reserved": {}, "reason": "", "detail": {},
                    "notes": ["budget_unbounded"], "reservation_id": ""}
        try:
            reservation = self.ledger.reserve(
                self.scope_id, amount, action_id=self.action_id,
                tool=self.tool,
                idempotency_key=(f"{self.action_id}:{self.tool}"
                                 if self.action_id else ""))
        except BudgetRefused as exc:
            return {"ok": False, "reserved": {}, "reason": exc.code,
                    "detail": exc.to_dict(), "notes": ["budget_exceeded"],
                    "reservation_id": ""}
        self._pending[threading.get_ident()] = reservation.reservation_id
        self._all.append(reservation.reservation_id)
        self._last = reservation
        return {"ok": True, "reserved": dict(reservation.amount),
                "reason": "", "notes": [],
                "detail": {k: {"want": v} for k, v in
                           reservation.amount.items()},
                "reservation_id": reservation.reservation_id}

    def settle(self, used: Mapping | None) -> dict:
        rid = self._pending.pop(threading.get_ident(), "")
        if not rid and self._all:
            # handler 在别的线程里跑完（或 check 与 settle 不同线程）时，退回
            # “最近一条还开着的预留”，不让它悬挂成永久占额。
            rid = self._all[-1]
        if rid and rid in self._all:
            self._all.remove(rid)
        if not rid:
            return {"settled": False, "reason": "no_open_reservation"}
        return self.ledger.settle(rid, used)

    def snapshot(self) -> dict:
        return self.ledger.snapshot(self.scope_id)

    def release_pending(self, *, reason: str = "rejected") -> dict:
        """闸门拒绝时退还（证明没有发出去，才允许退）。"""
        rid = self._pending.pop(threading.get_ident(), "")
        if not rid and self._all:
            rid = self._all[-1]
        if rid and rid in self._all:
            self._all.remove(rid)
        if not rid:
            return {"released": False}
        return self.ledger.release(rid, reason=reason)

    @property
    def last(self) -> Reservation | None:
        return self._last


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "LEVELS", "BUDGET_KEYS", "MONEY_KEYS",
    "RESERVATION_STATES", "BudgetError", "BudgetRefused", "PriceTable",
    "EMPTY_PRICES", "Reservation", "BudgetStop", "BudgetLedger", "LedgerBudget",
    "now",
]
