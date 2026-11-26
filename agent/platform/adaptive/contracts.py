"""V3-005：单一动作契约（ActionRequest / ActionResult / ToolSpec / Registry）。

口径（《V3 完整升级方案》§6「工具与权限」、§8「实验自修改与版本事务」、§9）：

- **同源**：工具契约、参数校验、handler、权限层级、预算计费与失效范围都来自
  同一个 `ToolSpec` 声明。`ToolSpec.__post_init__` 在构造期就把「模型可见 schema」
  与「handler 真实签名」逐参数对账，对不上直接抛 `ToolError`（import 期失败），
  从根上避免“schema 里支持、执行器不支持”。
- **身份由服务端填**：模型只能提 `ActionRequest`；受信身份（task/campaign/epoch/
  job/execution 与 `binding_hash`）由服务端 `Binding` 决定。请求里自带一套身份
  就是伪造，一律 `rejected`，不会“以请求里的为准”。
- **五态结果**：`applied / noop / rejected / failed / unknown`。
  `unknown` 表示事实不足——不是 false，也不是 0。读取类工具可以合法返回
  `unknown`；变更类工具只有真正改了东西才是 `applied`（同内容重复提交 = `noop`）。
- **失效范围要被消费**：每次成功变更都给出 `invalidations`，并进入
  `Registry` 的待消费集合；控制器必须 `consume_invalidations()` 才算生效
  （§8：“控制器必须实际消费失效标记”，不能只写在返回值里好看）。
- **权限 L0–L3**：L0 只读；L1 已授权任务内的隔离实验工件与执行（自动）；
  L2 新增外部访问/依赖/部署（需显式授权）；L3 写裁决/可信事件/其他任务/凭据，
  **永不**出现在工具表里（`ToolSpec` 拒绝注册 L3）。

本模块只做契约与闸门，不执行目标、不调 LLM、不写裁决字段。
"""
from __future__ import annotations

import hashlib
import inspect
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from ..authorization import AuthorizationError, parse_authorized, resolve as resolve_auth

SCHEMA = "vulnmap.adaptive.action.v1"
SCHEMA_VERSION = 1
TOOL_SCHEMA = "vulnmap.adaptive.tool.v1"

#: 动作结果的五态；`rejected` 是“没让做”，`failed` 是“做了没成”，
#: `unknown` 是“不知道成没成/事实不足”，三者不能互相顶替。
STATUSES = ("applied", "noop", "rejected", "failed", "unknown")

#: 未知事实的唯一词形（与 snapshot.UNKNOWN 同值；不引入第二种写法）
UNKNOWN = "unknown"

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,120}$")
SAFE_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

#: 工具分组（与方案 §6 的表格一一对应）
GROUPS = ("read", "input", "experiment", "close")


# ====================================================================== 错误
class ToolError(ValueError):
    """注册期错误：schema/handler/权限/失效声明不自洽，直接失败。"""


class ActionRejected(RuntimeError):
    """运行期拒绝：请求不合法、身份伪造、无权限、预算不够、参数越界。

    handler 里也可以抛它来表达“可修正的拒绝”（例如假设 id 不存在）。
    `Registry` 会把它翻成 `ActionResult(status="rejected")`，不落地任何变更。
    """

    def __init__(self, code: str, reason: str, *, field_name: str = "",
                 hint: str = "") -> None:
        self.code = str(code or "rejected") or "rejected"
        self.reason = str(reason or "")
        self.field = str(field_name or "")
        self.hint = str(hint or "")
        super().__init__(f"{self.code}: {self.reason}")

    def to_dict(self) -> dict:
        return {"code": self.code, "reason": self.reason,
                "field": self.field, "hint": self.hint}


# ====================================================================== 规范化
def canonical_json(doc: Any) -> str:
    """稳定序列化：同一内容恒得同一字符串（含 None→null，不排序丢失类型）。"""
    return json.dumps(doc, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def digest_of(doc: Any) -> str:
    """内容摘要；`None` 与 `{}` 得到不同摘要（不能把“没观测到”混成空对象）。"""
    if doc is None:
        return ""
    return hashlib.sha256(canonical_json(doc).encode("utf-8")).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def deep_copy(doc: Any) -> Any:
    return json.loads(json.dumps(doc, ensure_ascii=False, default=str))


# ====================================================================== 权限
#: 权限层级与语义；`auto=True` 表示满足前置（任务已授权）即可自动进行。
PERMISSIONS: dict[str, dict] = {
    "L0": {"auto": True, "title": "只读",
           "needs": "查询受绑定 artifact；未知能力返回 unsupported"},
    "L1": {"auto": True, "title": "隔离实验",
           "needs": "任务已授权（metadata.authorized=true）后自动允许："
                    "语料/种子/字典/隔离执行"},
    "L2": {"auto": False, "title": "外部与部署",
           "needs": "新增外部访问、依赖或部署修改：需 metadata.allow_external=true"},
    "L3": {"auto": False, "title": "裁决与可信面",
           "needs": "写裁决/可信事件/其他任务数据/凭据：永不暴露给研究 Agent"},
}

#: 永不进工具表的层级（有 spec 想注册它就连构造期都过不去）
NEVER_EXPOSED = frozenset({"L3"})


def permission_allows(level: str, grant: Iterable[str]) -> bool:
    """层级是否在本次授权集合内（不认识的层级一律不放行）。"""
    if level not in PERMISSIONS:
        return False
    return level in set(grant or ())


def grant_for(metadata: Mapping | None, *, extra: Iterable[str] = ()) -> frozenset[str]:
    """从任务元数据推出本次可用的权限集合（fail-closed）。

    - L0：只读，任何任务都给（读的是自己任务的受绑定事实）；
    - L1：仅 `authorization.resolve(metadata).ok` 为真（显式 authorized=true）；
    - L2：仅 `allow_external` 显式 true（同样是严格解析，字符串 "false" 不放行）；
    - L3：永不给。`extra` 只能追加 L0/L1/L2，写 L3 会被忽略。
    """
    grant = {"L0"}
    if resolve_auth(metadata).get("ok"):
        grant.add("L1")
        try:
            if "allow_external" in (metadata or {}) and parse_authorized(
                    (metadata or {})["allow_external"]):
                grant.add("L2")
        except AuthorizationError:
            pass                      # 写法非法 = 不授权，不猜
    for item in extra or ():
        if item in PERMISSIONS and item not in NEVER_EXPOSED:
            grant.add(item)
    return frozenset(grant)


# ====================================================================== 失效范围
#: 失效域（§8 表格的右侧：必须失效/重做的那一列）
INVALIDATION_SCOPES: dict[str, str] = {
    "input_dedup": "本轮输入去重与输入收益测量",
    "input_policy": "种子/字典策略派生出的输入计划",
    "corpus_members": "语料成员集合（manifest 与 corpus_hash）",
    "coverage_baseline": "覆盖基线（位图/调用点覆盖）",
    "build": "构建产物与构建身份（build_id）",
    "smoke": "冒烟结果",
    "execution_facts": "执行事实快照与既有游标之后的事实",
    "trial_compare": "trial 对照缓存（可比性判定）",
    "program_context": "程序上下文（入口/调用点/源码窗口）",
}

#: 变更类别 → 必须失效的域。`ToolSpec` 的 invalidations 只允许从这里派生，
#: 不允许工具自己写一套（否则“同源”就是空话）。
CHANGE_INVALIDATIONS: dict[str, tuple[str, ...]] = {
    "none": (),
    "proposal": (),                                    # 只提建议，不改工件
    "seed": ("input_dedup", "coverage_baseline"),      # §8: seed → 输入/收益测量
    "dictionary": ("input_dedup",),
    "corpus": ("input_dedup", "corpus_members"),
    "harness": ("build", "smoke", "coverage_baseline", "corpus_members"),
    "build_identity": ("build", "smoke", "coverage_baseline", "corpus_members"),
    "execution": ("execution_facts", "trial_compare", "coverage_baseline"),
    "program": ("program_context",),
}

#: 会改变会话状态、需要 before/after 摘要的变更类别（其余为纯读）
MUTATING_CHANGES = frozenset(
    {"proposal", "seed", "dictionary", "corpus", "harness", "build_identity",
     "program"})

#: 会写**会话状态之外**的副作用类别（语料目录、harness 副本、构建产物）。
#: 只有这些类别在 “failed 但已声明 changed_fields” 时才不回滚：磁盘上的东西
#: 撤不回来，回滚会话反而会让台账和磁盘对不上。其余类别的失败一律回滚。
EXTERNAL_EFFECT_CHANGES = frozenset({"corpus", "harness", "build_identity"})


# ====================================================================== 绑定
#: 受信身份字段（服务端填，请求不能自己指定）
BINDING_FIELDS = ("task_id", "campaign", "epoch", "job_id", "execution_id")

#: 绑定摘要覆盖的身份分量（§9：源码/目标、harness、build/镜像、基准、
#: 证明对象、工具 schema、policy 与生效配置）
BINDING_IDENTITY = ("source_sha256", "harness_revision", "build_id", "image",
                    "benchmark", "target", "policy_version", "tool_schema_hash")


@dataclass(frozen=True)
class Binding:
    """一次动作的受信身份；`hash` 由内容算出来，不由调用方说了算。

    `Binding.from_dict()` 会重算摘要：调用方给的 `hash` 与重算结果不一致
    → `ActionRejected("forged_identity")`。这样“改一个字段再沿用旧 hash”
    这种最常见的伪造走不通。
    """

    task_id: str
    campaign: str = ""
    epoch: int = 0
    job_id: str = ""
    execution_id: str = ""
    identity: Mapping[str, str] = field(default_factory=dict)
    hash: str = ""

    # ---- 构造 ----
    def __post_init__(self) -> None:
        task_id = str(self.task_id or "")
        if not SAFE_ID.match(task_id):
            raise ToolError(f"unsafe binding.task_id: {task_id!r}")
        epoch = int(self.epoch or 0)
        if epoch < 0:
            raise ToolError("binding.epoch must be >= 0")
        raw_identity = dict(self.identity or {})
        unknown_identity = sorted(str(k) for k in raw_identity
                                  if str(k) not in BINDING_IDENTITY)
        if unknown_identity:
            # 身份分量只认 BINDING_IDENTITY：夹带额外键（例如 trusted=true）
            # 会让“摘要覆盖什么”变得不可审计
            raise ActionRejected(
                "invalid_identity",
                f"binding.identity 含未知分量：{unknown_identity}",
                field_name="binding",
                hint=f"可声明 {list(BINDING_IDENTITY)}")
        identity = {str(k): str(v) for k, v in raw_identity.items()}
        object.__setattr__(self, "task_id", task_id)
        object.__setattr__(self, "campaign", str(self.campaign or ""))
        object.__setattr__(self, "epoch", epoch)
        object.__setattr__(self, "job_id", str(self.job_id or ""))
        object.__setattr__(self, "execution_id", str(self.execution_id or ""))
        object.__setattr__(self, "identity", identity)
        computed = self.compute_hash()
        claimed = str(self.hash or "")
        if claimed and claimed != computed:
            raise ActionRejected(
                "forged_identity",
                "binding.hash 与 binding 内容不一致（摘要被改写）",
                hint="binding 由服务端下发，不要自行拼装或改写")
        object.__setattr__(self, "hash", computed)

    def compute_hash(self) -> str:
        payload = {
            "schema": SCHEMA,
            "fields": {name: getattr(self, name) for name in BINDING_FIELDS},
            "identity": {k: self.identity.get(k, "") for k in BINDING_IDENTITY},
        }
        return "b" + digest_of(payload)[:32]

    # ---- 序列化 ----
    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            **{name: getattr(self, name) for name in BINDING_FIELDS},
            "identity": {k: self.identity.get(k, "") for k in BINDING_IDENTITY},
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, doc: Mapping | None) -> "Binding":
        if not isinstance(doc, Mapping) or not doc:
            raise ActionRejected("missing_identity",
                                 "ActionRequest.binding 缺失",
                                 field_name="binding",
                                 hint="把服务端下发的 binding 原样带回")
        unknown = {k for k in doc
                   if k not in BINDING_FIELDS + ("identity", "hash", "schema",
                                                 "schema_version")}
        if unknown:
            raise ActionRejected("invalid_identity",
                                 f"binding 含未知字段：{sorted(unknown)}",
                                 field_name="binding")
        try:
            return cls(
                task_id=str(doc.get("task_id") or ""),
                campaign=str(doc.get("campaign") or ""),
                epoch=int(doc.get("epoch") or 0),
                job_id=str(doc.get("job_id") or ""),
                execution_id=str(doc.get("execution_id") or ""),
                identity=dict(doc.get("identity") or {}),
                hash=str(doc.get("hash") or ""),
            )
        except ToolError as exc:
            raise ActionRejected("invalid_identity", str(exc),
                                 field_name="binding") from exc

    def same_scope(self, other: "Binding") -> tuple[bool, str]:
        """同一任务/研究轮次/执行？返回 (ok, 不一致的原因码)。"""
        if self.task_id != other.task_id:
            return False, "forged_identity"
        if self.execution_id and other.execution_id \
                and self.execution_id != other.execution_id:
            return False, "cross_execution"
        if self.campaign != other.campaign or self.epoch != other.epoch:
            return False, "binding_mismatch"
        return True, ""


# ====================================================================== 请求
@dataclass(frozen=True)
class ActionRequest:
    """模型可提交的唯一种类：一个动作 + 参数 + 声称的身份。"""

    action_id: str
    action: str
    binding: Mapping = field(default_factory=dict)
    params: Mapping = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()
    hypothesis_id: str = ""
    budget: Mapping = field(default_factory=dict)
    note: str = ""

    def __post_init__(self) -> None:
        action_id = str(self.action_id or "")
        if not SAFE_ID.match(action_id):
            raise ToolError(f"unsafe action_id: {action_id!r}")
        action = str(self.action or "")
        if not SAFE_TOOL_NAME.match(action):
            raise ToolError(f"unsafe action name: {action!r}")
        if not isinstance(self.params, Mapping):
            raise ToolError("params must be a mapping")
        if not isinstance(self.budget, Mapping):
            raise ToolError("budget must be a mapping")
        for key, value in dict(self.budget).items():
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ToolError(f"budget[{key}] must be numeric")
            if float(value) < 0:
                raise ToolError(f"budget[{key}] must be >= 0")
        refs = tuple(str(r) for r in (self.evidence_refs or ()))
        if any(not r.strip() for r in refs):
            raise ToolError("evidence_refs must be non-empty strings")
        object.__setattr__(self, "action_id", action_id)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "params", dict(self.params))
        object.__setattr__(self, "budget", dict(self.budget))
        object.__setattr__(self, "evidence_refs", refs)
        object.__setattr__(self, "hypothesis_id", str(self.hypothesis_id or ""))
        object.__setattr__(self, "note", str(self.note or ""))

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "action_id": self.action_id,
            "action": self.action,
            "binding": dict(self.binding),
            "params": dict(self.params),
            "evidence_refs": list(self.evidence_refs),
            "hypothesis_id": self.hypothesis_id,
            "budget": dict(self.budget),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, doc: Mapping) -> "ActionRequest":
        if not isinstance(doc, Mapping):
            raise ToolError("ActionRequest must be a mapping")
        return cls(
            action_id=str(doc.get("action_id") or ""),
            action=str(doc.get("action") or ""),
            binding=dict(doc.get("binding") or {}),
            params=dict(doc.get("params") or {}),
            evidence_refs=tuple(doc.get("evidence_refs") or ()),
            hypothesis_id=str(doc.get("hypothesis_id") or ""),
            budget=dict(doc.get("budget") or {}),
            note=str(doc.get("note") or ""),
        )


# ====================================================================== 结果
@dataclass(frozen=True)
class ActionResult:
    """一个动作的结算：状态、前后摘要、变更字段、失效范围与错误码。"""

    action_id: str
    tool: str
    status: str
    binding_hash: str = ""
    execution_id: str = ""
    hypothesis_id: str = ""
    before_sha256: str = ""
    after_sha256: str = ""
    changed_fields: tuple[str, ...] = ()
    invalidations: tuple[str, ...] = ()
    payload: Mapping = field(default_factory=dict)
    error: Mapping | None = None
    budget: Mapping = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()
    created_at: str = ""

    def __post_init__(self) -> None:
        status = str(self.status or "")
        if status not in STATUSES:
            raise ToolError(f"unknown result status: {status!r}")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "changed_fields",
                           tuple(str(f) for f in (self.changed_fields or ())))
        object.__setattr__(self, "invalidations",
                           tuple(str(s) for s in (self.invalidations or ())))
        if not self.created_at:
            object.__setattr__(self, "created_at", now())

    @property
    def ok(self) -> bool:
        """只有真正生效或确认无变化才算成功；unknown 不算成功也不算失败。"""
        return self.status in ("applied", "noop")

    @property
    def is_unknown(self) -> bool:
        return self.status == UNKNOWN

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "action_id": self.action_id,
            "tool": self.tool,
            "status": self.status,
            "ok": self.ok,
            "binding_hash": self.binding_hash,
            "execution_id": self.execution_id,
            "hypothesis_id": self.hypothesis_id,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "changed_fields": list(self.changed_fields),
            "invalidations": list(self.invalidations),
            "payload": dict(self.payload),
            "error": dict(self.error) if self.error else None,
            "budget": dict(self.budget),
            "evidence_refs": list(self.evidence_refs),
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class ToolOutcome:
    """handler 的返回值：动作事实，不含任何受信身份（身份由 Registry 补）。"""

    status: str = "applied"
    payload: Mapping = field(default_factory=dict)
    before: Any = None
    after: Any = None
    changed_fields: tuple[str, ...] = ()
    invalidations: tuple[str, ...] = ()
    error: Mapping | None = None
    budget_used: Mapping = field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        status = str(self.status or "")
        if status not in STATUSES:
            raise ToolError(f"unknown outcome status: {status!r}")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "changed_fields",
                           tuple(str(f) for f in (self.changed_fields or ())))
        object.__setattr__(self, "invalidations",
                           tuple(str(s) for s in (self.invalidations or ())))
        object.__setattr__(self, "evidence_refs",
                           tuple(str(r) for r in (self.evidence_refs or ())))


def applied(payload: Mapping | None = None, *, changed: Iterable[str] = (),
            before: Any = None, after: Any = None,
            invalidations: Iterable[str] = (),
            evidence_refs: Iterable[str] = (),
            budget_used: Mapping | None = None) -> ToolOutcome:
    return ToolOutcome(status="applied", payload=dict(payload or {}),
                       changed_fields=tuple(changed), before=before, after=after,
                       invalidations=tuple(invalidations),
                       evidence_refs=tuple(evidence_refs),
                       budget_used=dict(budget_used or {}))


def noop(payload: Mapping | None = None, *, reason: str = "",
         before: Any = None, after: Any = None) -> ToolOutcome:
    return ToolOutcome(status="noop", payload=dict(payload or {}),
                       before=before, after=after,
                       error={"code": "no_change", "reason": reason,
                              "field": "", "hint": ""} if reason else None)


def unknown(payload: Mapping | None = None, *, reason: str,
            code: str = "facts_unknown") -> ToolOutcome:
    """事实不足：合法结果，绝不降级成 False/0。"""
    return ToolOutcome(status=UNKNOWN, payload=dict(payload or {}),
                       error={"code": code, "reason": reason,
                              "field": "", "hint": ""})


def failed(code: str, reason: str, *, payload: Mapping | None = None) -> ToolOutcome:
    return ToolOutcome(status="failed", payload=dict(payload or {}),
                       error={"code": code, "reason": reason,
                              "field": "", "hint": ""})


# ====================================================================== 预算
def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class BudgetPort:
    """预算闸门的唯一接口：先 `check` 预留，后 `settle` 结算。"""

    def check(self, want: Mapping | None) -> dict:      # pragma: no cover - 协议
        return {"ok": True, "reserved": dict(want or {}), "reason": "",
                "detail": {}, "notes": []}

    def settle(self, used: Mapping | None) -> None:      # pragma: no cover - 协议
        return None

    def snapshot(self) -> dict:                          # pragma: no cover - 协议
        return {}


#: 预算键 → 限额键（与平台 Budget 同名字段；金额单列，不混进整数键）
BUDGET_LIMIT_KEYS = {
    "seconds": "max_seconds",
    "execs": "max_execs",
    "tokens": "max_tokens",
    "turns": "max_turns",
    "usd": "max_usd",
}


class NullBudget(BudgetPort):
    """不限额（仅用于纯离线测试/只读工具）；如实报告“没有限额声明”。"""

    def check(self, want: Mapping | None) -> dict:
        return {"ok": True, "reserved": dict(want or {}), "reason": "",
                "detail": {}, "notes": ["budget_unbounded"]}

    def snapshot(self) -> dict:
        return {"limits": {}, "used": {}, "notes": ["budget_unbounded"]}


class DeclaredBudget(BudgetPort):
    """按声明的上限做预留/结算的轻量账本。

    - 没有声明的限额键：放行但记 `limit_unknown:<key>`——不谎称成本受控；
    - 已声明：`used + want > limit` → 拒绝（`budget_exceeded`），并把差额放进 detail；
    - `settle()` 只累加真实用量，缺失的用量按预留保守扣账（§11）。
    """

    def __init__(self, limits: Mapping | None = None,
                 used: Mapping | None = None) -> None:
        self.limits = {str(k): float(v) for k, v in dict(limits or {}).items()
                       if v is not None}
        self.used = {str(k): float(v) for k, v in dict(used or {}).items()
                     if v is not None}

    def check(self, want: Mapping | None) -> dict:
        want = {str(k): float(v) for k, v in dict(want or {}).items()}
        notes: list[str] = []
        detail: dict[str, dict] = {}
        for key, amount in want.items():
            limit = self.limits.get(key)
            if limit is None:
                notes.append(f"limit_unknown:{key}")
                continue
            spent = self.used.get(key, 0.0)
            detail[key] = {"limit": limit, "used": spent,
                           "want": amount, "remaining": limit - spent}
            if spent + amount > limit:
                return {"ok": False, "reason": "budget_exceeded",
                        "reserved": {}, "notes": notes,
                        "detail": {"exceeded": key, **detail}}
        return {"ok": True, "reason": "", "reserved": want,
                "detail": detail, "notes": notes}

    def settle(self, used: Mapping | None) -> None:
        for key, value in dict(used or {}).items():
            if value is None:
                continue
            self.used[str(key)] = self.used.get(str(key), 0.0) + float(value)

    def snapshot(self) -> dict:
        remaining = {}
        for key, limit in self.limits.items():
            remaining[key] = limit - self.used.get(key, 0.0)
        return {"limits": dict(self.limits), "used": dict(self.used),
                "remaining": remaining}


# ====================================================================== 会话状态
@dataclass
class SessionState:
    """研究会话的动作侧状态（session.py 落地前的唯一落点）。

    只放“动作产生、尚未采纳”的工件：seed 规格、已物化种子、字典、trial 与
    收口结论。证据、候选、验证结论**不在这里**——那些由底座与独立验证写。
    """

    seed_specs: dict[str, dict] = field(default_factory=dict)
    seeds: dict[str, dict] = field(default_factory=dict)
    dictionary: dict = field(default_factory=dict)
    trials: dict[str, dict] = field(default_factory=dict)
    finished: dict | None = None
    revision: int = 0

    def touch(self) -> int:
        self.revision = int(self.revision) + 1
        return self.revision

    def to_dict(self) -> dict:
        return {
            "seed_specs": deep_copy(self.seed_specs),
            "seeds": deep_copy(self.seeds),
            "dictionary": deep_copy(self.dictionary),
            "trials": deep_copy(self.trials),
            "finished": deep_copy(self.finished),
            "revision": int(self.revision),
        }

    def fingerprint(self) -> str:
        """内容指纹：只对工件内容取哈希，`revision` 单独记（避免假变更）。"""
        body = self.to_dict()
        body.pop("revision", None)
        return digest_of(body)


# ====================================================================== 上下文
@dataclass
class ToolContext:
    """一次工具调用的全部受信输入（都由服务端组装，模型只能读返回值）。"""

    binding: Binding
    mode: str = "explore"
    grant: frozenset = field(default_factory=lambda: frozenset({"L0"}))
    budget: BudgetPort = field(default_factory=NullBudget)
    store: Any = None
    session: SessionState = field(default_factory=SessionState)
    corpus: Any = None
    index: Any = None
    evidence_root: Any = None
    exec_runner: Callable | None = None
    clock: Callable = field(default=time.time)
    #: None = 未追踪（快照里如实报 unknown），() = 追踪过且确实没有被拒
    tools_allowed: tuple[str, ...] | None = ()
    denials: tuple[str, ...] | None = None
    #: 后端实例（V3-018）：由控制器/测试注入；None = 用默认 HTTP 服务型后端
    backend: Any = None

    def state(self) -> SessionState:
        if self.session is None:
            self.session = SessionState()
        return self.session


# ====================================================================== schema
_TYPE_CHECKS: dict[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: (isinstance(v, (int, float))
                         and not isinstance(v, bool)),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, (list, tuple)),
    "object": lambda v: isinstance(v, Mapping),
}

#: 裁决/可信字段：**任何工具都不许把它声明成参数**（构造期就拦住）。
#: 它们只能由服务端与独立验证写，不是“模型可以声明后再被比对”的东西。
NEVER_DECLARABLE = frozenset({
    "status", "verdict", "verified", "confirmed", "pass", "trusted",
    "evidence_sha256", "oracle",
})

#: 模型不得写入的受信字段（工具若显式声明同名入参，需与绑定一致，见 Registry）
RESERVED_PARAMS = frozenset({
    "task_id", "campaign", "epoch", "job_id", "binding", "binding_hash",
    "status", "verdict", "verified", "confirmed", "pass", "trusted",
    "evidence_sha256", "authorized", "policy", "oracle",
})


def _check_value(name: str, decl: Mapping, value: Any) -> Any:
    if value is None and decl.get("nullable"):
        return None
    kind = str(decl.get("type") or "")
    checker = _TYPE_CHECKS.get(kind)
    if checker is None:
        raise ToolError(f"param {name}: unsupported type {kind!r}")
    if kind == "array":
        if not isinstance(value, (list, tuple)):
            raise ActionRejected("invalid_params",
                                 f"参数 {name} 需要 {kind}，实际 {type(value).__name__}",
                                 field_name=name)
        value = list(value)
        item = decl.get("items") or {}
        if item:
            for index, entry in enumerate(value):
                _check_value(f"{name}[{index}]", item, entry)
        max_items = decl.get("max_items")
        if max_items is not None and len(value) > int(max_items):
            raise ActionRejected(
                "invalid_params",
                f"参数 {name} 最多 {max_items} 项（实际 {len(value)}）",
                field_name=name, hint="分批提交")
        if decl.get("unique") and len(set(map(str, value))) != len(value):
            raise ActionRejected("invalid_params", f"参数 {name} 不允许重复项",
                                 field_name=name)
        return value
    if not checker(value):
        raise ActionRejected("invalid_params",
                             f"参数 {name} 需要 {kind}，实际 {type(value).__name__}",
                             field_name=name)
    if kind == "string":
        max_length = decl.get("max_length")
        if max_length is not None and len(value) > int(max_length):
            raise ActionRejected(
                "invalid_params",
                f"参数 {name} 长度 {len(value)} 超过 {max_length}",
                field_name=name)
        pattern = decl.get("pattern")
        if pattern and not re.search(str(pattern), value):
            raise ActionRejected("invalid_params",
                                 f"参数 {name} 不匹配 {pattern}",
                                 field_name=name)
    if decl.get("enum") and value not in tuple(decl["enum"]):
        raise ActionRejected("invalid_params",
                             f"参数 {name} 只能是 {list(decl['enum'])}",
                             field_name=name)
    if kind in ("integer", "number"):
        minimum = decl.get("minimum")
        maximum = decl.get("maximum")
        if minimum is not None and float(value) < float(minimum):
            raise ActionRejected("invalid_params",
                                 f"参数 {name} 不能小于 {minimum}",
                                 field_name=name)
        if maximum is not None and float(value) > float(maximum):
            raise ActionRejected("invalid_params",
                                 f"参数 {name} 不能大于 {maximum}",
                                 field_name=name)
        if kind == "integer":
            return int(value)
        return float(value)
    return value


def validate_params(spec: "ToolSpec", params: Mapping | None) -> dict:
    """按 spec 的声明校验并归一化参数（缺省补默认值，未知键拒绝）。"""
    given = dict(params or {})
    if not isinstance(params, Mapping):
        raise ActionRejected("invalid_params", "params 必须是对象",
                             field_name="params")
    unknown = sorted(set(given) - set(spec.params))
    if unknown:
        raise ActionRejected(
            "invalid_params", f"未知参数：{unknown}",
            field_name=unknown[0],
            hint=f"{spec.name} 只接受 {sorted(spec.params)}")
    out: dict[str, Any] = {}
    for name, decl in spec.params.items():
        if name in given:
            out[name] = _check_value(name, decl, given[name])
            continue
        if name in spec.required:
            raise ActionRejected("invalid_params", f"缺少必填参数 {name}",
                                 field_name=name)
        out[name] = deep_copy(decl.get("default"))
    return out


# ====================================================================== ToolSpec
def _handler_params(handler: Callable) -> dict[str, bool]:
    """读 handler 真实签名：{参数名: 是否有默认值}（`ctx` 除外）。"""
    if not callable(handler):
        raise ToolError("handler must be callable")
    try:
        sig = inspect.signature(handler)
    except (TypeError, ValueError) as exc:      # pragma: no cover
        raise ToolError(f"cannot inspect handler: {exc}") from exc
    out: dict[str, bool] = {}
    names = list(sig.parameters)
    if not names or names[0] != "ctx":
        raise ToolError("handler must take `ctx` as its first parameter")
    for name, param in list(sig.parameters.items())[1:]:
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            raise ToolError(
                f"handler param {name}: *args/**kwargs not allowed "
                "(schema cannot be derived)")
        out[name] = param.default is not inspect.Parameter.empty
    return out


@dataclass(frozen=True)
class ToolSpec:
    """一个工具的唯一声明：schema、handler、权限、失效范围都从这里派生。

    构造期对账（任一不满足 → `ToolError`）：

    1. `params` 的键集合 == handler 的实参集合（不含 `ctx`）；
    2. 没有默认值的实参 = `required`（由签名推出，不接受手工声明）；
    3. 每个参数的声明都有合法 type；默认值本身要通过该类型的校验；
    4. `permission` 在 PERMISSIONS 内且不是 L3；
    5. `changes` 在 CHANGE_INVALIDATIONS 内；显式 `invalidations` 必须与
       `CHANGE_INVALIDATIONS[changes]` 完全一致（不允许各写一套）；
    6. `cost` 只允许出现在 L1 工具上（只读工具不计费）。
    """

    name: str
    group: str
    summary: str
    handler: Callable
    params: Mapping = field(default_factory=dict)
    permission: str = "L0"
    changes: str = "none"
    allowed_modes: tuple[str, ...] = ("explore", "verify", "")
    cost: Callable | None = None
    invalidations: tuple[str, ...] = ()
    returns: Mapping = field(default_factory=dict)
    unsupported: str = ""

    def __post_init__(self) -> None:
        name = str(self.name or "")
        if not SAFE_TOOL_NAME.match(name):
            raise ToolError(f"unsafe tool name: {name!r}")
        if self.group not in GROUPS:
            raise ToolError(f"{name}: group must be one of {GROUPS}")
        if not str(self.summary or "").strip():
            raise ToolError(f"{name}: summary is required")
        if self.permission not in PERMISSIONS:
            raise ToolError(f"{name}: unknown permission {self.permission!r}")
        if self.permission in NEVER_EXPOSED:
            raise ToolError(
                f"{name}: permission {self.permission} 永不暴露给研究 Agent")
        if self.changes not in CHANGE_INVALIDATIONS:
            raise ToolError(
                f"{name}: changes must be one of {sorted(CHANGE_INVALIDATIONS)}")
        derived = tuple(CHANGE_INVALIDATIONS[self.changes])
        declared = tuple(str(s) for s in (self.invalidations or ()))
        if declared and declared != derived:
            raise ToolError(
                f"{name}: invalidations {declared} 与 changes={self.changes} 的"
                f"派生值 {derived} 不一致（失效范围必须同源）")
        for scope in derived:
            if scope not in INVALIDATION_SCOPES:
                raise ToolError(f"{name}: unknown invalidation {scope!r}")
        if self.cost is not None and self.permission == "L0":
            raise ToolError(f"{name}: 只读工具（L0）不允许计费")
        if self.cost is not None and not callable(self.cost):
            raise ToolError(f"{name}: cost must be callable")

        params = dict(self.params or {})
        forbidden = sorted(set(params) & NEVER_DECLARABLE)
        if forbidden:
            raise ToolError(
                f"{name}: 不许把裁决/可信字段声明成参数：{forbidden}"
                "（这些只能由服务端与独立验证写）")
        if not params and _handler_params(self.handler):
            raise ToolError(f"{name}: handler 有参数但 params 声明为空")
        for pname, decl in params.items():
            if not isinstance(decl, Mapping) or "type" not in decl:
                raise ToolError(f"{name}.{pname}: 声明必须是含 type 的对象")
            if decl["type"] not in _TYPE_CHECKS:
                raise ToolError(
                    f"{name}.{pname}: unsupported type {decl['type']!r}")
            if "default" in decl:
                try:
                    _check_value(pname, decl, decl["default"])
                except ActionRejected as exc:
                    raise ToolError(
                        f"{name}.{pname}: 默认值非法: {exc.reason}") from exc
        signature = _handler_params(self.handler)
        if set(signature) != set(params):
            raise ToolError(
                f"{name}: schema/handler 不对账：schema={sorted(params)} "
                f"handler={sorted(signature)}")
        # 默认值也必须同源：schema 说 7、handler 说 None 就是两套口径
        handler_defaults = {
            p.name: p.default for p in
            list(inspect.signature(self.handler).parameters.values())[1:]}
        for pname, decl in params.items():
            has_decl = "default" in decl
            default = handler_defaults.get(pname, inspect.Parameter.empty)
            if default is inspect.Parameter.empty:
                if has_decl:
                    raise ToolError(
                        f"{name}.{pname}: handler 没有默认值，schema 却声明了")
                continue
            if has_decl:
                if decl["default"] != default:
                    raise ToolError(
                        f"{name}.{pname}: 默认值不同源 "
                        f"schema={decl['default']!r} handler={default!r}")
                continue
            if default is not None:
                raise ToolError(
                    f"{name}.{pname}: handler 默认 {default!r} 未在 schema 声明"
                    "（只有 None 允许省略）")
        required = tuple(sorted(n for n, has_default in signature.items()
                                if not has_default))
        modes = tuple(str(m) for m in (self.allowed_modes or ("explore", "verify", "")))
        for mode in modes:
            if mode not in ("explore", "verify", ""):
                raise ToolError(f"{name}: unknown mode {mode!r}")

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "summary", str(self.summary))
        object.__setattr__(self, "params", params)
        object.__setattr__(self, "required", required)
        object.__setattr__(self, "allowed_modes", modes)
        object.__setattr__(self, "invalidations", derived)
        object.__setattr__(self, "returns", dict(self.returns or {}))
        object.__setattr__(self, "unsupported", str(self.unsupported or ""))
        object.__setattr__(self, "schema", self._build_schema(required))

    # ---- 派生 schema ----
    def _build_schema(self, required: tuple[str, ...]) -> dict:
        properties = {}
        for pname, decl in self.params.items():
            entry = dict(decl)
            entry.setdefault("description", "")
            properties[pname] = entry
        return {
            "schema": TOOL_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "name": self.name,
            "group": self.group,
            "description": self.summary,
            "type": "object",
            "properties": properties,
            "required": list(required),
            "additionalProperties": False,
            "permission": self.permission,
            "changes": self.changes,
            "invalidations": list(self.invalidations),
            "modes": list(self.allowed_modes),
            "returns": dict(self.returns),
            "unsupported": self.unsupported,
        }

    @property
    def schema_sha256(self) -> str:
        return digest_of(self.schema)

    def validate(self, params: Mapping | None) -> dict:
        return validate_params(self, params)

    def cost_of(self, params: Mapping) -> dict:
        """本次动作要预留的预算（只读工具恒为空）。"""
        if self.cost is None:
            return {}
        try:
            want = self.cost(params) or {}
        except ActionRejected:
            raise
        except Exception as exc:            # noqa: BLE001 - 计费失败即拒绝
            raise ActionRejected(
                "budget_error", f"{self.name}: 计费失败 {type(exc).__name__}: {exc}",
                hint="修正参数后重试") from exc
        out = {}
        for key, value in dict(want).items():
            try:
                out[str(key)] = float(value)
            except (TypeError, ValueError):
                out[str(key)] = 0.0
        return out

    def describe(self) -> dict:
        return {
            "name": self.name,
            "group": self.group,
            "summary": self.summary,
            "permission": self.permission,
            "changes": self.changes,
            "invalidations": list(self.invalidations),
            "required": list(self.required),
            "modes": list(self.allowed_modes),
            "cost": self.cost is not None,
            "unsupported": self.unsupported,
            "schema_sha256": self.schema_sha256,
        }


# ====================================================================== Registry
class Registry:
    """工具表 + 执行闸门：参数、身份、权限、模式、预算、失效都在这里。"""

    def __init__(self, specs: Iterable[ToolSpec] = ()) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._history: list[ActionResult] = []
        #: 待消费失效按 task 隔离：A 任务的 input_dedup 不能被 B 任务的
        #: consume 顺手取走（控制器永远带着自己的 task_id 来取）。
        self._pending: dict[str, list[str]] = {}
        for spec in specs:
            self.register(spec)

    # ---- 注册与查询 ----
    def register(self, spec: ToolSpec) -> ToolSpec:
        if not isinstance(spec, ToolSpec):
            raise ToolError("only ToolSpec can be registered")
        if spec.name in self._specs:
            raise ToolError(f"duplicate tool: {spec.name}")
        self._specs[spec.name] = spec
        return spec

    def get(self, name: str) -> ToolSpec:
        spec = self._specs.get(str(name or ""))
        if spec is None:
            raise ActionRejected(
                "unknown_tool", f"未注册的工具：{name!r}",
                field_name="action",
                hint=f"可用工具：{sorted(self._specs)}")
        return spec

    def specs(self) -> tuple[ToolSpec, ...]:
        return tuple(self._specs[name] for name in sorted(self._specs))

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def schema(self, name: str) -> dict:
        return dict(self.get(name).schema)

    def schemas(self) -> dict[str, dict]:
        return {spec.name: dict(spec.schema) for spec in self.specs()}

    def describe(self) -> list[dict]:
        return [spec.describe() for spec in self.specs()]

    @property
    def tool_schema_hash(self) -> str:
        """工具表摘要：进 binding，改 schema 就是新绑定（§9）。"""
        return digest_of({spec.name: spec.schema for spec in self.specs()})

    # ---- 失效消费 ----
    def pending_invalidations(self, task_id: str = "") -> tuple[str, ...]:
        """待消费的失效范围；给定 task_id 只看该任务，否则看全部任务的并集。"""
        if task_id:
            return tuple(dict.fromkeys(self._pending.get(str(task_id)) or []))
        merged: list[str] = []
        for rows in self._pending.values():
            merged.extend(rows)
        return tuple(dict.fromkeys(merged))

    def consume_invalidations(self, task_id: str = "") -> tuple[str, ...]:
        """控制器消费：取出并清空。只返回不消费 = 没生效（§8）。"""
        if task_id:
            taken = tuple(dict.fromkeys(self._pending.pop(str(task_id), [])))
            return taken
        taken = self.pending_invalidations()
        self._pending.clear()
        return taken

    def history(self) -> tuple[ActionResult, ...]:
        return tuple(self._history)

    # ---- 闸门 ----
    def _check_identity(self, request: ActionRequest, ctx: ToolContext,
                        spec: ToolSpec, params: Mapping) -> tuple[Binding, str]:
        claimed = Binding.from_dict(request.binding)
        same, why = claimed.same_scope(ctx.binding)
        if not same:
            raise ActionRejected(
                why,
                ("请求身份与本次会话不一致："
                 f"claimed task={claimed.task_id!r} exec={claimed.execution_id!r} / "
                 f"trusted task={ctx.binding.task_id!r} "
                 f"exec={ctx.binding.execution_id!r}"),
                field_name="binding",
                hint="身份由服务端填；请求只能原样回带")
        if claimed.hash != ctx.binding.hash:
            raise ActionRejected(
                "forged_identity",
                "binding.hash 与本次会话的可信绑定不一致",
                field_name="binding",
                hint="binding 必须来自服务端下发的本次会话绑定")
        reserved = RESERVED_PARAMS - set(spec.params)
        leaked = sorted(set(params) & reserved)
        if leaked:
            raise ActionRejected(
                "trusted_field_forbidden",
                f"{spec.name} 不接受受信字段：{leaked}",
                field_name=leaked[0],
                hint="裁决/身份/证据字段只能由服务端与独立验证写")
        execution = ""
        if "execution_id" in params:
            execution = str(params.get("execution_id") or "")
            if execution and ctx.binding.execution_id \
                    and execution != ctx.binding.execution_id:
                raise ActionRejected(
                    "cross_execution",
                    f"参数 execution_id={execution!r} 与绑定 "
                    f"{ctx.binding.execution_id!r} 不同（禁止跨 execution 拼接）",
                    field_name="execution_id")
        return claimed, execution

    def invoke(self, request: ActionRequest, ctx: ToolContext) -> ActionResult:
        """执行一个动作：先全部闸门，再 handler，最后结算与失效登记。"""
        try:
            spec = self.get(request.action)
        except ActionRejected as exc:
            return self._finish_rejected(request, ctx, str(request.action), exc)

        if spec.unsupported:
            return self._finish_rejected(
                request, ctx, spec.name,
                ActionRejected("unsupported",
                               f"{spec.name} 在本版本未接通：{spec.unsupported}",
                               field_name="action"))

        try:
            _, execution = self._check_identity(request, ctx, spec, request.params)
        except ActionRejected as exc:
            return self._finish_rejected(request, ctx, spec.name, exc)

        if not permission_allows(spec.permission, ctx.grant):
            return self._finish_rejected(
                request, ctx, spec.name,
                ActionRejected(
                    "permission_denied",
                    f"{spec.name} 需要 {spec.permission}"
                    f"（{PERMISSIONS[spec.permission]['title']}），"
                    f"本次授权={sorted(ctx.grant)}",
                    field_name="action",
                    hint=PERMISSIONS[spec.permission]["needs"]))

        mode = str(ctx.mode or "")
        if mode not in spec.allowed_modes:
            return self._finish_rejected(
                request, ctx, spec.name,
                ActionRejected(
                    "mode_not_allowed",
                    f"{spec.name} 只允许模式 {list(spec.allowed_modes)}，"
                    f"当前 {mode or '(空)'}",
                    field_name="mode",
                    hint="探索与独立验证必须分开进行（T14）"))

        allowed = ctx.tools_allowed
        if allowed is not None and spec.name not in tuple(allowed):
            return self._finish_rejected(
                request, ctx, spec.name,
                ActionRejected(
                    "tool_not_allowed",
                    f"{spec.name} 不在本次会话允许的工具集合内",
                    field_name="action",
                    hint=f"允许 {list(allowed)}"))

        try:
            params = spec.validate(request.params)
        except ActionRejected as exc:
            return self._finish_rejected(request, ctx, spec.name, exc)

        try:
            want = spec.cost_of(params)
        except ActionRejected as exc:
            return self._finish_rejected(request, ctx, spec.name, exc)
        if request.budget and spec.cost is not None:
            # 请求里的预算只能当“我最多能花这么多”的上限：
            # 声明得更宽不拦（只是上限），声明得更窄就是没钱做这件事——拒绝，
            # 不静默截断成本，也不替调用方放大额度。
            extra = sorted(set(request.budget) - set(want))
            if extra:
                return self._finish_rejected(
                    request, ctx, spec.name,
                    ActionRejected("invalid_params",
                                   f"{spec.name} 不接受预算键 {extra}",
                                   field_name="budget",
                                   hint=f"可声明 {sorted(want)}"))
            short = {key: float(value) for key, value in request.budget.items()
                     if float(value) < want[key]}
            if short:
                return self._finish_rejected(
                    request, ctx, spec.name,
                    ActionRejected(
                        "budget_exceeded",
                        f"{spec.name} 需要 {want}，请求声明的上限 {short} 不够",
                        field_name="budget",
                        hint="放大声明或缩小本次动作"))
        budget_port = ctx.budget or NullBudget()
        verdict = dict(budget_port.check(want) or {})
        if not verdict.get("ok", True):
            return self._finish_rejected(
                request, ctx, spec.name,
                ActionRejected(
                    "budget_exceeded",
                    f"{spec.name} 预留 {want} 超出可用预算",
                    field_name="budget",
                    hint=str(verdict.get("detail") or {})))

        before_fp = self._fingerprint(ctx)
        before_state = ctx.session.to_dict() if ctx.session is not None else None
        try:
            outcome = spec.handler(ctx, **params)
        except ActionRejected as exc:
            # 可修正的拒绝 = 没做事：回滚工件，也不扣预算。
            # 端口如果已经把额度**预留**出去了（LedgerBudget 就是这样），必须显式
            # 退还：否则一次参数错误就永久占住额度，越拒越穷。
            self._rollback(ctx, before_state)
            self._release_reserved(budget_port)
            return self._finish_rejected(request, ctx, spec.name, exc,
                                         budget=verdict, used={})
        except Exception as exc:            # noqa: BLE001 - handler 崩了是 failed
            self._rollback(ctx, before_state)
            budget_port.settle(want)
            return self._finish_failed(request, ctx, spec.name, exc,
                                       budget=verdict, used=want)
        if not isinstance(outcome, ToolOutcome):
            self._rollback(ctx, before_state)
            budget_port.settle(want)
            return self._finish_failed(
                request, ctx, spec.name,
                ToolError(f"{spec.name} handler 必须返回 ToolOutcome，"
                          f"实际 {type(outcome).__name__}"),
                budget=verdict, used=want)
        keep_external = (outcome.status == "failed"
                         and bool(outcome.changed_fields)
                         and spec.changes in EXTERNAL_EFFECT_CHANGES)
        rolled_back = False
        if outcome.status in ("rejected", "failed"):
            # 拒绝 / 失败一律回滚，除非：这个工具类别的变更是**会话外的副作用**
            # （语料/副本/构建产物，撤不回来）且它明确声明了 changed_fields。
            # 即使放行，也只保留**声明过的那几个会话字段**——corpus 类工具顺手
            # 改了字典/种子又不声明，照样被回滚（不靠“类别”一刀切）。
            self._rollback(ctx, before_state,
                           keep=outcome.changed_fields if keep_external else ())
            rolled_back = True

        after_fp = self._fingerprint(ctx)
        status = outcome.status
        changed = tuple(outcome.changed_fields)
        invalidations = tuple(outcome.invalidations)
        if status == "applied" and spec.changes in MUTATING_CHANGES:
            if before_fp and after_fp and before_fp == after_fp:
                status = "noop"
                changed = ()
                invalidations = ()
        if status == "applied":
            invalidations = tuple(dict.fromkeys(
                tuple(invalidations) + tuple(spec.invalidations)))
        else:
            invalidations = tuple(invalidations)
        for scope in invalidations:
            if scope not in INVALIDATION_SCOPES:
                return self._finish_failed(
                    request, ctx, spec.name,
                    ToolError(f"{spec.name} 返回未知失效域 {scope!r}"),
                    budget=verdict)
        if rolled_back and not keep_external:
            # 已回滚的动作不能对外声明“失效了什么”：那份变更不存在了。
            # （noop 分支同理：没有变化就没有失效。）
            changed = ()
            invalidations = ()
        used = dict(outcome.budget_used or want)
        if status == "rejected":
            # handler 自己判“没让做”（返回 ToolOutcome(status="rejected")）时同样
            # 不该扣钱：整条动作没发出去，退回预留；只有 failed 才是“做了没成”。
            self._release_reserved(budget_port)
        else:
            budget_port.settle(used)

        result = ActionResult(
            action_id=request.action_id,
            tool=spec.name,
            status=status,
            binding_hash=ctx.binding.hash,
            execution_id=execution or ctx.binding.execution_id,
            hypothesis_id=request.hypothesis_id,
            before_sha256=self._hash_of(outcome.before, before_fp),
            after_sha256=self._hash_of(outcome.after, after_fp),
            changed_fields=changed,
            invalidations=invalidations,
            payload={**dict(outcome.payload or {}),
                     **({"rolled_back": True} if rolled_back else {})},
            error=dict(outcome.error) if outcome.error else None,
            budget={"reserved": want, "used": used,
                    "port": budget_port.snapshot()},
            evidence_refs=tuple(request.evidence_refs) + tuple(outcome.evidence_refs),
        )
        if result.invalidations and (result.status == "applied" or keep_external):
            self._pending.setdefault(ctx.binding.task_id, []).extend(
                result.invalidations)
        self._history.append(result)
        return result

    # ---- 内部 ----
    #: 回滚能覆盖的会话字段（`changed_fields` 里的同名字段才会被保留）
    SESSION_FIELDS = ("seed_specs", "seeds", "dictionary", "trials", "finished")

    @classmethod
    def _rollback(cls, ctx: ToolContext, state: Mapping | None,
                  keep: Iterable[str] = ()) -> None:
        """把会话工件恢复到动作前的状态：拒绝/失败不留半截变更。

        `keep`：允许保留的会话字段（只有“会话外副作用”工具显式声明过的那几个）。
        未声明的字段一律回到动作前——按字段判定，不按“工具类别”一刀切。
        """
        if state is None or ctx.session is None:
            return
        session = ctx.session
        keep_set = {str(k) for k in (keep or ())}
        for field_name in cls.SESSION_FIELDS:
            if field_name in keep_set:
                continue
            if field_name == "finished":
                setattr(session, field_name, deep_copy(state.get(field_name)))
            else:
                setattr(session, field_name,
                        deep_copy(state.get(field_name) or {}))
        session.revision = int(state.get("revision") or 0)

    @staticmethod
    def _release_reserved(budget_port) -> None:
        """把“预留了但没发出去”的额度退掉；端口不支持就什么都不做。"""
        releaser = getattr(budget_port, "release_pending", None)
        if not callable(releaser):
            return
        try:
            releaser(reason="rejected")
        except Exception:              # noqa: BLE001 - 退还失败不改拒绝结论
            return

    @staticmethod
    def _fingerprint(ctx: ToolContext) -> str:
        session = ctx.state()
        return session.fingerprint()

    @staticmethod
    def _hash_of(explicit: Any, fallback: str) -> str:
        return digest_of(explicit) if explicit is not None else (fallback or "")

    def _finish_rejected(self, request: ActionRequest, ctx: ToolContext,
                         tool: str, exc: ActionRejected,
                         budget: Mapping | None = None,
                         used: Mapping | None = None) -> ActionResult:
        result = ActionResult(
            action_id=request.action_id, tool=tool, status="rejected",
            binding_hash=ctx.binding.hash if ctx.binding else "",
            execution_id=ctx.binding.execution_id if ctx.binding else "",
            hypothesis_id=request.hypothesis_id,
            error=exc.to_dict(),
            budget={"reserved": {}, "used": dict(used or {}),
                    "port": (ctx.budget or NullBudget()).snapshot()},
        )
        self._history.append(result)
        return result

    def _finish_failed(self, request: ActionRequest, ctx: ToolContext,
                       tool: str, exc: Exception,
                       budget: Mapping | None = None,
                       used: Mapping | None = None) -> ActionResult:
        error = (exc.to_dict() if isinstance(exc, ActionRejected)
                 else {"code": "handler_error",
                       "reason": f"{type(exc).__name__}: {exc}",
                       "field": "", "hint": ""})
        result = ActionResult(
            action_id=request.action_id, tool=tool, status="failed",
            binding_hash=ctx.binding.hash if ctx.binding else "",
            execution_id=ctx.binding.execution_id if ctx.binding else "",
            hypothesis_id=request.hypothesis_id,
            error=error,
            budget={"reserved": dict((budget or {}).get("reserved") or {}),
                    "used": dict(used or {}),
                    "port": (ctx.budget or NullBudget()).snapshot()},
        )
        self._history.append(result)
        return result


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "TOOL_SCHEMA", "STATUSES", "UNKNOWN",
    "GROUPS", "PERMISSIONS", "NEVER_EXPOSED", "permission_allows", "grant_for",
    "INVALIDATION_SCOPES", "CHANGE_INVALIDATIONS", "MUTATING_CHANGES",
    "BINDING_FIELDS", "BINDING_IDENTITY", "Binding", "ActionRequest",
    "ActionResult", "ToolOutcome", "applied", "noop", "unknown", "failed",
    "BudgetPort", "NullBudget", "DeclaredBudget", "BUDGET_LIMIT_KEYS",
    "SessionState", "ToolContext", "ToolSpec", "ToolError", "ActionRejected",
    "Registry", "validate_params", "RESERVED_PARAMS", "NEVER_DECLARABLE",
    "canonical_json",
    "digest_of", "now",
]
