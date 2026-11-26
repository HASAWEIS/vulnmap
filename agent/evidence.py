"""人工核对后的因果要素档案（workspace/propagation.json）的唯一读取入口。

为什么要独立成模块：
- 门禁（report）和定位（locate）都要消费同一份要素，但两边各自实现过一次
  合并逻辑，字段口径已经出现分叉（source / note / verified_by 各写各的）。
- `verified_by=manual_review` 曾被 locate 直接盖上去，等于"写文件即自证已复核"。
  这里改成：`verified_by` 取文件自己的声明（默认 `evidence_refs`），人工复核
  另记 `reviewed_by` / `reviewed_at`，二者都不由代码臆造。

文件格式（只认识 elements，其余字段原样透传）：

    {
      "case": "CG-18",
      "source": "COURSE-GAP-20261118 逐行核对",
      "verified_by": "evidence_refs",
      "reviewed_by": null,
      "elements": {
        "input_bytes":   {"value": "...", "refs": [...], "derivation": "direct_observation"},
        "reaches_sink":  {...},
        "missing_check": {...},
        "observed_oob":  {...}
      }
    }
"""
from __future__ import annotations

import json
from pathlib import Path

# 因果要素的规范顺序：memory_corruption 的四要素
PROPAGATION_KEYS = ("input_bytes", "reaches_sink", "missing_check", "observed_oob")

# 这些字段只作为元信息透传，不参与 elements 合并
META_KEYS = ("case", "workspace", "source", "note", "verified_by", "reviewed_by",
             "reviewed_at", "derivation", "refs", "generated_at", "schema")


def load_propagation(ws: Path) -> dict:
    """读取工作区的 propagation.json；没有/不可读就返回 {}（不臆造）。"""
    p = Path(ws) / "propagation.json"
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def element_values(manual: dict) -> dict:
    """把 elements 里的 {value, refs, ...} 压成 {key: value}（只保留有值的）。"""
    out: dict[str, str] = {}
    for key, spec in (manual.get("elements") or {}).items():
        if isinstance(spec, dict):
            val = spec.get("value")
        else:
            val = spec
        if val not in (None, ""):
            out[key] = val
    return out


def _dataflow_from(elements: dict) -> list[dict]:
    """由人工核对的要素生成数据流步骤（有据可依，不是编造）。

    只按规范顺序取三要素：observed_oob 是结果不是链路的一步。
    """
    return [{"step": k, "note": str(elements.get(k, ""))[:200]}
            for k in ("input_bytes", "reaches_sink", "missing_check")
            if elements.get(k)]


def merge_into_claim(claim: dict | None, manual: dict) -> dict:
    """把档案里的要素合并进 claim（返回新 dict，不改调用方对象）。

    - elements 逐个覆盖/补齐，保留 claim 已有的要素
    - dataflow 只在 claim 没有时由要素生成（已有的定位数据流更细，不覆盖）
    - verified_by / reviewed_by 分开记，代码不替人签字
    """
    claim = dict(claim or {})
    if not manual:
        return claim
    values = element_values(manual)
    if not values:
        return claim
    prop = dict(claim.get("propagation") or {})
    merged = dict(prop.get("elements") or {})
    merged.update(values)
    prop["elements"] = merged
    prop["source"] = manual.get("source") or manual.get("note") or ""
    prop["verified_by"] = manual.get("verified_by") or "evidence_refs"
    prop["reviewed_by"] = manual.get("reviewed_by") or ""
    prop["reviewed_at"] = manual.get("reviewed_at") or ""
    prop["refs"] = {k: list(spec.get("refs") or [])
                    for k in values
                    for spec in [(manual.get("elements") or {}).get(k)]
                    if isinstance(spec, dict)}
    claim["propagation"] = prop
    if not claim.get("dataflow"):
        claim["dataflow"] = _dataflow_from(merged)
    return claim


# ---- refs 复算：每条要素都要能在工作区内逐行核对 ----

def read_text(path: Path) -> str:
    """按 utf-8 → latin-1 顺序读；二进制/脏编码不抛异常。"""
    for enc in ("utf-8", "latin-1"):
        try:
            return Path(path).read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return Path(path).read_bytes().decode("utf-8", "replace")


def check_ref(ref: dict, root: Path | None = None) -> str | None:
    """核对一条 ref：文件存在且非空 / 行号在范围内 / 该行含 expect。

    返回 None 表示通过，否则返回失败原因。行号为 null 表示二进制或整文件证据，
    只查存在且非空（与 experiments/COURSE-GAP-verify.py 同一口径）。
    """
    root = Path(root) if root else None
    rel = (ref or {}).get("path")
    if not rel:
        return "ref 缺 path"
    p = (root / rel) if (root and not Path(rel).is_absolute()) else Path(rel)
    if not p.exists():
        return f"文件不存在 {rel}"
    if p.stat().st_size == 0:
        return f"文件为空 {rel}"
    line = ref.get("line")
    expect = ref.get("expect")
    if line is None:
        if expect:
            return f"{rel} 行号为 null 却给了 expect={expect!r}"
        return None
    text = read_text(p).splitlines()
    if not (1 <= int(line) <= len(text)):
        return f"{rel}:{line} 行号越界（共 {len(text)} 行）"
    if not expect:
        return None if text[int(line) - 1].strip() else f"{rel}:{line} 为空行"
    if expect not in text[int(line) - 1]:
        return f"{rel}:{line} 不含 {expect!r}（实际 {text[int(line)-1][:120]!r}）"
    return None


def check_all_refs(manual: dict, root: Path | None = None) -> list[dict]:
    """逐条核对档案里所有要素的 refs，返回失败清单（空 = 全部可复算）。"""
    out = []
    for key in PROPAGATION_KEYS:
        spec = (manual.get("elements") or {}).get(key)
        if not isinstance(spec, dict):
            continue
        for ref in spec.get("refs") or []:
            err = check_ref(ref, root)
            if err:
                out.append({"element": key, "ref": ref, "error": err})
    return out
