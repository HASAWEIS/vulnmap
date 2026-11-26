"""CG-30（arvo:29633 / fio）构造器契约测试。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.builders import maxpath  # noqa: E402


def test_ini_shape():
    r = maxpath.build({})
    assert r.ok, r.reason
    text = r.data.decode()
    assert text.startswith("[global]\nfilename=/tmp/fio_")
    assert text.endswith("\n")
    assert r.fields_used["name_len"] == 6000


def test_length_exceeds_path_max():
    r = maxpath.build({"name_len": 6000})
    assert r.fields_used["name_len"] > maxpath.PATH_MAX
    assert not maxpath.build({"name_len": 4095}).ok


def test_bounds_and_types():
    assert not maxpath.build({"name_len": "long"}).ok
    assert not maxpath.build({"name_len": 10 ** 9}).ok
    assert not maxpath.build({"prefix": "relative/path"}).ok


def test_prefix_and_section_used():
    r = maxpath.build({"prefix": "/var/tmp/x", "section": "[job1]"})
    text = r.data.decode()
    assert text.startswith("[job1]\nfilename=/var/tmp/x")


def test_unknown_fields_dropped():
    r = maxpath.build({"unknown": 1})
    assert r.ok and any(d["field"] == "unknown" for d in r.dropped)


def test_claim_shape():
    c = maxpath.declared_claim()
    assert c["subject"] == "add_file"
    assert c["sink"]["file"] == "filesetup.c"
    assert c["sink"]["line"] == 1656
    assert c["cwe"] == "CWE-121"


def test_record_shape():
    rec = maxpath.build({}).to_record()
    assert set(rec) == {"ok", "format", "size", "fields_used", "dropped_fields", "reason"}
