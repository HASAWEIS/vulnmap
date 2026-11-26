"""内容寻址证据存储：evidence/<sha256>，refs 写 SQLite。"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True)
class EvidenceRef:
    sha256: str
    size: int
    path: str
    kind: str


class EvidenceStore:
    def __init__(self, store, root: Path | str):
        self.store = store
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put_bytes(self, task_id: str, kind: str, data: bytes,
                  source_stage: str = "") -> EvidenceRef:
        digest = sha256(data).hexdigest()
        path = self.root / digest
        if not path.exists():
            path.write_bytes(data)
        self.store.add_evidence(task_id, digest, len(data), str(path),
                                kind=kind, source_stage=source_stage)
        return EvidenceRef(digest, len(data), str(path), kind)

    def put_file(self, task_id: str, kind: str, src: Path | str,
                 source_stage: str = "") -> EvidenceRef:
        src = Path(src)
        return self.put_bytes(task_id, kind, src.read_bytes(), source_stage)

    def verify(self, ref: EvidenceRef) -> bool:
        p = Path(ref.path)
        return p.is_file() and sha256(p.read_bytes()).hexdigest() == ref.sha256
