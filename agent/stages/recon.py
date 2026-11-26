"""Recon：环境校验 → 解包 → 构建探测 → 入口枚举 → 攻击面排序。"""
from __future__ import annotations

import json
import re
import tarfile
from pathlib import Path

from ..casekit import image_for as _case_image_for
from ..errors import BuildError, EnvError
from ..tools import binscan, shell
from ..util import append_jsonl, read_json, sha256_file
from ..validate import guard_upstream_untouched
from .base import Stage

BUILD_ORDER = (
    ("CMakeLists.txt", "cmake"),
    ("configure.ac", "autotools"),
    ("autogen.sh", "autotools"),
    ("meson.build", "meson"),
    ("Makefile", "make"),
    ("setup.py", "python"),
    ("pyproject.toml", "python"),
)

DEP_HINTS = {
    "png.h": "libpng-dev", "zlib.h": "zlib1g-dev", "jpeglib.h": "libjpeg-dev",
    "tiff.h": "libtiff-dev", "ft2build.h": "libfreetype-dev", "xml2": "libxml2-dev",
    "fontconfig": "libfontconfig1-dev", "bison": "bison", "flex": "flex",
    "autoconf": "autoconf", "automake": "automake", "libtool": "libtool",
}


def _safe_is_file(p) -> bool:
    """悬空符号链接 / 无权限路径不得让整阶段失败。

    镜像里常见指向 /root/.cache/bazel/... 的绝对符号链接，
    Path.is_file() 会跟随并抛 PermissionError，直接打断 recon。
    """
    try:
        return p.is_file()
    except OSError:
        return False


class ReconStage(Stage):
    name = "recon"
    role_version = "recon-v1"
    prompt_version = "recon-p1"
    schema_version = "vulnmap.repo_map.v1"
    requires_images = False

    def input_hashes(self) -> dict[str, str]:
        out = super().input_hashes()
        # recon 会解包并改写 src/，输入只看 tarball 本体；同时记录解包前的目录指纹
        src = self.layout["src"]
        if src.exists():
            files = sorted(p for p in src.rglob("*") if _safe_is_file(p))[:400]
            out["src/sha256_set"] = sha256_file_of_list(files)
        return out

    def cache_inputs(self) -> dict[str, str]:
        # recon 自己会解包/构建，src/ 指纹随执行变化，只以 tarball 作为可复用输入
        return {k: v for k, v in super().input_hashes().items() if k != "src/sha256_set"}

    def image_refs(self) -> list[str]:
        return [self.ws_image_vul()] if self.ws_image_vul() else []

    def ws_image_vul(self) -> str:
        return _case_image_for(self.ws, "vul")

    def execute(self) -> dict:
        src = self.layout["src"]
        tarball = self.ws / "repo-vul.tar.gz"
        if tarball.exists():
            self._extract(tarball, src)
        elif src.exists() and any(src.iterdir()):
            pass
        else:
            # ExploitGym 类任务不提供源码包：仅做镜像级侦察，不视为环境失败
            meta = json.loads((self.ws / "task.json").read_text()) if (self.ws / "task.json").exists() else {}
            if meta.get("benchmark") == "exploitgym":
                build = {"system": "na", "status": "no_source_archive",
                         "marker": "", "command": "", "note": "ExploitGym 任务无源码包"}
                repo_map = {"schema": "vulnmap.repo_map.v1",
                            "repo": {"root": str(src), "language": "binary",
                                     "loc": 0, "file_types": {}, "excluded": []},
                            "build": build, "entrypoints": [], "blockers": [],
                            "upstream": {n: h for n, h in self.input_hashes().items()
                                         if n in ("task.json", "description.txt")}}
                art = self.emit("recon/repo_map.json", repo_map, "vulnmap.repo_map.v1")
                self.store.add_blackboard(self.run_id, "action", "侦察完成（无源码）",
                                          "ExploitGym 任务，按镜像级侦察继续", status="ok")
                return {"repo_map": art, "build_status": "no_source_archive",
                        "entrypoints": 0}
            raise EnvError("no repo-vul.tar.gz and src/ is empty")

        profile = self._profile(src)
        build = self._detect_build(src)
        if build["system"] in ("cmake", "autotools", "meson", "make", "python"):
            build = self._try_build(src, build)
        entries = self._entrypoints(src)
        ranked = self._rank(entries, profile)

        upstream = {name: sha for name, sha in self.input_hashes().items()
                    if name in ("repo-vul.tar.gz", "description.txt", "error.txt", "task.json")}
        repo_map = {
            "schema": "vulnmap.repo_map.v1",
            "repo": profile,
            "build": build,
            "entrypoints": ranked,
            "blockers": [],
            "upstream": upstream,
        }
        # 走契约校验：上游工件必须与输入完全一致
        art = self.emit("recon/repo_map.json", repo_map, "vulnmap.repo_map.v1",
                        guards=[lambda d: guard_upstream_untouched(upstream, d)])
        self.store.add_blackboard(self.run_id, "action", "侦察完成",
                                  f"{len(ranked)} 个入口，构建 {build.get('status')}",
                                  status="ok")
        return {"repo_map": art, "build_status": build.get("status"), "entrypoints": len(ranked)}

    # ---- 步骤 ----
    def _extract(self, tarball: Path, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tarball, "r:*") as tf:
            members = tf.getmembers()
            for m in members:
                name = m.name
                if name.startswith("/") or ".." in Path(name).parts:
                    raise EnvError(f"unsafe tar member: {name}")
            top = {m.name.split("/")[0] for m in members if m.name}
            strip = 1 if len(top) == 1 else 0
            for m in members:
                parts = m.name.split("/")[strip:]
                if not parts or not parts[0]:
                    continue
                target = dest.joinpath(*parts)
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif m.isfile() and m.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tf.extractfile(m) as fh, target.open("wb") as out:
                        out.write(fh.read())

    def _profile(self, src: Path) -> dict:
        counts: dict[str, int] = {}
        loc = 0
        excluded = []
        for path in src.rglob("*"):
            if not _safe_is_file(path):
                continue
            suffix = path.suffix.lower() or "<none>"
            counts[suffix] = counts.get(suffix, 0) + 1
        for name in ("third_party", "vendor", "contrib", "test", "tests"):
            if (src / name).is_dir():
                excluded.append(name)
        code_suffixes = {".c", ".cc", ".cpp", ".h", ".hpp", ".py", ".go", ".rs", ".java", ".js"}
        for path in src.rglob("*"):
            if _safe_is_file(path) and path.suffix.lower() in code_suffixes:
                try:
                    loc += sum(1 for _ in path.open("rb"))
                except OSError:
                    pass
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        return {"root": str(src), "language": ranked[0][0] if ranked else "unknown",
                "loc": loc, "file_types": dict(ranked), "excluded": excluded}

    def _detect_build(self, src: Path) -> dict:
        for marker, system in BUILD_ORDER:
            found = [p for p in src.rglob(marker) if _safe_is_file(p)
                     and len(p.relative_to(src).parts) <= 2]
            if found:
                return {"system": system, "marker": str(found[0].relative_to(src)),
                        "status": "detected", "command": ""}
        return {"system": "none", "marker": "", "status": "na", "command": ""}

    def _try_build(self, src: Path, build: dict) -> dict:
        log = self.log_path("R3.build.log")
        system = build["system"]
        if system == "cmake":
            argv = ["cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                    "-DCMAKE_BUILD_TYPE=Debug"]
        elif system == "autotools":
            argv = ["sh", "-c", "(test -f configure || (autoreconf -fi)) && ./configure --disable-shared"]
        elif system == "meson":
            argv = ["meson", "setup", "build", "-Dbuildtype=debug"]
        elif system == "make":
            argv = ["make", "-n"]
        else:
            argv = ["python3", "-c", "import setuptools; print('setuptools ok')"]
        res = shell.run_logged(argv, log, cwd=src, timeout=600, stage=self.name)
        if res.exit_code == 127:
            build = dict(build)
            build.update({"status": "toolchain_missing", "command": " ".join(res.argv),
                          "error_tail": res.stderr[-500:]})
            self.store.add_evidence(self.run_id, self.name, "build",
                                    "toolchain missing, degrade to static analysis",
                                    observed_by="shell")
            return build
        build = dict(build)
        build["command"] = " ".join(res.argv)
        build["exit_code"] = res.exit_code
        build["status"] = "ok" if res.ok else "failed"
        if not res.ok:
            tail = (res.stdout + res.stderr)[-2000:]
            build["error_tail"] = tail
            build["missing_packages"] = sorted({pkg for hint, pkg in DEP_HINTS.items() if hint in tail})
        compile_db = src / "build" / "compile_commands.json"
        if compile_db.exists():
            try:
                import json
                build["compile_db"] = "build/compile_commands.json"
                build["compile_db_entries"] = len(json.loads(compile_db.read_text()))
            except Exception:
                build["compile_db_entries"] = 0
        self.store.add_evidence(self.run_id, self.name, "build",
                                f"{system} build {build['status']} exit={res.exit_code}",
                                observed_by="shell")
        if build["status"] == "failed" and not build.get("compile_db_entries"):
            build["status"] = "degraded"
            self.store.add_blackboard(self.run_id, "hypothesis", "构建未完成",
                                      f"{system} 构建失败，退化为静态分析；缺包："
                                      f"{build.get('missing_packages', [])}", status="unknown")
        return build

    def _entrypoints(self, src: Path) -> list[dict]:
        entries: list[dict] = []
        for hit in binscan.grep(src, r"^[A-Za-z_][\w \t\*]*\bmain\s*\(", limit=20, stage=self.name):
            entries.append({"kind": "main", "symbol": "main", **hit})
        for hit in binscan.grep(src, r"LLVMFuzzerTestOneInput", limit=20, stage=self.name):
            entries.append({"kind": "fuzz_target", "symbol": "LLVMFuzzerTestOneInput", **hit})
        for hit in binscan.grep(src, r"^[A-Za-z_][\w \t\*]*\b(parse|read|load|decode|import)\w*\s*\(", limit=30, stage=self.name):
            name = re.search(r"\b(\w+)\s*\(", hit["text"])
            if name:
                entries.append({"kind": "parser_candidate", "symbol": name.group(1), **hit})
        # 去重
        seen = set()
        out = []
        for e in entries:
            key = (e["file"], e["line"])
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
        return out

    def _rank(self, entries: list[dict], profile: dict) -> list[dict]:
        descr = ""
        dpath = self.ws / "description.txt"
        if dpath.exists():
            descr = dpath.read_text(encoding="utf-8", errors="ignore").lower()
        ranked = []
        for e in entries:
            sym = e["symbol"].lower()
            match = 1.0 if sym and sym in descr else 0.0
            kind_bonus = {"fuzz_target": 0.9, "main": 0.6, "parser_candidate": 0.5}.get(e["kind"], 0.3)
            score = round(0.35 * kind_bonus + 0.25 * 0.6 + 0.2 * 0.5 + 0.2 * match, 3)
            why = []
            if match:
                why.append("描述命中函数名")
            why.append(f"{e['kind']}")
            ranked.append({**e, "rank": score, "why": "; ".join(why)})
        ranked.sort(key=lambda x: x["rank"], reverse=True)
        for i, e in enumerate(ranked):
            e["id"] = f"ep{i+1}"
        return ranked[:10]


def sha256_file_of_list(files) -> str:
    """解包目录的确定性指纹：路径 + 内容 sha 的串联摘要。"""
    from ..util import canonical_json, short_hash
    return short_hash([(str(p), sha256_file(p)) for p in files], 64)
