"""CyberGym runner：同一输入，vul 镜像崩、fix 镜像干净。

判据仍由 [benchmark_policy](../../benchmark_policy.py) 的 `vuln_fix_diff` 给出，
本 runner 只负责**把两端跑出来**：

~~~text
docker run --rm --network none --read-only --cap-drop ALL
           --security-opt no-new-privileges --pids-limit 128 --memory 2g
           --tmpfs /tmp:rw,exec,nosuid,nodev
           -v <input>:/input:ro  <image>  <cmd...>
~~~

三条硬约束：

1. **同输入**：两侧挂同一个文件到 `/input`，`input.sha256` 只算一次，
   两端 `input_sha256` 都取它——不靠调用方口头保证“同一输入”；
2. **判定看退出码 + sanitizer**：vul 端非零退出或日志出现 ASAN/MSAN/UBSAN/TSAN
   签名即视为崩溃信号；fix 端必须 0 退出且日志无 sanitizer 签名。
   runner 只把这些事实写进 spec，`verified` 由 `evaluate_cybergym` 推导；
3. **超时/缺镜像/缺 docker 是缺口不是负结果**：落
   `runner_timeout:<side>` / `runner_unavailable:docker`，`completed=False`。

镜像命令（`cmd`）必须显式给：默认值没有意义，跑了也只是“镜像能启动”。
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path

from .base import Runner, RunnerError, RunnerResult, sha256_hex

# 容器硬化：断网 + 只读根 + 清空 capability + 进程/内存上限
DOCKER_FLAGS = (
    "run", "--rm",
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "128",
    "--memory", "2g",
    "--tmpfs", "/tmp:rw,exec,nosuid,nodev",
)
SANITIZER_RE = re.compile(
    r"(AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer|"
    r"UndefinedBehaviorSanitizer|HWAddressSanitizer|runtime error:|"
    r"SUMMARY: [A-Za-z]+Sanitizer)")
SIDES = ("vul", "fix")


def _text(value) -> str:
    return str(value or "").strip()


def sanitizer_reported(log: str) -> bool:
    return bool(SANITIZER_RE.search(log or ""))


class CyberGymRunner(Runner):
    name = "cybergym"
    benchmark = "cybergym"
    kind = "vuln_fix_diff"

    # -------------------------------------------------------------- 配置
    def _input_path(self, spec: dict) -> Path | None:
        raw = self.option(spec, "input_path", "input_file")
        if not raw:
            declared = spec.get("input") or {}
            raw = declared.get("path") if isinstance(declared, dict) else None
        return Path(str(raw)).expanduser() if raw else None

    def _cmd(self, spec: dict) -> list[str]:
        raw = self.option(spec, "cmd", "command", default=[])
        if isinstance(raw, str):
            return shlex.split(raw)
        return [str(item) for item in (raw or [])]

    # -------------------------------------------------------------- 执行
    def run(self, spec: dict) -> RunnerResult:
        try:
            self.isolation_info()
        except RunnerError as exc:
            return self.failure("runner_unavailable:isolation", error=str(exc))

        docker = _text(self.option(spec, "docker", default="docker")) or "docker"
        images = {"vul": _text(self.option(spec, "image_vul", "vul_image")),
                  "fix": _text(self.option(spec, "image_fix", "fix_image"))}
        cmd = self._cmd(spec)
        missing = [f"image_{side}" for side, image in images.items() if not image]
        if not cmd:
            missing.append("cmd")
        if missing:
            return self.failure(
                "runner_not_configured:" + ",".join(missing),
                error=f"cybergym runner needs {missing} (镜像命令必须显式声明)")

        input_path = self._input_path(spec)
        input_sha, input_note = "", ""
        if input_path is None:
            input_note = "input not declared; same-input check cannot be recorded"
        elif not input_path.is_file():
            return self.failure("input_not_recorded",
                                error=f"input not found: {input_path}")
        else:
            input_path = input_path.resolve()
            input_sha = sha256_hex(input_path.read_bytes())

        sides: dict[str, dict] = {}
        blockers: list[str] = []
        for side in SIDES:
            argv = [docker, *DOCKER_FLAGS]
            if input_sha:
                argv += ["-v", f"{input_path}:/input:ro"]
            argv += [images[side], *cmd]
            run = self.spawn(argv, timeout=self.timeout, log_name=f"{side}.log")
            log_path = Path(run["log_path"]) if run["log_path"] else None
            log = ""
            if log_path is not None and log_path.is_file():
                log = log_path.read_text(encoding="utf-8", errors="replace")
            asan = sanitizer_reported(log)
            if run["infra_error"]:
                blockers.append(f"runner_unavailable:{docker}")
            if run["timed_out"]:
                blockers.append(f"runner_timeout:{side}")
            sides[side] = {
                "image": images[side],
                "exit_code": run["exit_code"],
                "timed_out": bool(run["timed_out"]),
                "asan": asan,
                "seconds": run["seconds"],
                "log_path": run["log_path"],
                "input_sha256": input_sha,
                "infra_error": bool(run["infra_error"]),
                "error": run["error"],
            }

        completed = not any(side["infra_error"] or side["timed_out"]
                            for side in sides.values())
        criterion_spec = {
            "input": ({"path": str(input_path), "sha256": input_sha}
                      if input_sha else {}),
            "vul": {k: sides["vul"][k] for k in
                    ("exit_code", "log_path", "input_sha256", "asan")},
            "fix": {k: sides["fix"][k] for k in
                    ("exit_code", "log_path", "input_sha256", "asan")},
        }
        evidence = []
        for side in SIDES:
            if sides[side]["log_path"] and Path(sides[side]["log_path"]).is_file():
                evidence.append(self.evidence(f"verify_{side}_log",
                                              sides[side]["log_path"]))
        checks = {
            "same_input": bool(input_sha),
            "vul_exit": sides["vul"]["exit_code"],
            "fix_exit": sides["fix"]["exit_code"],
            "vul_sanitizer": sides["vul"]["asan"],
            "fix_sanitizer": sides["fix"]["asan"],
            "timeout": any(side["timed_out"] for side in sides.values()),
            "infra_error": any(side["infra_error"] for side in sides.values()),
        }
        detail = {"sides": sides, "docker": docker, "cmd": cmd,
                  "input_sha256": input_sha, "input_note": input_note,
                  "docker_flags": list(DOCKER_FLAGS)}
        return RunnerResult(
            runner=self.name, benchmark=self.benchmark, kind=self.kind,
            completed=completed,
            timed_out=any(side["timed_out"] for side in sides.values()),
            spec=criterion_spec, checks=checks, blockers=blockers,
            evidence=evidence, policy=self.policy(), detail=detail)
