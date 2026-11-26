#!/usr/bin/env bash
# vulnmap local CI entrypoint — offline, no API keys, no network.
#
# Steps: compile -> tests -> campaign
#
# Env toggles:
#   PYTHON=python3        interpreter override
#   ISO=auto              campaign isolation: auto|unshare|bwrap|none
#   REQUIRE_ISO=1         add --require-isolation (fail when isolation missing)
#   SKIP_TESTS=1          skip the pytest step
#   SKIP_CAMPAIGN=1       skip the example end-to-end campaign
#   KEEP=1                keep the temp dir holding campaign output/logs
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
cd "$REPO_ROOT"

PYTHON=${PYTHON:-python3}
ISO=${ISO:-auto}
REQUIRE_ISO=${REQUIRE_ISO:-0}
SKIP_TESTS=${SKIP_TESTS:-0}
SKIP_CAMPAIGN=${SKIP_CAMPAIGN:-0}
KEEP=${KEEP:-0}
# Fixed guards: a suite that silently collects fewer tests must fail CI.
# 总数下限 + 单独的 discovery 文件下限，防止"删掉整段新测试后总数仍 >= 30"蒙混过关。
readonly MIN_TESTS=60
readonly MIN_TESTS_DISCOVERY=55

# CI must never need a network or an API key.
export DISCOVERY_LLM_DISABLED=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vulnmap-ci.XXXXXX")"
cleanup() {
  local rc=$?
  if [ "$KEEP" = "1" ]; then
    echo "[cleanup] kept temp dir: $WORK_DIR"
  else
    rm -rf -- "$WORK_DIR"
  fi
  return $rc
}
trap cleanup EXIT

log()  { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

have_timeout=0
command -v timeout >/dev/null 2>&1 && have_timeout=1

# run_limited <seconds> <cmd...>
run_limited() {
  local limit="$1"; shift
  if [ "$have_timeout" = "1" ]; then
    timeout "$limit" "$@"
  else
    "$@"
  fi
}

command -v "$PYTHON" >/dev/null 2>&1 || die "interpreter not found: $PYTHON"
[ -d "$REPO_ROOT/agent" ] || die "missing agent/ under $REPO_ROOT"

log "repo:   $REPO_ROOT"
log "python: $($PYTHON --version 2>&1)"
log "llm:    DISCOVERY_LLM_DISABLED=$DISCOVERY_LLM_DISABLED (offline)"
log "tmp:    $WORK_DIR"

STATUS_COMPILE="skipped"
STATUS_TESTS="skipped"
STATUS_CAMPAIGN="skipped"
TEST_TOTAL="0"

# ---------------------------------------------------------------- compile ----
step_compile() {
  local out="$WORK_DIR/compile.log"
  log ""
  log "==> [compile] $PYTHON -m compileall -q agent bin"
  if ! run_limited 900 "$PYTHON" -m compileall -q agent bin >"$out" 2>&1; then
    cat "$out" >&2 || true
    die "compile step failed (see output above)"
  fi
  [ -s "$out" ] && cat "$out"
  STATUS_COMPILE="OK"
  log "[compile] OK"
}

# ------------------------------------------------------------------ tests ----
step_tests() {
  local out="$WORK_DIR/tests.log"
  local files=() f
  local -A seen=()

  add_test() {
    [ -e "$1" ] || return 0
    [ -n "${seen[$1]:-}" ] && return 0
    seen[$1]=1
    files+=("$1")
  }

  add_test tests/test_discovery.py
  add_test tests/test_agents.py
  add_test tests/test_agent_seeds.py
  add_test tests/test_platform_v2.py
  # discovery-era suites picked up automatically as they appear
  for f in tests/test_discovery*.py; do
    [ -e "$f" ] && add_test "$f"
  done

  [ "${#files[@]}" -gt 0 ] || die "no test files found (expected tests/test_discovery.py)"

  log ""
  log "==> [tests] $PYTHON -m pytest -q ${files[*]}"
  local rc=0
  run_limited 900 "$PYTHON" -m pytest -q "${files[@]}" >"$out" 2>&1 || rc=$?
  cat "$out"

  count_of() {
    grep -oE "[0-9]+ $1\b" "$out" 2>/dev/null | tail -n1 | grep -oE '^[0-9]+' || true
  }
  local passed failed errors skipped total
  passed=$(count_of passed);  passed=${passed:-0}
  failed=$(count_of failed);  failed=${failed:-0}
  errors=$(count_of errors);  errors=${errors:-0}
  skipped=$(count_of skipped); skipped=${skipped:-0}
  total=$((passed + failed + errors + skipped))
  TEST_TOTAL=$total

  log "[tests] collected/executed: $total (passed=$passed failed=$failed errors=$errors skipped=$skipped)"

  [ "$rc" -eq 0 ] || die "pytest exited $rc — see failing tests above"
  [ "$total" -ge "$MIN_TESTS" ] || die "only $total tests collected/passed, minimum is $MIN_TESTS (tests silently missing/deselected?)"

  # 文件级下限：tests/test_discovery.py 必须自己就够数（新增/原有测试都不许被删）
  local disc
  disc=$("$PYTHON" -m pytest -q --collect-only tests/test_discovery.py 2>/dev/null \
         | grep -cE '^tests/test_discovery\.py::' || true)
  disc=${disc:-0}
  log "[tests] test_discovery.py alone: $disc"
  [ "$disc" -ge "$MIN_TESTS_DISCOVERY" ] \
    || die "tests/test_discovery.py only has $disc tests, minimum is $MIN_TESTS_DISCOVERY (tests deleted/deselected?)"

  STATUS_TESTS="OK ($total tests)"
  log "[tests] OK ($total tests)"
}

# --------------------------------------------------------------- campaign ----
step_campaign() {
  local outdir="$WORK_DIR/campaign-out"
  local logf="$WORK_DIR/campaign.log"
  local args=(bin/discover.py fixtures/discovery
              --out "$outdir"
              --seconds 2 --max-sites 3 --workers 2
              --isolation "$ISO")
  [ "$REQUIRE_ISO" = "1" ] && args+=(--require-isolation)

  log ""
  log "==> [campaign] DISCOVERY_LLM_DISABLED=1 $PYTHON ${args[*]}"
  local rc=0
  run_limited 300 "$PYTHON" "${args[@]}" >"$logf" 2>&1 || rc=$?
  cat "$logf"
  [ "$rc" -eq 0 ] || die "campaign exited $rc (isolation=$ISO, require_iso=$REQUIRE_ISO)"

  local summary
  if ! summary=$("$PYTHON" - "$logf" <<'PY'
import json, sys
raw = open(sys.argv[1], encoding="utf-8", errors="replace").read()
end = raw.rfind("}")
i = raw.find("{")
data = None
while i != -1 and end > i:
    try:
        cand = json.loads(raw[i:end + 1])
    except Exception:
        cand = None
    if isinstance(cand, dict):
        data = cand
        break
    i = raw.find("{", i + 1)
if data is None:
    sys.exit("no JSON object found in campaign output")
if "risk_stats" not in data:
    sys.exit(f"campaign output has no risk_stats key; keys={sorted(data)}")
rs = data["risk_stats"]
print("risk_stats=" + json.dumps(rs, ensure_ascii=False, sort_keys=True))
if "campaign" in data:
    print("campaign=" + str(data["campaign"]))
if "coverage" in data:
    cov = data["coverage"]
    print("coverage=" + json.dumps({k: cov[k] for k in cov if k in ("planned", "covered", "status")},
                                   ensure_ascii=False, sort_keys=True))
PY
  ); then
    die "campaign output validation failed (no JSON with risk_stats)"
  fi
  printf '%s\n' "$summary"
  STATUS_CAMPAIGN="OK ($(printf '%s' "$summary" | grep -m1 '^risk_stats=' | cut -d= -f2-))"
  log "[campaign] OK"
}

step_compile
if [ "$SKIP_TESTS" = "1" ]; then
  log ""
  log "==> [tests] skipped (SKIP_TESTS=1)"
else
  step_tests
fi
if [ "$SKIP_CAMPAIGN" = "1" ]; then
  log ""
  log "==> [campaign] skipped (SKIP_CAMPAIGN=1)"
else
  step_campaign
fi

log ""
log "================ CI SUMMARY ================"
log "compile : $STATUS_COMPILE"
log "tests   : $STATUS_TESTS"
log "campaign: $STATUS_CAMPAIGN"
log "============================================"
log "ALL OK"
