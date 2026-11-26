#!/usr/bin/env bash
# VG-01 源码归属闸门：确认手上这份 wordnet_app.py 是 nltk@40d0bc1d 原件，
# 而不是 3.10.4 已修版、也不是仓库内的 patched 镜像 / 删除式重建件。
#
#   scripts/vg01_source_check.sh --dir DIR [--expect-sha256 H] [--commit-full SHA]
#   scripts/vg01_source_check.sh --dir DIR --record --commit-full SHA   # 落地清单
#
# 退出码（0 才算通过；任何"缺失"都是非 0）：
#   0  PASS
#   1  用法错误
#   2  源码缺失（目录 / nltk/app/wordnet_app.py 不存在）
#   3  文件 sha256 与清单/显式声明不一致
#   4  provenance 缺失（无 VGMANIFEST.json，或缺 40 位 commit）
#   5  含 token 校验（3.10.4 式 CWE-352 修复）→ 是 patched，不是原版
#   6  来源错误（site-packages / RECONSTRUCTED 文件名 / 已知的 patched 或重建件哈希）
#   7  shutdown 分支不成立（条件 / print / os._exit 缺失，或分支内夹着 403 鉴权）
#   8  commit 与 40d0bc1d 不符
#   9  --expect-line 与实测行号不符
#
# 设计取向：**fail-closed**。没有 commit 证据、没有哈希清单，一律非 0，
# 绝不用"看起来对"代替"核对过"。本脚本只读源码目录；唯一写操作是 --record
# 写 DIR/VGMANIFEST.json（在仓库外，绝不写 workspace/ 或历史证据）。
set -uo pipefail

PROG=$(basename "$0")

# ---- 已知的不合格件（本仓实测哈希，2026-11-19 复核） ----------------------
MIRROR_PATCHED_SHA=5a925994fcc5c199777b23e2bab7d9148bcf0715d9ef4c7369b31c77879ec31a
RECONSTRUCTED_SHA=f4fa4adcef89df0d861793a38e16d39c963825f17cbf1205d4682f9e5b9a4f23
INSTALLED_3104_SHA=58615acca7f0e8a7e820c930e3c611404459834d0eac1c754db701737d54b1ee

TASK_ID="vulngym/nltk/40d0bc1d"
EXPECT_COMMIT_DEFAULT="40d0bc1d"

DIR="${VG01_SRC:-$HOME/vg01-source/nltk-40d0bc1d}"
FILE=""
MANIFEST=""
EXPECT_SHA=""
EXPECT_COMMIT="$EXPECT_COMMIT_DEFAULT"
COMMIT_FULL=""
EXPECT_LINE=""
RECORD=0
QUIET=0

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) DIR="${2:?--dir 需要参数}"; shift 2 ;;
        --file) FILE="${2:?--file 需要参数}"; shift 2 ;;
        --manifest) MANIFEST="${2:?--manifest 需要参数}"; shift 2 ;;
        --expect-sha256) EXPECT_SHA="${2:?--expect-sha256 需要参数}"; shift 2 ;;
        --expect-commit) EXPECT_COMMIT="${2:?--expect-commit 需要参数}"; shift 2 ;;
        --commit-full) COMMIT_FULL="${2:?--commit-full 需要参数}"; shift 2 ;;
        --expect-line) EXPECT_LINE="${2:?--expect-line 需要参数}"; shift 2 ;;
        --record) RECORD=1; shift ;;
        --quiet|-q) QUIET=1; shift ;;
        --help|-h) usage 0 ;;
        *) echo "$PROG: 未知参数 $1" >&2; usage 1 ;;
    esac
done

[ -n "$FILE" ] || FILE="$DIR/nltk/app/wordnet_app.py"

pass() { [ "$QUIET" -eq 1 ] || printf '[PASS] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; printf 'VERDICT: FAIL (exit %s)\n' "$1" >&2; exit "$1"; }

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

# ---------------------------------------------------------------- 1. 文件在位
[ -f "$FILE" ] || fail 2 "源码缺失：$FILE 不存在。先在可联网机器取 40d0bc1d 并回传（见 docs/VG01-SOURCE-HANDOFF.md）"
pass "源码在位：$FILE（$(wc -l <"$FILE") 行，$(wc -c <"$FILE") 字节）"

# ------------------------------------------------- 2. 来源路径（不许是安装副本）
REAL=$(readlink -f "$FILE")
case "$REAL" in
    */site-packages/*|*/dist-packages/*|*/lib/python3.*/*)
        fail 6 "该文件位于解释器安装目录（$REAL）：这是 pip 安装的 nltk，不是 40d0bc1d 源码树"
        ;;
esac
case "$(basename "$REAL")" in
    *RECONSTRUCTED*|*reconstructed*)
        fail 6 "文件名标注为重建件（$REAL）：删除式重建 ≠ 上游原件"
        ;;
esac
case "$REAL" in
    */experiments/vg01/*)
        fail 6 "该文件在 experiments/vg01/ 内（$REAL）：仓库镜像是 patched，重建件是本地推演，两者都不能当原件"
        ;;
esac
pass "来源路径不是安装副本/镜像/重建件：$REAL"

# --------------------------------------------------------------- 3. 已知坏哈希
ACTUAL_SHA=$(sha256_of "$FILE")
for pair in "patched 镜像:$MIRROR_PATCHED_SHA" "删除式重建件:$RECONSTRUCTED_SHA" "已装 nltk 3.10.4:$INSTALLED_3104_SHA"; do
    label=${pair%%:*}; bad=${pair##*:}
    if [ "$ACTUAL_SHA" = "$bad" ]; then
        fail 6 "sha256 命中$label（$bad）：这不是 40d0bc1d 原件"
    fi
done
pass "sha256 未命中已知坏件：$ACTUAL_SHA"

# ------------------------------------------------------------- 4. token 校验
# 3.10.4 的修复引入 _shutdown_token / token_urlsafe / hmac.compare_digest /
# X-Shutdown-Token；本仓 patched 镜像引入 X-Shutdown-Token。命中任一即 patched。
GUARD_RE='_shutdown_token|_shutdown_authorized|X-Shutdown-Token|shutdown_token|token_urlsafe'
if grep -nEq "$GUARD_RE" "$FILE"; then
    grep -nE "$GUARD_RE" "$FILE" | head -5 >&2
    fail 5 "文件含 token 校验（CWE-352 修复的特征串）：这是 patched / 3.10.4，不是 40d0bc1d 原版"
fi
pass "无 token 校验特征串（_shutdown_token / X-Shutdown-Token / token_urlsafe 均未命中）"

# -------------------------------------------------------- 5. shutdown 分支形状
COND_RE='unquote_plus\(sp\)[[:space:]]*==[[:space:]]*"SHUTDOWN THE SERVER"'
PRINT_RE='(^|[^_[:alnum:]])print\("Server shutting down!"\)'
EXIT_RE='os\._exit\(0\)'

COND_LINE=$(grep -nE "$COND_RE" "$FILE" | head -1 | cut -d: -f1)
[ -n "$COND_LINE" ] || fail 7 "找不到未认证 shutdown 条件（unquote_plus(sp) == \"SHUTDOWN THE SERVER\"）：不是该漏洞的代码形状"
PRINT_LINE=$(grep -nE "$PRINT_RE" "$FILE" | head -1 | cut -d: -f1)
[ -n "$PRINT_LINE" ] || fail 7 "找不到 print(\"Server shutting down!\")（注意 3.10.4 用的是 safe_print，属已修版）"
EXIT_LINE=$(grep -nE "$EXIT_RE" "$FILE" | head -1 | cut -d: -f1)
[ -n "$EXIT_LINE" ] || fail 7 "找不到 os._exit(0)：shutdown 分支不完整"

[ "$COND_LINE" -lt "$PRINT_LINE" ] && [ "$PRINT_LINE" -lt "$EXIT_LINE" ] \
    || fail 7 "行序不对（条件:$COND_LINE print:$PRINT_LINE exit:$EXIT_LINE），不构成 go_GET → print → _exit 的直通路径"

# 分支内若夹着 403/鉴权，即使没有 token 字样也不是"未认证即关机"。
if sed -n "${COND_LINE},${EXIT_LINE}p" "$FILE" | grep -nEq 'send_error\(403|send_response\(403|401|Forbidden|authorized'; then
    sed -n "${COND_LINE},${EXIT_LINE}p" "$FILE" | grep -nE '403|401|Forbidden|authorized' >&2
    fail 7 "shutdown 分支内部夹着鉴权/拒绝（403/401/Forbidden）：不是未认证可达"
fi
pass "shutdown 分支成立：条件@${COND_LINE} → print@${PRINT_LINE} → os._exit@${EXIT_LINE}，分支内无鉴权"

if [ -n "$EXPECT_LINE" ] && [ "$COND_LINE" != "$EXPECT_LINE" ]; then
    fail 9 "行号不符：实测条件在 $COND_LINE 行，期望 $EXPECT_LINE 行（SOURCE.md 记的是 87；若真不符，是发现项，不是可忽略项）"
fi
if [ -z "$EXPECT_LINE" ] && [ "$COND_LINE" != "87" ]; then
    warn "条件实测在 ${COND_LINE} 行，而 SOURCE.md / case.json 记的是 87 行 —— 需在交接记录里作为发现项写清，不要静默改口径"
fi

# ------------------------------------------------------------- 6. commit 证据
# 优先 git；其次 --commit-full；再次清单里的 commit_full。三者皆无 → 4。
GIT_FULL=""
if command -v git >/dev/null 2>&1; then
    probe="$DIR"
    [ -d "$probe" ] || probe=$(dirname "$REAL")
    if GIT_FULL=$(git -C "$probe" rev-parse HEAD 2>/dev/null); then :; else GIT_FULL=""; fi
fi

[ -n "$MANIFEST" ] || MANIFEST="$DIR/VGMANIFEST.json"

MANIFEST_COMMIT=""
MANIFEST_SHA=""
if [ -f "$MANIFEST" ]; then
    MANIFEST_COMMIT=$(python3 - "$MANIFEST" <<'PY' 2>/dev/null || true
import json,sys
d=json.load(open(sys.argv[1]))
print(d.get("commit_full") or "")
PY
)
    MANIFEST_SHA=$(python3 - "$MANIFEST" <<'PY' 2>/dev/null || true
import json,sys
d=json.load(open(sys.argv[1]))
print(d.get("file_sha256") or "")
PY
)
fi

EFFECTIVE_COMMIT="${GIT_FULL:-${COMMIT_FULL:-$MANIFEST_COMMIT}}"

if [ -z "$EFFECTIVE_COMMIT" ]; then
    fail 4 "没有 commit 证据：源码树不是 git 检出，且未给 --commit-full，清单里也没有 commit_full。缺来源锚点就是缺证据（Tarball 流程见文档 §2.2）"
fi
case "$EFFECTIVE_COMMIT" in
    "$EXPECT_COMMIT"*) pass "commit = $EFFECTIVE_COMMIT（匹配前缀 $EXPECT_COMMIT）" ;;
    *) fail 8 "commit = $EFFECTIVE_COMMIT，与期望前缀 $EXPECT_COMMIT 不符" ;;
esac
if [ -n "$GIT_FULL" ] && [ -n "$MANIFEST_COMMIT" ] && [ "$GIT_FULL" != "$MANIFEST_COMMIT" ]; then
    fail 8 "git HEAD（$GIT_FULL）与清单记录的 commit（$MANIFEST_COMMIT）不一致：源码树被换过或清单过期"
fi

# --------------------------------------------------------------- 7. 哈希钉住
PIN="${EXPECT_SHA:-$MANIFEST_SHA}"
if [ -z "$PIN" ]; then
    if [ "$RECORD" -eq 1 ]; then
        :
    else
        fail 4 "没有哈希钉：清单缺 file_sha256，也未给 --expect-sha256。先 --record 落地清单，再用同一清单复核"
    fi
elif [ "$PIN" != "$ACTUAL_SHA" ]; then
    fail 3 "sha256 不一致：实测 $ACTUAL_SHA，期望 $PIN（源码被改过，或清单与文件不是同一份）"
else
    pass "sha256 = $PIN（与钉住值一致）"
fi

# ----------------------------------------------------------------- 8. --record
if [ "$RECORD" -eq 1 ]; then
    RECORDED_AT=$(date -Is)
    HOST=$(hostname 2>/dev/null || echo unknown)
    python3 - "$MANIFEST" "$ACTUAL_SHA" "$EFFECTIVE_COMMIT" "$FILE" \
        "$(wc -l <"$FILE")" "$COND_LINE" "$PRINT_LINE" "$EXIT_LINE" \
        "$RECORDED_AT" "$HOST" "$TASK_ID" "$EXPECT_COMMIT" <<'PY'
import json, sys
(path, sha, commit, file, lines, cond, prt, ex, at, host, task, prefix) = sys.argv[1:13]
doc = {
    "schema": "vulnmap.vg01.source.v1",
    "task_id": task,
    "expected_commit_prefix": prefix,
    "commit_full": commit,
    "commit_short": commit[:8],
    "file": "nltk/app/wordnet_app.py",
    "source_file": file,
    "file_sha256": sha,
    "file_lines": int(lines),
    "shutdown_line": int(cond),
    "print_line": int(prt),
    "os_exit_line": int(ex),
    "token_guard": False,
    "role": "upstream_original",
    "recorded_at": at,
    "recorded_by_host": host,
    "note": "由 scripts/vg01_source_check.sh --record 生成；只在 commit 已核对（git 或 --commit-full）时写入",
}
open(path, "w", encoding="utf-8").write(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
print("[PASS] 已写清单：%s" % path)
PY
    [ $? -eq 0 ] || fail 1 "写清单失败：$MANIFEST"
fi

printf 'VERDICT: PASS  (commit %s, sha256 %s, shutdown@%s)\n' \
    "$EFFECTIVE_COMMIT" "$ACTUAL_SHA" "$COND_LINE"
exit 0
