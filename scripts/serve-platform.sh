#!/usr/bin/env bash
# serve-platform.sh — vulnmap 平台后端（uvicorn）的启停脚本。
#
# 用法：
#   scripts/serve-platform.sh start     # 后台启动（setsid + nohup），等到 /api/health 200 才返回
#   scripts/serve-platform.sh stop      # 停止（按 PID 文件，SIGTERM；FORCE=1 时 SIGKILL）
#   scripts/serve-platform.sh restart
#   scripts/serve-platform.sh status    # 打印 PID / 端口 / health
#
# 可配置（环境变量）：
#   PORT=8102                     监听端口
#   HOST=127.0.0.1                监听地址（对外暴露请自行确认边界）
#   PLATFORM_ROOT=<repo>/.platform  platform.db 所在目录；默认不设，即 <repo>/.platform/platform.db
#   PYTHON=python3                解释器
#   WAIT=20                       start 等待 health 的就绪秒数
#   SERVE_STATE_DIR=<repo>/.platform/run   PID/日志落盘目录
#   LOG_LEVEL=info                uvicorn 日志级别
#
# 端口被占时：只报告占用进程（pid/cmd），不杀任何进程，退出码 75。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="vulnmap_platform.api.app:app"

PORT="${PORT:-8102}"
HOST="${HOST:-127.0.0.1}"
PYTHON="${PYTHON:-python3}"
WAIT="${WAIT:-20}"
LOG_LEVEL="${LOG_LEVEL:-info}"
STATE_DIR="${SERVE_STATE_DIR:-$REPO_ROOT/.platform/run}"
PID_FILE="$STATE_DIR/serve-$PORT.pid"
LOG_FILE="$STATE_DIR/serve-$PORT.log"
HEALTH_URL="http://$HOST:$PORT/api/health"

die() {
    local code=1
    if [[ "${2:-}" =~ ^[0-9]+$ ]]; then code="$2"; fi
    printf '[serve-platform] %s\n' "$1" >&2
    exit "$code"
}
say() { printf '[serve-platform] %s\n' "$*"; }

port_owner() {
    # 打印占用 PORT 的进程，无占用则输出为空
    ss -ltnpH "sport = :$PORT" 2>/dev/null \
        | sed -n 's/.*users:(("\([^"]*\)",pid=\([0-9]*\).*/\2 \1/p' \
        | sort -u
}

pid_alive() {
    local pid="${1:-}"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

health_ok() {
    curl -fsS -m 3 -o /dev/null "$HEALTH_URL" 2>/dev/null
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "缺少命令：$1"
}

do_start() {
    require_cmd "$PYTHON"
    require_cmd curl
    require_cmd setsid
    mkdir -p "$STATE_DIR"

    if [[ -f "$PID_FILE" ]]; then
        local old; old="$(cat "$PID_FILE" 2>/dev/null || true)"
        if pid_alive "$old"; then
            say "已在运行：pid=$old port=$PORT（不需要重复启动）"
            do_status
            return 0
        fi
        say "清理陈旧 PID 文件：$PID_FILE（pid=$old 已不存在）"
        rm -f "$PID_FILE"
    fi

    local owners; owners="$(port_owner)"
    if [[ -n "$owners" ]]; then
        while read -r opid oname; do
            printf '[serve-platform] 端口 %s 被占用：pid=%s cmd=%s\n' \
                "$PORT" "$opid" "$oname" >&2
        done <<< "$owners"
        ps -o pid=,etime=,cmd= -p "$(awk '{print $1}' <<< "$owners" | paste -sd, -)" >&2 || true
        die "端口 $PORT 已被占用，未做任何处理（不杀无关服务）。换端口：PORT=<new> $0 start" 75
    fi

    cd "$REPO_ROOT"
    : > "$LOG_FILE"
    # 仅当调用方显式设置了 PLATFORM_ROOT 才透传，默认沿用 .platform/platform.db
    if [[ -n "${PLATFORM_ROOT:-}" ]]; then
        export PLATFORM_ROOT
        say "PLATFORM_ROOT=$PLATFORM_ROOT（db=$PLATFORM_ROOT/platform.db）"
    else
        say "PLATFORM_ROOT 未设置，使用默认 db=$REPO_ROOT/.platform/platform.db"
    fi

    setsid nohup "$PYTHON" -m uvicorn "$APP" \
        --host "$HOST" --port "$PORT" --log-level "$LOG_LEVEL" \
        >>"$LOG_FILE" 2>&1 < /dev/null &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    say "已启动：pid=$pid log=$LOG_FILE"

    local i
    for ((i = 1; i <= WAIT; i++)); do
        if health_ok; then
            say "就绪：$HEALTH_URL 200（${i}s）"
            return 0
        fi
        if ! pid_alive "$pid"; then
            tail -n 40 "$LOG_FILE" >&2 || true
            rm -f "$PID_FILE"
            die "启动失败：进程已退出（见 $LOG_FILE）"
        fi
        sleep 1
    done
    tail -n 40 "$LOG_FILE" >&2 || true
    die "启动超时：${WAIT}s 内 $HEALTH_URL 未就绪（见 $LOG_FILE）"
}

do_stop() {
    if [[ ! -f "$PID_FILE" ]]; then
        say "没有 PID 文件（$PID_FILE），当前无本脚本启动的实例"
        local owners; owners="$(port_owner)"
        [[ -n "$owners" ]] && printf '[serve-platform] 但端口 %s 仍有进程：\n%s\n' "$PORT" "$owners" >&2
        return 0
    fi
    local pid; pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if ! pid_alive "$pid"; then
        say "pid=$pid 已不存在，清理 PID 文件"
        rm -f "$PID_FILE"
        return 0
    fi
    say "停止 pid=$pid ..."
    kill -TERM "$pid" 2>/dev/null || true
    local i
    for ((i = 1; i <= 10; i++)); do
        pid_alive "$pid" || { rm -f "$PID_FILE"; say "已停止"; return 0; }
        sleep 1
    done
    if [[ "${FORCE:-0}" == "1" ]]; then
        say "SIGTERM 超时，FORCE=1 → SIGKILL pid=$pid"
        kill -KILL "$pid" 2>/dev/null || true
        sleep 1
        rm -f "$PID_FILE"
        return 0
    fi
    die "pid=$pid 10s 内未退出；确认后可用 FORCE=1 $0 stop"
}

do_status() {
    local pid=""; [[ -f "$PID_FILE" ]] && pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    printf 'port=%s host=%s\n' "$PORT" "$HOST"
    if pid_alive "$pid"; then
        printf 'pid=%s 运行中（%s）\n' "$pid" "$(ps -o etime= -p "$pid" | tr -d ' ')"
    else
        printf 'pid=%s 未运行\n' "${pid:-<none>}"
    fi
    local owners; owners="$(port_owner)"
    [[ -n "$owners" ]] && printf '端口占用：\n%s\n' "$owners"
    if health_ok; then printf 'health=200 %s\n' "$HEALTH_URL"; else printf 'health=DOWN %s\n' "$HEALTH_URL"; fi
    printf 'log=%s\n' "$LOG_FILE"
}

case "${1:-start}" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_stop; do_start ;;
    status)  do_status ;;
    -h|--help|help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
    *) die "未知动作：$1（start|stop|restart|status）" ;;
esac
