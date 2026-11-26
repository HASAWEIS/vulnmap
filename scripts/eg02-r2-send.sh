#!/usr/bin/env bash
# EG-02 · R2 征询投递 —— 薄封装（真正的逻辑在 experiments/eg02-r2-outbox/build_outbox.py）
#
#   ./scripts/eg02-r2-send.sh --check            # 只读校验（19 组断言 / 20 个 D 标签）
#   ./scripts/eg02-r2-send.sh --check-doc         # 文档数字 vs 机读件
#   ./scripts/eg02-r2-send.sh --status           # 读 DELIVERY.json
#   ./scripts/eg02-r2-send.sh --build            # 重新渲染 outbox（不改征询结论）
#   ./scripts/eg02-r2-send.sh --send             # 投递：无 COURSE_EMAIL/COURSE_CONTACT 时只记 ready_not_sent
#   ./scripts/eg02-r2-send.sh --send --to a@b.c  # 人手显式指定收件人
#
# 环境变量（按需）：
#   COURSE_EMAIL / COURSE_CONTACT   收件人（二者都缺 → recipient=missing，不投递）
#   SMTP_HOST / SMTP_PORT / SMTP_STARTTLS / SMTP_USER / SMTP_PASS    SMTP 通道
#   EG02_MAIL_FROM / MAIL_FROM      发件人地址（缺省为占位 eg02-r2-request@vulnmap.local）
#
# 退出码：0 正常 / 2 断言失败 / 3 缺产物 / 4 投递失败（均如实落在 DELIVERY.json）
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/experiments/eg02-r2-outbox/build_outbox.py"

if [[ ! -f "$TOOL" ]]; then
  echo "[FAIL] 找不到 $TOOL" >&2
  exit 3
fi

if [[ $# -eq 0 ]]; then
  set -- --check
fi

PY="${PYTHON:-python3}"
exec "$PY" "$TOOL" "$@"
