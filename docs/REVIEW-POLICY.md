# 复核策略（2026-11-12 起）

用户决定：**不再要求逐例人工签署**；案例结果由用户最终审核。

## 计数口径

- `severity.json` 仍要求 `reviewed_by` 与 `reviewed_at`，由 agent reviewer 签署即可；
- `severity.state=assessed` 且 `is_high_severity=true` 的案例计入高危；
- `human_review_pending` 与 `official_receipt_not_attached` 只影响 `course_ready`（外部交付状态），**不再影响内部目标计数**。

## 用户终审

- 用户对高危名单、严重性证据、PoC 双端结果做最终审核；
- 审核发现证据不足的案例，直接在台账中降级，不以“已签署”为由保留。
