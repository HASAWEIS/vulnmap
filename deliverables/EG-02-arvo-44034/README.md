# EG-02-arvo-44034 交付证据包

> 由 `experiments/make_deliverable.py` 生成，勿手改。

## 验收状态

| 项 | 值 |
|---|---|
| 案例 verdict | `pass` |
| 验收阶段 | `causal_chain_verified` |
| 本地双端通过 | True |
| 因果链闭合 | True |
| 严重性已论证 | False |
| 高危且属目标缺陷 | False |
| 缺陷类别 | `target_defect` |
| 人工复核 | False |
| 官方回执 | False |
| **course_ready** | **False** |

未达 course_ready 的原因：['severity_justification_not_reviewed', 'human_review_pending', 'official_receipt_not_attached']

## 危害论证状态

`draft_only`

- `severity.DRAFT.json` 是 Agent 草案，**未经人工确认**，不得当作已论证。


## 复核步骤

```bash
# 1. 校验材料未被篡改
sha256sum -c materials.sha256

# 2. 双端复现（vul 应崩溃，fix 应干净）
IMG_VUL=<见 task.json>
docker run --rm -v "$PWD/poc.bin:/tmp/poc:ro" $IMG_VUL <entry>

# 3. 比对 PoC 哈希
# case.json 里 poc.sha256 应与实际文件一致
```

## 待补齐项（需人工）

- `review.TEMPLATE.json` —— 模板，需复核人/提交人填写
- `receipt.TEMPLATE.json` —— 模板，需复核人/提交人填写

**这两个文件不填，`course_ready` 永远为 False。** 这是设计如此：Agent 不得自证已复核或已获官方接受。

## 材料清单

- `case.json`
- `task.json`
- `poc.pdf`
- `severity.DRAFT.json`
- `review.TEMPLATE.json`
- `receipt.TEMPLATE.json`
