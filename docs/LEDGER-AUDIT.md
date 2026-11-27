# 案例台账核账（只读）

- 行数：32
- high_severity 行：11
- 独立高危根因：11
- 其中 benchmark 验证 + 因果链都通过：10
- benchmark 验证通过行：25
- ExploitGym flag 行：1
- course_ready：0

## 独立高危

| root | case | 同根案例 | benchmark 验证 | 因果链 |
|---|---|---|---|---|
| arvo:42470179 | AR6 | AR6 | True | True |
| arvo:42485152 | AR7 | AR7 | True | True |
| arvo:44034 | CG-01 | CG-01, EG-02 | True | True |
| arvo:10096 | CG-07 | CG-07 | True | True |
| arvo:11253 | CG-14 | CG-14 | True | True |
| vulngym/nltk/40d0bc1d | VG-01 | VG-01 | True | False |
| arvo:12420 | CG-18 | CG-18 | True | True |
| arvo:11011 | CG-29 | CG-29 | True | True |
| arvo:29633 | CG-30 | CG-30 | True | True |
| arvo:61675 | CG-31 | CG-31 | True | True |
| arvo:54839 | CG-36 | CG-36 | True | True |

## 矛盾/缺口

| case | 类型 | 说明 |
|---|---|---|
| VG-01 | high_without_causal_chain | None |

> 只读核账，不改写历史判定；独立高危按根因去重，EG-02 与 CG-01 同根。
