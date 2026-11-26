# Discovery D0-D5 结果（fixture）

> 目标：验证“无 error/patch/PoC”的挖掘闭环能否跑通；fixture 是自建 C 解析器，不是真实 0day。

## 目标

- 路径：`fixtures/discovery/vuln_parser.c`
- 入口：`main` 读取文件 → `parse_meta` / `parse_record`
- 漏洞：`parse_record` 把 `uint16 len` 直接 `memcpy` 到 16 字节堆缓冲

## D0 静态档案

```json
{"target":"discovery","source_count":1,"binaries":[{"path":"vuln_parser","sha256":"8068..."}],"entries":[{"kind":"main","line":25}]}
```

## D1 危险调用点

- 计划 4 个调用点：`memcpy`×2、`fread`、`malloc`
- 覆盖率：3/4（受 max-sites 限制）
- 排序：`parse_record` 的 `memcpy` 分数最高

## D2 输入构造与 fuzz

```text
iterations=...  crash=heap-buffer-overflow WRITE
input_sha256=...
```

## D3 复核

```json
{"verdict":"confirmed","access":"WRITE","reproduced":3,"function":"parse_record","line":13}
```

## D4 报告

- 完整性表：静态档案 1/1、调用点 3/4、执行 3/4
- 风险统计：confirmed 1
- 逐条：函数、file:line、WRITE、栈哈希、复现次数

## D5 对照评估

| 策略 | 耗时(s) | confirmed | 覆盖/计划 |
|---|---:|---:|---:|
| ranked | 1.11 | 1 | 4/4 |
| random | 1.11 | 1 | 4/4 |

结论：在该 fixture 上，排序策略**没有表现出优势**；原因是 fixture 只有 4 个调用点，随机顺序也能很快命中。
这是真实结果，不粉饰。

## 限制

1. 没有覆盖率引导（未接 AFL++/libFuzzer），只是变异闭环；
2. 调用点排序是启发式，未做完整污点/边界分析；
3. fixture 是合成目标，不能当作真实项目发现能力；
4. 复杂度上来后需要覆盖率、语料最小化、并行沙箱。

## 复现命令

```bash
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer fixtures/discovery/vuln_parser.c -o fixtures/discovery/vuln_parser
python3 bin/discover.py fixtures/discovery --out /tmp/discovery-out --seconds 3 --max-sites 3
python3 bin/discover.py fixtures/discovery --out /tmp/discovery-eval --seconds 2 --max-sites 4 --eval
pytest tests/test_discovery.py -q
```