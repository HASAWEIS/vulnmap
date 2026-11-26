# 真实目标发现：cJSON 1.7.10

> Discovery v1.0 实跑证据在 `discovery/real-cjson/`；完整结果见
> [DISCOVERY-V1-RESULTS.md](DISCOVERY-V1-RESULTS.md)，方案见 [DISCOVERY-V1.md](DISCOVERY-V1.md)。

## 构建（ASAN + 覆盖率）

```bash
gcc -c -O1 cov_rt.c -o cov_rt.o
gcc -g -O1 -no-pie -fsanitize=address -fsanitize-coverage=trace-pc -I. \
    cJSON.c harness.c cov_rt.o -o fuzz_target
```

harness 调用 `cJSON_Minify`、`cJSON_Parse`、`cJSON_PrintUnformatted`；输入是任意文件。

## 结果

| 项 | 值 |
|---|---|
| 崩溃 | heap-buffer-overflow READ of size 1 |
| 位置 | `cJSON_Minify` `cJSON.c:2642` |
| 复现 | 3/3（独立目录干净构建） |
| stack_hash | `2b707abbebd7eeb9` |
| verdict | weakened |
| 覆盖率 | 14/80（函数级命中，`covered_by_pc=false`） |
| 首次崩溃 | 0.118s（4 workers：0.171/0.173/0.118/0.123） |

构建产物 sha256：`64d1c6889d080720012afa04b88d03b956dc1f736cccb44f3c8ef396c5cb7751`。

## 结论

- 在真实开源项目上找到了可复现的越界读，不是合成 fixture；
- 结论是 `weakened`（READ），不是 high；没有把它写成高危；
- 触发点是 `cJSON_Minify`，属于公开 API，harness 直接调用，没有使用任何补丁/崩溃报告。

## 限制

1. 覆盖率是函数级命中（14/80），不能理解为 14 个调用点被逐行执行；
2. 只找到读越界，没有找到写/控制流；
3. 目标是最小 harness，不是完整应用入口；
4. 未做 CVE 编号断言，避免对号入座；
5. libpng 1.6.37 是负结果，见 `discovery/real-libpng/`。
