# target.yaml 示例

这些文件是 P4 的构建描述示例，路径按本机环境写死（`/tmp/cJSON`、`/tmp/libpng-1.6.37`、`/tmp/tiff-4.0.9`），
使用前把 `root` 改成你的目标目录。

- `cjson.yaml`：源码构建 + 内置 cJSON harness；
- `libpng.yaml`：链接预构建 ASAN+trace-pc 对象 + 自定义 harness（需把 `harness.c` 放到目标根目录）；
- `libtiff.yaml`：链接 ASAN+trace-pc 的 `libtiff.a` + `libport.a`，harness 同样放在目标根目录。

P1（2026-11-16）新增三条互补入口，harness 放在 `discovery/real-*/` 下，`sources` 用绝对路径：

- `libtiff-strip.yaml`：libtiff 4.0.9 目录 / Strip / Scanline 路径
  （`TIFFReadDirectory` 循环 + `TIFFStripSize` + `TIFFReadEncodedStrip`，不走 `TIFFReadRGBAImage`）；
- `libpng-row.yaml`：libpng 1.6.37 逐行 + 变换链
  （`png_read_row` + expand/strip_16/palette/tRNS/interlace，不走 `png_image_*`）；
- `cjson-parse.yaml`：cJSON 1.7.10 Parse/Print（跳过 `cJSON_Minify`）。

```bash
python3 bin/discover.py /tmp/cJSON --target-yaml examples/targets/cjson.yaml --out /tmp/cjson-out
python3 bin/discover.py /tmp/tiff-4.0.9 --target-yaml examples/targets/libtiff.yaml --out /tmp/tiff-out
python3 bin/discover.py /tmp/tiff-4.0.9 --target-yaml examples/targets/libtiff-strip.yaml \
  --out discovery/real-libtiff-strip --seconds 120 --workers 4
python3 bin/discover.py /tmp/libpng-1.6.37 --target-yaml examples/targets/libpng-row.yaml \
  --out discovery/real-libpng-row --seconds 120 --workers 4
python3 bin/discover.py /tmp/cJSON --target-yaml examples/targets/cjson-parse.yaml \
  --out discovery/real-cjson-parse --seconds 120 --workers 4
# 没有现成 YAML 时先生成草稿
python3 bin/discover.py /tmp/cJSON --init-target
```
