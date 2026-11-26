# VG-01 源码交接手册：把 `nltk@40d0bc1d` 原件取回来（可联网机器 → 本机）

> 面向：下一步在**能上网的机器**上取 `nltk` 的 `40d0bc1d`，把字节回传，在本机重跑"原版 server"。
> 写于：2026-11-19（Asia/Shanghai）。
> 纪律：**本机不抓源码、不伪造上游字节**；`nltk 3.10.4`（本机已装、已修 shutdown 鉴权）只能当**控制组**，任何情况下都不当原版引用。
> 配套闸门：[scripts/vg01_source_check.sh](../scripts/vg01_source_check.sh)（exit 0 才允许把证据对象写成"原件"）。

---

## 0. 一页结论

| 问题 | 答案 |
|---|---|
| 本机能不能直接取到 40d0bc1d？ | **不能**。本轮实测 `https://raw.githubusercontent.com/...` 超时（`curl: (28) Operation timed out after 12001 ms, 0 bytes`）；本机也无 git cache、无源码树 |
| 本机现有的三份 `wordnet_app.py` 能不能顶替？ | **都不能**。见 §1 指纹表：3.10.4 是**已修版**、仓库镜像是 **patched**、`*_RECONSTRUCTED.py` 是**删除式重建** |
| 那现在缺的到底是什么？ | 缺的是**字节归属**：`40d0bc1d:nltk/app/wordnet_app.py` 这一份文件的原始 sha256、行号、无 token 校验这三件事的**原始观测** |
| 拿到之后结论会变成什么？ | `docs/VG01-SERVER-EVIDENCE.md` 的 A 项从"对象＝重建件"升级为"对象＝原件"，C 项（原始 commit 归属）才可关闭；**在此之前**一律 `needs_evidence` |
| 取回来最省事的正确姿势 | codeload tarball（路 A）+ 在联网机上先算指纹（§3）+ 连同 sha 文件一起回传（§4）+ 本机过闸门（§5）+ 用 `--module` 直接跑原件（§6） |

**硬禁令（写进流程，不靠自觉）**：

1. 不许把 `~/.local/lib/python3.10/site-packages/nltk/app/wordnet_app.py`（3.10.4）当原版——它含 `_shutdown_token` + `hmac.compare_digest` + 403，是**修复后**的字节；本机现有 `evidence/04-upstream-3.10.4-control/` 只能当控制组。
2. 不许把 `experiments/vg01/wordnet_app_patched.py`（仓库镜像）当原版——它被加了 3 行 `X-Shutdown-Token` 守卫。
3. 不许把 `experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py`（删 3 行得到的重建件）当原版——它证明的是"布局一致"，不是"字节相同"。
4. 上面三条不是"注意一下"，而是 `scripts/vg01_source_check.sh` 的 **exit 6 / exit 5**。闸门不过，证据级别不许升。

---

## 1. 本机现状与三份"像原版"的件（2026-11-19 复核）

| 件 | 路径 | 行数 | sha256 | 判据 | 性质 |
|---|---|---|---|---|---|
| 已装 nltk **3.10.4** | `~/.local/lib/python3.10/site-packages/nltk/app/wordnet_app.py` | 1094 | `58615acca7f0e8a7e820c930e3c611404459834d0eac1c754db701737d54b1ee` | `_shutdown_token`@78、`_shutdown_authorized`@92、条件用 `unquote_plus(sp.partition("?")[0])`@105、`safe_print(...)`@110、403@114–118 | **已修版（CWE-352 修复）**，控制组 |
| 仓库镜像 | `experiments/vg01/wordnet_app_patched.py` | 1005 | `5a925994fcc5c199777b23e2bab7d9148bcf0715d9ef4c7369b31c77879ec31a` | 条件@87、守卫 88–90（`X-Shutdown-Token`）、print@95、`os._exit(0)`@96 | **patched 镜像**，非上游 |
| 删除式重建 | `experiments/vg01/wordnet_app_vuln_RECONSTRUCTED.py` | 1002 | `f4fa4adcef89df0d861793a38e16d39c963825f17cbf1205d4682f9e5b9a4f23` | 条件@87、print@92、`os._exit(0)`@93 | **reconstructed**，只证布局 |
| **40d0bc1d 原件** | 缺 | 未知 | **未知（本文要拿的就是它）** | 期望：条件@87、紧邻 `print("Server shutting down!")` + `os._exit(0)`、**零** token 特征串 | 目标 |

为什么"本机有 3.10.4 就够了"是错的：3.10.4 对同一请求返回 **403**、不打印、进程存活；拿它跑"漏洞复现"会直接得到负结果，而且会把"上游早已修复"当成"案例不成立"。这正是 `VG01-SERVER-EVIDENCE.md` §2 把它定成控制组的原因。

---

## 2. 在可联网机器上取源码

前置：`git`、`curl`、`python3`（≥3.8）、`sha256sum`。建议所有产物落在 `~/vg01-fetch/`。

### 2.1 第一步：把 8 位短 sha 解析成 40 位全 sha（**必做**）

`40d0bc1d` 是 8 位短 sha，在 git 里是**前缀**而非身份。没有 40 位全 sha，后面所有哈希都缺一个锚点。

```bash
mkdir -p ~/vg01-fetch && cd ~/vg01-fetch
curl -sS -H 'Accept: application/vnd.github+json' \
  https://api.github.com/repos/nltk/nltk/commits/40d0bc1d \
  -o commit-40d0bc1d.json
python3 - <<'PY'
import json
d = json.load(open('commit-40d0bc1d.json'))
print('full_sha :', d['sha'])
print('date     :', d['commit']['committer']['date'])
print('subject  :', d['commit']['message'].splitlines()[0])
print('tree_sha :', d['commit']['tree']['sha'])
PY
```

判读：

- 打印出 `full_sha` 且以 `40d0bc1d` 开头 → 继续；把 `commit-40d0bc1d.json` **原样回传**（这是 commit 归属的第一手证据）。
- `404` / `422` / 返回列表 → **停**。说明这个短 sha 在该仓库不存在或前缀不唯一；不许"找一个像的提交顶上"，也不许改用默认分支。

### 2.2 路 A（推荐）：codeload tarball

最小、可哈希、不依赖 git 协议。

```bash
cd ~/vg01-fetch
curl -sSL -o nltk-40d0bc1d.tar.gz \
  https://codeload.github.com/nltk/nltk/tar.gz/40d0bc1d
sha256sum nltk-40d0bc1d.tar.gz | tee nltk-40d0bc1d.tar.gz.sha256
ls -l nltk-40d0bc1d.tar.gz
```

**tar 结构（这个仓库的实际形状）**：

```text
nltk-40d0bc1d/                     ← 顶层目录名 = GitHub 用的 ref 字符串（这里是短 sha）
├── setup.py
├── pyproject.toml
├── README.rst / CHANGELOG.md 等
└── nltk/
    ├── __init__.py
    ├── app/
    │   ├── __init__.py
    │   └── wordnet_app.py        ← 关键文件（本案例唯一 sink）
    ├── corpus/  tokenize/  ...   （其余源码；**不含** wordnet 语料数据）
    └── test/
```

三条要点：

1. **顶层目录名不是 commit**：`nltk-40d0bc1d/` 里的 `40d0bc1d` 只是请求串。真正的 commit 是 §2.1 的 40 位 `full_sha`；交接记录里两者都写，但归属只认全 sha。
2. **tarball 不含 `.git`**：所以无法用 `git rev-parse` 自证；这正是要求同时回传 `commit-40d0bc1d.json` 的原因。
3. **不含 wordnet 语料**：原版跑 `/start_page` 仍会 `LookupError`（与重建件同现象）；判定只依赖 shutdown 分支（发生在语料访问之前），不受影响。

结构自检（缺任一项就停）：

```bash
tar -tzf nltk-40d0bc1d.tar.gz | grep -E '^nltk-40d0bc1d[^/]*/nltk/app/wordnet_app\.py$' \
  || { echo 'MISSING wordnet_app.py in tarball'; exit 1; }
tar -tzf nltk-40d0bc1d.tar.gz | grep -cE '^nltk-40d0bc1d[^/]*/nltk/' || true
```

解包到固定位置（本机与联网机都用这个名字，后面命令才可复制粘贴）：

```bash
mkdir -p ~/vg01-source
tar -xzf nltk-40d0bc1d.tar.gz -C ~/vg01-source
# 顶层实际目录名以 tar -tzf 第一条为准；下面这行把它归一到固定名
[ -d ~/vg01-source/nltk-40d0bc1d ] || mv ~/vg01-source/nltk-40d0bc1d* ~/vg01-source/nltk-40d0bc1d
ls ~/vg01-source/nltk-40d0bc1d/nltk/app/wordnet_app.py
```

### 2.3 路 B：git 浅取指定 commit（能拿 git 元数据，provenance 最强）

```bash
mkdir -p ~/vg01-source/nltk-git && cd ~/vg01-source/nltk-git
git init -q .
git remote add origin https://github.com/nltk/nltk.git
git fetch --depth 1 origin 40d0bc1d        # GitHub 允许按可达 sha 取
git checkout -q FETCH_HEAD
git rev-parse HEAD                          # 必须等于 §2.1 的 full_sha
git log -1 --format='%H%n%ci%n%s'
git describe --tags --always 2>&1 || echo 'describe: unavailable(depth=1, 无 tag 历史)'
git status --porcelain                      # 必须为空（未改动）
```

判读：

- `git rev-parse HEAD` ≠ API 的 `full_sha` → 停（说明 API 结果与取回物不是同一对象）。
- `git describe` 失败是**正常**的（浅取无 tag），记录 `unavailable`，不许补一个版本号上去。
- 路 B 的价值：`git cat-file -t 40d0bc1d` → `commit`、`git log` 时间/主题，可交叉验证 API。**不要求**联网机同时走路 B，但走了就把 `git log -1` 输出一起回传。

### 2.4 路 C：pip sdist（默认禁用，除非能证明版本映射）

```bash
pip download nltk==[VERSION] --no-deps --no-binary :all: -d ~/vg01-fetch
```

**默认不用**，原因写在 `VG01-SERVER-EVIDENCE.md` §9.6：`40d0bc1d` 对应的 nltk 版本号/tag **未知**（镜像 1005 行 vs 3.10.4 的 1094 行，只能推出"3.10.4 更晚"，推不出对应 release）。要用必须先在联网机上证明"该 release 的 tag 指向该 commit"（例如 `git tag --contains 40d0bc1d` 或 sdist 内 `PKG-INFO` 与 commit 的对应关系），并把该证明一起回传；否则一律走路 A/B。

---

## 3. 取回后**立刻**在联网机上算归属指纹

不要等回传后再算——联网机上这一步是"原始观测"，回传包里带的是它的输出。

```bash
cd ~/vg01-source/nltk-40d0bc1d
F=nltk/app/wordnet_app.py

sha256sum "$F"
wc -l "$F"; wc -c "$F"
grep -n 'SHUTDOWN THE SERVER' "$F"
grep -nE '(^|[^_[:alnum:]])print\("Server shutting down!"\)' "$F"
grep -n 'os\._exit(0)' "$F"
grep -nE '_shutdown_token|_shutdown_authorized|X-Shutdown-Token|token_urlsafe|shutdown_token' "$F" \
  && echo 'TOKEN_GUARD=present(patched!)' || echo 'TOKEN_GUARD=absent'
```

期望形状（判定表）：

| 断言 | 期望 | 不合格时怎么办 |
|---|---|---|
| shutdown 条件恰好 1 处 | `if unquote_plus(sp) == "SHUTDOWN THE SERVER":` | 0 处 → 不是该漏洞代码；>1 处 → 先搞清哪一处是 sink，再记录 |
| 紧邻 `print("Server shutting down!")` | 有（**不是** `safe_print`） | 出现 `safe_print` → 这是修复版（3.10.4 式），停 |
| 紧随 `os._exit(0)` | 有 | 缺 → 分支不完整，停 |
| 条件行号 | 与 `SOURCE.md` / `case.json` 记的 **87** 一致 | 不一致 → **发现项**：写进交接记录，不许静默改口径；先确认取的是不是 40d0bc1d |
| token 特征串 | **零命中** | 命中 → patched，停（这条就是 3.10.4 的修复特征） |
| 分支内 403/401/`Forbidden` | **无** | 有 → 不是"未认证即关机" |

补充：`getopt` 选项决定了能不能用 `-p PORT` 起服务。

```bash
sed -n '/^def app()/,/^if __name__/p' "$F" | grep -nE '"l:p:sh"|port'
```

期望看到 `getopt.getopt(argv[1:], "l:p:sh", ["logfile=", "port=", "server-mode", "help"])`——有它才能按 §6 起端口；若原件的选项集不同，按实际选项改启动命令，并把差异记进交接。

---

## 4. 回传包（tar 结构 + 校验）

在联网机上打一个**自描述**的包，缺一件都算交接不完整：

```bash
cd ~/vg01-fetch
cat > VG01-FETCH.json <<'JSON'
{
  "schema": "vulnmap.vg01.fetch.v1",
  "task_id": "vulngym/nltk/40d0bc1d",
  "requested_ref": "40d0bc1d",
  "commit_full": "[FULL_SHA_FROM_API]",
  "commit_date": "[YYYY-MM-DDTHH:MM:SSZ]",
  "commit_subject": "[SUBJECT]",
  "fetch_method": "codeload-tarball",
  "codeload_url": "https://codeload.github.com/nltk/nltk/tar.gz/40d0bc1d",
  "api_url": "https://api.github.com/repos/nltk/nltk/commits/40d0bc1d",
  "tarball_sha256": "[TARBALL_SHA256]",
  "file": "nltk/app/wordnet_app.py",
  "file_sha256": "[FILE_SHA256]",
  "file_lines": 0,
  "shutdown_line": 87,
  "print_line": 0,
  "os_exit_line": 0,
  "token_guard": false,
  "fetched_at": "[ISO8601]",
  "fetched_by_host": "[HOSTNAME]",
  "notes": "占位值必须替换；shutdown_line 与 87 不符时在此写明差异"
}
JSON
sha256sum nltk-40d0bc1d.tar.gz commit-40d0bc1d.json nltk-40d0bc1d.tar.gz.sha256 > FETCH-SHA256SUMS

tar -czf nltk-40d0bc1d-handoff.tar.gz \
  nltk-40d0bc1d.tar.gz nltk-40d0bc1d.tar.gz.sha256 \
  commit-40d0bc1d.json VG01-FETCH.json FETCH-SHA256SUMS \
  -C ~/vg01-source nltk-40d0bc1d
sha256sum nltk-40d0bc1d-handoff.tar.gz | tee nltk-40d0bc1d-handoff.tar.gz.sha256
```

回传包结构（本手册规定的最小集）：

```text
nltk-40d0bc1d-handoff.tar.gz
├── nltk-40d0bc1d.tar.gz              ← 上游 tarball 本体（唯一权威字节）
├── nltk-40d0bc1d.tar.gz.sha256       ← 上面的哈希
├── commit-40d0bc1d.json               ← GitHub API 原始响应（commit 归属第一手证据）
├── VG01-FETCH.json                    ← 本次抓取的自描述清单（占位必须替换）
├── FETCH-SHA256SUMS                   ← 上述文件的行式哈希
└── nltk-40d0bc1d/                     ← 解包后的树（方便直接跑；可重建）
    ├── nltk/__init__.py
    ├── nltk/app/__init__.py
    └── nltk/app/wordnet_app.py
```

**只回传单个 `wordnet_app.py` 是不够的**：单文件无法证明"它来自哪棵树"，也无法复核 tarball ↔ 文件的一致性。回传通道随意（U 盘 / scp / 内网跳板），但两个 `.sha256` 必须一起到。

---

## 5. 回传后在本机落地 + 过闸门

```bash
mkdir -p ~/vg01-source && cd ~/vg01-source
tar -xzf /path/to/nltk-40d0bc1d-handoff.tar.gz
sha256sum -c nltk-40d0bc1d.tar.gz.sha256
# 首次：核对 commit 后落地清单（commit 来自 VG01-FETCH.json / git HEAD / --commit-full）
ROOT=/home/root_bupt/桌面/file/vulnmap
"$ROOT/scripts/vg01_source_check.sh" --dir ~/vg01-source/nltk-40d0bc1d \
    --record --commit-full [FULL_SHA_FROM_API]
# 之后每次复核（CI / 交接复算都用这条）
"$ROOT/scripts/vg01_source_check.sh" --dir ~/vg01-source/nltk-40d0bc1d
echo "rc=$?   # 必须是 0"
```

退出码语义（`[FAIL]` 行会给出具体原因）：

| rc | 含义 | 处置 |
|---|---|---|
| 0 | PASS：commit + 哈希 + 分支形状 + 无 token 校验全过 | 才允许把证据对象写成"原件" |
| 2 | 目录或 `nltk/app/wordnet_app.py` 缺失 | 回传包不完整，重传 |
| 3 | 文件 sha256 与清单/`--expect-sha256` 不一致 | 文件被改过，或清单与文件不是同一份 |
| 4 | 无 commit 证据（非 git 树且没给 `--commit-full`，清单也没有） | 补 §2.1 的 full sha |
| 5 | 文件含 token 校验特征串 | patched/3.10.4，**停** |
| 6 | 来源错误（site-packages / RECONSTRUCTED 文件名 / 已知 patched 或重建件哈希） | 拿错文件，回 §2 |
| 7 | shutdown 分支不成立（条件/print/_exit 缺失，或分支内夹 403） | 不是该漏洞代码形状 |
| 8 | commit 与 `40d0bc1d` 不符 / git HEAD 与清单冲突 | 取错 commit 或树被换过 |
| 9 | `--expect-line` 与实测行号不符 | 行号发现项，先解释再继续 |

闸门行为已自测（fixture 全在 `/tmp`，非证据）：3.10.4 → 6；镜像 → 6；重建件 → 6；无清单 → 4；改字节 → 3；加 token 守卫 → 5；分支加 403 → 7；commit 不符 → 8；行号不符 → 9；正常原件（合成样例）→ 0。矩阵与命令见 `docs/VG01-HANDOFF-20261119.md` §3。

---

## 6. 用**原版** `wordnet_app.py` 重跑 server（本机命令）

### 6.1 用本仓探针（推荐：stdout/rc/端口/body 哈希一起抓）

```bash
cd /home/root_bupt/桌面/file/vulnmap/experiments/vg01
/usr/bin/python3.10 run_server_evidence.py \
  --module ~/vg01-source/nltk-40d0bc1d/nltk/app/wordnet_app.py \
  --scenario vuln \
  --out /tmp/vg01-orig-40d0bc1d/01-vuln-ORIGINAL \
  --label "vuln: nltk@40d0bc1d ORIGINAL bytes; runtime=nltk 3.10.4 (mixed, shutdown path only)"
```

要点：

- `--module` 接受**绝对路径**（脚本内 `os.path.isabs` 分支），不会去 `sys.path` 里找同名模块；`module_sha256` 会写进 `summary.json`，必须等于 §3 的文件哈希。
- `--out` 用**绝对路径**写 `/tmp`：本轮写入范围只有 `docs/`、`scripts/`，**不把新证据塞进 `experiments/vg01/evidence/`**。若要并入仓内 evidence 目录并让 `verify_evidence.py` 覆盖，需另开一轮（那套校验器的 22 项断言是绑定现有 5 组的）。
- 探针会自动 `-u` + `PYTHONUNBUFFERED=1`、清空代理变量、`BROWSER=/bin/true`、随机空闲端口、只连 `127.0.0.1`。
- `--scenario vuln` 会先打 `/`，再打 `/start_page`（触发 `LookupError`，用来对照"客户端同样 0 字节 EOF"），最后打未认证 shutdown。**顺序不能改**：`os._exit(0)` 之后进程就没了。

### 6.2 裸跑（不依赖本仓脚本，给评审手工复算）

```bash
mkdir -p /tmp/vg01-orig-bare && cd /tmp/vg01-orig-bare
PORT=8123
PYTHONUNBUFFERED=1 BROWSER=/bin/true \
  /usr/bin/python3.10 -u ~/vg01-source/nltk-40d0bc1d/nltk/app/wordnet_app.py -p "$PORT" \
  >server.stdout.log 2>server.stderr.log &
SRV=$!
sleep 1
python3 - "$PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
def get(target):
    s = socket.create_connection(("127.0.0.1", port), timeout=6)
    s.sendall(("GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n"
               % (target, port)).encode())
    data = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
    s.close()
    return data
print("index:", get("/")[:15].decode("latin1", "replace"))
print("shutdown:", repr(get("/SHUTDOWN%20THE%20SERVER")[:15]))
PY
wait "$SRV"; echo "_server_rc=$?"
```

**注意**：不要用 `curl -w '%{exitcode}'` 判服务端退出码——`%{exitcode}` 是 curl 自身退出码且老版本不支持；服务端 rc 只能用 `wait $!` 拿。curl 对"连接被对端关闭"通常给 52（empty reply）/56；把它当客户端侧记录即可，**不能当服务端证据**。

### 6.3 必须抓的 6 项证据（缺一项就不算升级）

| # | 证据 | 位置 / 期望 | 为什么必需 |
|---|---|---|---|
| 1 | **服务端 stdout 唯一一行** | `server.stdout.log` = `Server shutting down!\n`（22 B，sha256 `17e15001cc167e53…a385c5b`） | 唯一能区分"进 shutdown 分支"与"handler 崩了"的观测 |
| 2 | **stderr 无该请求的 traceback** | `server.stderr.log` 中不得出现对应 shutdown 请求的帧（`/start_page` 的 `LookupError` 属另一请求，可存在） | 排除"崩溃导致 EOF" |
| 3 | **服务端退出码** | rc = **0**（`os._exit(0)`；脚本写 `summary.json.server_returncode`） | `_exit(0)` 与 403/异常的分水岭 |
| 4 | **端口状态** | shutdown 后 `port_listening_after_shutdown=false`（3 s 内）；裸跑可 `ss -ltn \| grep ":8123"` 为空 | 证明"进程真的退了" |
| 5 | **模块字节** | `summary.json.module_sha256` == §3 的 `file_sha256`，且 `module` 路径含 `vg01-source/nltk-40d0bc1d` | 证明跑的是原件，不是镜像/重建件 |
| 6 | **A/B 对照仍在** | 同一探针对 `patched`（镜像或 3.10.4）打同一请求 → **403 / 无 stdout / 进程存活** | 证明探针有区分力，不是"随便打一下就死" |

落盘建议（`/tmp`，不污染仓库）：

```text
/tmp/vg01-orig-40d0bc1d/01-vuln-ORIGINAL/{server.stdout.log,server.stderr.log,client.requests.jsonl,summary.json}
/tmp/vg01-orig-40d0bc1d/02-control-patched/{...}      # 用 experiments/vg01/wordnet_app_patched.py 重跑一次
/tmp/vg01-orig-40d0bc1d/VG01-ORIGINAL-RUN.md         # 谁、何时、什么命令、rc、哈希
```

### 6.4 与重建件的差分（顺手把"镜像 provenance"验一遍）

```bash
MIRROR=/home/root_bupt/桌面/file/vulnmap/experiments/vg01/wordnet_app_patched.py
ORIG=~/vg01-source/nltk-40d0bc1d/nltk/app/wordnet_app.py
# 镜像第 88–90 行是插入的 X-Shutdown-Token 守卫；删掉后应与原件逐字节相同
sed '88,90d' "$MIRROR" | diff -u - "$ORIG" && echo 'IDENTICAL after removing guard'
```

- 输出为空 → 镜像 provenance 成立（"镜像 = 原件 + 3 行守卫"），重建件的行号链条也跟着成立。
- 有差异 → **重要发现**：说明镜像不是该 commit 的字节（可能是别的版本），`SOURCE.md` 的声明要改，`reconstructed` 证据要降级为"仅布局参考"。

---

## 7. 拿到原件后，结论怎么改（口径）

| 项 | 现在（`VG01-SERVER-EVIDENCE.md`） | 拿到原件并过闸门后 |
|---|---|---|
| A. 未认证请求进入 shutdown 分支 | 成立（对象＝**reconstructed**） | 成立（对象＝**40d0bc1d 原件**），附 §6.3 六项 |
| B. `RemoteDisconnected` 单独可判 | 不成立（保留） | 不变，仍不成立 |
| C. 证据对象是 40d0bc1d 原始字节 | `needs_evidence` | **可关闭**（commit full sha + 文件 sha256 + tarball sha + API json 齐备） |
| 行号 87 | 只能锚到日志 | 由原件实测复核；不符则作为发现项写清 |
| 镜像 provenance | 仅 `SOURCE.md` 声明 | 由 §6.4 差分支持（或推翻） |

写法纪律：

1. **不覆盖历史**：`workspace/VG-01-nltk-wordnet/artifacts/RESULT.json` 保持原样；新结论写在新的 docs/ 与 `/tmp` 证据目录里。
2. 台账若要更新，只加字段：`evidence_level: server_stdout_confirmed(original_commit)` + `original_commit_provenance: verified(sha256=…, commit=…)`，原 `shutdown_result` 不动。
3. 原件若跑不起来（见 §8），结论**不许**降级成"通过"，写 `needs_evidence` + 具体阻塞。

---

## 8. 失败模式与处置

| 现象 | 含义 | 处置 |
|---|---|---|
| API 404 / 422 | 短 sha 不存在或前缀不唯一 | 停；换正确 ref，不许拿相近提交顶替 |
| `git fetch --depth 1 origin 40d0bc1d` 报 `not our ref` | 服务端不允许按 sha 取 | 改走路 A（codeload）；或 fetch 全历史后 `git checkout 40d0bc1d`（慢） |
| `git rev-parse HEAD` ≠ API `full_sha` | 取回物不是同一对象 | 停，重取 |
| 原件含 `safe_print` 或 403 | 取到的是修复版 | 停：不是 40d0bc1d |
| 条件行号 ≠ 87 | 版本/文件不符，或 `SOURCE.md` 记错 | 写发现项；先证 commit 再谈行号 |
| 原件在 py3.10 下 import 失败（老代码 API 漂移） | 文件是原件，但运行时年代不匹配 | **不改源码**；用匹配年代的容器/venv 跑，或在 `notes` 里写明"未执行，原因=import error + traceback"，结论保持 `needs_evidence` |
| 不带 `-u` 时 stdout 为空 | `os._exit(0)` 吞掉块缓冲的 print（本仓已实测） | 一律 `-u` + `PYTHONUNBUFFERED=1`；见 `evidence/05-buffering-trap/` |
| `/start_page` 抛 `LookupError` | 本机无 wordnet 语料 | 正常；判定不依赖它，别把 traceback 当"漏洞证据" |
| 8000 端口被占 | 本机一个无关静态服务器占着 8000（历史记录） | 探针默认随机端口；裸跑显式换端口 |

---

## 9. 一句话交接

> 在联网机上：`API 解短 sha → codeload tarball → 算指纹 → 打自描述包回传`；
> 在本机：`过 vg01_source_check.sh（rc=0）→ 用 --module 指到原件跑 vuln 场景 → 抓 stdout/rc/端口/模块哈希 → 与镜像做 88–90 行差分`。
> 四步都留下原始输出，A 项才能从"对象＝重建件"改成"对象＝原件"；任何一步缺失，就继续写 `needs_evidence`。
