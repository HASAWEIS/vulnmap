-- Discovery v1.0 台账（与 agent/discovery/store.py 的 SCHEMA 保持一致）
-- campaign: 一次目标 campaign 的构建与预算
CREATE TABLE IF NOT EXISTS campaign (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    "commit" TEXT,
    build_flags TEXT,
    budget TEXT,
    status TEXT,
    created_at TEXT
);

-- binary: 参与分析的二进制（构建产物 + 目标内已有 ELF）
CREATE TABLE IF NOT EXISTS binary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign TEXT NOT NULL,
    path TEXT,
    sha256 TEXT,
    arch TEXT,
    bits INTEGER,
    endian TEXT
);

-- call_site: 危险调用点台账
CREATE TABLE IF NOT EXISTS call_site (
    id TEXT PRIMARY KEY,
    campaign TEXT NOT NULL,
    function TEXT,
    file TEXT,
    line INTEGER,
    callee TEXT,
    score REAL,
    status TEXT
);

-- candidate: 一次崩溃候选
CREATE TABLE IF NOT EXISTS candidate (
    id TEXT PRIMARY KEY,
    call_site TEXT,
    input_sha256 TEXT,
    crash_type TEXT,
    stack_hash TEXT,
    log_path TEXT
);

-- review: 复核结论（confirmed/weakened/excluded/needs_human）
CREATE TABLE IF NOT EXISTS review (
    id TEXT PRIMARY KEY,
    candidate TEXT,
    verdict TEXT,
    root_cause TEXT,
    reproducible INTEGER,
    notes TEXT
);

-- finding: 报告条目；severity 不按崩溃数推定
CREATE TABLE IF NOT EXISTS finding (
    id TEXT PRIMARY KEY,
    review TEXT,
    severity TEXT,
    cwe TEXT,
    report_path TEXT
);

-- coverage: 每个阶段的 planned/covered/uncovered
CREATE TABLE IF NOT EXISTS coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign TEXT,
    stage TEXT,
    planned INTEGER,
    covered INTEGER,
    uncovered INTEGER
);
