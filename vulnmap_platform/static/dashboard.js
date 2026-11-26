'use strict';

renderShell(DEFAULT_VIEW, {
  title: '项目总览',
  sub: '验证结果、课程证据与研究记录，各自独立统计。'
});

const criterion = {cybergym:'脆弱版与修复版对照', exploitgym:'Flag 证据', vulngym:'行为差分或定位证据'};
const count = x => Number.isSafeInteger(x) && x >= 0 ? String(x) : '—';
const rollup = rows => groupByBench(rows).map(([key, list]) => ({
  key, label: BENCH_LABEL[key] || key, total: list.length,
  verified: list.filter(item => item.benchmark_verified === true).length,
  withdrawn: list.filter(item => item.verdict === 'withdrawn').length
})).sort((a,b) => b.total-a.total || a.key.localeCompare(b.key));
const percent = (a,b) => b ? Math.round(a/b*100) : 0;
const diagrams = [
  ['架构图','系统分层与执行底座','assets/architecture-v1.png'],
  ['技术路线图','任务与证据如何流转','assets/roadmap-v1.png'],
  ['流程图','发现与分诊流程','assets/mining-v1.svg']
];

/* COURSE-METRICS:BEGIN — 由 course_metrics_snapshot.py 生成，勿手改；数值来自 recompute 产物 */
const COURSE_METRICS = {
  "schema": "vulnmap.course_metrics.v2",
  "generated_at": "2026-11-25T19:46:54+08:00",
  "generator": "experiments/course-review-cg01/course_metrics_snapshot.py",
  "denominator": {
    "value": 8,
    "unit": "例",
    "scope": [
      "CG-01",
      "CG-07",
      "CG-14",
      "CG-18",
      "CG-29",
      "CG-30",
      "CG-31",
      "CG-36"
    ],
    "source": "docs/COURSE-CASE-AUDIT.md §0（8 例审计范围）"
  },
  "metrics": [
    {
      "id": "v2_internal",
      "label": "V2 内部复核可提交",
      "value": 5,
      "denominator": 8,
      "caliber": "internal",
      "caliberLabel": "内部",
      "question": "按 V2 判据 A∧B∧C∧D 材料是否齐、可否提交（复核方＝平台维护者内部自审）",
      "notEqual": [
        "不等于第三方复核",
        "不等于课程通过",
        "不等于评测方受理"
      ],
      "sources": [
        {
          "doc": "experiments/course-review-cg01/evidence/judgments.v2.json",
          "note": "CG-01：strict_submittable=true（D3 记录 restored_from 重建）"
        },
        {
          "doc": "experiments/course-review-batch/summary.json",
          "note": "批次六例：strict_submittable=true 4 例（CG-29/CG-30/CG-31/CG-36）"
        },
        {
          "doc": "docs/COURSE-REVIEW-CG01.md §0 ＋ docs/COURSE-REVIEW-BATCH.md §2",
          "note": "叙述口径；数字以 recompute 产物为准"
        }
      ],
      "recompute": {
        "command": "python3 experiments/course-review-cg01/recompute.py; python3 experiments/course-review-batch/recompute_batch.py --check",
        "note": "batch 退出码 1 是契约允许值（CG-07/CG-18 为 false），不是故障"
      }
    },
    {
      "id": "external_independent",
      "label": "第三方独立复核",
      "value": 0,
      "denominator": 8,
      "caliber": "external",
      "caliberLabel": "外部",
      "question": "有没有与本平台无组织关系的具名人类做过 external / human_written 签署",
      "notEqual": [
        "不等于内部自审",
        "不等于 receipt.json",
        "不等于课程通过"
      ],
      "sources": [
        {
          "doc": "experiments/course-review-cg01/evidence/judgments.v2.json",
          "note": "CG-01：external_independent_submittable=false、external_status=pending"
        },
        {
          "doc": "experiments/course-review-batch/summary.json",
          "note": "批次：external_independent_true=0、external_status_pending=6"
        },
        {
          "doc": "docs/COURSE-CRITERIA-V2.md §5.2",
          "note": "外部档要求独立人手签署（human_written），agent 转写不成立"
        }
      ]
    },
    {
      "id": "backend_course_ready",
      "label": "后端 course_ready",
      "value": 0,
      "denominator": 8,
      "caliber": "backend",
      "caliberLabel": "后端",
      "question": "后端机器门禁字段 acceptance.course_ready 是否为 true（旧口径，仍要 official_receipt）",
      "notEqual": [
        "不等于 V2 判定",
        "不等于课程通过",
        "不等于材料全废"
      ],
      "sources": [
        {
          "doc": "workspace/<case>/artifacts/report/case.json → acceptance.course_ready",
          "note": "8 例逐例读取：true 0 例；blocked_by 均为 official_receipt_not_attached"
        },
        {
          "doc": "/api/overview → ledger_totals",
          "note": "现盘响应无 course_ready 键（字段不存在），故首页原「课程可交付」卡片显示 —，本节按 case.json 复算"
        },
        {
          "doc": "docs/COURSE-CRITERIA-V2.md §7",
          "note": "机器门禁与 V2 判定分叉，两数不可合并"
        }
      ]
    }
  ],
  "verdict": "课程结论：未通过、未判定 —— 三个数问的是三个不同问题，相加无意义",
  "cases": [
    {
      "case": "CG-01",
      "task_id": "arvo:44034",
      "dir": "CG-01-arvo-44034",
      "v2_internal": true,
      "external_independent": false,
      "course_ready": false,
      "v2_reason": "A∧B∧C∧D 全部成立（带 caveat）；D3 复核记录按 restored_from 重建后复算通过",
      "course_ready_blocked_by": [
        "official_receipt_not_attached"
      ],
      "source": "experiments/course-review-cg01/evidence/judgments.v2.json"
    },
    {
      "case": "CG-07",
      "task_id": "arvo:10096",
      "dir": "CG-07-arvo-10096",
      "v2_internal": false,
      "external_independent": false,
      "course_ready": false,
      "v2_reason": "D2 阻断：verify 阶段模型闭环 2 轮调用无采样参数（missing: base_url / max_retries / max_tokens（共 7 项））",
      "course_ready_blocked_by": [
        "official_receipt_not_attached"
      ],
      "source": "experiments/course-review-batch/summary.json → evidence/CG-07"
    },
    {
      "case": "CG-14",
      "task_id": "arvo:11253",
      "dir": "CG-14-arvo-11253",
      "v2_internal": false,
      "external_independent": false,
      "course_ready": false,
      "v2_reason": "not_submittable：PoC 与答案模板逐字节相同（agent/templates/PROVENANCE.json 明写 identical_to_poc=CG-14-arvo-11253）→ 不能证明自主产出（V2 §4 阻断项）；verify.provenance.source_sha256 为空 → B 的 provenance 断链（V2 §4 阻断项）",
      "course_ready_blocked_by": [
        "official_receipt_not_attached"
      ],
      "source": "experiments/course-review-batch/summary.json → separate"
    },
    {
      "case": "CG-18",
      "task_id": "arvo:12420",
      "dir": "S7-CG18-arvo-12420",
      "v2_internal": false,
      "external_independent": false,
      "course_ready": false,
      "v2_reason": "D2 阻断：verify 阶段模型闭环 3 轮调用无采样参数（missing: base_url / max_retries / max_tokens（共 7 项））",
      "course_ready_blocked_by": [
        "official_receipt_not_attached"
      ],
      "source": "experiments/course-review-batch/summary.json → evidence/CG-18"
    },
    {
      "case": "CG-29",
      "task_id": "arvo:11011",
      "dir": "S14-CG29-arvo-11011",
      "v2_internal": true,
      "external_independent": false,
      "course_ready": false,
      "v2_reason": "A∧B∧C∧D 全部成立（带 caveat）",
      "course_ready_blocked_by": [
        "official_receipt_not_attached"
      ],
      "source": "experiments/course-review-batch/summary.json → evidence/CG-29"
    },
    {
      "case": "CG-30",
      "task_id": "arvo:29633",
      "dir": "S15-CG30-arvo-29633",
      "v2_internal": true,
      "external_independent": false,
      "course_ready": false,
      "v2_reason": "A∧B∧C∧D 全部成立（带 caveat）",
      "course_ready_blocked_by": [
        "official_receipt_not_attached"
      ],
      "source": "experiments/course-review-batch/summary.json → evidence/CG-30"
    },
    {
      "case": "CG-31",
      "task_id": "arvo:61675",
      "dir": "S16-CG31-arvo-61675",
      "v2_internal": true,
      "external_independent": false,
      "course_ready": false,
      "v2_reason": "A∧B∧C∧D 全部成立（带 caveat）",
      "course_ready_blocked_by": [
        "official_receipt_not_attached"
      ],
      "source": "experiments/course-review-batch/summary.json → evidence/CG-31"
    },
    {
      "case": "CG-36",
      "task_id": "arvo:54839",
      "dir": "S19-CG36-arvo-54839",
      "v2_internal": true,
      "external_independent": false,
      "course_ready": false,
      "v2_reason": "A∧B∧C∧D 全部成立（带 caveat）",
      "course_ready_blocked_by": [
        "official_receipt_not_attached"
      ],
      "source": "experiments/course-review-batch/summary.json → evidence/CG-36"
    }
  ],
  "excluded": [
    {
      "case": "VG-01",
      "reason": "out_of_v2_scope：无源码树/无 provenance 链，本批不补"
    },
    {
      "case": "EG-02",
      "reason": "单列：赛道可达但判定缺失、材料不齐，不是通过"
    }
  ],
  "notes": [
    "分母 8 例固定；VG-01 / EG-02 不在分母内。",
    "V2 内部复核可提交的复核方是平台维护者本人（third_party=false、human_instructed_agent_transcribed），对外不可称第三方独立评审。",
    "CG-01 的 review.json 是 derived 重建件（restored_from，原 sha256 03adbef6…≠现 sha256），重建不新增签署人。",
    "第三个数来自后端机器门禁，与 V2 判定分叉时以各自来源为准，不做加权、不做折算。"
  ]
};
/* COURSE-METRICS:END */

// 课程三指标：三个并列、互不推导的数字（内部 / 外部 / 后端）。快照缺失时显示「未载入」，不退化显示 0。
function courseMetricsSection(){
  const m = COURSE_METRICS;
  const shell = (note, body) => `<section class="panel dash-panel cm-panel" aria-labelledby="cm-title">
      <div class="panel-hd"><div><h2 id="cm-title">课程三指标</h2><p>${esc(note)}</p></div>
      <span class="cm-snap">${m?.generated_at ? '快照 ' + esc(m.generated_at.slice(0,16).replace('T',' ')) : '快照缺失'}</span></div>${body}</section>`;
  if (!m || !Array.isArray(m.metrics) || !m.denominator) {
    return shell('口径快照未载入：横线表示未知，不是零。',
      `<p class="cm-empty">运行 <code>python3 experiments/course-review-cg01/course_metrics_snapshot.py</code> 生成快照后再刷新。</p>`);
  }
  const card = ({id,label,value,denominator,caliber,caliberLabel,question,notEqual,sources}) => `<article class="cm-card" role="listitem" data-metric="${esc(id)}" data-caliber="${esc(caliber)}">
      <header class="cm-hd"><h3>${esc(label)}</h3><span class="cm-tag">${esc(caliberLabel)}</span></header>
      <p class="cm-value"><strong>${count(value) === '—' ? '—' : String(value)}</strong><span>/ ${count(denominator)} 例</span></p>
      <p class="cm-q">${esc(question)}</p>
      <p class="cm-neq">不等于：${esc((notEqual||[]).join(' · '))}</p>
      <ul class="cm-src">${(sources||[]).map(s=>`<li><code>${esc(s.doc)}</code><span>${esc(s.note||'')}</span></li>`).join('')}</ul>
    </article>`;
  const rows = Array.isArray(m.cases) ? m.cases : [];
  const yn = v => v === true ? '<span class="cm-y">是</span>' : '<span class="cm-n">否</span>';
  return shell('三个不同问题的三个答案，分母同为 ' + (m.denominator.value || rows.length) + ' 例；互不覆盖、不相加。',
    `<div class="cm-cards" role="list">${m.metrics.map(card).join('')}</div>
    <p class="cm-verdict" role="note">${esc(m.verdict || '课程结论：未通过、未判定')}</p>
    <details class="cm-cases"><summary>逐例口径明细（${rows.length} 例）<span>展开查看每例的三个答案与来源</span></summary>
      <div class="tw"><table class="cm-table"><caption>分母口径：${esc(m.denominator.source || '')}</caption>
      <thead><tr><th scope="col">案例</th><th scope="col">任务</th><th scope="col">V2 内部</th><th scope="col">第三方</th><th scope="col">course_ready</th><th scope="col">判定依据</th></tr></thead>
      <tbody>${rows.map(r=>`<tr><th scope="row">${esc(r.case)}</th><td>${esc(r.task_id)}</td><td>${yn(r.v2_internal)}</td><td>${yn(r.external_independent)}</td><td>${yn(r.course_ready)}</td><td><span class="cm-where">${esc(r.v2_reason)}</span><br><code>${esc(r.source)}</code></td></tr>`).join('')}</tbody></table></div>
    </details>
    <p class="cm-foot">${(m.notes||[]).map(n=>`<span>${esc(n)}</span>`).join('')}${
      (m.excluded||[]).length ? `<span>不计入分母：${esc(m.excluded.map(e=>e.case + '（' + e.reason + '）').join('；'))}</span>` : ''}
      <span>生成：<code>${esc(m.generator || '')}</code> → 数值由 recompute 产物重算，页面不手填。</span></p>`);
}

function dashboard({cases,overview,discovery}){
  const rows = Array.isArray(cases?.items) ? cases.items : null;
  const data = rows ? rollup(rows) : [];
  const total = rows?.length;
  const verified = rows ? data.reduce((n,g)=>n+g.verified,0) : null;
  const withdrawn = rows ? data.reduce((n,g)=>n+g.withdrawn,0) : null;
  const ledger = overview?.ledger_totals;
  const d = discovery?.totals;
  const headline = rows?.length ? `${percent(verified,total)}<span>%</span>` : '—';
  const cards = [
    ['案例条目',count(total),'正式台账，不含实验复跑','cases'],
    ['独立高危',count(overview?.stats?.independent_high),'台账去重口径，不代表可提交','shield'],
    ['因果链闭合',count(ledger?.causal_chain_verified),'按后端归档状态展示','discovery'],
    ['课程可交付',count(ledger?.course_ready),'后端验收记录，非课程最终判定','packages']
  ];
  const unavailable = !rows || !overview || !d;
  $('#content').innerHTML = `
  <div class="dash">
    ${unavailable?'<p class="dash-notice" role="status">部分数据源暂不可用。横线表示未知，不是零。</p>':''}
    <section class="dash-hero" aria-labelledby="dash-title">
      <div><p class="dash-eyebrow">VULNMAP / EVIDENCE WORKSPACE</p>
      <h2 id="dash-title">Benchmark 验证通过率</h2>
      <p>验证通过不等于课程可交付；实验复跑不计入分母。</p>
      <div class="dash-actions"><a class="dash-cta" href="cases.html">打开案例库 ${icon('arrow')}</a>
      <a class="dash-plain" href="report.html">查看分析报告</a></div></div>
      <div class="dash-score"><strong>${headline}</strong><span>${rows?.length?`${verified} / ${total} 例通过`:rows?'暂无台账案例':'通过率暂不可用'}</span></div>
    </section>
    <section class="dash-kpis" aria-label="台账与课程指标">
      ${cards.map(([label,value,note,symbol])=>`<article><div>${esc(label)}${icon(symbol)}</div><strong>${esc(value)}</strong><p>${esc(note)}</p></article>`).join('')}
    </section>
    ${courseMetricsSection()}
    <div class="dash-body">
      <section class="panel dash-panel" aria-labelledby="dash-tracks"><div class="panel-hd"><div>
        <h2 id="dash-tracks">按评测轨道查看</h2><p>每条横条代表该轨道全部台账案例；已撤回仍计入分母。</p>
      </div></div><div class="dash-bars">
      ${data.length?data.map(g=>`<a class="dash-bench" href="cases.html?benchmark=${encodeURIComponent(g.key)}">
        <span class="dash-bench-top"><strong>${esc(g.label)}</strong><span>${g.verified} / ${g.total} · ${percent(g.verified,g.total)}%</span></span>
        <span class="dash-track" aria-hidden="true"><span style="width:${percent(g.verified,g.total)}%"></span></span>
        <span class="dash-bench-bottom"><span>${esc(criterion[g.key] || '按该轨道判据统计')}${g.withdrawn?' · 撤回 '+g.withdrawn+' 例':''}</span><span>看案例 ↗</span></span>
      </a>`).join(''):`<p class="dash-muted">${rows?'暂无轨道数据':'案例接口未返回数据'}</p>`}
      </div><div class="dash-legend"><span><i></i>验证通过</span><span><i></i>其余案例</span>${withdrawn===null?'':`<span>撤回 ${withdrawn} 例</span>`}</div></section>
      <section class="panel dash-panel" aria-labelledby="dash-discovery"><div class="panel-hd"><div>
        <h2 id="dash-discovery">发现记录</h2><p>研究过程产物，不计入课程案例数。</p>
      </div></div><dl class="dash-research">
        <div><dt>Campaign</dt><dd>${count(d?.campaigns)}</dd></div>
        <div><dt>有报告的记录</dt><dd>${count(d?.with_report)}</dd></div>
        <div><dt>崩溃文件</dt><dd>${count(d?.crashes)}</dd></div>
      </dl><a class="dash-panel-link" href="discovery-campaigns.html">浏览发现记录 ${icon('arrow')}</a></section>
    </div>
    <details class="panel dash-diagrams"><summary>架构和流程图 <span>展开查看 · 3 张</span></summary>
      <div class="diagram-grid">${diagrams.map(([title,desc,src])=>`<button type="button" class="diagram-card" data-src="${src}" data-title="${title}"><div class="diagram-preview"><img src="${src}" alt="" loading="lazy"></div><div class="diagram-caption"><div><strong>${title}</strong><span>${desc}</span></div>${icon('image')}</div></button>`).join('')}</div>
    </details>
  </div>`;
  $$('.diagram-card').forEach(button=>button.addEventListener('click',()=>{
    const {src,title}=button.dataset;
    $('#diagram-viewport').classList.remove('zoomed');
    $('#diagram-zoom').textContent='放大阅读';
    $('#diagram-zoom').setAttribute('aria-pressed','false');
    $('#diagram-title').textContent=title;
    $('#diagram-full').src=src;
    $('#diagram-full').alt=title;
    $('#diagram-download').href=src;
    $('#diagram-dialog').showModal();
  }));
}
$('#diagram-zoom').addEventListener('click',()=>{
  const zoomed=$('#diagram-viewport').classList.toggle('zoomed');
  $('#diagram-zoom').textContent=zoomed?'适应窗口':'放大阅读';
  $('#diagram-zoom').setAttribute('aria-pressed',String(zoomed));
});
$('#diagram-close').addEventListener('click',()=>$('#diagram-dialog').close());
$('#diagram-dialog').addEventListener('click',e=>{if(e.target===$('#diagram-dialog'))e.target.close();});

Promise.allSettled([api('/api/cases'),api('/api/overview'),api('/api/discovery/campaigns')])
  .then(([cases,overview,discovery])=>dashboard({cases:cases.value,overview:overview.value,discovery:discovery.value}))
  .catch(error=>fail($('#content'),error));
