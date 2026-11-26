// Shared read-only workspace shell. No state-changing API calls.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g,c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try { const r = await fetch(path, {signal:controller.signal}); if (!r.ok) throw new Error(`HTTP ${r.status}`); return await r.json(); }
  finally { clearTimeout(timeout); }
}
const badge = (t,c='b-dim') => `<span class="badge ${c}">${esc(t)}</span>`;
const dot = (on,kind='ok') => `<span class="dot ${on ? 'd-'+kind : 'd-no'}"></span>`;
const LAYER = {
 local_verified:{on:['通过','b-ok'],off:['未通过','b-dim']},
 causal_chain_verified:{on:['闭合','b-purple'],off:['待补证据','b-dim']},
 high_severity_confirmed:{on:['高危标记','b-bad'],off:['—','b-dim']},
 course_ready:{on:['可交付','b-ok'],off:['待验收','b-warn']},
};
function layerBadge(key,val) {const m=LAYER[key];return badge(...(val?m.on:m.off));}
const STAGE={causal_chain_verified:['因果链闭合','b-purple'],local_verified_pending_evidence:['待补证据','b-warn'],not_verified:['未验证','b-dim'],withdrawn:['已撤回','b-dim']};
const stageBadge = s => badge(...(STAGE[s] || [s || '未开始','b-dim']));
// 主导航只列高频入口；细分证据页面仍保留原 URL。
const DEFAULT_VIEW='discovery';
const VIEWS=[
 ['index.html','discovery','总览'], ['cases.html','cases','案例库'],
 ['discovery-campaigns.html','discovery-campaigns','发现记录'],
 ['platform-tasks.html','platform-tasks','任务队列'], ['report.html','report','分析报告']
];
const SECONDARY_VIEWS=[
 ['discovery-findings.html','discovery-findings','发现证据'],
 ['discovery-reports.html','discovery-reports','分赛道报告索引'],
 ['packages.html','packages','交付包'], ['lab.html','lab','实验记录']
];
const navLink = (active, [href,key,title]) => `<a class="sb-item ${key===active?'active':''}" ${key===active?'aria-current="page"':''} href="${href}">${icon(key)}<span class="nm">${title}</span>${key===active?'<span class="nav-active-dot"></span>':''}</a>`;
const BENCH_LABEL={cybergym:'CyberGym',exploitgym:'ExploitGym',vulngym:'VulnGym'};
const ICONS={overview:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',cases:'M9 3h6l2 4v10l-2 4H9l-2-4V7z M3 8l4 2 M17 10l4-2 M3 16l4-2 M17 14l4 2 M12 7v10',report:'M6 3h9l4 4v14H6z M14 3v5h5 M9 12h7 M9 16h7',packages:'M3 7l9-4 9 4v11l-9 4-9-4z M3 7l9 5 9-5 M12 12v10',lab:'M9 3h6 M10 3v6L4 19q-1 2 2 2h12q3 0 2-2L14 9V3 M8 14h8',search:'M10.5 3a7.5 7.5 0 1 0 0 15a7.5 7.5 0 1 0 0-15 M16 16l5 5',arrow:'M5 12h14 M13 6l6 6-6 6',refresh:'M20 7a9 9 0 1 0 1 8 M20 3v5h-5',menu:'M4 6h16 M4 12h16 M4 18h16',close:'M5 5l14 14 M19 5L5 19',shield:'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6z M8 12l3 3 5-6',chevron:'M9 5l7 7-7 7',image:'M3 3h18v18H3z M3 17l6-6 5 5 3-3 4 4 M15 7h1',discovery:'M12 3a9 9 0 1 0 9 9 M12 3v9l6-6 M12 12l7 7','discovery-campaigns':'M4 6h16 M4 12h16 M4 18h10 M18 16l2 2 3-4','discovery-findings':'M12 4v16 M8 8h8 M6 12h12 M8 20l4-4 4 4 M8 4l4 4 4-4','discovery-reports':'M5 3h10l4 4v14H5z M15 3v5h5 M8 12h8 M8 16h8 M8 8h3','platform-tasks':'M4 5h16 M4 12h16 M4 19h16 M7 3v18 M17 3v18'};
function icon(name,cls=''){return `<svg class="icon ${cls}" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${ICONS[name]||ICONS.overview}"/></svg>`;}
function groupByBench(items){const g=new Map();for(const c of items){const k=(c.benchmark||'other').toLowerCase();if(!g.has(k))g.set(k,[]);g.get(k).push(c);}return [...g.entries()].sort((a,b)=>a[0].localeCompare(b[0]));}
function renderShell(active,{title,sub,chips=[]}={}){
 document.body.dataset.view=active;
 const side=$('#sidebar'),head=$('#tophead');
 if(side)side.innerHTML=`<a class="sb-brand" href="index.html" aria-label="vulnmap 项目总览"><span class="logo">${icon('shield')}</span><span>vulnmap<small>VULNERABILITY WORKSPACE</small></span></a>
 <div class="workspace-label"><span class="workspace-dot"></span>课程研究项目<span class="workspace-version">v0.1</span></div>
 <div class="sb-label">工作空间</div><nav id="main-nav" class="sb-list" aria-label="主导航">${VIEWS.map(v=>navLink(active,v)).join('')}</nav>
 <details class="sb-more" ${SECONDARY_VIEWS.some(v=>v[1]===active)?'open':''}><summary>${icon('chevron')}<span>更多资料</span></summary><nav class="sb-list" aria-label="更多资料">${SECONDARY_VIEWS.map(v=>navLink(active,v)).join('')}</nav></details>
 <div class="sb-foot">${icon('shield')}<div>只读证据视图<small>不修改案例与验收结果</small></div><a href="/api/docs" target="_blank" rel="noopener" aria-label="打开 API 文档">↗</a></div>`;
 renderHeader(active,{title,sub});
 if(!$('.nav-backdrop')){const overlay=document.createElement('button');overlay.type='button';overlay.className='nav-backdrop';overlay.setAttribute('aria-label','关闭导航');overlay.onclick=closeNavigation;document.body.appendChild(overlay);}
 syncNavigation();
}

function renderHeader(active,{title,sub}={}){const head=$('#tophead');
 if(head)head.innerHTML=`<div class="header-context"><button class="menu-toggle" type="button" aria-label="打开导航" aria-controls="sidebar" aria-expanded="false">${icon('menu')}</button><span>工作空间</span><span class="crumb-slash">/</span><strong>${esc(title||'vulnmap')}</strong><span class="header-readonly"><i></i>只读模式</span></div>
 <div class="title-row"><div><h1>${esc(title||'vulnmap')}</h1><p class="subline">${esc(sub||'')}</p></div><div class="head-actions"><span class="sync-label">来自本地运行工件</span><button class="refresh" type="button" onclick="location.reload()">${icon('refresh')}<span>刷新数据</span></button></div></div>`;
 const toggle=$('.menu-toggle'); if(toggle)toggle.addEventListener('click',()=>{const open=document.body.classList.toggle('nav-open');toggle.setAttribute('aria-expanded',String(open));syncNavigation();});
}
function closeNavigation(){document.body.classList.remove('nav-open');const b=$('.menu-toggle');if(b)b.setAttribute('aria-expanded','false');syncNavigation();}
window.addEventListener('keydown',e=>{if(e.key==='Escape')closeNavigation();});
function renderProjects(items,expandBench){const el=$('#sbProj');if(!el)return;const groups=groupByBench(items);const cnt=$('#projCount');if(cnt)cnt.textContent=groups.length;el.innerHTML=groups.map(([bench,list])=>`<details class="proj" ${bench===expandBench?'open':''}><summary><span class="tri"></span><span>${esc(BENCH_LABEL[bench]||bench)}</span><span class="cnt">${list.length}</span></summary><div class="proj-body"><div class="proj-actions"><button class="text-button" onclick="event.preventDefault();rerunBenchmark('${bench}')">重跑该 benchmark</button></div>${list.map(c=>`<a class="proj-case" href="cases.html#${esc(c.dir)}" title="${esc(c.task_id)}"><span class="st ${c.course_ready?'ok':c.local_verified?'warn':'bad'}"></span><span class="nm">${esc(c.case_id)}</span><span class="pj">${esc(c.project||'—')}</span></a>`).join('')}</div></details>`).join('');}

// P4.5：写请求统一走 writeJSON（可选 Bearer token）；postJSON 保留为别名，旧调用点不用改
async function postJSON(path, body){ return writeJSON(path, body); }

// ---- V2 任务 P4.5：执行作业（Job）写请求 + 可选 token 鉴权 ----
// token 只存在浏览器本地；服务端未设置 PLATFORM_API_TOKEN 时写操作本地开放。
const PLATFORM_TOKEN_KEY = 'platform_token';
function platformToken(){
  try { return localStorage.getItem(PLATFORM_TOKEN_KEY) || ''; } catch(e) { return ''; }
}
async function writeJSON(path, body){
  const headers = {'content-type':'application/json'};
  const token = platformToken();
  if (token) headers.authorization = 'Bearer ' + token;
  const r = await fetch(path, {method:'POST', headers, body:JSON.stringify(body ?? {})});
  let data = {}; try { data = await r.json(); } catch(e) {}
  if (!r.ok) {
    const detail = data && typeof data.detail === 'string' ? data.detail : '';
    throw new Error(detail || ('HTTP ' + r.status));
  }
  return data;
}
// job.status: PENDING / RUNNING / EXITED / FAILED / CANCELLED
const JOB_BADGE = {PENDING:'b-dim', RUNNING:'b-warn', EXITED:'b-ok', FAILED:'b-bad', CANCELLED:'b-dim'};
const jobBadge = status => badge(status || '无作业', JOB_BADGE[status] || 'b-dim');
const jobHref = id => 'platform-task.html?job_id=' + encodeURIComponent(id);
// 作业还没结束：只有这两种状态可以取消
const jobLive = status => status === 'PENDING' || status === 'RUNNING';
async function rerunCase(dir){
  if (!confirm('重跑会先备份旧 artifacts/logs，然后重新执行该案例。继续？')) return;
  try { const r = await postJSON('/api/rerun', {dir}); alert('已启动：'+r.target+'\n可刷新页面查看最新产物'); }
  catch(e){ alert('启动失败：'+e.message); }
}
async function rerunBenchmark(bench){
  if (!confirm('重跑该 benchmark 会串行重跑其全部案例，耗时较长。继续？')) return;
  try { const r = await postJSON('/api/rerun', {benchmark:bench}); alert('已启动：'+r.target+'\n进度见 /api/rerun/status'); }
  catch(e){ alert('启动失败：'+e.message); }
}
window.rerunCase = rerunCase; window.rerunBenchmark = rerunBenchmark;

// ---- V2 任务视图（P4）：只读页面共用的状态色与子导航 ----
const PSTATE={
 RECEIVED:['已提交','b-dim'],PREFLIGHT:['准入中','b-info'],READY:['就绪','b-ok'],
 UNDERSTANDING:['程序理解','b-info'],HYPOTHESES:['假设集','b-info'],PLANNED:['已规划','b-info'],
 RUNNING:['执行中','b-warn'],CANDIDATE:['有候选','b-warn'],VERIFYING:['验证中','b-warn'],
 REVIEW:['复核中','b-purple'],REPORTED:['已出包','b-ok'],CLOSED:['已结案','b-ok'],
 BLOCKED:['受阻','b-bad'],FAILED:['失败','b-bad'],NO_REPRO:['不可复现','b-bad'],
 NEEDS_EVIDENCE:['待补证据','b-warn'],REJECTED:['已拒绝','b-bad'],
};
const stateBadge=s=>badge(...(PSTATE[s]||[s||'未知','b-dim']));
const stateLabel=s=>(PSTATE[s]||[null,s||'未知'])[0];
const taskHref=(f,id)=>f+(id?'?task_id='+encodeURIComponent(id):'');
const TASK_VIEWS=[['platform-task.html','任务详情'],['platform-events.html','事件流'],['platform-evidence.html','证据'],['platform-casepack.html','CasePack']];
function taskNav(tid,active){return `<nav class="pf-tasks-nav" aria-label="任务子视图">${TASK_VIEWS.map(([f,t])=>
 `<a href="${taskHref(f,tid)}" class="${f===active?'on':''}" ${f===active?'aria-current="page"':''}>${t}</a>`).join('')}</nav>`;}
function taskPicker(items,emptyText){
 if(!items.length)return `<div class="pf-empty">${esc(emptyText||'还没有任务，去「V2 任务」页提交一个。')}</div>`;
 return `<div class="pf-kpis">${items.map(t=>`<a class="pf-kpi" href="${taskHref('platform-task.html',t.task_id)}">
   ${stateBadge(t.state)}<b>${esc(t.task_id)}</b><span>${esc(t.benchmark)} · ${esc(t.target)}</span></a>`).join('')}</div>`;}
async function getOr404(url){const r=await fetch(url);if(r.status===404)return null;if(!r.ok)throw new Error('HTTP '+r.status);return r.json();}

function fail(el,err){el.innerHTML=`<div class="error" role="alert"><b>暂时无法读取数据</b><p>${esc(err.name==='AbortError'?'请求超时，请检查本地服务后重试。':err.message)}</p><button class="refresh" onclick="location.reload()">重新加载</button></div>`;}

function syncNavigation(){const side=$('#sidebar');if(side)side.inert=matchMedia('(max-width:860px)').matches&&!document.body.classList.contains('nav-open');}
window.addEventListener('resize',syncNavigation);document.addEventListener('DOMContentLoaded',syncNavigation);
