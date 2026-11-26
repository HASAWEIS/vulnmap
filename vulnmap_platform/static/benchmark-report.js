// Pure aggregation: each case belongs only to the benchmark recorded in /api/cases.
// Join on workspace dir, not case_id (case aliases can collide across reruns).
function buildBenchmarkReports(report, cases) {
  const groups = new Map();
  const summaries = new Map();
  (cases || []).forEach(function(c) {
    const key = String(c.benchmark || 'unknown').toLowerCase();
    if (!groups.has(key)) groups.set(key, {key:key, cases:[], entries:[]});
    groups.get(key).cases.push(c);
    summaries.set(c.dir, c);
  });
  (report.entries || []).forEach(function(e) {
    const c = summaries.get(e.dir);
    const key = c ? String(c.benchmark || 'unknown').toLowerCase() : 'unknown';
    if (!groups.has(key)) groups.set(key, {key:key, cases:[], entries:[]});
    groups.get(key).entries.push(e);
  });
  const order = ['cybergym', 'exploitgym', 'vulngym'];
  return Array.from(groups.values()).map(function(g) {
    const count = function(field) { return g.cases.filter(function(c){ return !!c[field]; }).length; };
    g.counts = {cases:g.cases.length, reports:g.entries.length,
      local:count('local_verified'), causal:count('causal_chain_verified'),
      high:count('high_severity_confirmed')};
    g.distributions = {verdict:{}, cwe:{}, generation:{}};
    g.cases.forEach(function(c) {
      [['verdict',c.verdict||'unknown'],['cwe',c.cwe||'未记录'],['generation',c.generation_path||'未记录']].forEach(function(pair) {
        const dict=g.distributions[pair[0]];dict[pair[1]]=(dict[pair[1]]||0)+1;
      });
    });
    g.blockers = {};
    g.cases.forEach(function(c) {
      Array.from(new Set(c.blockers || [])).forEach(function(b) {g.blockers[b]=(g.blockers[b]||0)+1;});
    });
    return g;
  }).sort(function(a,b) {
    const ai=order.indexOf(a.key),bi=order.indexOf(b.key);
    return (ai<0?order.length:ai)-(bi<0?order.length:bi)||a.key.localeCompare(b.key);
  });
}
if (typeof module !== 'undefined' && module.exports) module.exports={buildBenchmarkReports:buildBenchmarkReports};
