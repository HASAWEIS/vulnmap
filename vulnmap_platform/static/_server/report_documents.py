"""Read-only, evidence-based benchmark reports and real PDF/Markdown downloads.

Structure inspired by BinSight's report outline / coverage / evidence index.
No target execution, model calls, shell commands, network calls or state writes.
"""
from __future__ import annotations
import hashlib, io, json, re
from collections import Counter
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from xml.sax.saxutils import escape

LABELS={'cybergym':'CyberGym','exploitgym':'ExploitGym','vulngym':'VulnGym'}
BLOCKERS={'human_review_pending':'人工复核待完成','official_receipt_not_attached':'必要官方回执未附',
 'severity_justification_not_reviewed':'严重性论证待复核','causal_chain_not_verified':'因果链门禁未通过',
 'severity_not_high':'未满足高危门禁','material_completeness_not_checked':'必需材料不完整',
 'task_unreachable':'目标缺陷路径不可达','defect_class_harness_ub_not_target':'疑似测试框架自身问题，不能计为目标高危'}

def text(value,limit=2000):
    if value is None or value=='': return '未记录'
    if isinstance(value,(dict,list)): value=json.dumps(value,ensure_ascii=False,sort_keys=True)
    value=re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]','',str(value))
    value=re.sub(r'flag\{[^}\r\n]*\}','[FLAG 已脱敏]',value,flags=re.I)
    value=re.sub(r'(?i)(bearer\s+)[A-Za-z0-9._~+/-]+',r'\1[已脱敏]',value)
    value=re.sub(r'\bsk-[A-Za-z0-9_-]{8,}\b','[密钥已脱敏]',value)
    return value[:limit]+('…（仅显示摘录）' if len(value)>limit else '')

def boolean(v): return '是（工件记录，未在本次重新验证）' if v is True else '否 / 未证实'
def table(headers,rows): return {'kind':'table','headers':headers,'rows':[[text(v) for v in row] for row in rows]}
def para(v):return {'kind':'paragraph','text':text(v,6000)}
def code(v):return {'kind':'code','text':text(v,3000)}
def heading(v):return {'kind':'heading','text':v}

def _build_evidence_document(root:Path,benchmark:str)->dict:
    if not re.fullmatch(r'[a-z0-9_-]{1,64}',benchmark):raise ValueError('invalid benchmark')
    root=Path(root).resolve();ws=root/'workspace';manifest={}
    def read(p):
        try:
            raw=p.read_bytes();manifest[str(p.relative_to(root))]=hashlib.sha256(raw).hexdigest()
            value=json.loads(raw);return value if isinstance(value,dict) else {}
        except (OSError,ValueError):return {}
    def raw_text(p,limit=4000):
        try:
            raw=p.read_bytes();manifest[str(p.relative_to(root))]=hashlib.sha256(raw).hexdigest()
            return text(raw.decode('utf-8',errors='replace'),limit)
        except OSError:return '未归档原始日志'
    ledger=read(root/'experiments/LEDGER.json')
    sample_dirs=[];seen=set()
    for row in ledger.get('rows',[]):
        parts=Path(str(row.get('source',''))).parts
        if len(parts)<2 or parts[0]!='workspace' or parts[1] in ('..','.') :continue
        d=(ws/parts[1]).resolve()
        if d.parent!=ws.resolve() or not d.is_dir() or d.name in seen:continue
        seen.add(d.name);t=read(d/'task.json');c=read(d/'artifacts/report/case.json')
        if str(t.get('benchmark') or c.get('benchmark') or 'unknown').lower()==benchmark:sample_dirs.append((d,t,c))
    if not sample_dirs:raise LookupError('benchmark not found in ledger')
    counts=Counter();samples=[];sections=[];all_blockers=Counter();verdicts=Counter();cwes=Counter()
    for idx,(d,t,c) in enumerate(sample_dirs,1):
        v=read(d/'artifacts/verify/result.json');loc=read(d/'artifacts/locate/findings.json');recon=read(d/'artifacts/recon/repo_map.json')
        exp=read(d/'artifacts/exploit/result.json');review=read(d/'review.json');receipt=read(d/'receipt.json');sev=read(d/'severity.json') or c.get('severity') or {}
        acc=c.get('acceptance') or {};mc=c.get('model_contribution') or {};sink=c.get('sink') or {};poc=c.get('poc') or v.get('poc') or {}
        claim=v.get('claim_used') or {};claim=claim if isinstance(claim,dict) else {}
        available=[x for x in (loc.get('claims') or loc.get('claims_llm') or []) if isinstance(x,dict)]
        matched=next((x for x in available if (claim.get('claim_id') and x.get('claim_id')==claim['claim_id']) or (claim.get('subject') and x.get('subject')==claim['subject'])),None)
        if matched:claim={**matched,**claim}
        elif not claim:claim=next(iter(available),{})
        if not sink:sink=claim.get('sink') or {}
        case_id=str(c.get('case_id') or t.get('case_id') or d.name);project=str(t.get('project') or c.get('project') or '未记录')
        name=f'{case_id} · {project}';anchor=f'sample-{idx:03d}'
        for field,key in [('local_verified','local'),('causal_chain_verified','causal'),('high_severity_confirmed','high'),('course_ready','ready')]:counts[key]+=bool(acc.get(field))
        counts['reports']+=bool(c);counts['model']+=bool(mc.get('verified_new_contribution'));counts['cases']+=1
        verdicts[str(c.get('verdict') or v.get('verdict') or '未记录')]+=1;cwes[str(c.get('cwe') or '未记录')]+=1
        blockers=list(dict.fromkeys(acc.get('course_ready_blocked_by') or c.get('blockers') or []));all_blockers.update(blockers)
        samples.append({'id':anchor,'title':name,'case_id':case_id,'dir':d.name,'task_id':t.get('task_id') or c.get('task_id'),
          'project':project,'cwe':c.get('cwe'),'verdict':c.get('verdict') or v.get('verdict'),'local':bool(acc.get('local_verified')),'ready':bool(acc.get('course_ready'))})
        blocks=[heading(f'2.{idx}.1 样例概览'),table(['字段','归档记录'],[
          ['案例 / 任务',case_id+' / '+str(t.get('task_id') or c.get('task_id') or '未记录')],['Benchmark',LABELS.get(benchmark,benchmark)],
          ['项目 / 版本',project+' / '+text(t.get('commit') or t.get('repo_commit') or t.get('version'))],['工作区证据目录',str(d)],
          ['CWE / 归档判定',text(c.get('cwe'))+' / '+text(c.get('verdict') or v.get('verdict'))],
          ['当前交付状态','可交付（归档字段）' if acc.get('course_ready') else '未达到项目交付门禁'],
          ['数据来源','task.json、case.json、findings.json、verify/result.json、已有原始日志；本次仅汇总，不重跑目标。']]),
          heading(f'2.{idx}.2 漏洞定位与根因分析'),table(['要素','证据'],[
          ['入口',claim.get('entry')],['缺陷点',sink],['缺陷函数',claim.get('subject')],['缺陷假设',claim.get('predicate')],
          ['结论来源',c.get('discovery')],['根因匹配',v.get('root_cause') or (c.get('stage_status') or {}).get('root_cause')]])]
        propagation=claim.get('propagation') or {}
        if propagation:blocks += [para('归档传播分析：'),table(['字段','已记录证据'],[[k,v] for k,v in (propagation.get('elements') or {}).items()]),para('传播分析来源：'+text(propagation.get('source'))+'；复核标记：'+text(propagation.get('verified_by')))]
        if claim.get('assumptions'):blocks += [para('分析前提：'+text(claim['assumptions']))]
        if claim.get('test_plan'):blocks += [para('归档验证设计：'+text(claim['test_plan']))]
        flow=claim.get('dataflow') or []
        if flow:blocks += [para('已归档传播链（按工件原顺序，未补造缺失跳转）：')]+[para(str(i+1)+'. '+text(x,1500)) for i,x in enumerate(flow)]
        else:blocks += [para('未归档可复核的完整传播链；不能仅凭函数名、行号或一次崩溃推断攻击路径闭合。')]
        # Source context is optional evidence; never infer file existence from a claim.
        source_file=sink.get('file');source_line=sink.get('line');source_root=(d/'src').resolve();source_path=None
        if source_file and isinstance(source_line,int) and source_line>0:
            p=(source_root/str(source_file)).resolve()
            if p.is_relative_to(source_root) and p.is_file():source_path=p
            if source_path:
                lines=raw_text(source_path,2_000_000).splitlines();start=max(0,source_line-5);snippet='\n'.join(str(i+1)+': '+lines[i] for i in range(start,min(len(lines),source_line+4)))
                blocks += [para('源码上下文：'+str(source_path.relative_to(d))+':'+str(source_line)),code(snippet)]
        if not source_path:blocks += [para('未在本工作区解析到对应源码上下文；上述定位属于归档记录，需结合固定版本源码人工复核。')]
        blocks += [heading(f'2.{idx}.3 挖掘与验证过程'),para('候选、模型轮次和退出状态来自已有执行工件。未触发不等于安全，环境失败不等于漏洞触发。')]
        candidates=v.get('candidates') or []
        if candidates:blocks += [table(['候选 / 提出者','关联假设','vul / fix','判定'],[[str(x.get('candidate') or x.get('name') or '未记录')+' / '+str(x.get('proposed_by') or '未记录'),x.get('claim_id') or x.get('subject'),str(x.get('vul_exit'))+' / '+str(x.get('fix_exit')),x.get('verdict')] for x in candidates])]
        else:blocks += [para('未归档候选逐次记录，不能将现有汇总判定还原为完整挖掘轨迹。')]
        rounds=(v.get('model_loop') or {}).get('rounds') or []
        if rounds:
            blocks += [table(['轮次','输入编码 / 大小','vul / fix','判定'],[[x.get('round'),str(x.get('encoding'))+' / '+str(x.get('size'))+' B',str(x.get('vul_exit'))+' / '+str(x.get('fix_exit')),x.get('verdict')] for x in rounds])]
            for x in rounds:blocks += [para('轮次 '+str(x.get('round'))+' 的生成理由：'+text(x.get('rationale'),1000)),para('执行反馈：'+text(x.get('feedback'),1200))]
        blocks += [table(['运行字段','归档结果'],[['脆弱版退出码',(v.get('vul') or {}).get('exit_code',c.get('vul_exit'))],['修复版退出码',(v.get('fix') or {}).get('exit_code',c.get('fix_exit'))],['环境异常',v.get('infra_error')],['判定原因',v.get('reason')]])]
        # Read only known logs within the case workspace. At most one per side.
        log_candidates=[]
        for side in ('vul','fix'):
            logrel=(v.get(side) or {}).get('log')
            if logrel:
                p=(d/str(logrel)).resolve()
                if p.is_relative_to(d) and p.is_file():log_candidates.append((side,p))
            if not any(k==side for k,_ in log_candidates):
                choices=sorted((d/'logs').glob('*'+side+'*.log')) if (d/'logs').is_dir() else []
                choices=[x for x in choices if x.resolve().is_relative_to(d)]
                if choices:log_candidates.append((side,choices[0]))
        for side,p in log_candidates:
            raw=raw_text(p,6000);lines=raw.splitlines();excerpt='\n'.join(lines[:4]+(['…（中间日志省略，详见原始文件）…'] if len(lines)>25 else [])+lines[-21:]) if len(lines)>25 else raw
            blocks += [para(side+' 侧原始日志摘录：'+str(p.relative_to(d))),code(excerpt)]
        if not log_candidates:blocks += [para('未解析到原始双端运行日志，退出码汇总不能代替原始观察证据。')]
        blocks += [heading(f'2.{idx}.4 PoC / EXP 与复现材料'),table(['工件字段','归档内容'],[
          ['PoC 路径',poc.get('path')],['PoC SHA-256',poc.get('sha256')],['PoC 大小（字节）',poc.get('size')],
          ['已有复现入口','案例工作区中的输入和原始日志；本次未执行输入、未生成新的 EXP。']])]
        if benchmark=='exploitgym':
            ev=acc.get('exploit_evidence') or {};blocks += [table(['利用证据项','工件记录'],[
              ['EXP 路径',(exp.get('exp') or {}).get('path')],['目标漏洞利用标记',boolean(exp.get('on_target'))],
              ['重放统计',exp.get('stability')],['官方证据标记',boolean(ev.get('issued'))],['flag 记录','有记录（内容已脱敏）' if exp.get('flag') or ev.get('flag') else '未记录'],['证据缺口',exp.get('blocked_on') or ev.get('reason')]]),para('EXP 执行、取得 flag、官方接受和目标漏洞因果是不同结论。此处仅展示历史字段，未经本次靶机重验，不能替代官方回执与人工复核。')]
        else:blocks += [para('本样例不属于 ExploitGym，未要求从 PoC 自动推导 RCE；不把跳过 Exploit 阶段表述为利用成功。')]
        blocks += [heading(f'2.{idx}.5 危害分析与验收状态'),table(['检查项','归档记录'],[
          ['高危标记',boolean(acc.get('high_severity_confirmed'))],['严重性状态',sev.get('state') or (c.get('severity') or {}).get('state')],
          ['CVSS 向量（历史论证）',sev.get('cvss_vector') or (c.get('severity') or {}).get('cvss_vector')],['缺陷类别',acc.get('defect_class')],
          ['因果链闭合',boolean(acc.get('causal_chain_verified'))],['人工复核标记',boolean(acc.get('human_reviewed'))],['官方回执标记',boolean(acc.get('official_receipt'))],
          ['复核记录文件','存在' if review else '未读取到有效 JSON'],['回执记录文件','存在（本次未校验真伪）' if receipt else '未读取到有效 JSON']])]
        dims=sev.get('dimensions') or (c.get('severity') or {}).get('dimensions') or {}
        if dims:blocks += [table(['危害维度','取值 / 影响','证据依据'],[[key,(value or {}).get('value'),(value or {}).get('evidence')] for key,value in dims.items() if isinstance(value,dict)])]
        blocks += [para('严重性为归档论证，不由 CWE、崩溃或内存读写类型自动推导。部署条件、实际可达性与影响仍需人工确认。'),
          heading(f'2.{idx}.6 Agent 贡献与模型记录'),table(['字段','已归档内容'],[
            ['模型身份', (c.get('agent') or {}).get('model') or (t.get('llm') or {}).get('model') or t.get('model')],
            ['提示词版本',(loc.get('llm') or {}).get('prompt_version') or (c.get('agent') or {}).get('prompt_version')],
            ['采样参数',(loc.get('llm') or {}).get('params')],['调用次数（记录）',mc.get('llm_calls')],
            ['定位贡献验证标记',boolean(mc.get('verified_pinpoint'))],['生成贡献验证标记',boolean(mc.get('verified_generation'))],
            ['新增贡献验证标记',boolean(mc.get('verified_new_contribution'))],['报告自述生成路径',c.get('generation_path')],
            ['模型失败或拒绝项',mc.get('llm_rejected') or mc.get('rejected_by_llm')]])]
        blocks += [heading(f'2.{idx}.7 分析限制、交付缺口与后续复核')]
        blocks += [para(BLOCKERS.get(b,b)+' ['+b+']') for b in blockers] if blockers else [para('当前记录未列出交付阻塞项；未记录不等于已经验证完成。')]
        for item in c.get('open_items') or []:blocks += [para('待补项：'+text(item))]
        blocks += [para('后续复核建议：核对固定版本源码、PoC 哈希、原始日志与根因对应关系；补齐真实人工复核及必要官方证据后再判断交付。不在本报告中补造模型参数、重放成功率或修复已验证的结论。')]
        sections.append({'id':anchor,'title':f'2.{idx} {name}','level':2,'sample':True,'blocks':blocks})
    name=LABELS.get(benchmark,benchmark)
    overview=[para('本报告按一个 Benchmark 汇总其台账样例。报告依据现有工件生成，不调用模型、不执行目标、不更改任何验收状态。'),
      table(['指标','该 Benchmark 的记录数'],[[k,counts[v]] for k,v in [('台账样例','cases'),('已有案例报告','reports'),('本地验证标记','local'),('因果链标记','causal'),('高危标记','high'),('可交付标记','ready'),('模型新增贡献标记','model')]]),
      para('口径边界：不同 Benchmark 分开统计，同根因跨轨案例不能在课程独立漏洞总量中重复计数；本地通过不等于官方接受，高危标记不等于已验收高危。'),
      heading('1.1 样例与验证结论分布'),table(['归档判定','数量'],sorted(verdicts.items())),
      heading('1.2 CWE 分布'),table(['CWE','数量'],sorted(cwes.items())),
      heading('1.3 主要交付缺口'),table(['已记录缺口','样例数'],[[BLOCKERS.get(k,k),v] for k,v in all_blockers.most_common()])]
    intro={'id':'overview','title':'1. 总览','level':1,'blocks':overview}
    sampleintro={'id':'samples','title':'2. 样例挖掘报告','level':1,'blocks':[para('每个样例按概览、根因、验证过程、PoC/EXP、危害、Agent 贡献与限制组织。缺失内容明确标记“未记录”，不从任务名称或汇总数字推断补齐。')]}
    end={'id':'evidence','title':'3. 证据来源与报告边界','level':1,'blocks':[para('参考 BinSight 的“概览 - 数据流 - 分析覆盖与限制 - 证据索引”组织方式；本报告仍使用 vulnmap 自身的工件与门禁，不宣称运行了 BinSight 的分析器。'),para('本页与 PDF、Markdown 共用同一份结构化报告。原始路径仅为本机复核线索；常见 flag、Bearer 和 sk- 密钥模式已过滤；对外分享前仍应人工检查日志与其他敏感字段。'),para('历史记录中的标签可能与最新实现的严格门禁不同。请复核源工件，不将报告渲染或导出成功当作漏洞验收。')]}
    document={'schema':'vulnmap.benchmark.report.v2','benchmark':benchmark,'label':name,'title':name+' 漏洞挖掘分析报告',
      'counts':dict(counts),'samples':samples,'sections':[intro,sampleintro]+sections+[end],
      'source_manifest':manifest,'method':'已有工件汇总；本次不重跑目标、不调用模型、不改变验收状态'}
    # Exclude the display timestamp so exports can bind to the exact viewed evidence.
    document['snapshot']=hashlib.sha256(json.dumps(document,ensure_ascii=False,sort_keys=True).encode()).hexdigest()
    document['generated_at']=datetime.now(ZoneInfo('Asia/Shanghai')).isoformat(timespec='seconds')
    return document

VERDICTS={'pass':'本地验证通过','withdrawn':'已撤回','not_triggered':'未触发目标缺陷','inconclusive':'证据不足，结论待定','generation_unsupported':'当前方法尚不能生成验证输入','generated_but_unverified':'已生成输入，尚未完成验证'}
DEFECTS={'stack-buffer-overflow':'栈缓冲区越界','heap-buffer-overflow':'堆缓冲区越界','heap-use-after-free':'释放后使用','stack-buffer-underflow':'栈缓冲区下溢','global-buffer-overflow':'全局缓冲区越界','undefined-behavior':'未定义行为'}
CWE_NAMES={'CWE-121':'栈缓冲区越界候选','CWE-122':'堆缓冲区越界候选','CWE-125':'越界读取候选','CWE-124':'缓冲区下溢候选','CWE-306':'关键功能缺少身份认证'}
REASONS={'no_constructor_for_format':'当前输入构造器不支持该文件格式。','model_loop_candidates_all_unverified':'生成的候选输入均未得到有效验证。','root_cause:no_sink_declared':'尚未明确缺陷点，无法完成根因对应核查。','no_defect_diagnosis':'运行结果没有给出可归属于目标缺陷的诊断。','first_user_frame_matches_sink':'诊断中的首个业务代码栈帧与记录的缺陷位置一致。','task_unreachable':'当前任务包无法到达预期目标路径。'}
FIELD_NAMES={'input_bytes':'输入来源','reaches_sink':'到达缺陷点的路径','missing_check':'缺少的检查','observed_oob':'观测到的异常','required_signature':'要求的函数签名','actual_definition':'实际函数定义','call_relationship':'调用关系','runtime_diagnosis':'运行时诊断','fix_contrast':'修复版对照'}

def _narrative_document(root,document):
    """Present evidence as Chinese findings, not a projection of JSON fields.

    BinSight report-writer/finding_template.md informs the presentation shape only.
    Deterministic local composition: no model request and no changed verdicts.
    """
    root=Path(root).resolve();result=[];samples=[]
    def read(p):
        try:
            raw=p.read_bytes();value=json.loads(raw)
            document['source_manifest'][str(p.relative_to(root))]=hashlib.sha256(raw).hexdigest()
            return value if isinstance(value,dict) else {}
        except (OSError,ValueError):return {}
    for index,(sample,old_section) in enumerate(zip(document['samples'],[s for s in document['sections'] if s.get('sample')]),1):
        d=root/'workspace'/sample['dir'];c=read(d/'artifacts/report/case.json');t=read(d/'task.json');v=read(d/'artifacts/verify/result.json');loc=read(d/'artifacts/locate/findings.json');severity=read(d/'severity.json') or c.get('severity') or {};exp=read(d/'artifacts/exploit/result.json') or c.get('exploit') or {}
        acc=c.get('acceptance') or {};stage=c.get('stage_status') or {};mc=c.get('model_contribution') or {}
        chosen=v.get('claim_used') or {};claims=[x for x in (loc.get('claims') or []) if isinstance(x,dict)]
        identifier=chosen.get('claim_id') or chosen.get('id')
        matches=[x for x in claims if (identifier and (x.get('claim_id') or x.get('id'))==identifier) or (chosen.get('subject') and x.get('subject')==chosen.get('subject'))]
        claim={**(matches[0] if matches else (claims[0] if not chosen and claims else {})),**chosen}
        sink=c.get('sink') or claim.get('sink') or {};cause=v.get('root_cause') or stage.get('root_cause') or {};diag=(cause.get('evidence') or {}).get('diagnosis') or {}
        prop=claim.get('propagation') or stage.get('propagation') or {};elements={k:(val.get('value') if isinstance(val,dict) else val) for k,val in (prop.get('elements') or {}).items()}
        verdict=c.get('verdict') or v.get('verdict') or 'unrecorded';status=VERDICTS.get(verdict,'尚无完整验证结论');harness=acc.get('defect_class')=='harness_ub_not_target' or 'defect_class_harness_ub_not_target' in (acc.get('course_ready_blocked_by') or [])
        project=str(t.get('project') or severity.get('project') or sample['project'] or '项目名称未记录')
        if project.startswith('/'):project='项目名称未记录'
        project=project.split(' (')[0]
        def prose(value,limit=2000):
            if value is None or value=='':return ''
            if isinstance(value,list):return '；'.join(prose(x,limit) for x in value if x is not None)
            if isinstance(value,dict):return '；'.join(FIELD_NAMES.get(str(k),str(k))+'：'+prose(x,limit) for k,x in value.items() if x is not None)
            value=text(value,limit).replace(str(d)+'/','').replace('workspace/'+d.name+'/','')
            for token,label in DEFECTS.items():value=value.replace(token,label)
            return value
        def location(value):
            if not isinstance(value,dict):return prose(value)
            file=prose(value.get('file'));line=value.get('line');symbol=value.get('function') or value.get('symbol')
            return ('`'+file+((':'+str(line)) if line else '')+'`' if file else '')+(('（`'+str(symbol)+'`）') if symbol else '')
        kind=diag.get('kind') or elements.get('observed_oob') or ''
        observed=next((label for token,label in DEFECTS.items() if token in str(kind)),None)
        if not observed:
            observed=next((label for token,label in DEFECTS.items() if token in str((v.get('evidence') or {}).get('vul_asan') or '')),None)
        issue=observed or CWE_NAMES.get(str(c.get('cwe')),'验证结果待复核')
        if observed and diag.get('write') is True:issue+='写入'
        if harness:title=project+'：测试框架异常，不能计为目标漏洞'
        elif verdict=='withdrawn':title=project+'：已撤回的验证任务'
        elif verdict!='pass':title=project+'：'+status
        else:title=project+'：'+issue
        local=acc.get('local_verified') is True;causal=acc.get('causal_chain_verified') is True
        summary=[]
        if verdict=='withdrawn':summary.append('该任务已撤回，不应作为成功挖掘或利用案例。'+prose(c.get('detail') or REASONS.get(c.get('reason'),c.get('reason'))))
        elif harness:summary.append('记录中的运行异常涉及测试框架自身的调用或类型问题。即使脆弱版与修复版表现不同，也不能据此认定目标程序存在可计入考核的漏洞。')
        elif verdict=='pass':
            summary.append('现有记录显示，'+project+' 在处理归档的测试输入时出现了'+(observed or '异常行为')+'。'+('异常定位在 `'+str(claim.get('subject') or sink.get('symbol'))+'`。' if claim.get('subject') or sink.get('symbol') else ''))
            summary.append('该样例已有本地验证记录'+('，且验收字段记录了因果链闭合。' if causal else '，但尚不能仅凭本地通过认定攻击路径和根因证据已经闭合。'))
        else:summary.append('本样例目前的结论是“'+status+'”，不是已确认漏洞。'+REASONS.get(v.get('reason'),prose(v.get('reason')) or '现有材料不足以形成完整结论。'))
        blocks=[heading(f'2.{index}.1 结论概述'),{'kind':'callout','tone':'success' if local and causal and not harness else 'warning','text':' '.join(summary)},table(['样例','当前结论','分类 / 危害等级'],[[sample['case_id'],status,str(c.get('cwe') or '分类待定')+' / '+{'high':'高危（已有论证）','medium':'中危（已有论证）','low':'低危（已有论证）'}.get(severity.get('severity'),'尚未完成等级论证')]]),heading(f'2.{index}.2 漏洞触发链路与证据')]
        subject=claim.get('subject') or sink.get('function') or sink.get('symbol')
        # An evidence-bound explanation for the supplied example, not a copied JSON value.
        # Fall back to recorded facts if the precise BaseFont/copy chain is absent.
        basefont_chain=(sink.get('symbol')=='memcpy' and 'BaseFont' in str(elements.get('input_bytes')) and 'cidname->length' in str(elements.get('reaches_sink')) and bool(elements.get('missing_check')))
        if basefont_chain:
            blocks.append(para('Ghostscript 解析 PDF 的 BaseFont 字体名称时，会把名称复制到栈上的文件名缓冲区。名称内容和长度来自输入文件，而这条分支在复制前没有检查名称是否装得下；因此，过长的名称会使复制操作越过缓冲区边界。'))
            blocks.append(para('具体来说，函数 `pdfi_open_CIDFont_substitute_file` 先通过 `pdfi_dict_get` 取出 BaseFont 名称，再使用 `cidname->length` 作为 `memcpy` 的复制长度。目标位置是 `fontfname + fsprefixlen`，但代码没有先扣除前缀占用和结尾空字符所需空间。对应的越界写位置是 '+location(sink)+'。'))
        elif elements.get('input_bytes'):blocks.append(para('输入与可控内容：'+prose(elements['input_bytes'])+'。'))
        if elements.get('reaches_sink') and not basefont_chain:blocks.append(para('输入到达缺陷点的过程：'+prose(elements['reaches_sink']).replace(' -> ','，随后 ').replace(' ->','，随后 ')+'。'))
        elif subject and not basefont_chain:blocks.append(para('当前定位指向函数 `'+str(subject)+'`'+('，位置为 '+location(sink) if sink else '')+'。这只确定了分析位置；未记录的输入传播环节不能由函数名补齐。'))
        elif not basefont_chain:blocks.append(para('尚无足够材料解释输入如何到达缺陷点，因此这里不编造调用链或触发条件。'))
        if elements.get('missing_check'):blocks.append(para('问题出在：'+prose(elements['missing_check'])+'。这使输入约束与实际操作之间缺少必要的安全边界。'))
        for k in ('required_signature','actual_definition','call_relationship','runtime_diagnosis','fix_contrast'):
            if elements.get(k):blocks.append(para(FIELD_NAMES[k]+'：'+prose(elements[k])+'。'))
        if not elements.get('missing_check'):
            detail=claim.get('description') or claim.get('note')
            if detail:blocks.append(para('定位记录说明：'+prose(detail)))
            blocks.append(para('现有定位记录未充分说明缺失了哪一项检查或约束；需要补齐源码级解释，不能仅将崩溃点视为完整根因。'))
        if claim.get('assumptions'):blocks.append(para('上述分析依赖的前提：'+prose(claim['assumptions'])+'。'))
        for old in old_section['blocks']:
            if old['kind']=='paragraph' and old['text'].startswith('源码上下文：'):
                j=old_section['blocks'].index(old)
                if j+1<len(old_section['blocks']) and old_section['blocks'][j+1]['kind']=='code':
                    blocks.extend([para('对应源码片段（'+prose(old['text'].removeprefix('源码上下文：'))+'）：'),old_section['blocks'][j+1]])
                break
        if cause.get('matched') is True:blocks.append(para('根因核查：'+REASONS.get(cause.get('reason'),prose(cause.get('reason')) or '归档记录标记为匹配。')+' 这支持异常与该代码位置相关，但不等于已经证明远程可利用。'))
        elif verdict=='pass':blocks.append(para('根因核查尚缺少可确认的对应关系，本地运行差异不能替代这一项证据。'))
        blocks.append(heading(f'2.{index}.3 验证结果与可信边界'))
        vul=v.get('vul') or {};fix=v.get('fix') or {};ve=vul.get('exit_code',c.get('vul_exit'));fe=fix.get('exit_code',c.get('fix_exit'));evidence=v.get('evidence') or {}
        if ve is not None or fe is not None:
            error=('AddressSanitizer 检测到'+observed+('写入异常' if diag.get('write') is True else '')+'；位置与归档缺陷点对应' if observed and cause.get('matched') is True else 'AddressSanitizer 检测到'+observed+'；具体归属仍需核对' if observed else '运行记录中有诊断信息，具体归属仍需核对') if evidence.get('vul_asan') else ''
            blocks.append(table(['对照对象','已记录的观察','退出码'],[['脆弱版本',error or ('出现异常；具体诊断需查原始日志' if ve not in (None,0) else '未记录目标缺陷诊断'),ve if ve is not None else '未记录'],['修复版本','记录未出现同类诊断' if evidence.get('fix_clean') is True else '仅有退出状态，不能推断已修复',fe if fe is not None else '未记录']]))
            blocks.append(para('这是已有工件记载的对照结果，不是本次重新运行。退出码不同本身并不证明修复有效，还应确认两边使用同一输入、环境可比，并且诊断确实属于目标缺陷。'))
        else:blocks.append(para('未读取到完整的脆弱版与修复版对照记录。没有运行材料的部分不写成已验证。'))
        if v.get('infra_error'):blocks.append(para('记录中存在运行环境异常，必须先排除环境问题，再判断是否触发漏洞。'))
        if document['benchmark']=='exploitgym':
            socket=exp.get('official_socket') or (c.get('exploit') or {}).get('official_socket')
            if socket:blocks.append(para('利用验证记录另记载：通过任务 socket 的历史成功次数为 '+prose(socket)+'。这里仅引用该历史实验记录；完整日志仍需复核，不能替代正式回执与验收。'))
            else:blocks.append(para('现有材料未给出可核对的端到端利用成功次数，不把生成 EXP 或存在利用策略当作利用成功。'))
        blocks.append(heading(f'2.{index}.4 影响与适用条件'))
        dims=severity.get('dimensions') or (c.get('severity') or {}).get('dimensions') or {};rationale=severity.get('rationale') or (c.get('severity') or {}).get('rationale')
        impact=(dims.get('observed_impact') or {}).get('evidence') if isinstance(dims.get('observed_impact'),dict) else ''
        if impact:blocks.append(para('已有影响证据：'+prose(impact,2000)))
        if rationale:blocks.append(para('已有危害论证：'+prose(rationale,2600)))
        else:blocks.append(para('当前材料尚未形成充分的逐例危害论证。不能仅凭 CWE 编号、一次崩溃或本地验证通过，自动给出高危或远程代码执行结论。'))
        for field,label in [('attack_vector','输入如何接触目标'),('user_interaction','用户交互条件'),('deployment_conditions','部署条件与限制')]:
            dim=dims.get(field) or {}
            if isinstance(dim,dict) and dim.get('evidence'):blocks.append(para(label+'：'+prose(dim['evidence'],900)))
        if severity.get('cwe') and severity['cwe']!=c.get('cwe'):blocks.append(para('分类记录存在差异：案例标注 '+str(c.get('cwe'))+'，危害论证标注 '+str(severity['cwe'])+'。应回到缺陷机理核对，不能在报告中静默合并。'))
        blocks.append(para('影响边界：上面的危害论证是已有材料中的分析，不等于已实际控制执行流、完成远程利用或通过课程验收。未观测到的影响不在本报告中升级认定。'))
        blocks.append(heading(f'2.{index}.5 修复建议'))
        symbol=str(sink.get('symbol') or '')
        if verdict=='withdrawn':remedy='先修正任务包和目标路径的可达性，再恢复对目标缺陷的分析；不要围绕不可达目标继续报告利用成果。'
        elif harness:remedy='先核对测试入口的声明、定义和调用处是否使用一致的函数类型，排除测试框架自身的未定义行为；重新运行后再判断目标缺陷。'
        elif c.get('cwe')=='CWE-306':remedy='在执行敏感操作之前验证请求身份与权限；对缺失或无效凭据的请求明确拒绝，并验证被拒绝后服务仍保持运行。该建议不代表当前平台已应用此修复。'
        elif any(x in issue for x in ['缓冲区','越界']):
            remedy='在 '+('`'+str(subject)+'` 的相关路径' if subject else '已定位的输入处理路径')+' 中，在复制、写入或读取前校验实际长度与缓冲区剩余容量；涉及偏移、终止符或多步写入时，应把这些开销计入边界，并先检查加法、乘法是否溢出。'
            if basefont_chain:remedy='在复制 BaseFont 名称前，统一校验前缀长度、名称长度和结尾空字符的总空间需求，确保不会超过 `fontfname` 的容量；检查长度相加是否溢出，并对过长名称明确拒绝处理。不能只改用另一种复制函数而保留不可信的长度参数。'
            if symbol=='sprintf':remedy+=' 将无容量限制的格式化写入改为显式传入目标容量的写入方式，并检查截断与错误返回值。'
            if symbol in ('memcpy','memmove','strcpy') and not basefont_chain:remedy+=' 不能仅替换函数名；应在调用 `'+symbol+'` 前证明本次操作长度不超过目标剩余空间。'
        elif '释放后使用' in issue:remedy='明确对象的所有权与生命周期，保证最后一次使用之后才释放，避免释放后的指针继续被访问；为相关错误路径补充生命周期回归测试。'
        else:remedy='先补齐可控输入、传播路径和缺失检查的证据，再据此确定修复位置；在根因未明时不建议仅围绕崩溃点添加临时判断。'
        blocks.extend([para(remedy),para('回归验证建议：固定版本、环境和同一份输入，比较修复前后的行为，并补充边界内、恰好到边界、超出边界及异常输入测试。这里是修复与验证建议，未声称已实施或验证补丁。')])
        blocks.append(heading(f'2.{index}.6 分析来源与贡献'))
        discovery=c.get('discovery') or {};origin=discovery.get('discovery_source')
        if origin=='rule' or (claim.get('proposed_by') in ('rule','builder')):blocks.append(para('当前关键定位或输入构造由规则路径、已有构造器产生；不能把这些既有结果表述为模型独立发现。'))
        elif origin=='none':blocks.append(para('没有可归属的有效发现记录。'))
        else:blocks.append(para('分析来源需要结合原始记录核对；模型参与过某一步，不等于模型提出了关键漏洞结论。'))
        if mc.get('verified_new_contribution') is True:blocks.append(para('当前记录标记存在已验证的模型新增贡献；具体贡献范围与对应验证仍以证据附录为准，不扩大到整个样例。'))
        else:blocks.append(para('现有贡献字段尚未确认模型的新增贡献。报告中不把生成文字或调用模型本身记为漏洞发现成果。'))
        blocks.append(heading(f'2.{index}.7 交付状态与下一步'))
        blockers=acc.get('course_ready_blocked_by') or c.get('blockers') or []
        gaps='；'.join(BLOCKERS.get(x,x) for x in blockers)
        blocks.append(para(('该样例已有可交付标记。' if acc.get('course_ready') else '该样例目前不可按已验收成果交付。')+('主要缺口：'+gaps+'。' if gaps else '应补充核对完整材料和人工验收记录。')))
        if c.get('open_items'):blocks.append(para('需补齐的材料：'+prose(c['open_items'])))
        blocks.append({'kind':'appendix','title':'技术证据附录 · 原始字段、运行日志与工件哈希','blocks':old_section['blocks']})
        sample={**sample,'title':title,'project':project,'status_label':status,'display_id':f'2.{index}'};samples.append(sample)
        result.append({**old_section,'title':f'2.{index} {title}','blocks':blocks})
    overview=document['sections'][0];counts=document['counts'];name=document['label']
    overview['blocks']=[{'kind':'callout','tone':'info','text':f'本报告包含 {name} 的 {counts["cases"]} 个台账样例。其中 {counts["local"]} 个已有本地验证记录，{counts["causal"]} 个记录了因果链闭合，{counts["ready"]} 个具有可交付标记。各项是独立条件，不能把“本地通过”理解为“已验收”。'},para('阅读方式：先看每个样例的结论，再阅读输入如何到达缺陷、验证实际观察到了什么，以及影响和修复建议。原始字段、完整哈希和日志摘录收进样例末尾的证据附录，默认折叠。'),*overview['blocks'][2:]]
    # Translate machine verdicts in the overview, too.
    for b in overview['blocks']:
        if b['kind']=='table' and b.get('headers',[''])[0]=='归档判定':
            b['headers'][0]='验证结论'
            for row in b['rows']:row[0]=VERDICTS.get(row[0],row[0])
    intro={**document['sections'][1],'blocks':[para('以下按实际验证状态逐例分析。漏洞概述、触发链路、对照验证、影响和修复建议面向阅读；证据附录面向核查。失败、待定和撤回样例保留原状态，不包装成成功漏洞。')]}
    end=document['sections'][-1]
    end['blocks']=[para('报告组织参考本机 BinSight 的 report-writer 与 finding_template.md：中文结论、连贯的触发链路、影响和修复建议。这里只复用写作组织方式，没有调用 BinSight 或模型，也没有重新运行目标。'),para('本文由现有证据确定性编排而成。正文与技术附录分层，但不改变验证、严重性或验收字段。PDF 将技术证据集中在文末，Markdown 与页面按样例保留折叠附录。'),para('原始路径用于本机核查。常见 flag 和令牌模式已过滤，对外分享前仍需检查敏感信息。')]
    document.update(schema='vulnmap.benchmark.report.v3',samples=samples,sections=[overview,intro]+result+[end])
    document.pop('snapshot',None);stamp=document.pop('generated_at',None)
    document['snapshot']=hashlib.sha256(json.dumps(document,ensure_ascii=False,sort_keys=True).encode()).hexdigest()
    document['generated_at']=stamp
    return document

def build_document(root:Path,benchmark:str)->dict:
    return _narrative_document(root,_build_evidence_document(root,benchmark))


def markdown(document):
    def cell(v):return text(v,6000).replace('|','\\|').replace('\n','<br>')
    def blocks(items):
        lines=[]
        for b in items:
            if b['kind']=='heading':lines+=['','### '+b['text'],'']
            elif b['kind'] in ('paragraph','callout'):lines += [b['text'],'']
            elif b['kind']=='appendix':lines += ['','<details>','<summary>'+b['title']+'</summary>','']+blocks(b['blocks'])+['','</details>','']
            elif b['kind']=='code':
                fence='`'*max(3,max((len(x) for x in re.findall(r'`+',b['text'])),default=0)+1)
                lines += [fence+'text',b['text'],fence,'']
            elif b['kind']=='table':
                lines += ['| '+' | '.join(cell(x) for x in b['headers'])+' |','| '+' | '.join('---' for _ in b['headers'])+' |']
                lines += ['| '+' | '.join(cell(x) for x in row)+' |' for row in b['rows']];lines.append('')
        return lines
    lines=['# '+document['title'],'','- 生成时间：'+document['generated_at'],'- 证据快照：'+document['snapshot'],'- '+document['method'],'','## 目录','']
    for s in document['sections']:lines.append('- '+s['title'])
    for s in document['sections']:lines+=['','## '+s['title'],'']+blocks(s['blocks'])
    return '\n'.join(lines)+'\n'

def pdf(document):
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    if 'STSong-Light' not in pdfmetrics.getRegisteredFontNames():pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'))
    navy=colors.HexColor('#1B355A');muted=colors.HexColor('#64768C');line=colors.HexColor('#DCE4EF')
    base=ParagraphStyle('body',fontName='STSong-Light',fontSize=9.2,leading=15,wordWrap='CJK',spaceAfter=7,textColor=navy)
    h1=ParagraphStyle('title',parent=base,fontSize=24,leading=32,spaceAfter=20)
    h2=ParagraphStyle('section',parent=base,fontSize=16,leading=23,spaceBefore=15,spaceAfter=12,keepWithNext=True)
    h3=ParagraphStyle('sub',parent=base,fontSize=11,leading=18,spaceBefore=12,spaceAfter=8,keepWithNext=True)
    tiny=ParagraphStyle('tiny',parent=base,fontSize=8,leading=12,textColor=muted)
    code_style=ParagraphStyle('code',parent=base,fontSize=8,leading=12,backColor=colors.HexColor('#F4F7FB'),borderPadding=7)
    stream=io.BytesIO();doc=SimpleDocTemplate(stream,pagesize=A4,rightMargin=42,leftMargin=42,topMargin=49,bottomMargin=45,title=document['title'],author='vulnmap')
    width=A4[0]-84;story=[]
    def p(value,style=base):return Paragraph(re.sub(r'`([^`]+)`',r'\1',escape(text(value,12000).replace('·',' / '))).replace('\n','<br/>'),style)
    story += [p('VULNMAP  /  BENCHMARK RESEARCH REPORT',tiny),Spacer(1,17),p(document['title'],h1),p('生成时间：'+document['generated_at'],tiny),p('证据快照：'+document['snapshot'],tiny),p(document['method'],tiny),Spacer(1,18),p('报告目录',h2)]
    for s in document['sections']:story.append(p(s['title'],tiny))
    main_sections=[];appendices=[]
    for section in document['sections']:
        main_sections.append({**section,'blocks':[b for b in section['blocks'] if b['kind']!='appendix']})
        for b in section['blocks']:
            if b['kind']=='appendix':appendices.append({'title':'证据附录 / '+section['title'],'sample':True,'blocks':b['blocks']})
    for s in main_sections+appendices:
        if s.get('sample'):story.append(PageBreak())
        story.append(p(s['title'],h2))
        for b in s['blocks']:
            kind=b['kind']
            if kind=='heading':story.append(p(b['text'],h3))
            elif kind in ('paragraph','callout'):story.append(p(b['text']))
            elif kind=='code':story.append(p(b['text'],code_style));story.append(Spacer(1,5))
            elif kind=='table':
                n=len(b['headers']);ratios=([.27,.73] if n==2 else [.22,.36,.42] if n==3 else [.30,.30,.18,.22] if n==4 else [1/n]*n)
                rows=[[p(x,tiny) for x in b['headers']]]+[[p(x,tiny) for x in row] for row in b['rows']]
                if len(rows)==1:rows.append([p('暂无记录',tiny)]+[p('',tiny) for _ in range(n-1)])
                t=Table(rows,colWidths=[width*r for r in ratios],repeatRows=1,hAlign='LEFT')
                t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#EDF2FA')),('GRID',(0,0),(-1,-1),.4,line),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]))
                story.extend([t,Spacer(1,10)])
    def page(canvas,doc):
        canvas.saveState();canvas.setStrokeColor(line);canvas.line(42,A4[1]-30,A4[0]-42,A4[1]-30);canvas.setFont('STSong-Light',8);canvas.setFillColor(muted)
        canvas.drawString(42,A4[1]-22,'VULNMAP / '+document['label']);canvas.drawRightString(A4[0]-42,25,str(doc.page));canvas.drawString(42,25,'归档证据汇总，不代表新增验证或课程验收');canvas.restoreState()
    doc.build(story,onFirstPage=page,onLaterPages=page)
    return stream.getvalue()

def register_routes(app,root):
    from fastapi import HTTPException
    from fastapi.responses import Response
    def load(benchmark):
        try:return build_document(root,benchmark.lower())
        except ValueError:raise HTTPException(400,'invalid benchmark')
        except LookupError:raise HTTPException(404,'benchmark not found')
    @app.get('/api/benchmark-reports/{benchmark}')
    def benchmark_document(benchmark:str):return load(benchmark)
    @app.get('/api/benchmark-reports/{benchmark}/export')
    def benchmark_export(benchmark:str,format:str='md',snapshot:str=''):
        if format not in ('md','pdf'):raise HTTPException(400,'format must be md or pdf')
        document=load(benchmark)
        if snapshot and snapshot!=document['snapshot']:raise HTTPException(409,'证据已更新，请刷新报告后重新导出')
        filename='vulnmap-'+document['benchmark']+'-report.'+format
        try:
            payload=markdown(document).encode('utf-8') if format=='md' else pdf(document)
        except ImportError:raise HTTPException(503,'PDF 依赖未安装，请安装 reportlab 或先导出 Markdown')
        return Response(payload,media_type='text/markdown; charset=utf-8' if format=='md' else 'application/pdf',headers={'Content-Disposition':'attachment; filename="'+filename+'"','Cache-Control':'no-store','X-Report-Snapshot':document['snapshot']})
