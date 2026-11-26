"""Native editable overview diagrams; current Discovery source, not legacy reproduction pipeline."""
from pathlib import Path
OUT=Path(__file__).resolve().parent
legacy=(OUT/'draw_diagrams.py').read_text().split("s=SVG('系统总体架构'")[0]
exec(legacy)
s=SVG('系统总体架构','Discovery 当前实现：集中式编排 + 并行 LLM 分析 + 覆盖率 Fuzz + 证据门禁',1)
s.a=[x.replace('规则 / 构造器基线 + 模型辅助循环；图示描述实现结构与目标闭环，不代表全部案例已验收','当前发现入口为 CLI；历史 Web 展示单独保留，不表示 Discovery 已完整接入前端。') for x in s.a]
s.rect(40,183,286,819,'white',B,dash=True);s.text(183,225,'发现主链路',28,B,True,'middle')
steps=[('目标与构建描述','源码 / 二进制 / target.yaml'),('D0 / D1 静态分析','画像 / 调用点 / 排序'),('D1.5 分析 Agent','默认 LLM / 并行任务'),('D2 种子与 Fuzz','假设驱动规则种子'),('D3 / D3.5 验证复核','干净重建 / 重放 / 门禁'),('D4 / D5 报告与评估','证据归档 / 对照实验')]
for i,(title,sub) in enumerate(steps):
 y=254+i*119;s.box(63,y,240,88,title,sub,size=24)
 if i<5:s.line(183,y+88,183,y+115,arrow=True)
x=358;w=1522;s.rect(x,183,w,58,B,B);s.text(x+w/2,223,'VULNMAP · Discovery 分层架构',30,'white',True,'middle')
layers=[('入口与配置层',[('CLI 发现入口','bin/discover.py / covfuzz.py'),('目标接入','targetspec.py / target.yaml'),('模型配置','环境变量 / 兼容 API'),('历史 Web 展示','FastAPI / HTML / JS')]),('集中式编排层',[('Campaign 顺序编排','D0 → D5 / 记录失败'),('调用点选择','ranked / random'),('并行分析任务池','ThreadPoolExecutor'),('执行预算与参数','时长 / workers / 超时')]),('Agent 与分析层',[('静态画像与台账','profile.py / callsites.py'),('默认 LLM 分析','假设 / 置信度 / 引用'),('假设驱动种子','propose_seeds / 格式模板'),('可选 LLM 复核','默认规则 / 证据限制上限')]),('Fuzz 与验证层',[('自建最小 harness','main / API / 自定义入口'),('覆盖率引导 Fuzz','ASAN / trace-pc / 比较反馈'),('干净重建与重放','triage.py / 同输入 3 次'),('目标执行隔离','bwrap 优先 / unshare 回退')]),('数据、报告与评估层',[('结构化归档','JSON / 内存 dict 与 list'),('原始证据文件','输入 / 日志 / 哈希 / 构建'),('报告与 SQLite','report.json / MD / 台账'),('对照与负结果','排序对照 / 种子 A/B')])]
for i,(title,items) in enumerate(layers):
 y=257+i*148;s.rect(x,y,w,134,'white',B);s.text(x+22,y+32,title,25,B,True)
 for j,(title,sub) in enumerate(items):s.box(x+20+j*373,y+48,360,71,title,sub,PALE if i==3 else LIGHT,size=23)
 if i<4:s.line(1119,y+134,1119,y+147,arrow=True)
s.save('01_平台架构图')
s=SVG('核心技术路线','模型提出假设，规则构造种子，Fuzz 与重放提供证据；不是模型直接判定漏洞',2)
s.a=[x.replace('规则 / 构造器基线 + 模型辅助循环；图示描述实现结构与目标闭环，不代表全部案例已验收','已接通：假设 → 规则种子；尚需证明：LLM 相对基线的增益。流程完成不等于高危成立。') for x in s.a]
cols=[('01','目标画像','D0 / D1：从源码出发',[('固定输入边界',['源码 / 二进制 / 构建描述','不输入官方 PoC 或补丁']),('静态画像与调用点',['入口 / 格式 / 危险函数','近似可达性 / 参数线索']),('选点与台账',['固定评分排序 / 随机对照','记录计划与未覆盖调用点'])],'target.json / callsites.json'),('02','Agent 分析','D1.5：默认 LLM',[('并行只读分析',['调用点元数据 + 源码窗口','不执行目标 / 不给 verdict']),('结构化假设',['hypothesis / confidence','citations / LLM 使用记录']),('故障回退可见',['无 Key / 无效响应 / 超时','转规则分析并记录状态'])],'hypotheses.json'),('03','种子与 Fuzz','D2：假设指导测试',[('假设驱动规则种子',['关键词 / 数值 / 字符串线索','JSON / PNG / TIFF 模板']),('构建与并行变异',['自建 API harness / ASAN','trace-pc / trace-cmp / 字典']),('覆盖反馈与执行隔离',['新覆盖入语料 / 记录崩溃','bwrap / unshare / 资源限制'])],'corpus/ · crashes/ · stats/'),('04','分诊与复核','D3 / D3.5：证据约束',[('诊断解析与去重',['类型 / 读写 / 根因栈帧','栈签名归并候选崩溃']),('干净重建与重放',['同输入重放 3 次','无有效诊断不得升级确认']),('规则 / 可选 LLM 复核',['四类结论 + 理由','模型结论不得超过规则上限'])],'triage.json / reviews.json'),('05','报告与评估','D4 / D5：结果可审计',[('报告与证据落盘',['完整性 / 覆盖 / 发现条目','JSON + Markdown + SQLite']),('效果对照',['ranked vs random','假设驱动种子 vs 基础种子']),('诚实表达能力边界',['受控 fixture 与真实目标分开','保留 0 崩溃 / 不夸大高危'])],'report.json / MD / 对照结果')]
for i,(num,title,sub,items,files) in enumerate(cols):
 x=40+i*374;s.rect(x,190,344,112,B if i%2==0 else MID,stroke='none');s.text(x+22,226,num,21,'#C6D8F5',True);s.text(x+172,248,title,32,'white',True,'middle');s.text(x+172,281,sub,20,'white',False,'middle');s.rect(x,320,344,552,'white',MID)
 for k,(head,lines) in enumerate(items):
  y=343+k*169;s.rect(x+18,y,308,142,LIGHT if k!=1 else 'white',LINE);s.text(x+34,y+37,head,24,B,True)
  for z,t in enumerate(lines):s.text(x+34,y+77+z*31,t,19,INK)
  if k<2:s.line(x+172,y+142,x+172,y+163,arrow=True)
 s.box(x,893,344,101,'阶段产物',files,PALE,size=22)
 if i<4:s.line(x+346,595,x+372,595,arrow=True,w=3)
s.save('02_技术路线图')
print('OVERVIEW_UPDATED: architecture + roadmap; SVG + PNG')
