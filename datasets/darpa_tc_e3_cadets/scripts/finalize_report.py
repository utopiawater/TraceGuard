"""Render the retained single-topic audit snapshot after raw data cleanup."""
import collections,json
from common import ROOT,dump
report=ROOT/'dataset_analysis_report.json'
data=json.loads(report.read_text(encoding='utf-8'))
data['files']=[f for f in data['files'] if 'cadets/' in f['file']]
data['streams']=[s for s in data['streams'] if s['provider']=='cadets']
data['raw_event_archives_retained']=False
summary=json.loads((ROOT/'source_metadata/selection_manifest.json').read_text(encoding='utf-8'))
summary['raw_retention']='deleted: original event archives and full temporary SQLite index; source documents and selected evidence retained'
data['selection']=summary; dump(report,data); dump(ROOT/'source_metadata/selection_manifest.json',summary)
lines=['# DARPA TC E3 CADets 数据分析与筛选报告','','本报告是原始数据删除前的完整扫描快照。最终仅使用 CADets official-2；原始事件文件和完整中间数据库已删除。','', '## 原文件', '', '|文件|字节|SHA256|','|---|---:|---|']
for f in data['files']: lines.append(f"|{f['file']}|{f['bytes']}|{f['sha256']}|")
lines += ['', '## 压缩包成员与数据规模','','|成员|解压字节|记录数|解析错误|','|---|---:|---:|---:|']
for s in data['streams']: lines.append(f"|{s['file']}|{s['bytes']}|{s['records']}|{s['parse_errors']}|")
kinds=collections.Counter(); fields=collections.defaultdict(collections.Counter)
for s in data['streams']:
    kinds.update(s['record_types'])
    for k,v in s['fields'].items(): fields[k].update(v)
lines+=['','### CDM18 记录类型','','|类型|数量|','|---|---:|']+[f'|{k}|{v}|' for k,v in sorted(kinds.items())]
lines+=['','Event 为事件；Subject、Host、Principal、FileObject、NetFlowObject 等为实体。顶层 datum 以 CDM 类型名称包装；CDMVersion=18，source 标识 CADets。事件引用 UUID，需要关联实体解析。','','## 字段名称、类型、用途','','|字段路径|观察类型与次数|用途|','|---|---|---|']
for k,v in sorted(fields.items()):
    purpose='时间字段（纳秒）' if 'timestamp' in k.lower() else '主机字段' if 'host' in k.lower() else '事件或实体类型' if k=='type' else '身份与关系引用' if k in ('uuid','subject','parentSubject','predicateObject','predicateObject2','localPrincipal') else '保留上下文'
    lines.append(f'|{k}|{dict(v)}|{purpose}|')
lines+=['','## 最终筛选结果','',f"选定 Ground Truth 第 3.13 节（CADets 2018-04-12）。事件 {summary['events']} 条，其中指标命中 {summary['direct_ioc_events']} 条、上下文 {summary['context_events']} 条。另有 {summary['excluded_context_candidates']} 条上下文候选因规模限制未纳入。",'',f"时间窗口 UTC：{summary['windows_utc']}。最终数据 {summary['bytes']:,} 字节，低于 500,000,000 字节。",'','窗口内按 CDM UUID 关联进程和对象；全部指标命中事件保留。标签仅为 ioc_match/context，不是人工确认的恶意/正常标签。所选事件的完整解包原文在 evidence，相关实体在图节点 details。删除的是未入选原始数据及大型中间副本。','','质量检查详见 source_metadata/verification.json，筛选规则详见 README.md 和 source_metadata/selection_manifest.json。']
(ROOT/'dataset_analysis_report.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('Updated single-topic report:',dict(kinds))
