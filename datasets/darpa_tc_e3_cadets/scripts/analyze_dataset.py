"""Full streaming inventory; called independently or as part of preprocess."""
import argparse, collections, hashlib, json
from pathlib import Path
from common import *

def analyze(raw, report):
    result=[]
    for name,size,f in streams(raw):
        item=dict(file=name,bytes=size,provider=provider(name),records=0,parse_errors=0,fields={},record_types={},status='not_event_format')
        if supported(name):
            item['status']='scanned'; fields=collections.defaultdict(collections.Counter); kinds=collections.Counter()
            for pos,r,error in records(name,f):
                item['records']+=1
                if error: item['parse_errors']+=1; continue
                k,d=datum(r); kinds[k]+=1
                def visit(v,prefix=''):
                    if isinstance(v,dict):
                        for key,val in v.items():
                            key=prefix+key; fields[key][type(val).__name__]+=1
                            if isinstance(val,dict): visit(val,key+'.')
                visit(d)
            item['fields']=dict(fields); item['record_types']=dict(kinds)
        result.append(item)
    write_report(raw,report,result)
    return result

def write_report(raw,report,result):
    raw=Path(raw); inventory=[]
    for p in sorted(raw.rglob('*')):
        if p.is_file():
            h=hashlib.sha256()
            with p.open('rb') as f:
                while c:=f.read(8*1024*1024): h.update(c)
            inventory.append(dict(file=p.relative_to(raw).as_posix(),bytes=p.stat().st_size,sha256=h.hexdigest()))
    dump(Path(report).with_suffix('.json'),{'files':inventory,'streams':result})
    lines=['# DARPA TC E3 原始数据分析报告','', '统计范围仅包括本机 raw_dataset 中已下载文件；不代表 E3 全量。压缩包逐成员读取，不修改或解压覆盖原件。', '', '## 物理文件清单', '', '|文件|字节数|SHA256|','|---|---:|---|']
    lines += [f"|{i['file']}|{i['bytes']}|{i['sha256']}|" for i in inventory]
    for item in result:
        lines += ['', '## '+item['file'], '', f"来源：{item['provider']}；未压缩字节：{item['bytes']}；记录：{item['records']}；解析错误：{item['parse_errors']}；状态：{item['status']}", '', '记录类型：`'+json.dumps(item['record_types'])+'`','', '|字段路径|观察到的类型和次数|用途|','|---|---|---|']
        for k,v in sorted(item['fields'].items()):
            purpose='时间' if 'time' in k.lower() else '主机' if 'host' in k.lower() else '事件或实体类型' if k=='type' else '关联 ID' if k in ('uuid','subject','predicateObject','parentSubject') else '上下文'
            lines.append(f'|{k}|{dict(v)}|{purpose}|')
    lines += ['', '## 结构与清洗规则', '', 'CDM18 包装包含 datum、CDMVersion、source。Event 是事件；Subject、Host、Principal、FileObject、NetFlowObject 等是实体。先建立实体索引再解析事件，支持事件先于实体出现。纳秒时间使用整数运算；未知时区不猜测。', '', '所有 Event 保留；其他实体及未知记录保存在 SQLite records。无法解析记录进入 quarantine.json。severity 不由事件名称推断。网络时间关联不等于已确认攻击。详见 README.md。']
    Path(report).write_text('\n'.join(lines)+'\n',encoding='utf-8')

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--raw',type=Path,default=ROOT/'raw_dataset'); p.add_argument('--report',type=Path,default=ROOT/'dataset_analysis_report.md'); a=p.parse_args(); analyze(a.raw,a.report)
