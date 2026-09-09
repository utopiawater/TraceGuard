import argparse, json, os, shutil
from pathlib import Path
from common import *

def alias(source,target):
    target=Path(target); target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists(): target.unlink()
    try: os.link(source,target)
    except OSError: shutil.copyfile(source,target)

def generate(out):
    if (out/'process_events.json').exists():
        events=[]
        for name in ('process_events.json','network_events.json','file_events.json'):
            events.extend(json.loads((out/name).read_text(encoding='utf-8')))
        events.sort(key=lambda e:(e['timestamp_ns'],e['event_id']))
        array(out/'attack_timeline.json',(dict(time=e['timestamp'],host=e['host'],event=e['event_type'],description=' '.join(str(x) for x in (e['process'],e['action'],e['object_path']) if x),related_node=e['event_id'],attack_label=e['attack_label']) for e in events))
        return
    con=connect(out)
    def items():
        for (data,) in con.execute('SELECT data FROM events ORDER BY ns IS NULL, ns, id'):
            e=json.loads(data)
            yield {'time':e['timestamp'],'host':e['host'],'event':e['event_type'],'description':' '.join(str(x) for x in (e['process'],e['action'],e['object_path']) if x is not None),'related_node':e['event_id'],'provider':e['provider'],'attack_label':None}
    target=out/'attack_timeline'/'timeline.json'; array(target,items()); alias(target,out/'attack_timeline.json'); con.close()

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--out',type=Path,default=ROOT/'processed_dataset'); a=p.parse_args(); generate(a.out)
