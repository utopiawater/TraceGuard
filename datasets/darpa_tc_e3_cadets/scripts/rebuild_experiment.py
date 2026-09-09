"""Regenerate the five small outputs from retained evidence, no raw download."""
import argparse, json, hashlib
from pathlib import Path
from common import ROOT,dump
from preprocess import normalize
from extract_experiment import write_products

def rebuild(out):
    graph=json.loads((out/'attack_graph.json').read_text(encoding='utf-8'))
    entities={n['uuid']:n.get('details') or {} for n in graph['nodes'] if n.get('uuid')}
    lookup=lambda provider,ident:entities.get(ident,{})
    events=[]
    for name in ('process_events.json','file_events.json','network_events.json'):
        for old in json.loads((out/name).read_text(encoding='utf-8')):
            event=normalize(old['evidence'],'Event',old['provider'],old['event_id'],lookup)
            for field in ('user','process','parent_process'):
                if event[field] is None: event[field]=old[field]
            event.update({k:old[k] for k in ('selection_reason','attack_label','raw_location','evidence')}); events.append(event)
    partitions,nodes,edges,size=write_products(events,lookup,out)
    path=ROOT/'source_metadata/selection_manifest.json'
    if path.exists():
        summary=json.loads(path.read_text(encoding='utf-8')); summary.update(bytes=size,counts={k:len(v) for k,v in partitions.items()},graph_nodes=len(nodes),graph_edges=len(edges)); dump(path,summary)
    dump(ROOT/'source_metadata/output_checksums.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file()})
    print('Rebuilt',len(events),'events,',size,'bytes')

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--out',type=Path,default=ROOT/'processed_dataset'); a=p.parse_args(); rebuild(a.out)
