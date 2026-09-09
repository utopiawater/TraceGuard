"""Disk-backed two-pass CDM preprocessing. Raw files are opened read-only."""
import argparse, collections, functools, ipaddress, json, shutil, sqlite3
from pathlib import Path
from common import *
from analyze_dataset import write_report

def uid(value):
    return None if value in (None,'00000000-0000-0000-0000-000000000000') else str(value)

def normalize(d, kind, prov, key, lookup):
    subid=uid(d.get('subject')); sub=lookup(prov,subid)
    objid=uid(d.get('predicateObject')); obj=lookup(prov,objid)
    obj2id=uid(d.get('predicateObject2')); obj2=lookup(prov,obj2id)
    parentid=uid(sub.get('parentSubject')); parent=lookup(prov,parentid)
    principal=lookup(prov,uid(sub.get('localPrincipal')))
    rawtime=d.get('timestampNanos',d.get('timestamp',d.get('time')))
    time,ns=timestamp(rawtime,'ns' if 'timestampNanos' in d else None)
    original=d.get('type',d.get('event_type')); typ=str(original or 'unknown').removeprefix('EVENT_').lower()
    properties=sub.get('properties') or {}
    proc=(d.get('properties') or {}).get('exec') or properties.get('path') or sub.get('cmdLine') or d.get('process')
    par=(parent.get('properties') or {}).get('path') or parent.get('cmdLine') or d.get('parent_process')
    host=uid(d.get('hostId') or sub.get('hostId') or d.get('host'))
    category='other'
    object_kind=obj.get('_kind','')
    if object_kind=='NetFlowObject' or typ in ('connect','accept','sendto','recvfrom','sendmsg','recvmsg'): category='network'
    elif object_kind=='RegistryKeyObject' or 'reg' in typ: category='registry'
    elif object_kind=='FileObject' or typ in ('open','unlink','rename','link','truncate','create_object'): category='file'
    elif typ in ('login','logout','change_principal','modify_process_credentials'): category='user'
    elif object_kind=='Subject' or typ in ('clone','fork','exec','exit','signal','process_create'): category='process'
    path=d.get('predicateObjectPath') or (obj.get('baseObject',{}).get('properties') or {}).get('filename')
    endpoints={}; warnings=[]
    for side in ('local','remote'):
        address=obj.get(side+'Address')
        try: address=str(ipaddress.ip_address(str(address).strip().strip('[]'))) if address else None
        except ValueError: warnings.append('invalid_'+side+'_ip'); address=None
        endpoints[side]={'ip':address,'port':obj.get(side+'Port')}
    source=destination=None
    if category=='network':
        receive=typ in ('recvfrom','recvmsg','read','accept')
        source=endpoints['remote' if receive else 'local']; destination=endpoints['local' if receive else 'remote']
    elif kind=='Generic': source=d.get('source'); destination=d.get('destination')
    if rawtime is not None and time is None: warnings.append('invalid_or_timezone_missing_timestamp')
    for label,ident,record in [('subject',subid,sub),('object',objid,obj),('object2',obj2id,obj2),('parent',parentid,parent)]:
        if ident and not record: warnings.append('unresolved_'+label)
    e=dict(event_id=key,timestamp=time,host=host,event_type={'clone':'process_create','fork':'process_create','exec':'process_execute'}.get(typ,typ),user=principal.get('username') or principal.get('userId') or d.get('user'),process=proc,parent_process=par,source=source,destination=destination,action=d.get('name') or typ,severity=d.get('severity'))
    e.update(provider=prov,original_event_id=d.get('uuid',d.get('event_id')),original_event_type=original,subject_id=subid,parent_subject_id=parentid,object_id=objid,object2_id=obj2id,object_path=path,object2_path=d.get('predicateObject2Path'),timestamp_ns=ns,category=category,quality_flags=warnings,attack_label=None)
    return e

def run(raw,out,report,index_only=False):
    if raw.resolve()==out.resolve() or raw.resolve() in out.resolve().parents or out.resolve() in raw.resolve().parents:
        raise ValueError('Raw and output directories must be disjoint')
    (out/'metadata').mkdir(parents=True,exist_ok=True)
    dump(out/'metadata'/'run_status.json',{'status':'running','raw':str(raw.resolve())})
    con=connect(out)
    con.executescript('DROP TABLE IF EXISTS records; DROP TABLE IF EXISTS entities; DROP TABLE IF EXISTS events; DROP TABLE IF EXISTS quarantine; CREATE TABLE records(id INTEGER PRIMARY KEY,provider TEXT,kind TEXT,uuid TEXT,file TEXT,position INTEGER,data TEXT); CREATE TABLE entities(provider TEXT,uuid TEXT,record_id INTEGER,PRIMARY KEY(provider,uuid)); CREATE TABLE events(id INTEGER PRIMARY KEY,ns INTEGER,host TEXT,provider TEXT,category TEXT,data TEXT); CREATE TABLE quarantine(file TEXT,position INTEGER,error TEXT,data TEXT);')
    stats=[]; count=0; conflict=0
    for name,size,f in streams(raw):
        item=dict(file=name,bytes=size,provider=provider(name),records=0,parse_errors=0,fields={},record_types={},status='not_event_format')
        fields=collections.defaultdict(collections.Counter); kinds=collections.Counter()
        if supported(name):
            print('Ingest',name,flush=True); item['status']='scanned'
            for pos,r,error in records(name,f):
                item['records']+=1
                if error or not isinstance(r,dict):
                    item['parse_errors']+=1; con.execute('INSERT INTO quarantine VALUES(?,?,?,?)',(name,pos,error or 'Not an object',json.dumps(r))); continue
                k,d=datum(r); prov=provider(name,r); kinds[k]+=1
                def visit(v,prefix=''):
                    if isinstance(v,dict):
                        for field,value in v.items():
                            key=prefix+field; fields[key][type(value).__name__]+=1
                            if isinstance(value,dict): visit(value,key+'.')
                visit(d)
                # Full original record remains available for evidence and new mappings.
                cur=con.execute('INSERT INTO records(provider,kind,uuid,file,position,data) VALUES(?,?,?,?,?,?)',(prov,k,uid(d.get('uuid')),name,pos,json.dumps(r,separators=(',',':'))))
                if k not in ('Event','Generic') and uid(d.get('uuid')):
                    inserted=con.execute('INSERT OR IGNORE INTO entities VALUES(?,?,?)',(prov,uid(d['uuid']),cur.lastrowid))
                    if not inserted.rowcount: conflict+=1
                count+=1
                if count%50000==0:
                    con.commit(); print('Records',count,flush=True)
                    if shutil.disk_usage(out).free<3*1024**3: raise RuntimeError('Less than 3 GiB free; stopped without deleting raw files')
        item['fields']=dict(fields); item['record_types']=dict(kinds); stats.append(item); con.commit()
    write_report(raw,report,stats)
    if index_only:
        con.execute('PRAGMA wal_checkpoint(TRUNCATE)'); con.close(); return {'records':count}
    return finish(out,con,count,conflict)

def finish(out,con,count,conflict):
    con.execute('DELETE FROM events'); con.execute('DROP INDEX IF EXISTS events_time'); con.execute('DROP INDEX IF EXISTS events_host_time'); con.execute('DROP INDEX IF EXISTS events_category'); con.commit()
    @functools.lru_cache(maxsize=100000)
    def lookup(prov,ident):
        if not ident: return {}
        row=con.execute('SELECT r.kind,r.data FROM entities e JOIN records r ON r.id=e.record_id WHERE e.provider=? AND e.uuid=?',(prov,ident)).fetchone()
        if not row: return {}
        k,d=datum(json.loads(row[1])); return dict(d,_kind=k)
    total=0; flags=collections.Counter(); providers=collections.Counter()
    for rid,prov,k,data in con.execute("SELECT id,provider,kind,data FROM records WHERE kind IN ('Event','Generic') ORDER BY id"):
        _,d=datum(json.loads(data)); e=normalize(d,k,prov,f'{prov}:record:{rid}',lookup)
        con.execute('INSERT INTO events VALUES(?,?,?,?,?,?)',(rid,e['timestamp_ns'],e['host'],prov,e['category'],json.dumps(e,separators=(',',':'),ensure_ascii=False)))
        total+=1; flags.update(e['quality_flags']); providers[prov]+=1
        if total%50000==0: con.commit(); print('Normalized',total,flush=True)
    con.commit(); con.execute('CREATE INDEX events_time ON events(ns,id)'); con.execute('CREATE INDEX events_host_time ON events(provider,host,ns,id)'); con.execute('CREATE INDEX events_category ON events(category)'); con.commit()
    for cat,path in [('process','host_events/process_events.json'),('file','host_events/file_events.json'),('registry','host_events/registry_events.json'),('user','host_events/user_events.json'),('other','host_events/other_events.json'),('network','network_events/connections.json')]:
        array(out/path,(json.loads(r[0]) for r in con.execute('SELECT data FROM events WHERE category=? ORDER BY id',(cat,))))
    array(out/'metadata'/'quarantine.json',(dict(file=r[0],position=r[1],error=r[2],raw=json.loads(r[3])) for r in con.execute('SELECT * FROM quarantine')))
    array(out/'metadata'/'unresolved_references.json',({'event_id':json.loads(data)['event_id'],'flags':json.loads(data)['quality_flags']} for (data,) in con.execute('SELECT data FROM events') if json.loads(data)['quality_flags']))
    dump(out/'metadata'/'schema.json',{'schema_version':'1.0','required':FIELDS,'timestamp':'UTC ISO8601 with 9 fractional digits; null if timezone unknown','timestamp_ns':'integer nanoseconds since Unix epoch; preserve exact precision','source_destination':'network endpoint {ip,port}, otherwise source values or null','severity':'source value only; null when unlabeled','event_id':'provider:record:<SQLite record id>; deterministic for same ordered input inventory','raw_lookup':'event id numeric suffix -> records.id; records includes original JSON and file position','provider':['cadets','theia','clearscope','fivedirections','trace','unknown'],'attack_label':'null; no ground truth labels imported','entity_resolution':'provider+UUID, first observed record; all later versions retained in records; repeated IDs counted','fields':{f:'nullable except event_id and event_type' for f in FIELDS}})
    summary={'status':'normalized','records':count,'events':total,'events_by_provider':dict(providers),'quality_flags':dict(flags),'repeated_entity_ids':conflict,'quarantined_records':con.execute('SELECT count(*) FROM quarantine').fetchone()[0],'scope':'downloaded local files only; not full E3'}
    dump(out/'metadata'/'run_status.json',summary); con.close(); return summary

if __name__=='__main__':
    from run_pipeline import main
    main()
