import csv, gzip, hashlib, io, json, tarfile, zipfile, re, uuid, base64
from pathlib import Path
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation

ROOT=Path(__file__).resolve().parents[1]
FIELDS='event_id timestamp host event_type user process parent_process source destination action severity'.split()

def dump(path, value):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')

def array(path, items):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix(path.suffix+'.tmp')
    with temp.open('w',encoding='utf-8') as f:
        f.write('['); sep=''
        for item in items:
            f.write(sep+json.dumps(item,ensure_ascii=False,separators=(',',':'))); sep=',\n'
        f.write(']\n')
    temp.replace(path)

def unwrap(x):
    if isinstance(x,dict):
        if len(x)==1:
            k=next(iter(x))
            if k in ('string','long','int','double','float','boolean','map','array','bytes') or k.startswith('com.bbn.'):
                return unwrap(x[k])
        return {k:unwrap(v) for k,v in x.items()}
    if isinstance(x,list): return [unwrap(v) for v in x]
    return None if x=='' else x

def datum(record):
    if isinstance(record,dict) and isinstance(record.get('datum'),dict):
        value=record['datum']
        if len(value)==1:
            k=next(iter(value)); return k.rsplit('.',1)[-1],unwrap(value[k])
    return 'Generic',unwrap(record)

def provider(path, record=None):
    s=(str(path)+' '+str((record or {}).get('source',''))).lower()
    return next((x for x in ('cadets','theia','clearscope','fivedirections','trace') if x in s),'unknown')

def streams(raw):
    for path in sorted(Path(raw).rglob('*')):
        if not path.is_file() or path.name.endswith('.partial'): continue
        relative=path.relative_to(raw).as_posix()
        if path.name.endswith(('.tar.gz','.tgz','.tar')):
            with tarfile.open(path,'r|*') as t:
                for m in t:
                    if m.isfile():
                        with t.extractfile(m) as f: yield relative+'!'+m.name,m.size,f
        elif path.suffix=='.zip':
            with zipfile.ZipFile(path) as z:
                for m in z.infolist():
                    if not m.is_dir():
                        with z.open(m) as f: yield relative+'!'+m.filename,m.file_size,f
        elif path.suffix=='.gz':
            with gzip.open(path,'rb') as f: yield relative[:-3],None,f
        else:
            with path.open('rb') as f: yield relative,path.stat().st_size,f

def records(name, binary):
    """Yield (record position, value, error); never silently skip corrupt input."""
    lower=name.lower()
    if lower.endswith(('.avro','.bin')):
        try: from fastavro import reader
        except ImportError: raise RuntimeError('Binary Avro requires: pip install fastavro')
        def avro_json(v):
            if isinstance(v,tuple) and len(v)==2 and isinstance(v[0],str): return {v[0]:avro_json(v[1])}
            if isinstance(v,bytes): return str(uuid.UUID(bytes=v)).upper() if len(v)==16 else {'base64':base64.b64encode(v).decode('ascii')}
            if isinstance(v,dict): return {k:avro_json(x) for k,x in v.items()}
            if isinstance(v,list): return [avro_json(x) for x in v]
            return v
        for i,r in enumerate(reader(binary,return_record_name=True),1): yield i,avro_json(r),None
        return
    class ReadOnly(io.RawIOBase):
        def readable(self): return True
        def readinto(self,b):
            data=binary.read(len(b)); b[:len(data)]=data; return len(data)
    text=io.TextIOWrapper(io.BufferedReader(ReadOnly()),encoding='utf-8-sig',errors='strict')
    try:
        if lower.endswith(('.csv','.tsv')):
            for i,r in enumerate(csv.DictReader(text,delimiter='\t' if lower.endswith('.tsv') else ','),2): yield i,r,None
            return
        first=text.read(1)
        while first and first.isspace(): first=text.read(1)
        if first=='[':
            # Incremental JSON array parsing; memory bounded by largest record.
            dec=json.JSONDecoder(); buf=''; i=0; eof=False; expect=True; after_comma=False
            while True:
                if not eof and (not buf or len(buf)<65536):
                    chunk=text.read(65536); buf+=chunk; eof=not chunk
                buf=buf.lstrip()
                if buf.startswith(']'):
                    if after_comma: yield i+1,None,'Trailing comma in JSON array'; return
                    if buf[1:].strip() or text.read().strip(): yield i+1,None,'Trailing data after JSON array'
                    return
                if not expect:
                    if buf.startswith(','): buf=buf[1:].lstrip(); expect=True; after_comma=True
                    elif eof: yield i+1,None,'Missing comma or closing bracket'; return
                    else:
                        chunk=text.read(65536); buf+=chunk; eof=not chunk; continue
                try: value,end=dec.raw_decode(buf)
                except json.JSONDecodeError as exc:
                    if eof: yield i+1,{'unparsed':buf},str(exc); return
                    chunk=text.read(65536); buf+=chunk; eof=not chunk; continue
                i+=1; yield i,value,None; buf=buf[end:]; expect=False; after_comma=False
        else:
            lines=enumerate(iter(lambda:text.readline(),''),1)
            for i,line in lines:
                if i==1: line=first+line
                if not line.strip(): continue
                if line.strip()=='{':
                    # A pretty-printed object is one record, not corrupt JSONL lines.
                    for _,extra in lines:
                        line+=extra
                        try: json.loads(line); break
                        except json.JSONDecodeError: pass
                try: yield i,json.loads(line),None
                except json.JSONDecodeError as exc: yield i,{'unparsed':line.rstrip('\n')},str(exc)
    finally:
        text.detach()

def supported(name):
    return bool(re.search(r'\.(json|jsonl|ndjson|csv|tsv|log|txt|avro|bin)(\.\d+)?$',name.lower()))

def timestamp(value, unit=None):
    if value is None: return None,None
    try:
        number=Decimal(str(value))
        if unit is None:
            magnitude=abs(number)
            unit='ns' if magnitude>=Decimal('1e17') else 'us' if magnitude>=Decimal('1e14') else 'ms' if magnitude>=Decimal('1e11') else 's'
        ns=int(number*{'s':10**9,'ms':10**6,'us':1000,'ns':1}[unit])
        seconds,rem=divmod(ns,10**9)
        dt=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(seconds=seconds)
        return dt.strftime('%Y-%m-%dT%H:%M:%S')+f'.{rem:09d}Z',ns
    except (InvalidOperation,ValueError,OverflowError):
        try:
            dt=datetime.fromisoformat(str(value).replace('Z','+00:00'))
            if dt.tzinfo is None: return None,None
            delta=dt.astimezone(timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)
            ns=(delta.days*86400+delta.seconds)*10**9+delta.microseconds*1000
            return timestamp(ns,'ns')
        except (ValueError,TypeError,OverflowError): return None,None

def connect(output):
    import sqlite3
    con=sqlite3.connect(Path(output)/'metadata'/'dataset.sqlite')
    con.execute('PRAGMA journal_mode=WAL'); con.execute('PRAGMA synchronous=NORMAL')
    return con
