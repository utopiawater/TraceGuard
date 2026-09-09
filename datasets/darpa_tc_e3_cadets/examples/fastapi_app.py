"""Optional local API over the small experiment. No full raw DB required."""
import json
from functools import lru_cache
from pathlib import Path
from fastapi import FastAPI, Query
from typing import Literal
app=FastAPI(title='CADets E3 provenance experiment')
ROOT=Path(__file__).resolve().parents[1]/'processed_dataset'

@lru_cache(maxsize=3)
def read_events(category):
    return json.loads((ROOT/(category+'_events.json')).read_text(encoding='utf-8'))

@app.get('/events')
def events(category:Literal['process','network','file']='network',offset:int=Query(0,ge=0),limit:int=Query(100,ge=1,le=1000)):
    data=read_events(category)
    return {'total':len(data),'items':data[offset:offset+limit],'next_offset':offset+limit if offset+limit<len(data) else None}
