import io, json, sys, tempfile, unittest, hashlib, tarfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from common import timestamp, records, streams, supported
from preprocess import run
from generate_timeline import generate
from build_attack_graph import build

class PipelineTests(unittest.TestCase):
    def test_nanoseconds(self):
        self.assertEqual(timestamp(1523278015004734360,'ns'),('2018-04-09T12:46:55.004734360Z',1523278015004734360))
        self.assertEqual(timestamp('2018-04-09 10:00:00'),(None,None))
        self.assertEqual(timestamp('2018-04-09T20:46:55.004734+08:00')[1],1523278015004734000)

    def test_formats(self):
        for name,content in [('x.json',b'[\n {"x":1},\n {"x":2}\n]'),('x.json.1',b'{"x":1}\n{"x":2}\n')]:
            self.assertTrue(supported(name)); self.assertEqual([r[1]['x'] for r in records(name,io.BytesIO(content))],[1,2])
        rows=list(records('bad.log',io.BytesIO(b'{"x":1}\nbroken\n')))
        self.assertIsNotNone(rows[1][2]); self.assertEqual(rows[1][1]['unparsed'],'broken')
        self.assertEqual(list(records('pretty.json',io.BytesIO(b'{\n "x":1\n}')))[0][1],{'x':1})
        self.assertIsNotNone(list(records('bad.json',io.BytesIO(b'[{},]')))[-1][2])

    def test_integration(self):
        def cdm(kind,**data): return {'datum':{'com.bbn.tc.schema.avro.cdm18.'+kind:data},'source':'SOURCE_LINUX_THEIA','CDMVersion':'18'}
        inputs=[cdm('Event',uuid='evt',type='EVENT_RECVFROM',hostId='h',subject={'com.bbn.tc.schema.avro.cdm18.UUID':'p'},predicateObject='n',timestampNanos=1523278015004734360),cdm('Event',uuid='evt',type='EVENT_MYSTERY',hostId='h',subject='missing',timestampNanos=1523278015004734000),cdm('Host',uuid='h'),cdm('Subject',uuid='p',parentSubject='parent',hostId='h',localPrincipal='u',cmdLine={'string':'shell -c echo'}),cdm('Subject',uuid='parent',hostId='h'),cdm('Principal',uuid='u',username='alice'),cdm('NetFlowObject',uuid='n',localAddress='2001:0db8::1',localPort=443,remoteAddress='10.0.0.2',remotePort=12)]
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); raw=base/'raw'; raw.mkdir(); data='\n'.join(json.dumps(r) for r in inputs)+'\nbroken\n'
            path=raw/'theia.json'; path.write_text(data); original=hashlib.sha256(path.read_bytes()).hexdigest()
            out=base/'out'; agent=base/'agent'; run(raw,out,base/'report.md'); generate(out); build(out,agent)
            self.assertEqual(original,hashlib.sha256(path.read_bytes()).hexdigest())
            e=json.loads((out/'network_events/connections.json').read_text())[0]
            self.assertEqual(e['user'],'alice'); self.assertEqual(e['source']['ip'],'10.0.0.2'); self.assertEqual(e['destination']['ip'],'2001:db8::1'); self.assertIsNone(e['severity'])
            timeline=json.loads((out/'attack_timeline.json').read_text()); self.assertEqual(len(timeline),2); self.assertLess(timeline[0]['time'],timeline[1]['time'])
            graph=json.loads((out/'attack_graph.json').read_text()); ids={n['id'] for n in graph['nodes']}
            self.assertTrue(all(e['source'] in ids and e['target'] in ids for e in graph['edges']))
            self.assertEqual(len(json.loads((out/'metadata/quarantine.json').read_text())),1)
            self.assertTrue(any(e['relation']=='parent_process' for e in graph['edges']))
            before=(out/'network_events/connections.json').read_bytes(); run(raw,out,base/'report.md'); self.assertEqual(before,(out/'network_events/connections.json').read_bytes())

if __name__=='__main__': unittest.main()
