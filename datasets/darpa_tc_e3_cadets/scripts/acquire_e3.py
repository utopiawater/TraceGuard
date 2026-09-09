"""Inventory official public Drive folders; download explicitly selected file IDs."""
import argparse, hashlib, json, re, urllib.request, urllib.parse, http.cookiejar
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOLDER = '1QlbUFWAGq3Hpl8wVdzOdIoZLFxkII4EK'

def listing(fid):
    url = 'https://drive.google.com/drive/folders/' + fid
    text = urllib.request.urlopen(url, timeout=60).read().decode('utf-8')
    match = re.search(r"window\['_DRIVE_ivd'\] = '(.*?)';", text)
    if not match:
        raise RuntimeError('Public folder metadata unavailable: ' + url)
    decoded = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m[1],16)), match[1])
    decoded = decoded.replace('\\/', '/')
    return json.loads(decoded)[0]

def inventory(fid=FOLDER, prefix='E3'):
    for row in listing(fid):
        item = dict(id=row[0], path=prefix+'/'+row[2], mime=row[3], bytes=row[13])
        print(item['path'], item['bytes'], flush=True)
        yield item
        if row[3] == 'application/vnd.google-apps.folder':
            yield from inventory(row[0], item['path'])

def main():
    p=argparse.ArgumentParser(); p.add_argument('--inventory', action='store_true'); p.add_argument('--id'); a=p.parse_args()
    target=ROOT/'source_metadata'; target.mkdir(exist_ok=True)
    if a.inventory:
        items=list(inventory()); (target/'remote_manifest.json').write_text(json.dumps(items,indent=2),encoding='utf-8')
    if a.id:
        items=json.loads((target/'remote_manifest.json').read_text(encoding='utf-8'))
        item=next(x for x in items if x['id']==a.id)
        dest=ROOT/'raw_dataset'/item['path']; dest.parent.mkdir(parents=True,exist_ok=True)
        if dest.exists(): raise RuntimeError('Refusing to overwrite raw file')
        url='https://drive.usercontent.google.com/download?id='+a.id+'&export=download&confirm=t'
        temp=dest.with_name(dest.name+'.partial')
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        response=opener.open(url,timeout=120)
        if 'text/html' in response.headers.get('Content-Type',''):
            page=response.read().decode('utf-8'); response.close()
            class Form(HTMLParser):
                action=None
                values={}
                def handle_starttag(self,tag,attrs):
                    attrs=dict(attrs)
                    if tag=='form': self.action=attrs.get('action')
                    if tag=='input' and attrs.get('name'): self.values[attrs['name']]=attrs.get('value','')
            form=Form(); form.feed(page)
            if not form.action or urllib.parse.urlparse(form.action).hostname!='drive.usercontent.google.com':
                (target/(a.id+'.download_error.html')).write_text(page,encoding='utf-8')
                raise RuntimeError('Drive did not provide a public download form; saved diagnostic HTML')
            response=opener.open(form.action+'?'+urllib.parse.urlencode(form.values),timeout=120)
        with response, temp.open('wb') as f:
            if 'text/html' in response.headers.get('Content-Type',''): raise RuntimeError('Drive returned an HTML page instead of data')
            while chunk:=response.read(8*1024*1024): f.write(chunk)
        if item['bytes'] and temp.stat().st_size!=int(item['bytes']): raise RuntimeError('Download size mismatch')
        temp.rename(dest)
        print('Saved',dest)

if __name__=='__main__': main()
