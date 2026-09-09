"""Single-topic, size-limited pipeline; never downloads automatically."""
import argparse, shutil
from pathlib import Path
from common import ROOT
from preprocess import run
from extract_experiment import extract

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--raw',type=Path,default=ROOT/'raw_dataset/E3/data/cadets')
    p.add_argument('--out',type=Path,default=ROOT/'processed_dataset')
    p.add_argument('--context-limit',type=int,default=20000)
    p.add_argument('--keep-temporary-input',action='store_true',help='Explicitly keep downloaded topic after verification')
    a=p.parse_args()
    files=[x for x in a.raw.rglob('*') if x.is_file()]
    expected='ta1-cadets-e3-official-2.json.tar.gz'
    if len(files)!=1 or files[0].name!=expected:
        raise RuntimeError('Provide only '+expected+' in --raw; automatic/full E3 download is disabled')
    if a.out.exists() and any(a.out.iterdir()):
        raise RuntimeError('Use a new empty --out directory, then replace the old result after verification')
    work=ROOT/'.work'/'tc_index'; work.mkdir(parents=True,exist_ok=True)
    run(a.raw,work,ROOT/'dataset_analysis_report.md',index_only=True)
    extract(work/'metadata/dataset.sqlite',a.out,ROOT/'source_metadata',a.context_limit)
    # Exact owned workspace path, never a computed external directory.
    if work.resolve()!= (ROOT/'.work/tc_index').resolve() or ROOT.resolve() not in work.resolve().parents: raise RuntimeError('Invalid work path')
    shutil.rmtree(work)
    if not a.keep_temporary_input:
        candidate=files[0].resolve()
        if ROOT.resolve() in candidate.parents: candidate.unlink()
        else: print('External input retained:',candidate)
    print('Completed selected experiment; temporary index removed.')

if __name__=='__main__': main()
