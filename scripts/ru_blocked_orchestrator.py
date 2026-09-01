#!/usr/bin/env python3
"""Monthly two-stage ru-blocked-cleaned orchestrator.

Stage 1 creates runs/<RUN_ID>/ and builds a cleaned candidate.
Stage 2 builds Happ/Shadowrocket artifacts from a completed Stage 1 run.
The frozen manual baselines under baselines/manual-2026-08-27 are never modified.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, subprocess, sys, traceback, urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "runs"
SUFFIX_DEFAULT = ROOT / "config/ru-blocked-suffixes.txt"
SOURCE_URL = "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/ru-blocked.txt"
GEO_URL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
BASE = ROOT / "baselines/manual-2026-08-27"
MANUAL_CLEAN = BASE / "ru-blocked-cleaned-15759.txt"
MANUAL_NX = BASE / "confirmed-nxdomain-6230.txt"
CURRENT_NX = ROOT / "generated/automation/nxdomain/confirmed-current.txt"
STABLE = ROOT / "generated/clients/ru-blocked-cleaned"
CHECK = ROOT / "scripts/check_hostnames.py"
RECHECK = ROOT / "scripts/recheck_uncertain.py"
CONFIRM = ROOT / "scripts/confirm_nxdomain.py"
CLIENTS = ROOT / "scripts/build_ru_blocked_cleaned_clients.py"
MERGE = ROOT / "scripts/merge_runetfreedom_geosite.go"
BRANCH = os.getenv("RU_BLOCKED_BRANCH", "build-ru-blocked-server-allow-20260826")
RAW = f"https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/{BRANCH}/generated/clients/ru-blocked-cleaned"

def now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
def new_run_id(): return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%SZ")
def lines(p): return [x.strip() for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
def write(p, xs): p.parent.mkdir(parents=True, exist_ok=True); p.write_text("".join(f"{x}\n" for x in xs), encoding="utf-8")
def sha(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1<<20), b""): h.update(b)
    return h.hexdigest()
def jwrite(p, obj):
    p.parent.mkdir(parents=True, exist_ok=True); q=p.with_suffix(p.suffix+".tmp")
    q.write_text(json.dumps(obj,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8"); os.replace(q,p)
def uniq(xs): return list(dict.fromkeys(xs))
def download(url,p):
    p.parent.mkdir(parents=True,exist_ok=True); req=urllib.request.Request(url,headers={"User-Agent":"ru-blocked-orchestrator/1"})
    with urllib.request.urlopen(req,timeout=180) as r: data=r.read()
    q=p.with_suffix(p.suffix+".tmp"); q.write_bytes(data); os.replace(q,p)
def baseline_check():
    if len(lines(MANUAL_CLEAN))!=15759 or len(lines(MANUAL_NX))!=6230: raise RuntimeError("manual baseline count mismatch")

def state(run, **kw):
    p=run/"state.json"; d=json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}; d.update(kw); d["updated_at_utc"]=now(); jwrite(p,d)
def done(run,name): return (run/".steps"/f"{name}.json").exists()
def mark(run,name,extra=None): jwrite(run/".steps"/f"{name}.json",{"step":name,"completed_at_utc":now(),**(extra or {})}); state(run,last_completed_step=name,current_step=None,status="RUNNING")
def step(run,name,resume,fn):
    if resume and done(run,name): print(f"[SKIP] {name}"); return
    state(run,current_step=name,status="RUNNING",last_error=None); print(f"[STEP] {name}")
    try: result=fn() or {}; mark(run,name,result)
    except BaseException as e:
        (run/"logs").mkdir(parents=True,exist_ok=True); ep=run/"logs"/f"{name}.error.txt"; ep.write_text(traceback.format_exc(),encoding="utf-8")
        state(run,status="ERROR",failed_step=name,last_error=f"{type(e).__name__}: {e}",error_log=str(ep.relative_to(run))); raise

def cmd(run,name,args,cwd=ROOT):
    (run/"logs").mkdir(parents=True,exist_ok=True); log=run/"logs"/f"{name}.log"
    with log.open("a",encoding="utf-8") as f:
        f.write(f"\n[{now()}] {' '.join(map(str,args))}\n"); p=subprocess.Popen(list(map(str,args)),cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        for s in p.stdout or []: print(s,end=""); f.write(s); f.flush()
        rc=p.wait(); f.write(f"EXIT={rc}\n")
    if rc==75: raise RuntimeError(f"{name} paused; rerun with --resume")
    if rc: raise RuntimeError(f"{name} exit={rc}")

def suffixes(path):
    out=[]
    for s in path.read_text(encoding="utf-8").splitlines():
        s=s.split("#",1)[0].strip().lower().strip(".")
        if s and s not in out: out.append(s)
    if not out: raise RuntimeError("empty suffix profile")
    return out

def filter_source(src,out,sufs):
    selected=[]; counts=Counter(); total=0
    ss=sorted(sufs,key=lambda x:(-len(x),x))
    for raw in src.read_text(encoding="utf-8").splitlines():
        raw=raw.strip()
        if not raw or raw.startswith("#"): continue
        kind,val=(raw.split(":",1) if ":" in raw else ("domain",raw))
        if kind.lower()!="domain": continue
        total+=1; host=val.strip().rstrip(".")
        for s in ss:
            if host==s or host.endswith("."+s): selected.append(host); counts[s]+=1; break
    selected=sorted(uniq(selected)); write(out,selected)
    jwrite(out.parent/"filter-report.json",{"source_sha256":sha(src),"domain_lines":total,"selected":len(selected),"suffixes":sufs,"suffix_counts":dict(counts)})

def compare_manual(run,candidate):
    a,b=set(lines(candidate)),set(lines(MANUAL_CLEAN)); d=run/"05_comparison"; write(d/"added-vs-manual-15759.txt",sorted(a-b)); write(d/"removed-vs-manual-15759.txt",sorted(b-a)); jwrite(d/"summary.json",{"candidate":len(a),"manual":len(b),"added":len(a-b),"removed":len(b-a)})
def gitflag(): return ["--git-checkpoint"] if os.getenv("ORCHESTRATOR_GIT_CHECKPOINT")=="1" else []
def empty_recheck(d):
    for n in ("01_LIVE_WEB","02_DNS_ALIVE_WEB_DEAD","03_NXDOMAIN_DEAD","04_STILL_UNCERTAIN"): write(d/f"{n}.txt",[])
def empty_confirm(d):
    for n in ("01_CONFIRMED_NXDOMAIN","02_DNS_ALIVE_RESCUED","03_INCONSISTENT_DNS","04_UNCERTAIN_RECHECK"): write(d/f"{n}.txt",[])
def combine(ps,out): write(out,uniq(sum((lines(p) for p in ps if p.exists()),[]))); return len(lines(out))

def stage1_fast(run,filtered,resume):
    final=run/"04_final"
    def work():
        db=CURRENT_NX if CURRENT_NX.exists() else MANUAL_NX; src=lines(filtered); nx=set(lines(db)); removed=[x for x in src if x in nx]; kept=[x for x in src if x not in nx]
        write(final/"confirmed-nxdomain-removed.txt",removed); write(final/"ru-blocked-cleaned.txt",kept); write(final/"unresolved-keep.txt",[])
        jwrite(final/"summary.json",{"mode":"FAST","input":len(src),"nxdomain_db":str(db.relative_to(ROOT)),"removed":len(removed),"cleaned":len(kept),"cleaned_sha256":sha(final/"ru-blocked-cleaned.txt")}); return {"cleaned":len(kept)}
    step(run,"fast-apply-current-nxdomain",resume,work); return final/"ru-blocked-cleaned.txt"

def recheck(run,name,inp,out,st,resume,c,q,t,hard,host):
    n=len(lines(inp))
    if not n: return step(run,name,resume,lambda:(empty_recheck(out) or {"input":0}))
    step(run,name,resume,lambda:(cmd(run,name,[sys.executable,RECHECK,"--input",inp,"--output-dir",out,"--state-dir",st,"--expected-count",n,"--concurrency",c,"--dns-query-concurrency",q,"--dns-timeout",t,"--dns-hard-timeout",hard,"--http-connect-timeout",5,"--http-total-timeout",15,"--hostname-hard-timeout",host,"--checkpoint-every",50,"--checkpoint-seconds",180,"--soft-limit-seconds",19000,*gitflag()]) or {"input":n}))
def confirm(run,name,inp,out,st,resume,c=4,q=6,t=8,host=180):
    n=len(lines(inp))
    if not n: return step(run,name,resume,lambda:(empty_confirm(out) or {"input":0}))
    step(run,name,resume,lambda:(cmd(run,name,[sys.executable,CONFIRM,"--input",inp,"--output-dir",out,"--state-dir",st,"--expected-count",n,"--concurrency",c,"--dns-query-concurrency",q,"--dns-timeout",t,"--hostname-hard-timeout",host,"--max-authoritative-ns",8,"--checkpoint-every",25,"--checkpoint-seconds",180,"--soft-limit-seconds",19000,*gitflag()]) or {"input":n}))

def stage1_full(run,filtered,resume,update_db):
    p1=run/"03_checks/pass1"; s1=run/"state/pass1"; n=len(lines(filtered))
    step(run,"full-pass1",resume,lambda:(cmd(run,"full-pass1",[sys.executable,CHECK,"--input",filtered,"--output-dir",p1,"--state-dir",s1,"--expected-count",n,"--concurrency",16,"--dns-timeout",3.5,"--dns-hard-timeout",8,"--http-connect-timeout",4,"--http-total-timeout",10,"--hostname-hard-timeout",45,"--checkpoint-every",100,"--checkpoint-seconds",120,"--soft-limit-seconds",19000,*gitflag()]) or {"input":n}))
    p2=run/"03_checks/pass2"; recheck(run,"full-pass2",p1/"04_UNCERTAIN_RECHECK.txt",p2,run/"state/pass2",resume,8,12,5,30,70)
    p3=run/"03_checks/pass3"; recheck(run,"full-pass3",p2/"04_STILL_UNCERTAIN.txt",p3,run/"state/pass3",resume,4,6,8,45,90)
    cand=run/"03_checks/nxdomain-candidates.txt"; step(run,"build-nxdomain-candidates",resume,lambda:{"count":combine([p1/"03_NXDOMAIN_DEAD.txt",p2/"03_NXDOMAIN_DEAD.txt",p3/"03_NXDOMAIN_DEAD.txt"],cand)})
    c1=run/"03_checks/confirm-nxdomain"; confirm(run,"confirm-nxdomain",cand,c1,run/"state/confirm-nxdomain",resume)
    fin=run/"03_checks/final-authoritative-input.txt"; step(run,"build-final-authoritative-input",resume,lambda:{"count":combine([p3/"04_STILL_UNCERTAIN.txt",c1/"04_UNCERTAIN_RECHECK.txt"],fin)})
    c2=run/"03_checks/confirm-final"; confirm(run,"confirm-final",fin,c2,run/"state/confirm-final",resume,3,6,8,180)
    final=run/"04_final"
    def consolidate():
        src=lines(filtered); nx=uniq(lines(c1/"01_CONFIRMED_NXDOMAIN.txt")+lines(c2/"01_CONFIRMED_NXDOMAIN.txt")); ns=set(nx)
        unresolved=uniq(lines(c1/"03_INCONSISTENT_DNS.txt")+lines(c1/"04_UNCERTAIN_RECHECK.txt")+lines(c2/"03_INCONSISTENT_DNS.txt")+lines(c2/"04_UNCERTAIN_RECHECK.txt")); unresolved=[x for x in unresolved if x not in ns]; clean=[x for x in src if x not in ns]
        if len(clean)+len(nx)!=len(src): raise RuntimeError("accounting mismatch")
        write(final/"confirmed-nxdomain-this-run.txt",nx); write(final/"unresolved-keep.txt",unresolved); write(final/"ru-blocked-cleaned.txt",clean); jwrite(final/"summary.json",{"mode":"FULL","input":len(src),"confirmed_nxdomain":len(nx),"unresolved_keep":len(unresolved),"cleaned":len(clean),"cleaned_sha256":sha(final/"ru-blocked-cleaned.txt")}); return {"cleaned":len(clean),"nxdomain":len(nx)}
    step(run,"full-consolidate",resume,consolidate)
    if update_db:
        step(run,"promote-current-nxdomain-db",resume,lambda:(CURRENT_NX.parent.mkdir(parents=True,exist_ok=True) or shutil.copy2(final/"confirmed-nxdomain-this-run.txt",CURRENT_NX) or {}))
    return final/"ru-blocked-cleaned.txt"

def stage1(a):
    baseline_check(); rid=a.run_id or new_run_id(); run=RUNS/rid
    if run.exists() and not a.resume: raise RuntimeError(f"run {rid} exists; use --resume")
    run.mkdir(parents=True,exist_ok=True); sf=Path(a.suffix_file).resolve(); sufs=suffixes(sf)
    if not (run/"state.json").exists(): state(run,version=1,run_id=rid,started_at_utc=now(),status="RUNNING",requested_stage="stage1",nxdomain_mode=a.nxdomain_mode.upper(),suffix_file=str(sf),suffixes=sufs,update_nxdomain_db=a.update_nxdomain_db)
    src=run/"01_source/ru-blocked.txt"; step(run,"download-source",a.resume,lambda:(download(SOURCE_URL,src) or {"sha256":sha(src),"bytes":src.stat().st_size}))
    filtered=run/"02_filtered/ru-blocked-filtered.txt"; step(run,"filter-suffixes",a.resume,lambda:(filter_source(src,filtered,sufs) or {"count":len(lines(filtered)),"sha256":sha(filtered)}))
    candidate=stage1_fast(run,filtered,a.resume) if a.nxdomain_mode=="fast" else stage1_full(run,filtered,a.resume,a.update_nxdomain_db)
    step(run,"compare-manual-baseline",a.resume,lambda:(compare_manual(run,candidate) or {})); step(run,"stage1-manifest",a.resume,lambda:(jwrite(run/"manifest.json",{"run_id":rid,"mode":a.nxdomain_mode.upper(),"completed_at_utc":now(),"suffixes":sufs,"source_sha256":sha(src),"filtered_count":len(lines(filtered)),"cleaned_count":len(lines(candidate)),"cleaned_sha256":sha(candidate),"manual_cleaned_sha256":sha(MANUAL_CLEAN)}) or {}))
    state(run,status="STAGE1_COMPLETE",current_step=None,last_error=None); write(ROOT/"generated/automation/latest-stage1-run.txt",[rid]); print(f"RUN_ID={rid}\nCANDIDATE={candidate.relative_to(ROOT)}"); return 0

def stage2(a):
    baseline_check(); rid=a.run_id or (lines(ROOT/"generated/automation/latest-stage1-run.txt")[0]); run=RUNS/rid; candidate=run/"04_final/ru-blocked-cleaned.txt"
    if not candidate.exists(): raise RuntimeError("completed Stage 1 candidate not found")
    n=len(lines(candidate)); out=run/"06_clients"; state(run,requested_stage="stage2",status="RUNNING",publish_clients=a.publish)
    step(run,"build-client-text",a.resume,lambda:(cmd(run,"build-client-text",[sys.executable,CLIENTS,"--input",candidate,"--output-dir",out,"--expected-count",n]) or {"count":n}))
    base=out/"runetfreedom.geosite.dat"; shaf=out/"runetfreedom.geosite.dat.sha256sum"
    def getgeo():
        download(GEO_URL,base); download(GEO_URL+".sha256sum",shaf); expected=shaf.read_text().strip().split()[0]
        if sha(base)!=expected: raise RuntimeError("Runet Freedom geosite SHA mismatch")
        return {"sha256":expected,"bytes":base.stat().st_size}
    step(run,"download-full-geosite",a.resume,getgeo)
    merged=out/"geosite.dat"
    def merge():
        tmp=Path(os.getenv("RUNNER_TEMP","/tmp"))/f"dlc-{rid}"; shutil.rmtree(tmp,ignore_errors=True); cmd(run,"clone-v2fly",["git","clone","--depth","1","https://github.com/v2fly/domain-list-community.git",tmp])
        cmd(run,"merge-geosite",["go","run",MERGE,"--base",base,"--canonical",candidate,"--output",merged,"--category","RU-BLOCKED-CLEANED","--expected-count",n],tmp); return {"sha256":sha(merged),"bytes":merged.stat().st_size}
    step(run,"merge-full-geosite",a.resume,merge)
    step(run,"client-manifest",a.resume,lambda:(jwrite(out/"manifest.json",{"run_id":rid,"hostname_count":n,"shadowrocket":f"RULE-SET,{RAW}/ru-blocked-cleaned.list,PROXY","happ_geosite_url":f"{RAW}/geosite.dat","happ_category":"geosite:ru-blocked-cleaned","geosite_sha256":sha(merged)}) or write(out/"USAGE.txt",["Shadowrocket:",f"RULE-SET,{RAW}/ru-blocked-cleaned.list,PROXY","","Happ:",f"Geositeurl: {RAW}/geosite.dat","ProxySites: geosite:ru-blocked-cleaned"]) or {}))
    if a.publish:
        def pub():
            STABLE.mkdir(parents=True,exist_ok=True)
            for f in ("ru-blocked-cleaned.list","geosite.dat","USAGE.txt"): shutil.copy2(out/f,STABLE/f)
            shutil.copy2(out/"manifest.json",STABLE/"orchestrator-manifest.json"); return {"published":True}
        step(run,"publish-stable-client-files",a.resume,pub)
    state(run,status="STAGE2_COMPLETE",current_step=None,last_error=None); print(f"RUN_ID={rid}\nCLIENT_DIR={out.relative_to(ROOT)}"); return 0

def main():
    p=argparse.ArgumentParser(); s=p.add_subparsers(dest="cmd",required=True)
    a=s.add_parser("stage1"); a.add_argument("--run-id",default=""); a.add_argument("--suffix-file",default=str(SUFFIX_DEFAULT)); a.add_argument("--nxdomain-mode",choices=("fast","full"),default="fast"); a.add_argument("--update-nxdomain-db",action="store_true"); a.add_argument("--resume",action="store_true")
    b=s.add_parser("stage2"); b.add_argument("--run-id",default=""); b.add_argument("--publish",action="store_true"); b.add_argument("--resume",action="store_true")
    x=p.parse_args()
    try: return stage1(x) if x.cmd=="stage1" else stage2(x)
    except Exception as e: print(f"[ERROR] {type(e).__name__}: {e}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
