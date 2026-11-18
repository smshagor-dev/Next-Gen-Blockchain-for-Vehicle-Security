"""Non-actuating SQLite replay fault campaign; no physical hardware or power-loss claims."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
from research_contracts.durable_replay_gate import DurableReplayGate

WORKER = """import os,sys
from research_contracts.durable_replay_gate import DurableReplayGate
p,mode=sys.argv[1:]
g=DurableReplayGate(p)
if mode=="post_commit":
 assert g.admit_authenticated("node",11,authenticated=True)=="accept"
 print("COMMITTED",flush=True)
 os.kill(os.getpid(),9)
if mode=="pre_commit":
 g.db.execute("BEGIN IMMEDIATE")
 g.db.execute("INSERT INTO replay(sender,high_water) VALUES ('node',11)")
 print("UNCOMMITTED",flush=True)
 os.kill(os.getpid(),9)
"""

def run_trial(mode, root):
    db=root/"replay.sqlite"
    if mode=="rollback":
        with DurableReplayGate(db) as gate:
            assert gate.admit_authenticated("node",10,authenticated=True)=="accept"
        backup=root/"older.sqlite"
        shutil.copy2(db,backup)
        with DurableReplayGate(db) as gate:
            assert gate.admit_authenticated("node",11,authenticated=True)=="accept"
        shutil.copy2(backup,db)
        expected="accept" # Negative control: rollback defeats local high-water.
    elif mode=="corruption":
        db.write_bytes(b"not a sqlite database")
        try:
            with DurableReplayGate(db) as gate:
                observed=gate.admit_authenticated("node",11,authenticated=True)
        except Exception as exc:
            return {"fault":mode,"observed":"startup_error","expected":"startup_error","pass":True,"exception":type(exc).__name__}
        return {"fault":mode,"observed":observed,"expected":"startup_error","pass":False}
    else:
        proc=subprocess.run([sys.executable,"-c",WORKER,str(db),mode],capture_output=True,text=True,timeout=10)
        marker="COMMITTED" if mode=="post_commit" else "UNCOMMITTED"
        if marker not in proc.stdout or proc.returncode != -signal.SIGKILL:
            return {"fault":mode,"observed":"worker_failure","expected":marker+" then SIGKILL","pass":False,"stderr":proc.stderr[-500:]}
        expected="replay" if mode=="post_commit" else "accept"
    with DurableReplayGate(db) as gate:
        observed=gate.admit_authenticated("node",11,authenticated=True)
    return {"fault":mode,"observed":observed,"expected":expected,"pass":observed==expected}

def campaign(modes=("post_commit","pre_commit","rollback","corruption"),trials=1):
    if trials<1 or trials>10000: raise ValueError("trials must be 1..10000")
    results=[]
    for mode in modes:
        if mode not in ("post_commit","pre_commit","rollback","corruption"): raise ValueError("invalid fault mode")
        for i in range(trials):
            with tempfile.TemporaryDirectory(prefix="v2x-replay-fault-") as d:
                results.append({"trial":i,**run_trial(mode,Path(d))})
    return results

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--trials",type=int,default=1)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    records=campaign(trials=args.trials)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("w",encoding="utf-8") as f:
        for record in records: f.write(json.dumps(record,sort_keys=True)+"\n")
    print(json.dumps({"records":len(records),"passed":sum(r["pass"] for r in records),"output":str(args.output)}))
    return 0 if all(r["pass"] for r in records) else 1
if __name__=="__main__": raise SystemExit(main())
