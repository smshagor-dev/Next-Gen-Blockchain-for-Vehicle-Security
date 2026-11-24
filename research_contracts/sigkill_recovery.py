"""POSIX SIGKILL/WAL checkpoint experiment; non-actuating and NOT a trusted anchor."""
import argparse, csv, os, signal, sqlite3, subprocess, sys, tempfile
from pathlib import Path
PROTOCOLS=("reserve_first","local_first")
BOUNDARIES=("first","second")

def connect(path):
    db=sqlite3.connect(path,timeout=5,isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS claims(nonce TEXT PRIMARY KEY)")
    return db

def claim(path,nonce):
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO claims VALUES (?)",(nonce,))
        db.execute("COMMIT")

def exists(path,nonce):
    with connect(path) as db:
        return db.execute("SELECT COUNT(*) FROM claims WHERE nonce=?",(nonce,)).fetchone()[0]==1

def worker(folder,protocol,boundary,nonce):
    if protocol not in PROTOCOLS or boundary not in BOUNDARIES:
        raise ValueError("invalid protocol/boundary")
    order=("anchor","local") if protocol=="reserve_first" else ("local","anchor")
    for index,store in enumerate(order):
        claim(folder/(store+".sqlite"),nonce)
        if boundary==("first" if index==0 else "second"):
            os.kill(os.getpid(),signal.SIGKILL)
    raise AssertionError("unreachable")

def run_case(protocol,boundary,folder):
    if protocol not in PROTOCOLS or boundary not in BOUNDARIES:
        raise ValueError("invalid protocol/boundary")
    nonce="fixed-incident-nonce"
    command=[sys.executable,"-m","research_contracts.sigkill_recovery","--worker",
             "--directory",str(folder),"--protocol",protocol,"--boundary",boundary,"--nonce",nonce]
    result=subprocess.run(command,capture_output=True,text=True,timeout=15)
    if result.returncode!=-signal.SIGKILL:
        raise RuntimeError(f"expected SIGKILL, got {result.returncode}: {result.stderr}")
    local,anchor=folder/"local.sqlite",folder/"anchor.sqlite"
    before=(exists(local,nonce),exists(anchor,nonce))
    checkpoint=[]
    for path in (local,anchor):
        with connect(path) as db:
            checkpoint.append(db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0])
    after=(exists(local,nonce),exists(anchor,nonce))
    if before!=after or any(checkpoint):
        raise AssertionError("checkpoint changed claims or was blocked")
    first=anchor if protocol=="reserve_first" else local
    try:
        claim(first,nonce)
        rejected=False
    except sqlite3.IntegrityError:
        rejected=True
    return dict(protocol=protocol,boundary=boundary,local_claim=int(after[0]),
                anchor_claim=int(after[1]),inconsistent=int(after[0]!=after[1]),
                retry_rejected=int(rejected),checkpoint_preserved=int(before==after))

def experiment():
    for protocol in PROTOCOLS:
        for boundary in BOUNDARIES:
            with tempfile.TemporaryDirectory(prefix="omni-sigkill-") as tmp:
                yield run_case(protocol,boundary,Path(tmp))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--worker",action="store_true")
    parser.add_argument("--directory",type=Path)
    parser.add_argument("--protocol",choices=PROTOCOLS)
    parser.add_argument("--boundary",choices=BOUNDARIES)
    parser.add_argument("--nonce",default="fixed-incident-nonce")
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if args.worker:
        if not all((args.directory,args.protocol,args.boundary)):
            parser.error("worker requires directory, protocol, boundary")
        worker(args.directory,args.protocol,args.boundary,args.nonce)
        return 0
    rows=list(experiment())
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open("w",newline="",encoding="utf-8") as handle:
            writer=csv.DictWriter(handle,fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    for row in rows:
        print(row)
    return 0

if __name__=="__main__":
    sys.exit(main())
