"""Non-actuating localhost TCP HMAC/replay experiment. Synthetic data only."""
import argparse, csv, hashlib, hmac, json, socket, struct, threading, time
from pathlib import Path
KEY=b'local-experiment-key-not-for-deployment'
MAX_FRAME=1024
def envelope(sender,seq,value,corrupt=False):
    body=json.dumps({'sender':sender,'seq':seq,'value':value},sort_keys=True,separators=(',',':')).encode()
    tag=hmac.new(KEY,body,hashlib.sha256).hexdigest()
    if corrupt: tag=('0' if tag[0]!='0' else '1')+tag[1:]
    payload=json.dumps({'body':body.decode(),'tag':tag},separators=(',',':')).encode()
    return struct.pack('!I',len(payload))+payload
def exact(sock,n):
    data=bytearray()
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part: raise ValueError('truncated')
        data.extend(part)
    return bytes(data)
class Receiver:
    def __init__(self):
        self.high_water={}
        self.lock=threading.Lock()
    def handle(self,conn):
        conn.settimeout(0.5)
        try:
            size=struct.unpack('!I',exact(conn,4))[0]
            if size==0 or size>MAX_FRAME: return 'oversize'
            obj=json.loads(exact(conn,size))
            body=obj['body'].encode()
            tag=obj['tag']
            if not isinstance(tag,str) or not hmac.compare_digest(hmac.new(KEY,body,hashlib.sha256).hexdigest(),tag): return 'tamper'
            record=json.loads(body)
            sender,seq=record['sender'],record['seq']
            if not isinstance(sender,str) or not sender or type(seq) is not int or seq<0: return 'invalid'
            with self.lock:
                if seq<=self.high_water.get(sender,-1): return 'replay'
                self.high_water[sender]=seq
            return 'accept'
        except (ValueError,KeyError,TypeError,UnicodeError,socket.timeout,OSError): return 'invalid'
def run(trials=20,output=None):
    if trials<1: raise ValueError('trials must be positive')
    receiver=Receiver()
    rows=[]
    with socket.socket() as server:
        server.bind(('127.0.0.1',0))
        server.listen(1)
        port=server.getsockname()[1]
        for i in range(trials):
            for kind,packet,expected in (
                ('honest',envelope('node',i,1),'accept'),
                ('replay',envelope('node',i,1),'replay'),
                ('tamper',envelope('node',i+trials,1,True),'tamper'),
                ('oversize',struct.pack('!I',MAX_FRAME+1),'oversize')):
                with socket.create_connection(('127.0.0.1',port),timeout=1) as client:
                    client.sendall(packet)
                    client.shutdown(socket.SHUT_WR)
                    with server.accept()[0] as conn:
                        start=time.perf_counter_ns()
                        observed=receiver.handle(conn)
                        elapsed=time.perf_counter_ns()-start
                rows.append({'trial':i,'kind':kind,'expected':expected,'observed':observed,'latency_ns':elapsed})
                if observed!=expected: raise AssertionError(f'{kind}: {observed} != {expected}')
    if output:
        target=Path(output)
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('w',newline='') as fh:
            writer=csv.DictWriter(fh,fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    return rows
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--trials',type=int,default=20)
    p.add_argument('--output')
    a=p.parse_args()
    rows=run(a.trials,a.output)
    print(json.dumps({'attempts':len(rows),'matched_expectations':sum(r['expected']==r['observed'] for r in rows),'simulation_only':True}))
