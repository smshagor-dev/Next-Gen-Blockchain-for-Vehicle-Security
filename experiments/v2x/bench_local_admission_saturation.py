"""Real socketpair resource baseline; does not measure authentication or network stack."""
import argparse, json, os, resource, socket, statistics, threading, time
from bounded_tcp_admission import BoundedTCPAdmission

def run(max_clients=4, attempts=1000, repetitions=5):
    results=[]
    for seed in range(repetitions):
        gate=threading.Event(); ready=threading.Barrier(max_clients+1)
        def blocked(conn):
            ready.wait(timeout=5)
            gate.wait(timeout=10)
        admission=BoundedTCPAdmission(blocked,max_clients=max_clients)
        clients=[]
        try:
            for _ in range(max_clients):
                client,server=socket.socketpair(); clients.append(client)
                assert admission.dispatch(server)
            ready.wait(timeout=5)
            before_cpu=time.process_time_ns(); before_wall=time.perf_counter_ns()
            latencies=[]
            for _ in range(attempts):
                client,server=socket.socketpair()
                start=time.perf_counter_ns()
                accepted=admission.dispatch(server)
                latencies.append(time.perf_counter_ns()-start)
                assert not accepted and server.fileno()==-1
                client.close()
            cpu=(time.process_time_ns()-before_cpu)/1e6
            wall=(time.perf_counter_ns()-before_wall)/1e6
            assert admission.active==max_clients and admission.rejected==attempts
            results.append({'replicate':seed,'attempts':attempts,'active':admission.active,'rejected':admission.rejected,'cpu_ms':round(cpu,3),'wall_ms':round(wall,3),'median_reject_us':round(statistics.median(latencies)/1e3,3),'p99_reject_us':round(sorted(latencies)[int(.99*(len(latencies)-1))]/1e3,3),'ru_maxrss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})
        finally:
            gate.set()
            for client in clients: client.close()
            deadline=time.monotonic()+3
            while admission.active and time.monotonic()<deadline: time.sleep(.001)
            assert admission.active==0
    return {'study':'local socketpair admission saturation only','publishable':False,'python':os.sys.version.split()[0],'max_clients':max_clients,'replicates':results,'limitations':['Not TCP network latency','No MAC/ledger/actuator path','Single process, sequential attack attempts','maxrss is process high-water mark not isolated per trial']}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--clients',type=int,default=4);p.add_argument('--attempts',type=int,default=1000);p.add_argument('--repetitions',type=int,default=5);a=p.parse_args()
    if not 1<=a.clients<=64 or not 1<=a.attempts<=100000 or not 2<=a.repetitions<=100: p.error('bounds exceeded')
    print(json.dumps(run(a.clients,a.attempts,a.repetitions),sort_keys=True,indent=2))
