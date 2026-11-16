"""Actual loopback socket admission tests; no physical hardware, no internet."""
import json, socket, statistics, threading, time, unittest
from bounded_tcp_admission import BoundedTCPAdmission

class AdmissionRuntimeTests(unittest.TestCase):
    def test_saturated_sessions_reject_and_recover(self):
        release=threading.Event(); entered=threading.Event(); started=0; lock=threading.Lock()
        def handler(conn):
            nonlocal started
            with lock:
                started+=1
                if started==2: entered.set()
            release.wait(3)
        admission=BoundedTCPAdmission(handler,max_clients=2)
        sockets=[]
        try:
            for _ in range(2):
                client,server=socket.socketpair(); sockets.append(client)
                self.assertTrue(admission.dispatch(server))
            self.assertTrue(entered.wait(2))
            latencies=[]
            for _ in range(100):
                client,server=socket.socketpair(); sockets.append(client)
                begin=time.perf_counter_ns()
                self.assertFalse(admission.dispatch(server))
                latencies.append((time.perf_counter_ns()-begin)/1e6)
                self.assertEqual(server.fileno(),-1)
            self.assertEqual(admission.active,2)
            self.assertEqual(admission.rejected,100)
            release.set()
            deadline=time.monotonic()+2
            while admission.active and time.monotonic()<deadline: time.sleep(.001)
            self.assertEqual(admission.active,0)
            client,server=socket.socketpair(); sockets.append(client)
            self.assertTrue(admission.dispatch(server))
            print('RUNTIME_OBSERVATION='+json.dumps({'rejected':100,'peak_active':2,'median_rejection_ms':round(statistics.median(latencies),5),'max_rejection_ms':round(max(latencies),5),'recovered':True,'environment':'local socketpair Linux, no network or vehicle hardware'}))
        finally:
            release.set()
            for sock in sockets: sock.close()
    def test_handler_exception_releases_slot(self):
        finished=threading.Event()
        def fail(conn):
            finished.set()
            raise RuntimeError('synthetic worker fault')
        admission=BoundedTCPAdmission(fail,max_clients=1)
        client,server=socket.socketpair()
        try:
            self.assertTrue(admission.dispatch(server)); self.assertTrue(finished.wait(1))
            deadline=time.monotonic()+2
            while admission.active and time.monotonic()<deadline: time.sleep(.001)
            self.assertEqual(admission.active,0)
        finally: client.close()
if __name__=='__main__': unittest.main()
