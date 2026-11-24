import unittest
from research_contracts.can_attack_protocol import Frame, generate_scenario

class AttackProtocolTests(unittest.TestCase):
    def setUp(self):
        self.frames = [Frame(i*1000, 0x100+i, "AABB") for i in range(1,21)]

    def test_deterministic(self):
        self.assertEqual(generate_scenario(self.frames,seed=42,mode="spoof"),generate_scenario(self.frames,seed=42,mode="spoof"))

    def test_exact_injection_count(self):
        for mode in ("replay","spoof","false_data"):
            result=generate_scenario(self.frames,seed=2,mode=mode)
            self.assertEqual(result["injected_count"],4)
            self.assertEqual(len(result["records"]),20)
            self.assertEqual([x["timestamp_ns"] for x in result["records"]],[f.timestamp_ns for f in self.frames])

    def test_spoof_changes_only_id(self):
        result=generate_scenario(self.frames,seed=2,mode="spoof")
        for before,after in zip(self.frames,result["records"]):
            self.assertEqual(before.payload_hex,after["payload_hex"])
            self.assertEqual(after["arbitration_id"] != before.arbitration_id,after["injected"])

    def test_false_data_changes_only_payload(self):
        result=generate_scenario(self.frames,seed=2,mode="false_data")
        for before,after in zip(self.frames,result["records"]):
            self.assertEqual(before.arbitration_id,after["arbitration_id"])
            self.assertEqual(before.payload_hex != after["payload_hex"],after["injected"])

    def test_reject_bad_input(self):
        with self.assertRaises(ValueError): Frame(0,0x20000000,"AA")
        with self.assertRaises(ValueError): Frame(0,0x100,"GG")
        with self.assertRaises(ValueError): generate_scenario(self.frames[::-1],seed=1,mode="replay")
        with self.assertRaises(ValueError): generate_scenario(self.frames,seed=1,mode="dos")
        with self.assertRaises(ValueError): generate_scenario(self.frames,seed=1,mode="spoof",attack_fraction=0)

    def test_replay_is_not_claimed_real_ground_truth(self):
        result=generate_scenario(self.frames,seed=9,mode="replay")
        self.assertEqual(result["ground_truth"],"synthetic_injection_only")
        self.assertTrue(all(x["source_index"]==i for i,x in enumerate(result["records"])))

if __name__=="__main__": unittest.main()
