import unittest
from research_contracts.seed_cluster_inference import cluster_paired_interval as ci


def rows(values):
    result = []
    for seed, diffs in enumerate(values):
        for incident, (a, b) in enumerate(diffs):
            for protocol, value in [('a', a), ('b', b)]:
                result.append(dict(seed=seed, incident=incident, protocol=protocol, outcome=value))
    return result


class ClusterInferenceTests(unittest.TestCase):
    def test_deterministic_constant_difference(self):
        r = rows([[(1, 0)] * 3, [(1, 0)] * 8, [(1, 0)]])
        result = ci(r, 'a', 'b', 'outcome', repetitions=100)
        self.assertEqual((result['risk_difference'], result['ci_lower'], result['ci_upper']), (1, 1, 1))
        self.assertEqual(result['paired_incidents'], 12)

    def test_cluster_resampling_preserves_unequal_cluster_sizes(self):
        r = rows([[(1, 0)] * 9, [(0, 1)]])
        result = ci(r, 'a', 'b', 'outcome', repetitions=300, bootstrap_seed=5)
        self.assertAlmostEqual(result['risk_difference'], .8)
        self.assertEqual(result, ci(r, 'a', 'b', 'outcome', repetitions=300, bootstrap_seed=5))
        self.assertEqual((result['ci_lower'], result['ci_upper']), (-1, 1))

    def test_reject_missing_duplicate_nonbinary_and_single_cluster(self):
        r = rows([[(1, 0)], [(0, 1)]])
        for bad in (r[:-1], r + [r[0]], [dict(r[0], outcome=float('nan'))] + r[1:]):
            with self.assertRaises(ValueError):
                ci(bad, 'a', 'b', 'outcome', repetitions=100)
        with self.assertRaises(ValueError):
            ci(rows([[(1, 0)]]), 'a', 'b', 'outcome', repetitions=100)

    def test_no_iid_incident_resampling(self):
        r = rows([[(1, 0)] * 20, [(0, 1)] * 20])
        result = ci(r, 'a', 'b', 'outcome', repetitions=200)
        self.assertEqual(result['risk_difference'], 0)
        self.assertEqual((result['ci_lower'], result['ci_upper']), (-1, 1))

if __name__ == '__main__':
    unittest.main()
