import json
import tempfile
import unittest
from pathlib import Path

from adversarial_validation import (
    DEFAULT_SEED,
    REPORT_VERSION,
    campaign_control_api_contract,
    campaign_ledger_integrity,
    campaign_permissioned_consensus,
    campaign_sync_parser,
    main,
    run_adversarial_validation,
)


class AdversarialValidationTests(unittest.TestCase):
    def test_bounded_campaigns_pass(self):
        report = run_adversarial_validation(seed=DEFAULT_SEED, iterations=48, max_duration_sec=15.0)
        self.assertTrue(report.passed, report.to_dict())
        self.assertEqual(report.version, REPORT_VERSION)
        self.assertEqual(len(report.campaigns), 4)
        for campaign in report.campaigns:
            self.assertGreater(campaign.iterations, 0)
            self.assertEqual(campaign.unexpected_failures, [])

    def test_seed_reproduces_campaign_outcomes(self):
        first = run_adversarial_validation(seed=424242, iterations=24, max_duration_sec=15.0)
        second = run_adversarial_validation(seed=424242, iterations=24, max_duration_sec=15.0)
        first_shape = [
            (item.name, item.iterations, item.accepted, item.rejected, item.unexpected_failures)
            for item in first.campaigns
        ]
        second_shape = [
            (item.name, item.iterations, item.accepted, item.rejected, item.unexpected_failures)
            for item in second.campaigns
        ]
        self.assertEqual(first_shape, second_shape)

    def test_individual_campaigns_reject_adversarial_cases(self):
        campaigns = [
            campaign_sync_parser(1, 16),
            campaign_permissioned_consensus(2, 16),
            campaign_ledger_integrity(3, 16),
            campaign_control_api_contract(4, 16),
        ]
        for campaign in campaigns:
            self.assertTrue(campaign.passed, campaign)
            self.assertGreater(campaign.rejected, 0, campaign.name)

    def test_cli_writes_machine_readable_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "adversarial-validation.json"
            code = main([
                "--seed", "5150",
                "--iterations", "12",
                "--max-duration-sec", "15",
                "--output", str(target),
            ])
            self.assertEqual(code, 0)
            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertTrue(payload["passed"])
            self.assertEqual(payload["version"], REPORT_VERSION)
            self.assertEqual(payload["seed"], 5150)
            self.assertEqual(payload["summary"]["unexpected_failure_count"], 0)

    def test_static_security_corpora_are_present(self):
        root = Path(__file__).resolve().parent / "security_corpus"
        sync_corpus = json.loads((root / "sync_malformed.json").read_text(encoding="utf-8"))
        ledger_corpus = json.loads((root / "ledger_corruption_cases.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(sync_corpus), 10)
        self.assertGreaterEqual(len(ledger_corpus), 10)


if __name__ == "__main__":
    unittest.main()
