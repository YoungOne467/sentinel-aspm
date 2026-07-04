import unittest

from core.finding_contract import normalize_finding
from core.risk_model import score_finding


class RiskModelTests(unittest.TestCase):
    def test_verified_high_confidence_finding_scores_above_candidate_critical(self):
        verified_high = score_finding({
            "severity": "High",
            "verified": True,
            "confidence": "high",
            "evidence": "scratch/evidence/proof.txt",
            "type": "GraphQL Introspection Enabled",
        })
        candidate_critical = score_finding({
            "severity": "Critical",
            "confidence": "low",
            "verification_state": "candidate",
            "type": "Unverified RCE Candidate",
        })

        self.assertGreater(verified_high, candidate_critical)

    def test_normalized_finding_gets_numeric_risk_score(self):
        normalized = normalize_finding({
            "type": "Web Cache Poisoning",
            "severity": "High",
            "confidence": "high",
            "evidence_details": {"confidence_score": 6, "signals": ["marker_reflection"]},
        })

        self.assertIsInstance(normalized["risk_score"], int)
        self.assertGreaterEqual(normalized["risk_score"], 80)


if __name__ == "__main__":
    unittest.main()
