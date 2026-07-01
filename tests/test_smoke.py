import unittest

from vea_aeg.smoke import run_smoke_flow


class SmokeFlowTests(unittest.TestCase):
    def test_smoke_flow_returns_findings_and_plans(self):
        report = run_smoke_flow()
        self.assertGreaterEqual(report.dangerous_functions_count, 1)
        self.assertGreaterEqual(len(report.simulated_findings), 2)
        self.assertEqual(len(report.simulated_findings), len(report.exploit_plans))


if __name__ == "__main__":
    unittest.main()

