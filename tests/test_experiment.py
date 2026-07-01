import unittest

from vea_aeg.experiment import ExperimentRow, markdown_table


class ExperimentTests(unittest.TestCase):
    def test_markdown_table_uses_paper_columns(self):
        table = markdown_table(
            [ExperimentRow("sample", "√", "x", "N/R", "N/R", "N/R", "0.001s")]
        )
        self.assertIn("| Challenge | NX | PIE | AEGAngr | Zeratool | BofAEG | VEA-AEG |", table)
        self.assertIn("| sample | √ | x | N/R | N/R | N/R | 0.001s |", table)


if __name__ == "__main__":
    unittest.main()

