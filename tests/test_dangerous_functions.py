import unittest

from vea_aeg.dangerous_functions import (
    DEFAULT_DANGEROUS_FUNCTIONS,
    normalize_function_names,
    parse_dangerous_functions,
)


class DangerousFunctionTests(unittest.TestCase):
    def test_default_list_contains_common_overflow_sources(self):
        self.assertIn("gets", DEFAULT_DANGEROUS_FUNCTIONS)
        self.assertIn("strcpy", DEFAULT_DANGEROUS_FUNCTIONS)
        self.assertIn("read", DEFAULT_DANGEROUS_FUNCTIONS)

    def test_parse_csv_and_deduplicate(self):
        self.assertEqual(parse_dangerous_functions("gets, read ; gets"), ("gets", "read"))

    def test_normalize_skips_comments_and_blanks(self):
        self.assertEqual(normalize_function_names(["", "# comment", "scanf"]), ("scanf",))


if __name__ == "__main__":
    unittest.main()

