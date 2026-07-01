import unittest

from vea_aeg.basic_inventory import extract_ascii_strings, read_c_string


class BasicInventoryTests(unittest.TestCase):
    def test_read_c_string(self):
        self.assertEqual(read_c_string(b"abc\x00def", 0), "abc")

    def test_extract_ascii_strings(self):
        self.assertIn("hello-world", extract_ascii_strings(b"\x00hello-world\x00", min_length=5))


if __name__ == "__main__":
    unittest.main()

