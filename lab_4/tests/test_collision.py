import unittest
from collision import find_collision, truncated_hash


class TestCollision(unittest.TestCase):

    def test_collision_found(self):
        result = find_collision(8, max_attempts=5000)
        self.assertIsNotNone(result)
        m1, m2, h = result
        self.assertNotEqual(m1, m2)
        self.assertEqual(truncated_hash(m1, 8), truncated_hash(m2, 8))

    def test_no_collision_for_high_bits(self):
        result = find_collision(24, max_attempts=100)
        if result is not None:
            m1, m2, h = result
            self.assertEqual(truncated_hash(m1, 24), truncated_hash(m2, 24))

    def test_truncated_hash_output_type(self):
        h = truncated_hash(b"test", 16)
        self.assertIsInstance(h, int)

    def test_find_collision_raises_on_bad_bits(self):
        with self.assertRaises(ValueError):
            find_collision(bits=0, max_attempts=100)


if __name__ == '__main__':
    unittest.main()