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
    result = find_collision(24, max_attempts=10)
    self.assertIsNone(result)

    def test_truncated_hash_output_type(self):
        h = truncated_hash(b"test", 16)
        self.assertIsInstance(h, int)

    def test_find_collision_raises_on_bad_bits(self):
        with self.assertRaises(ValueError):
            find_collision(bits=0, max_attempts=100)

    def test_find_collision_raises_on_bits_too_high(self):
    with self.assertRaises(ValueError):
        find_collision(bits=33, max_attempts=100)

    def test_find_collision_raises_on_wrong_type(self):
        with self.assertRaises(TypeError):
            find_collision(bits="8", max_attempts=100)

    def test_truncated_hash_boundary_bits(self):
        h1 = truncated_hash(b"data", 1)
        h32 = truncated_hash(b"data", 32)
        self.assertIn(h1, (0, 1))
        self.assertLess(h32, 2**32)

    def test_truncated_hash_raises_on_non_bytes(self):
        with self.assertRaises(TypeError):
            truncated_hash("not bytes", 16)

if __name__ == '__main__':
    unittest.main()