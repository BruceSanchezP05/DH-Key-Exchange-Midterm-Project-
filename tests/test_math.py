"""Deterministic math tests and separate PyCryptodome integration tests."""

import unittest
from modular_math import modular_exponentiation
from parameters import (
    find_generator, generate_prime, prime_factors, validate_bits,
    validate_modulus, verify_generator,
)


class SquareMultiplyTests(unittest.TestCase):
    def test_fixture(self):
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)

    def test_zero_exponent(self):
        self.assertEqual(modular_exponentiation(5, 0, 23), 1)
        self.assertEqual(modular_exponentiation(5, 0, 1), 0)

    def test_negative_base(self):
        self.assertEqual(modular_exponentiation(-5, 7, 23), pow(-5, 7, 23))

    def test_against_reference_pow(self):
        for base in (-23, -5, 0, 1, 2, 19):
            for exponent in (0, 1, 2, 7, 30, 100):
                for modulus in (1, 2, 23, 65537):
                    with self.subTest(base=base, exponent=exponent, modulus=modulus):
                        self.assertEqual(modular_exponentiation(base, exponent, modulus),
                                         pow(base, exponent, modulus))

    def test_invalid_inputs(self):
        for bad_args in [(5, -1, 23), (5, 6, 0), (5, 6, -1)]:
            with self.subTest(bad_args=bad_args), self.assertRaises(ValueError):
                modular_exponentiation(*bad_args)
        for bad_args in [(True, 2, 23), (5, False, 23),
                         (5, 6, True), (5.0, 6, 23), ("5", 6, 23)]:
            with self.subTest(bad_args=bad_args), self.assertRaises(TypeError):
                modular_exponentiation(*bad_args)


class PrimeAndGeneratorTests(unittest.TestCase):
    def test_prime_range(self):
        for bits in (16, 24, 32):
            with self.subTest(bits=bits):
                p = generate_prime(bits)
                self.assertEqual(p.bit_length(), bits)
                self.assertEqual(p % 2, 1)
                self.assertTrue(validate_modulus(p))

    def test_bad_bit_sizes(self):
        for size in (True, False, 12, 33, "16", 16.0, None):
            with self.subTest(size=size), self.assertRaises(ValueError):
                validate_bits(size)
            with self.subTest(size=size), self.assertRaises(ValueError):
                generate_prime(size)

    def test_received_bad_moduli(self):
        for p in (32769, True, "65521", 21, 2, 65536):
            with self.subTest(p=p), self.assertRaises(ValueError):
                validate_modulus(p)
        self.assertTrue(validate_modulus(23, allow_fixture=True))
        with self.assertRaises(ValueError):
            validate_modulus(23)

    def test_factorization(self):
        self.assertEqual(prime_factors(1), set())
        self.assertEqual(prime_factors(22), {2, 11})
        self.assertEqual(prime_factors(65536), {2})
        self.assertEqual(prime_factors(2 * 2 * 3 * 3 * 5), {2, 3, 5})
        for value in (0, -1, True, 2.4, "10"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                prime_factors(value)

    def test_generators(self):
        self.assertFalse(verify_generator(2, 23, allow_fixture=True))
        self.assertTrue(verify_generator(5, 23, allow_fixture=True))
        self.assertEqual(find_generator(23, allow_fixture=True), 5)
        self.assertTrue(verify_generator(3, 65537))
        self.assertEqual(find_generator(65537), 3)
        self.assertFalse(verify_generator(5, 23, {2}, allow_fixture=True))
        with self.assertRaises(ValueError):
            find_generator(23, allow_fixture=True, factors={2})


if __name__ == "__main__":
    unittest.main()
