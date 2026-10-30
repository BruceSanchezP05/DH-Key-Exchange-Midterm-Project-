
"""Generate primes and find generators."""

import secrets
from Crypto.Util.number import getPrime, isPrime
from modular_math import modular_exponentiation


def validate_bits(bits):
    """Check prime size."""
    if type(bits) is not int or bits < 16 or bits > 32:
        raise ValueError("prime size must be between 16 and 32 bits")


def generate_prime(bits=16):
    """Generate a prime number."""
    validate_bits(bits)
    p = getPrime(bits, randfunc=secrets.token_bytes)
    if p.bit_length() != bits or p % 2 == 0:
        raise RuntimeError("library did not return the requested prime")
    return p


def validate_modulus(p, *, allow_fixture=False):
    """Check if the modulus is valid."""
    if type(p) is not int:
        raise ValueError("modulus must be an integer")
    if not (allow_fixture and p == 23):
        validate_bits(p.bit_length())
    if p <= 2 or p % 2 == 0 or not isPrime(p):
        raise ValueError("modulus must be an odd prime")
    return True


def prime_factors(n):
    """Find prime factors."""
    if type(n) is not int or n < 1:
        raise ValueError("factorization input must be a positive integer")

    factors = set()
    if n % 2 == 0:
        factors.add(2)
        while n % 2 == 0:
            n //= 2

    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            factors.add(divisor)
            while n % divisor == 0:
                n //= divisor
        divisor += 2

    if n > 1:
        factors.add(n)
    return factors


def generator_passes_tests(g, p, factors):
    """Test if the generator is valid."""
    for factor in factors:
        exponent = (p - 1) // factor
        if modular_exponentiation(g, exponent, p) == 1:
            return False
    return True


def verify_generator(g, p, factors=None, *, allow_fixture=False):
    """Verify the generator."""
    validate_modulus(p, allow_fixture=allow_fixture)
    if type(g) is not int or g < 2 or g > p - 2:
        return False
    real_factors = prime_factors(p - 1)
    if factors is not None and factors != real_factors:
        return False
    return generator_passes_tests(g, p, real_factors)


def find_generator(p, *, allow_fixture=False, factors=None):
    """Find a valid generator."""
    validate_modulus(p, allow_fixture=allow_fixture)
    real_factors = prime_factors(p - 1)
    if factors is not None and factors != real_factors:
        raise ValueError("prime factor set does not match p - 1")
    for g in range(2, p - 1):
        if generator_passes_tests(g, p, real_factors):
            return g
    raise RuntimeError("could not find a generator")


def make_private_public(p, g, *, fixed_private=None):
    """Generate private and public values."""
    if fixed_private is not None:
        if type(fixed_private) is not int or not 2 <= fixed_private <= p - 2:
            raise ValueError("invalid test private exponent")
        private = fixed_private
        public = modular_exponentiation(g, private, p)
        if not 2 <= public <= p - 2:
            raise ValueError("test public value outside permitted range")
        return private, public

    # Keep trying until the public value is valid.
    while True:
        private = secrets.randbelow(p - 3) + 2
        public = modular_exponentiation(g, private, p)
        if 2 <= public <= p - 2:
            return private, public
