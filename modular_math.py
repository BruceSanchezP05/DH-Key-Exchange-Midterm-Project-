"""Square-and-multiply calculation."""
def modular_exponentiation(base, exponent, modulus):
    """Calculate the power using modulus."""
    # Check inputs.
    if type(base) is not int or type(exponent) is not int or type(modulus) is not int:
        raise TypeError("base, exponent, and modulus must all be integers")
    if exponent < 0:
        raise ValueError("exponent must be nonnegative")
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    # Square and multiply.
    result = 1 % modulus
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent // 2
    return result
