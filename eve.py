"""Show what Eve can do WITHOUT authentication, then WITH signatures."""

from authentication import ProtocolError, canonical_bytes, parse_message
from modular_math import modular_exponentiation
from protocol import AuthenticatedDH


def unauthenticated_attack():
    """Follow the professor's small example (p=23, g=5)."""
    p, g = 23, 5
    alice_private, bob_private = 6, 15
    eve_private_1, eve_private_2 = 3, 7

    # Alice and Bob's real public values are A=8, B=19.
    alice_public = modular_exponentiation(g, alice_private, p)
    bob_public = modular_exponentiation(g, bob_private, p)

    # Eve substitutes these two public values: E1=10, E2=17.
    e1 = modular_exponentiation(g, eve_private_1, p)
    e2 = modular_exponentiation(g, eve_private_2, p)

    # Alice and Bob end up with DIFFERENT secrets. Eve knows both.
    alice_secret = modular_exponentiation(e1, alice_private, p)
    bob_secret = modular_exponentiation(e2, bob_private, p)
    eve_secret_with_alice = modular_exponentiation(alice_public, eve_private_1, p)
    eve_secret_with_bob = modular_exponentiation(bob_public, eve_private_2, p)

    assert (alice_public, bob_public, e1, e2) == (8, 19, 10, 17)
    assert alice_secret == eve_secret_with_alice == 6
    assert bob_secret == eve_secret_with_bob == 15
    return {"Alice_public": alice_public, "Bob_public": bob_public,
            "E1": e1, "E2": e2, "Alice_secret": alice_secret,
            "Bob_secret": bob_secret, "Eve_knows_both": True}


def authenticated_attack():
    """Eve changes B=19 to B=17 without having Bob's private signing key."""
    exchange = AuthenticatedDH(fixture_mode=True)
    initiation = exchange.alice_initiate()
    response = exchange.bob_respond(initiation)

    # Unpack Bob's signed message, modify B, but keep the OLD signature.
    payload, old_signature = parse_message(response)
    payload["transcript"]["B"] = 17
    altered = canonical_bytes({"payload": payload,
                               "signature": old_signature.hex()})

    try:
        exchange.alice_finish(altered)
    except ProtocolError:
        return "REJECTED: Bob response signature INVALID; exchange aborted"
    raise AssertionError("Eve's changed response must not be accepted")
