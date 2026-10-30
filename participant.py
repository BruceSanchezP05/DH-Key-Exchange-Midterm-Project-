"""Alice and Bob each keep a private signing key and trust the other's public key."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class Participant:
    def __init__(self, name):
        self.name = name
        self.signing_key = Ed25519PrivateKey.generate()  # Keep private.
        self.trusted_keys = {}  # Public identity keys trusted BEFORE messages.


def trusted_setup():
    """Set up trusted identity keys outside the simulated network."""
    alice = Participant("Alice")
    bob = Participant("Bob")
    alice.trusted_keys["Bob"] = bob.signing_key.public_key()
    bob.trusted_keys["Alice"] = alice.signing_key.public_key()
    return alice, bob
