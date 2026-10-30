"""Handle Alice and Bob's authenticated key exchange."""

import secrets
import time
from authentication import (
    PROTOCOL_LABEL, ProtocolError, check_followup, check_initiation,
    parse_message, sign_message, verify_message,
)
from modular_math import modular_exponentiation
from parameters import (
    find_generator, generate_prime, make_private_public,
    prime_factors, validate_modulus, verify_generator,
)
from participant import trusted_setup


class AuthenticatedDH:
    def __init__(self, *, fixture_mode=False):
        # Set up Alice and Bob.
        self.alice, self.bob = trusted_setup()
        self.fixture_mode = fixture_mode

        # Store session information.
        self.alice_pending = {}
        self.bob_pending = {}
        self.seen_initiations = set()
        self.completed_alice = set()
        self.completed_bob = set()
        self.last_alice_shared = None
        self.last_bob_shared = None
        self.setup_timings = {}
        self.last_status = {}

    def _abort_alice(self):
        """Clear Alice's session."""
        self.alice_pending.clear()
        self.last_alice_shared = None

    def _abort_bob(self):
        """Clear Bob's session."""
        self.bob_pending.clear()
        self.last_bob_shared = None

    def alice_initiate(self, bits=16):
        """Alice starts the exchange."""
        if self.alice_pending:
            raise ProtocolError("Alice already has a pending session")
        self.last_alice_shared = None
        self.last_bob_shared = None

        if self.fixture_mode:
            # Use the test example.
            p, g = 23, 5
            validate_modulus(p, allow_fixture=True)
            if prime_factors(p - 1) != {2, 11}:
                raise RuntimeError("invalid teaching example")
            a, A = make_private_public(p, g, fixed_private=6)
            self.setup_timings = {"prime": 0.0, "factors": 0.0, "generator": 0.0}
        else:
            # Record calculation times.
            start = time.perf_counter()
            p = generate_prime(bits)
            after_prime = time.perf_counter()
            factors = prime_factors(p - 1)
            after_factors = time.perf_counter()
            g = find_generator(p, factors=factors)
            after_generator = time.perf_counter()
            a, A = make_private_public(p, g)
            self.setup_timings = {
                "prime": after_prime - start,
                "factors": after_factors - after_prime,
                "generator": after_generator - after_factors,
            }

        nonce_a = secrets.token_bytes(32).hex()
        payload = {
            "protocol": PROTOCOL_LABEL, "message_type": "init",
            "initiator": "Alice", "responder": "Bob",
            "p": p, "g": g, "A": A, "nonce_A": nonce_a,
        }
        # Save Alice's values.
        self.alice_pending[nonce_a] = {
            "p": p, "g": g, "private": a, "public": A, "nonce_A": nonce_a,
        }
        self.last_status = {"init": "SIGNED"}
        return sign_message(payload, self.alice.signing_key)

    def bob_respond(self, initiation):
        """Bob checks Alice's message and responds."""
        try:
            if self.bob_pending:
                raise ProtocolError("Bob already has a pending session")

            payload, signature = parse_message(initiation)
            check_initiation(payload, fixture_mode=self.fixture_mode)
            verify_message(payload, signature, self.bob.trusted_keys["Alice"])

            p = payload["p"]
            g = payload["g"]
            A = payload["A"]
            nonce_a = payload["nonce_A"]
            if nonce_a in self.seen_initiations:
                raise ProtocolError("replayed initiation")

            # Check the prime and generator.
            validate_modulus(p, allow_fixture=self.fixture_mode)
            factors = prime_factors(p - 1)
            if not verify_generator(g, p, factors, allow_fixture=self.fixture_mode):
                raise ProtocolError("invalid primitive generator")

            fixed_b = 15 if self.fixture_mode else None
            b, B = make_private_public(p, g, fixed_private=fixed_b)
            nonce_b = secrets.token_bytes(32).hex()
            transcript = {
                "protocol": PROTOCOL_LABEL,
                "initiator": "Alice", "responder": "Bob",
                "p": p, "g": g, "A": A, "B": B,
                "nonce_A": nonce_a, "nonce_B": nonce_b,
            }
            response = {"message_type": "response", "transcript": transcript}
            signed_response = sign_message(response, self.bob.signing_key)
            self.bob_pending[nonce_a] = {
                "p": p, "private": b, "alice_public": A,
                "transcript": transcript,
            }
            self.seen_initiations.add(nonce_a)
            self.last_status["init_verify"] = "VALID"
            return signed_response
        except (ProtocolError, ValueError) as error:
            self._abort_bob()
            raise ProtocolError(str(error)) from error

    def alice_finish(self, response_message):
        """Alice checks Bob's message and finishes."""
        try:
            payload, signature = parse_message(response_message)
            transcript = check_followup(payload, "response",
                                        fixture_mode=self.fixture_mode)
            nonce_a = transcript["nonce_A"]
            if nonce_a not in self.alice_pending:
                raise ProtocolError("response is stale or unexpected")
            pending = self.alice_pending[nonce_a]

            # Check Alice's session values.
            if (transcript["p"] != pending["p"] or
                transcript["g"] != pending["g"] or
                transcript["A"] != pending["public"] or
                transcript["nonce_A"] != pending["nonce_A"]):
                raise ProtocolError("response does not match Alice's session")

            verify_message(payload, signature, self.alice.trusted_keys["Bob"])
            shared = modular_exponentiation(transcript["B"],
                                             pending["private"], pending["p"])
            finish = {"message_type": "finish", "transcript": transcript}
            signed_finish = sign_message(finish, self.alice.signing_key)
            self.last_alice_shared = shared
            self.completed_alice.add(nonce_a)
            del self.alice_pending[nonce_a]
            self.last_status["response_verify"] = "VALID"
            return signed_finish
        except (ProtocolError, ValueError) as error:
            self._abort_alice()
            raise ProtocolError(str(error)) from error

    def bob_complete(self, finish_message):
        """Bob checks the final message."""
        try:
            payload, signature = parse_message(finish_message)
            transcript = check_followup(payload, "finish",
                                        fixture_mode=self.fixture_mode)
            nonce_a = transcript["nonce_A"]
            if nonce_a in self.completed_bob or nonce_a not in self.bob_pending:
                raise ProtocolError("finish is duplicate, stale, or unexpected")
            pending = self.bob_pending[nonce_a]
            if transcript != pending["transcript"]:
                raise ProtocolError("finish does not match Bob's session")

            verify_message(payload, signature, self.bob.trusted_keys["Alice"])
            shared = modular_exponentiation(pending["alice_public"],
                                             pending["private"], pending["p"])
            self.last_bob_shared = shared
            self.completed_bob.add(nonce_a)
            del self.bob_pending[nonce_a]
            self.last_status["finish_verify"] = "VALID"
            return shared
        except (ProtocolError, ValueError) as error:
            self._abort_bob()
            raise ProtocolError(str(error)) from error

    def complete_exchange(self, bits=16):
        """Run the full exchange."""
        initiation = self.alice_initiate(bits)
        response = self.bob_respond(initiation)
        finish = self.alice_finish(response)
        self.bob_complete(finish)
        original_payload, _ = parse_message(initiation)
        auth_ok = (self.last_status.get("init_verify") == "VALID" and
                   self.last_status.get("response_verify") == "VALID" and
                   self.last_status.get("finish_verify") == "VALID")
        return {
            "p": original_payload["p"],
            "g": original_payload["g"],
            "authenticated": auth_ok,
            "secrets_match": self.last_alice_shared is not None and
                             self.last_alice_shared == self.last_bob_shared,
            "timings": dict(self.setup_timings),
        }
