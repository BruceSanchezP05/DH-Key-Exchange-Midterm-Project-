"""Valid exchanges, active-session binding, and all required Eve attacks."""

import json
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authentication import (ProtocolError, canonical_bytes, parse_message,
                            sign_message)
from eve import authenticated_attack, unauthenticated_attack
from protocol import AuthenticatedDH


def edit_signed(raw: bytes, editor) -> bytes:
    payload, sig = parse_message(raw)
    editor(payload)
    return canonical_bytes({"payload": payload, "signature": sig.hex()})


def corrupt_signed(raw: bytes) -> bytes:
    payload, sig = parse_message(raw)
    wrong_sig = bytes([sig[0] ^ 1]) + sig[1:]
    return canonical_bytes({"payload": payload, "signature": wrong_sig.hex()})


class ProtocolTests(unittest.TestCase):
    def test_successful_fixture_and_generated(self):
        fx = AuthenticatedDH(fixture_mode=True)
        result = fx.complete_exchange()
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["secrets_match"])
        self.assertEqual(fx.last_alice_shared, 2)
        self.assertEqual(fx.last_bob_shared, 2)
        for bits in (16, 24, 32):
            with self.subTest(bits=bits):
                exchange = AuthenticatedDH()
                result = exchange.complete_exchange(bits)
                self.assertTrue(result["authenticated"])
                self.assertTrue(result["secrets_match"])
                self.assertEqual(result["p"].bit_length(), bits)

    def test_simple_attack_demonstrations(self):
        self.assertTrue(unauthenticated_attack()["Eve_knows_both"])
        self.assertIn("REJECTED", authenticated_attack())

    def test_modify_public_a(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        init = exchange.alice_initiate()
        tampered = edit_signed(init, lambda p: p.__setitem__("A", 9))
        with self.assertRaises(ProtocolError):
            exchange.bob_respond(tampered)
        self.assertFalse(exchange.bob_pending)

    def test_modify_public_b(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        response = exchange.bob_respond(exchange.alice_initiate())
        tampered = edit_signed(response,
                               lambda p: p["transcript"].__setitem__("B", 17))
        with self.assertRaises(ProtocolError):
            exchange.alice_finish(tampered)
        self.assertIsNone(exchange.last_alice_shared)
        self.assertFalse(exchange.alice_pending)

    def test_modify_p_or_g(self):
        for key, new in (("p", 29), ("g", 6)):
            with self.subTest(key=key):
                exchange = AuthenticatedDH(fixture_mode=True)
                init = exchange.alice_initiate()
                tampered = edit_signed(init, lambda p: p.__setitem__(key, new))
                with self.assertRaises(ProtocolError):
                    exchange.bob_respond(tampered)

    def test_modify_identity_labels(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        init = exchange.alice_initiate()
        tampered = edit_signed(init,
                               lambda p: p.__setitem__("initiator", "Eve"))
        with self.assertRaises(ProtocolError):
            exchange.bob_respond(tampered)

    def test_corrupt_signature(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        init = exchange.alice_initiate()
        with self.assertRaises(ProtocolError):
            exchange.bob_respond(corrupt_signed(init))

    def test_eve_signs_claiming_to_be_alice(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        init = exchange.alice_initiate()
        payload, _ = parse_message(init)
        eve_key = Ed25519PrivateKey.generate()
        forged = sign_message(payload, eve_key)
        with self.assertRaises(ProtocolError):
            exchange.bob_respond(forged)

    def test_replay_old_response_into_fresh_alice_session(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        init = exchange.alice_initiate()
        old_response = exchange.bob_respond(init)
        old_finish = exchange.alice_finish(old_response)
        exchange.bob_complete(old_finish)
        exchange.alice_initiate()
        with self.assertRaises(ProtocolError):
            exchange.alice_finish(old_response)
        self.assertFalse(exchange.alice_pending)

    def test_replay_old_finish_into_fresh_bob_session(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        old_response = exchange.bob_respond(exchange.alice_initiate())
        old_finish = exchange.alice_finish(old_response)
        exchange.bob_complete(old_finish)
        exchange.bob_respond(exchange.alice_initiate())
        with self.assertRaises(ProtocolError):
            exchange.bob_complete(old_finish)
        self.assertFalse(exchange.bob_pending)

    def test_duplicate_finish(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        response = exchange.bob_respond(exchange.alice_initiate())
        finish = exchange.alice_finish(response)
        exchange.bob_complete(finish)
        with self.assertRaises(ProtocolError):
            exchange.bob_complete(finish)

    def test_old_initiation_replay_is_cached(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        init = exchange.alice_initiate()
        response = exchange.bob_respond(init)
        exchange.bob_complete(exchange.alice_finish(response))
        with self.assertRaises(ProtocolError):
            exchange.bob_respond(init)

    def test_malformed_oversize_and_wrong_order(self):
        for malformed in (b"not JSON", b"x" * 4097,
                          b'{"payload":{},"payload":{},"signature":"x"}'):
            with self.subTest(malformed=malformed[:12]):
                exchange = AuthenticatedDH(fixture_mode=True)
                with self.assertRaises(ProtocolError):
                    exchange.bob_respond(malformed)
        exchange = AuthenticatedDH(fixture_mode=True)
        exchange.alice_initiate()
        bogus = sign_message({"message_type": "finish", "transcript": {}},
                              exchange.alice.signing_key)
        with self.assertRaises(ProtocolError):
            exchange.bob_respond(bogus)

    def test_extra_fields_wrong_types_and_nonce(self):
        for field, replacement in (("p", True), ("p", 2**80),
                                   ("nonce_A", "invalid"),
                                   ("g", "5")):
            with self.subTest(field=field):
                exchange = AuthenticatedDH(fixture_mode=True)
                init = exchange.alice_initiate()
                tampered = edit_signed(init,
                      lambda p: p.__setitem__(field, replacement))
                with self.assertRaises(ProtocolError):
                    exchange.bob_respond(tampered)
        exchange = AuthenticatedDH(fixture_mode=True)
        init = exchange.alice_initiate()
        with self.assertRaises(ProtocolError):
            exchange.bob_respond(edit_signed(init,
                lambda p: p.__setitem__("extra", 123)))

    def test_finish_tampering_and_abort(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        response = exchange.bob_respond(exchange.alice_initiate())
        finish = exchange.alice_finish(response)
        with self.assertRaises(ProtocolError):
            exchange.bob_complete(corrupt_signed(finish))
        self.assertIsNone(exchange.last_bob_shared)
        self.assertFalse(exchange.bob_pending)

    def test_initial_message_has_no_private_values(self):
        exchange = AuthenticatedDH(fixture_mode=True)
        init = exchange.alice_initiate()
        obj = json.loads(init)
        self.assertEqual(set(obj), {"payload", "signature"})
        self.assertEqual(set(obj["payload"]),
                         {"protocol", "message_type", "initiator", "responder",
                          "p", "g", "A", "nonce_A"})
        self.assertNotIn("a", obj["payload"])
        self.assertNotIn("b", obj["payload"])


if __name__ == "__main__":
    unittest.main()
