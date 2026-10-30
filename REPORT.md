**# CSC-364 Midterm 2 Project Report
##This Python project shows how Alice and Bob establish a shared Diffie-Hellman secret using a public prime and generator. It also shows why they must authenticate messages: without authentication, Eve can replace the public values and create separate secrets with both parties.

## Algorithms and worked examples

**Square-and-multiply:** My `modular_exponentiation` function starts with `result = 1 % modulus`, repeatedly squares the base, multiplies the result only for odd exponent bits, and halves the exponent using integer division. It takes `O(log exponent)` loop iterations. For the example `5^6 mod 23`, it returns `8`. The source code does not call Python's three-argument `pow` for this algorithm.

**Primes and generators:** The program gets a prime `p` of exactly the requested 16-32 bit length from PyCryptodome. Bob separately checks its type, bit size, and library primality before use. My `prime_factors` function tries division by 2 and then odd divisors to obtain the distinct prime factors of `p-1`. For `p=23`, `22=2*11`, so the factor set is `{2,11}`. A candidate generator `g` is accepted only when `g^((p-1)/r) mod p != 1` for **every** distinct prime factor `r`. For `p=23`, `g=2` fails, while `g=5` passes. For `p=65537`, the factors of `p-1` are `{2}` and `g=3` passes.

**DH agreement:** In the teaching example, `p=23`, `g=5`, Alice's private value `a=6`, and Bob's private value `b=15`. Alice publishes `A=8`, Bob publishes `B=19`, and both calculate `2` locally as their shared secret. Ordinary runs generate fresh exponents using Python's `secrets` module.

**Authentication:** Alice signs the initiation, Bob signs a complete transcript that includes both public values and both fresh nonces, and Alice signs a finish over the same transcript. Each receiver verifies against a public signing key trusted before the exchange. Unexpected fields, changed values, bad signatures, mismatched nonces, wrong order, and replays cause rejection. Bob does not complete until the signed finish is valid. This authenticates the transcript but is **not** explicit proof that the peer calculated the shared integer.

**Eve's attack:** Without signatures, Eve substitutes `10` for Bob's public value and `17` for Alice's. Alice gets secret `6`, Bob gets `15`, and Eve calculates both. With signatures, changing Bob's public value from `19` to `17` without changing Bob's valid signature makes verification fail, so the exchange is aborted.

## Tests and timing measurements

Run `python -m unittest discover -s tests -v` to test the algorithms and attacks.
Run `python collect_evidence.py` on the student's computer. This runs all nine trials,
saves output in `sample_outputs/`, and fills in the actual results below.

<!-- AUTO-RESULTS-START -->
### Measured results (generated on this computer)

- OS: Windows-11-10.0.26200-SP0
- Python: 3.13.9
- cryptography: 46.0.4
- PyCryptodome: 3.23.0

| Bits | Trial | Prime (s) | Factor (s) | Generator (s) | Authenticated | Secrets match |
|---|---|---|---|---|---|---|
| 16 | 1 | 0.0003165999660268426 | 9.700015652924776e-06 | 0.0003024999750778079 | YES | YES |
| 16 | 2 | 0.00027570000384002924 | 5.499983672052622e-06 | 0.0002756000030785799 | YES | YES |
| 16 | 3 | 0.00039679999463260174 | 3.900029696524143e-06 | 0.00044600002001971006 | YES | YES |
| 24 | 1 | 0.0007764000329189003 | 4.799978341907263e-06 | 0.0007307000341825187 | YES | YES |
| 24 | 2 | 0.0007714999956078827 | 2.300000051036477e-05 | 0.0007995999767445028 | YES | YES |
| 24 | 3 | 0.0007646000012755394 | 0.00014220003504306078 | 0.000893999997060746 | YES | YES |
| 32 | 1 | 0.0009045000188052654 | 0.00118530000327155 | 0.00222690001828596 | YES | YES |
| 32 | 2 | 0.0010210000327788293 | 0.00045930000487715006 | 0.001446699956431985 | YES | YES |
| 32 | 3 | 0.0008968000183813274 | 4.329998046159744e-05 | 0.0009799000108614564 | YES | YES |

### Timing variation
- 16-bit prime generation: min 0.000276s, max 0.000397s, average 0.000330s
- 16-bit factorization: min 0.000004s, max 0.000010s, average 0.000006s
- 16-bit generator search: min 0.000276s, max 0.000446s, average 0.000341s
- 24-bit prime generation: min 0.000765s, max 0.000776s, average 0.000771s
- 24-bit factorization: min 0.000005s, max 0.000142s, average 0.000057s
- 24-bit generator search: min 0.000731s, max 0.000894s, average 0.000808s
- 32-bit prime generation: min 0.000897s, max 0.001021s, average 0.000941s
- 32-bit factorization: min 0.000043s, max 0.001185s, average 0.000563s
- 32-bit generator search: min 0.000980s, max 0.002227s, average 0.001551s

These nine trials were generated with real random primes, so the timings can change from one run to another. Smaller prime factors or simpler generators can be found more quickly; no exact runtime is expected.
<!-- AUTO-RESULTS-END -->

## Trust assumptions and limitations

Eve can intercept, alter, and replay public messages but cannot change Alice/Bob's preconfigured trusted Ed25519 verification keys or steal their private signing keys. The program only models a local exchange. It does not use sockets, encrypt messages, or provide explicit key confirmation. The assigned 16-32 bit primes are tiny, so secrets can be recovered by brute force. Trial-division factorization also gets less practical with larger groups. Our square-and-multiply code is not constant-time. A real system would use a standard authenticated protocol and well-reviewed cryptographic libraries.

## Research comparison: finite-field DH versus ECDH (approximately 400 words)

Finite-field Diffie-Hellman (DH) and elliptic-curve Diffie-Hellman (ECDH) both allow two parties to agree on shared secret material without sending their private keys to each other. The main difference is the math. In this classroom project, we use a prime number `p` and a generator `g`. Alice and Bob raise `g` to their private powers and reduce the results modulo `p`. This is called modular exponentiation. ECDH instead uses scalar multiplication of points on an elliptic curve. Both methods depend on mathematical problems that are difficult to reverse when secure parameters and proper implementations are used.

The project uses 16- to 32-bit primes because these small numbers make it easier to follow the calculations, write tests, and factor `p-1`. These primes are not safe in a real application. An attacker can try possible private exponents until one works. Our generator check needs every distinct prime factor of `p-1`, which our own program finds by trial division. This process is manageable for the small assigned sizes, but it does not scale well to the large numbers used in secure finite-field DH systems. ECDH works with standardized curves, so it does not use the arbitrary-prime generation and factoring process from our assignment.

Ephemeral ECDH, also written ECDHE, means the participants use new key-agreement private values for each session rather than reusing the same secret each time. When old private session values are erased and the full protocol is designed correctly, this helps provide forward secrecy. Forward secrecy means that stealing a long-term authentication key later should not reveal the secrets from earlier sessions. Fresh values matter, but using them alone is not enough to create a secure protocol.

ECDH still needs authentication. Without authentication, Eve can replace the public key information in transit and create two different exchanges, just as she does against the unauthenticated finite-field DH demonstration. Digital signatures or another trusted authentication mechanism help prevent that substitution. The Ed25519 keys in our project are for **signing** and verifying identities, not for ECDH key agreement, even though both involve elliptic-curve techniques. These keys serve different purposes.

Real applications should use tested cryptographic libraries, validated parameters, standard protocols, and careful handling of secrets instead of inventing a key-exchange protocol. For example, the IETF's EDHOC standard combines authenticated ephemeral Diffie-Hellman with other protocol protections. Our project is useful for understanding the main ideas, but it is not a secure production implementation.
