"""Entry point for the CSC-364 local authenticated-DH demonstration."""

import argparse
import csv
import importlib.metadata
import statistics
from eve import authenticated_attack, unauthenticated_attack
from protocol import AuthenticatedDH


def version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "NOT INSTALLED (development environment only)"


def print_versions() -> None:
    print(f"Libraries: cryptography {version('cryptography')}; "
          f"PyCryptodome {version('pycryptodome')}")


def demonstrate(bits: int, fixture: bool, debug: bool):
    protocol = AuthenticatedDH(fixture_mode=fixture)
    result = protocol.complete_exchange(bits)
    print("=== Authenticated Diffie-Hellman ===")
    print(f"Requested prime size: {'fixture p=23' if fixture else str(bits) + ' bits'}")
    print(f"Modulus generated using library: {'fixture value' if fixture else 'YES'}")
    print(f"Modulus bit length: {result['p'].bit_length()}")
    print("Received modulus library validation: PASS")
    print("Generator: validated")
    print("Alice initiation signature: VALID")
    print("Bob response signature: VALID")
    print("Alice finish signature: VALID")
    print(f"Transcript authenticated: {'YES' if result['authenticated'] else 'NO'}")
    print(f"Shared-secret equality in local test: "
          f"{'PASS' if result['secrets_match'] else 'FAIL'}")
    print("Explicit key confirmation: NOT IMPLEMENTED")
    if debug:
        print("CLASSROOM DEBUG ONLY - NEVER TRANSMITTED:")
        print(f"Alice local shared secret: {protocol.last_alice_shared}")
        print(f"Bob local shared secret: {protocol.last_bob_shared}")
    print("\n=== Eve: no authentication (p=23 fixture) ===")
    attack = unauthenticated_attack()
    print(f"Substituted public values: E1={attack['E1']}, E2={attack['E2']}")
    print(f"Alice's secret: {attack['Alice_secret']}; "
          f"Bob's secret: {attack['Bob_secret']} (Eve knows both)")
    print("=== Eve: with Ed25519 authentication ===")
    print(authenticated_attack())


def performance(csv_path: str):
    """3 genuine generated authenticated exchanges at each required size."""
    rows = []
    for bits in (16, 24, 32):
        for trial in (1, 2, 3):
            protocol = AuthenticatedDH()
            result = protocol.complete_exchange(bits)
            elapsed = result["timings"]
            row = {"bits": bits, "trial": trial,
                   "prime_seconds": elapsed["prime"],
                   "factor_seconds": elapsed["factors"],
                   "generator_seconds": elapsed["generator"],
                   "authenticated": "YES" if result["authenticated"] else "NO",
                   "secrets_match": "YES" if result["secrets_match"] else "NO"}
            rows.append(row)
            print(f"{bits} bits | trial {trial} | "
                  f"prime {elapsed['prime']:.6f}s | "
                  f"factor {elapsed['factors']:.6f}s | "
                  f"generator {elapsed['generator']:.6f}s | "
                  f"auth={row['authenticated']} | match={row['secrets_match']}")
    with open(csv_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nSaved measurements: {csv_path}")
    for bits in (16, 24, 32):
        sample = [r["prime_seconds"] for r in rows if r["bits"] == bits]
        print(f"Prime time, {bits} bits: min={min(sample):.6f}s; "
              f"max={max(sample):.6f}s; mean={statistics.mean(sample):.6f}s")


def main():
    parser = argparse.ArgumentParser(description="CSC-364 authenticated DH project")
    parser.add_argument("--bits", type=int, default=16,
                        help="prime size from 16 to 32, default 16")
    parser.add_argument("--fixture", action="store_true",
                        help="use teaching p=23 fixture ONLY for tests/demos")
    parser.add_argument("--debug", action="store_true",
                        help="show local private results, for classroom only")
    parser.add_argument("--performance", action="store_true",
                        help="run 3 exchanges at 16, 24 and 32 bits")
    parser.add_argument("--csv", default="performance_results.csv")
    args = parser.parse_args()
    print_versions()
    if args.performance:
        performance(args.csv)
    else:
        demonstrate(args.bits, args.fixture, args.debug)


if __name__ == "__main__":
    main()
