
"""Save test results and update the report."""

import csv
import importlib.metadata
import pathlib
import platform
import statistics
import subprocess
import sys

OUTPUT = pathlib.Path("sample_outputs")


def capture(filename, *command):
    """Run a command and save the results."""
    result = subprocess.run([sys.executable, *command],
                            capture_output=True, text=True)
    path = OUTPUT / filename
    path.write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise SystemExit(f"FAILED: see {path}")
    print(f"Saved {path}")


def update_report():
    """Add test results to the report."""
    with (OUTPUT / "performance_results.csv").open(newline="", encoding="utf-8") as file:
        trials = list(csv.DictReader(file))
    if len(trials) != 9:
        raise SystemExit("Expected 9 measured trials, not " + str(len(trials)))
    if any(row["authenticated"] != "YES" or row["secrets_match"] != "YES"
           for row in trials):
        raise SystemExit("A measured exchange failed; review before submission")

    lines = [
        "### Measured results (generated on this computer)",
        "",
        "- OS: " + platform.platform(),
        "- Python: " + platform.python_version(),
        "- cryptography: " + importlib.metadata.version("cryptography"),
        "- PyCryptodome: " + importlib.metadata.version("pycryptodome"),
        "",
        "| Bits | Trial | Prime (s) | Factor (s) | Generator (s) | Authenticated | Secrets match |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in trials:
        lines.append("| {bits} | {trial} | {prime_seconds} | {factor_seconds} | {generator_seconds} | {authenticated} | {secrets_match} |".format(**row))
    lines.append("")
    lines.append("### Timing variation")
    for bits in (16, 24, 32):
        group = [row for row in trials if int(row["bits"]) == bits]
        for column, name in (("prime_seconds", "prime generation"),
                             ("factor_seconds", "factorization"),
                             ("generator_seconds", "generator search")):
            times = [float(row[column]) for row in group]
            lines.append(f"- {bits}-bit {name}: min {min(times):.6f}s, "
                         f"max {max(times):.6f}s, "
                         f"average {statistics.mean(times):.6f}s")
    lines.append("")
    lines.append("These nine trials were generated with real random primes, "
                 "so the timings can change from one run to another. "
                 "Smaller prime factors or simpler generators can be found "
                 "more quickly; no exact runtime is expected.")

    report = pathlib.Path("REPORT.md")
    text = report.read_text(encoding="utf-8")
    first, second = "<!-- AUTO-RESULTS-START -->", "<!-- AUTO-RESULTS-END -->"
    before, remainder = text.split(first, 1)
    _, after = remainder.split(second, 1)
    report.write_text(before + first + "\n" + "\n".join(lines) +
                      "\n" + second + after, encoding="utf-8")
    print("Updated REPORT.md with real timing results and environment")


def main():
    OUTPUT.mkdir(exist_ok=True)
    capture("successful_exchange_and_attacks.txt", "main.py", "--bits", "16")
    capture("teaching_fixture.txt", "main.py", "--fixture", "--debug")
    capture("automated_tests.txt", "-m", "unittest", "discover", "-s", "tests", "-v")
    capture("performance_summary.txt", "main.py", "--performance", "--csv",
            str(OUTPUT / "performance_results.csv"))
    update_report()
    print("Finished. Read REPORT.md and commit the sample_outputs/ files to GitHub.")


if __name__ == "__main__":
    main()
