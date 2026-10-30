CSC 364 - Diffie-Hellman Key Exchange

This project uses Python to show how Alice and Bob can exchange a shared secret using Diffie-Hellman. It also uses digital signatures to check messages and detect changes made by an attacker named Eve.

Setup

Download or clone this GitHub repository.

Install the required libraries:

python -m pip install -r requirements.txt

Run the Program

Run the main program:

python main.py

This shows a successful key exchange and shows how Eve's attack is detected using authentication.

Run the Tests

To run the automated tests:

python -m unittest discover -s tests -v

The project includes 26 automated tests.

Performance Results

To generate the test results and performance measurements:

python collect_evidence.py

This runs the required tests for 16, 24, and 32-bit prime numbers and saves the results in the sample_outputs folder.

Project Files

main.py - Runs the project.

modular_math.py - Performs modular exponentiation.

parameters.py - Generates primes and checks generators.

participant.py - Creates Alice and Bob's identities.

authentication.py - Handles message signatures.

protocol.py - Handles the key exchange.

eve.py - Demonstrates Eve's attack.

collect_evidence.py - Saves test and performance results.

tests/ - Contains automated tests.

sample_outputs/ - Contains saved results.

REPORT.md - Contains the project report and research comparison.

Libraries Used

cryptography 46.0.4

PyCryptodome 3.23.0
