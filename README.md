# Password Strength Checker 🔐

![Tests](https://github.com/gardnerjelani97-coder/Password-strength-checker/actions/workflows/tests.yml/badge.svg)

A command-line tool written in Python that evaluates password strength against common security rules, a list of commonly used passwords, and the Have I Been Pwned breach database.

Built as part of my cybersecurity learning path to practise secure coding habits, working with APIs, testing, and thinking about how attackers guess passwords.

---

## Features

- Minimum length check (12 characters)
- Uppercase letter, number, and special character requirements
- Detection of commonly used passwords via a wordlist
- **Breach check** using the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) k-anonymity API
- Reports **all** problems at once, not just the first one found
- Hidden input, so the password is never echoed to the screen
- Automated tests run on every push with GitHub Actions

## Demo

```text
$ python password_checker.py
Enter a password:
❌ Weak password:
  - shorter than 12 characters
  - no number
  - no special character
  - found in 10,434,004 known data breaches
```

```text
$ python password_checker.py
Enter a password:
✅ Strong password.
```

## Getting Started

### Requirements

- Python 3.10 or newer
- No third-party libraries needed to run it (`pytest` is only needed for the tests)

### Installation

```bash
git clone https://github.com/gardnerjelani97-coder/Password-strength-checker.git
cd Password-strength-checker
```

### Usage

```bash
python password_checker.py
```

Type a password when prompted. Nothing will appear on screen as you type.

| Option | Description |
| --- | --- |
| `--offline` | Skip the Have I Been Pwned check (no internet needed) |
| `--wordlist PATH` | Use a different common-passwords file |

The program exits with code `0` for a strong password, `1` for a weak one, and `2` if the wordlist can't be found.

## How the Breach Check Works

The password is never sent anywhere. Instead:

1. The password is hashed with SHA-1 locally.
2. Only the **first 5 characters** of that hash are sent to the API.
3. The API replies with every known breached hash starting with those 5 characters.
4. The tool looks for the rest of the hash in that list on your own machine.

This is called **k-anonymity**: the service can't tell which password you were checking. If the lookup fails (for example, no internet), the tool says so and carries on with the other checks.

## Running the Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The tests mock the network, so they run offline and never contact the real API. They cover each password rule, the wordlist loader, the breach-response parser, error handling, and the command-line behaviour.

## Project Structure

```text
Password-strength-checker/
├── .github/workflows/tests.yml   # Runs the tests on every push and pull request
├── password_checker.py           # Main script
├── test_password_checker.py      # pytest test suite
├── common_passwords.txt          # Wordlist of commonly used passwords
├── requirements-dev.txt          # Test dependencies
└── README.md
```

## Roadmap

- [x] Breach check using the Have I Been Pwned k-anonymity API
- [x] Unit tests with `pytest`
- [x] GitHub Actions workflow to run tests on every push
- [x] Command-line arguments with `argparse`
- [ ] Strength score (weak / medium / strong) based on length and entropy

## What I Learned

- Reading files and handling input safely in Python
- Why password length matters more than forced complexity
- How wordlist attacks make common passwords weak, whatever their "rules"
- How k-anonymity lets you check a secret against a public database without revealing it
- Mocking network calls so tests are fast, repeatable, and work offline

## Security Note

This is a learning project. Do not rely on it to judge real passwords for sensitive accounts, and never type a password you actively use into any tool you do not fully trust. A password manager is the best way to generate and store strong passwords.

## Author

**J**, aspiring cybersecurity professional
GitHub: [@gardnerjelani97-coder](https://github.com/gardnerjelani97-coder)
