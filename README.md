# Password Strength Checker 🔐

A command-line tool written in Python that evaluates password strength against common security rules and a list of commonly used passwords.

Built as part of my cybersecurity learning path to practise secure coding habits, file handling, and thinking about how attackers guess passwords.

---

## Features

- Minimum length check (12 characters)
- Uppercase letter, number, and special character requirements
- Detection of commonly used passwords via a wordlist
- Reports **all** problems at once, not just the first one found
- Hidden input, so the password is never echoed to the screen

## Demo

```text
$ python password_checker.py
Enter a password:
❌ Weak password:
  - shorter than 12 characters
  - no number
  - no special character
```

```text
$ python password_checker.py
Enter a password:
✅ Strong password.
```

## Getting Started

### Requirements

- Python 3.8 or newer
- No third-party libraries needed

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

## How It Works

1. The common-password list (`common_passwords.txt`) is loaded into a set for fast lookups.
2. The entered password is lowercased and checked against that list.
3. It is then tested against each rule: length, uppercase, digit, special character.
4. Every failed rule is collected and printed. If none fail, the password is rated strong.

## Project Structure

```text
Password-strength-checker/
├── password_checker.py     # Main script
├── common_passwords.txt    # Wordlist of commonly used passwords
└── README.md
```

## Roadmap

- [ ] Strength score (weak / medium / strong) based on length and entropy
- [ ] Breach check using the Have I Been Pwned k-anonymity API
- [ ] Unit tests with `pytest`
- [ ] GitHub Actions workflow to run tests on every push
- [ ] Command-line arguments with `argparse` (e.g. check a file of passwords)

## What I Learned

- Reading files and handling input safely in Python
- Why password length matters more than forced complexity
- How wordlist attacks make common passwords weak, whatever their "rules"

## Security Note

This is a learning project. Do not rely on it to judge real passwords for sensitive accounts, and never type a password you actively use into any tool you do not fully trust. A password manager is the best way to generate and store strong passwords.

## Author

**J**, aspiring cybersecurity professional
GitHub: [@gardnerjelani97-coder](https://github.com/gardnerjelani97-coder)
