"""Password strength checker.

Checks a password against basic rules, a wordlist of common passwords, and
(optionally) the Have I Been Pwned breach database using its k-anonymity API.
Only the first 5 characters of the password's SHA-1 hash are ever sent over
the network, so the password itself never leaves your machine.
"""

import argparse
import getpass
import hashlib
import sys
import urllib.error
import urllib.request
from pathlib import Path

SPECIAL_CHARACTERS = set("!@#$%^&*()-_+=[]{};:'\",.<>/?\\|`~")
MIN_LENGTH = 12
DEFAULT_WORDLIST = Path(__file__).with_name("common_passwords.txt")
HIBP_URL = "https://api.pwnedpasswords.com/range/"


class BreachCheckError(Exception):
    """Raised when the Have I Been Pwned lookup cannot be completed."""


def load_common_passwords(path=DEFAULT_WORDLIST):
    """Load the wordlist into a set of lowercase passwords for fast lookups."""
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    return {line.strip().lower() for line in text.splitlines() if line.strip()}


def check_password(password, common_passwords):
    """Return a list of problems with the password (empty list = passes all rules)."""
    problems = []
    if password.lower() in common_passwords:
        problems.append("commonly used password")
    if len(password) < MIN_LENGTH:
        problems.append(f"shorter than {MIN_LENGTH} characters")
    if not any(c.isupper() for c in password):
        problems.append("no uppercase letter")
    if not any(c.isdigit() for c in password):
        problems.append("no number")
    if not any(c in SPECIAL_CHARACTERS for c in password):
        problems.append("no special character")
    return problems


def parse_range_response(body, suffix):
    """Find our hash suffix in an HIBP range response and return its breach count.

    Each line looks like ``SUFFIX:COUNT``. Returns 0 if the suffix is not listed.
    """
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            return int(count)
    return 0


def get_breach_count(password, timeout=5):
    """Return how many times the password appears in known breaches.

    Uses the k-anonymity model: we send only the first 5 hex characters of the
    SHA-1 hash and compare the rest locally. SHA-1 is used here because the HIBP
    API requires it, not for any security purpose of our own.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    request = urllib.request.Request(
        HIBP_URL + prefix,
        headers={"User-Agent": "password-strength-checker", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BreachCheckError(str(exc)) from exc
    return parse_range_response(body, suffix)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check how strong a password is.")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip the Have I Been Pwned breach check",
    )
    parser.add_argument(
        "--wordlist",
        default=DEFAULT_WORDLIST,
        help="path to a common-passwords file (default: common_passwords.txt next to this script)",
    )
    args = parser.parse_args(argv)

    try:
        common_passwords = load_common_passwords(args.wordlist)
    except FileNotFoundError:
        print(f"Wordlist not found: {args.wordlist}")
        return 2

    password = getpass.getpass("Enter a password: ")
    problems = check_password(password, common_passwords)

    if not args.offline:
        try:
            breaches = get_breach_count(password)
        except BreachCheckError as exc:
            print(f"⚠️  Could not check Have I Been Pwned ({exc}). Use --offline to skip this check.")
        else:
            if breaches:
                problems.append(f"found in {breaches:,} known data breaches")

    if problems:
        print("❌ Weak password:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("✅ Strong password.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
