import getpass
from pathlib import Path

SPECIAL_CHARACTERS = set("!@#$%^&*()-_+=[]{};:'\",.<>/?\\|`~")

def load_common_passwords(path="common_passwords.txt"):
    return set(Path(path).read_text().splitlines())

def check_password(password, common_passwords):
    problems = []
    if password.lower() in common_passwords:
        problems.append("commonly used password")
    if len(password) < 12:
        problems.append("shorter than 12 characters")
    if not any(c.isupper() for c in password):
        problems.append("no uppercase letter")
    if not any(c.isdigit() for c in password):
        problems.append("no number")
    if not any(c in SPECIAL_CHARACTERS for c in password):
        problems.append("no special character")
    return problems

if __name__ == "__main__":
    common = load_common_passwords()
    password = getpass.getpass("Enter a password: ")
    problems = check_password(password, common)
    if problems:
        print("❌ Weak password:")
        for p in problems:
            print(f"  - {p}")
    else:
        print("✅ Strong password.")
