password = input("Enter a password: ")

if len(password) < 8:
    print("❌ Weak password: must be at least 8 characters.")
else:
    print("✅ Password length is acceptable.")
