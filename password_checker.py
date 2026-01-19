special_characters = "!@#$%^&*()-_+="

password = input("Enter a password: ")

if len(password) < 8:
    print("❌ Weak password: too short.")
elif not any(char.isupper() for char in password):
    print("❌ Weak password: no uppercase letter.")
elif not any(char.isdigit() for char in password):
    print("❌ Weak password: no number.")
elif not any(char in special_characters for char in password):
    print("❌ Weak password: no special character.")
else:
    print("✅ Strong password.")
