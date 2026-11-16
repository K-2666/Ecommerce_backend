
from core.security import (
    hash_password,
    verify_password,
    create_token,
    decode_token
)

password = "TestPassword@123"

hashed_password = hash_password(password)

print("Password hashed:", hashed_password != password)
print("Password verification:", verify_password(password, hashed_password))
print("Wrong password:", verify_password("WrongPassword", hashed_password))

access_token, access_jti, access_expiry = create_token(1, "access")

print("Access token generated:", bool(access_token))

payload = decode_token(access_token)

print("User ID:", payload["sub"])
print("Token type:", payload["type"])
print("Token decoded successfully")
