import jwt
import datetime
import secrets

secret_key = secrets.token_hex(32)
print("Generated Secret Key:", secret_key)

# Secret key for encoding and decoding the token
SECRET_KEY = secret_key

# Function to generate a personalized JWT token
def generate_token(user_id, user_type, username):
    payload = {
        'user_id': user_id,
        'user_type': user_type,
        'username': username,  # Additional personalized information
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expiration time
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

# Function to decode a JWT token
def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return 'Token has expired'
    except jwt.InvalidTokenError:
        return 'Invalid token'

# Example usage
admin_token = generate_token(user_id=1, user_type='admin', username='Pranav')
normal_user_token = generate_token(user_id=2, user_type='normal', username='normal_user')

print("Admin Token:", admin_token)
print("Normal User Token:", normal_user_token)

decoded_admin_token = decode_token(admin_token)
decoded_normal_user_token = decode_token(normal_user_token)

print("\nDecoded Admin Token:", decoded_admin_token)
print("Decoded Normal User Token:", decoded_normal_user_token)
# import json
# import base64
# import hashlib
# import hmac
# import datetime
# import secrets
#
#
# def custom_encode(payload, secret_key):
#     header = {
#         "alg": "HS256",
#         "typ": "JWT"
#     }
#
#     encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
#     encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
#
#     signature = hmac.new(secret_key.encode(), f"{encoded_header}.{encoded_payload}".encode(), hashlib.sha256)
#     encoded_signature = base64.urlsafe_b64encode(signature.digest()).decode()
#
#     return f"{encoded_header}.{encoded_payload}.{encoded_signature}"
#
#
# def custom_decode(token, secret_key):
#     encoded_header, encoded_payload, encoded_signature = token.split('.')
#
#     expected_signature = base64.urlsafe_b64encode(
#         hmac.new(secret_key.encode(), f"{encoded_header}.{encoded_payload}".encode(), hashlib.sha256).digest()).decode()
#
#     if encoded_signature != expected_signature:
#         raise ValueError("Invalid signature")
#
#     decoded_payload = json.loads(base64.urlsafe_b64decode(encoded_payload).decode())
#     return decoded_payload
#
#
# # Secret key for encoding and decoding the token
# SECRET_KEY = secrets.token_urlsafe(32)
# print("Generated Secret Key:", SECRET_KEY)
#
# # Example usage
# payload = {
#     'user_id': 1,
#     'user_type': 'admin',
#     'username': 'admin_user',
#     'exp': int((datetime.datetime.utcnow() + datetime.timedelta(days=1)).timestamp())
# }
#
# token = custom_encode(payload, SECRET_KEY)
# print("Custom Token:", token)
#
# decoded_payload = custom_decode(token, SECRET_KEY)
# print("\nDecoded Payload:", decoded_payload)
