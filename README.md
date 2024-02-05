# jwt-tokenization-to-validate-login

1. **Generating a Secret Key:**
   - `secrets.token_hex(32)` generates a random hexadecimal string with 32 bytes (256 bits) to be used as a secret key for encoding and decoding the JWTs. This key is printed and used as `SECRET_KEY`.

2. **Token Generation Function (`generate_token`):**
   - This function takes three parameters: `user_id`, `user_type`, and `username`.
   - It creates a payload dictionary containing user information (`user_id`, `user_type`, and `username`) and sets an expiration time (`exp`) for the token, which is one day from the current time.
   - The `jwt.encode` function is then used to encode the payload into a JWT using the `HS256` (HMAC with SHA-256) algorithm and the secret key.
   - The generated token is returned.

3. **Token Decoding Function (`decode_token`):**
   - This function takes a JWT (`token`) as a parameter.
   - It attempts to decode the token using `jwt.decode`. If successful, it returns the decoded payload.
   - If the token has expired (`jwt.ExpiredSignatureError`), it returns 'Token has expired'.
   - If the token is invalid (`jwt.InvalidTokenError`), it returns 'Invalid token'.

4. **Example Usage:**
   - Two tokens are generated for demonstration purposes: one for an admin user and one for a normal user.
   - The generated tokens are printed.
   - The `decode_token` function is then used to decode the generated tokens.
   - The decoded payloads or error messages (if any) are printed.

In summary, this script demonstrates the creation of JWTs for users with personalized information and provides a mechanism to decode and verify these tokens. The `jwt` library simplifies the process of working with JWTs, and the script showcases a basic usage scenario.
