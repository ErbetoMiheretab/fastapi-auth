import base64
import hashlib
import hmac
import json
import struct
import time
import urllib.request


def generate_totp(secret: str, digits: int = 10, time_step: int = 30) -> str:
    # Calculate counter based on Unix epoch time T0=0
    counter = int(time.time() // time_step)
    msg = struct.pack(">Q", counter)

    # HMAC-SHA512 hashing
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha512).digest()
    # digest_bytes = bytes.fromhex(digest)

    # Dynamic truncation
    offset = digest[-1] & 0x0F
    code = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )

    otp = code % (10**digits)
    return str(otp).zfill(digits)


# Configuration
EMAIL = "mengeshamiheretab36@gmail.com"
GIST_URL = "https://gist.github.com/ErbetoMiheretab/1e1b4151e39dfdff9423accd26588d30"
LANG = "python"  # Choose "python" or "golang"

# Shared secret derivation: HENNGECHALLENGE004
secret = f"{EMAIL}HENNGECHALLENGE004"
password = generate_totp(secret)

# HTTP Basic Authentication header
auth_str = f"{EMAIL}:{password}"
auth_header = "Basic " + base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")

# JSON Payload
payload = {
    "github_url": GIST_URL,
    "contact_email": EMAIL,
    "solution_language": LANG,
}

# Request execution
url = "https://api.challenge.hennge.com/challenges/backend-recursion/004"
req = urllib.request.Request(
    url,
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "Authorization": auth_header,
    },
    method="POST",
)

try:
    with urllib.request.urlopen(req) as response:
        print("Status Code:", response.status)
        print("Response:", response.read().decode("utf-8"))
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code, e.read().decode("utf-8"))
