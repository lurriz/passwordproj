import secrets
import string

def make_password(length=16):
    symbols = string.punctuation.replace(",", "").replace(".", "").replace("`", "")
    alphabet = string.ascii_letters + symbols
    password = "".join(secrets.choice(alphabet) for _ in range(length))
    return password