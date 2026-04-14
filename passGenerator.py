import secrets
import string

def make_password():
    lenght = 16
    symbols = string.punctuation.replace(",","").replace(".","").replace("`","")
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    alphabet = lowercase + uppercase + symbols

    password = "".join(secrets.choice(alphabet) for _ in range(lenght))
    return password

    print (password)
