import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
from cryptography.hazmat.backends import default_backend
import gmpy2
import shared as sh

serverAddressPort = ("192.168.100.4", 3010)
bufferSize = 2048

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)

public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

sha256_hasher = hashlib.sha256(public_key_bytes)
print("SHA256 of PK: ", sha256_hasher.hexdigest())

UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

puk_bytes = public_key_bytes
hashBytes = sha256_hasher.digest()

# Append hash to PU_key
payload = puk_bytes + hashBytes

print(f"Message to {serverAddressPort[0]}:{serverAddressPort[1]}: {payload}")
UDPClientSocket.sendto(payload, serverAddressPort)

response = UDPClientSocket.recvfrom(bufferSize)
print(f"Response from {serverAddressPort[0]}:{serverAddressPort[1]}: {response[0]}")

key_as_int = sh.bytes_to_int(response[0])

# RSA D(m)
m = gmpy2.powmod(key_as_int, private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
m = sh.int_to_bytes(m)

print(f"Decrypted response: {m}")

# Symm key and IV bytes
symm_key = m[:32]
IV = m[32:]

enc = Cipher(algorithms.AES(symm_key),
             modes.CBC(IV),
             backend=default_backend()).encryptor()

# Payload
message = b'I will not say: do not weep; for not all tears are an evil.'
message += b"E" * (-len(message) % 16)  # Pad to fill 16 byte block

print(f"E(m): {message}")
cipher = enc.update(message)
print(f"C(m): {cipher}")
UDPClientSocket.sendto(cipher, serverAddressPort)
