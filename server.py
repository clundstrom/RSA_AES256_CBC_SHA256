import socket
import gmpy2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms

import shared as sh

myIP = "192.168.100.4"
myPort = 3010
bufferSize = 2048

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((myIP, myPort))

print(f"Listening on {myIP}:{myPort}")

while (True):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]

    print(f"Message from {address}: {message}")

    if not sh.asymm_handshake(message):
        raise ValueError("Hash mismatch")

    public_key = serialization.load_pem_public_key(
        message[0:-32],
        backend=default_backend())

    # Symmetric key + iv
    IV = b'1111111111111111'
    aes_key_256 = b'___CXz2+z0kXhg8s6aSnxSvnJKLLasS^'

    # Encrypt symm key with rsa_pk, append symm key with IV for CBC
    print(f"Encrypting symmetric key: {aes_key_256}")
    key_as_int = sh.bytes_to_int(aes_key_256 + IV)
    ciphertext = gmpy2.powmod(key_as_int, public_key.public_numbers().e, public_key.public_numbers().n)
    ciphertext = sh.int_to_bytes(ciphertext)

    UDPServerSocket.sendto(ciphertext, address)
    print(f"Sending encrypted symmetric key: {ciphertext}")

    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    message = bytesAddressPair[0]
    address = bytesAddressPair[1]

    aes_cipher = Cipher(algorithms.AES(aes_key_256),
                        modes.CBC(IV),
                        backend=default_backend())
    dec = aes_cipher.decryptor()
    message = dec.update(message)
    print(f"Decrypted message from {address}: {message}")
