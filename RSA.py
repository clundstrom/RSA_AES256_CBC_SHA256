import gmpy2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def simple_rsa_decrypt(c, publickey):
    rsa_public_key = publickey.public_numbers()
    return gmpy2.powmod(c, rsa_public_key.e, rsa_public_key.n)


def simple_rsa_encrypt(m, privatekey):
    rsa_private_key = privatekey.private_numbers()
    return gmpy2.powmod(m, rsa_private_key.d, rsa_private_key.public_numbers.n)


def int_to_bytes(i):
    i = int(i)
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')


def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')


def keysize(byte_key):
    key_str = byte_key.decode("utf-8").replace('\n', '')
    key_arr = key_str.split('-----')
    return len(key_arr[2])


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=512,
    backend=default_backend()
)

public_key = private_key.public_key()

private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

private_key = serialization.load_pem_private_key(
    private_key_bytes,
    backend=default_backend(),
    password=None)

public_key = serialization.load_pem_public_key(
    public_key_bytes,
    backend=default_backend())

print(f"Private key size: {keysize(private_key_bytes)}")
print(f"Public key size: {keysize(public_key_bytes)}")
print(private_key_bytes.decode("utf-8").replace('\n', ''))

message = input("\nPlaintext: ").encode()

message_as_int = bytes_to_int(message)
cipher_as_int = simple_rsa_encrypt(message_as_int, private_key)
cipher = int_to_bytes(cipher_as_int)

print("E(m):", cipher.hex())

message_as_int = simple_rsa_decrypt(cipher_as_int, public_key)
message = int_to_bytes(message_as_int)
print("\nD(m): {}\n".format(message))
