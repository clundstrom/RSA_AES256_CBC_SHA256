# Safe key exchange using modern encryption standards

This is an exercise in key exchange for a client and server. The scripts provided are used to spin up a client and server. Tested on two VMs running Kali Linux and Python 3.9 on a NAT network.

## Handshake

1. Client initiates handshake. Passes public key + SHA hash of the key to preserve message integrity.
2. Server receives payload. Hashes the public key. Hash match? -> payload PU key has not been altered.
3. Server generates a symmetric key and an initialization vector.
4. Server encrypts symmetric key with PU key.
5. Payload is passed to client.
6. Client decrypts payload using private key. Now , both client and server has a shared symmetric key and IV.
7. Communication continues with AES256 and cipher block chaining mode of operation.


