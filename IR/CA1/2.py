from Crypto.Cipher import DES
import binascii


def decrypt_des(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


# Hexadecimal key and ciphertext
hex_key = "AABB09182736CCDD"
hex_ciphertext = "C0B7A8D05F3A829C"

# Convert hexadecimal key and ciphertext to bytes
byte_key = bytes.fromhex(hex_key)
byte_ciphertext = bytes.fromhex(hex_ciphertext)

# Decrypt the ciphertext
plaintext = decrypt_des(byte_ciphertext, byte_key)

# Print the decrypted plaintext as hexadecimal
print("Decrypted Plaintext (Hex):", binascii.hexlify(plaintext).decode("utf-8"))


# client.py
import socket
from Crypto.Cipher import DES

DES_KEY = b"K Ashish"
cipher = DES.new(DES_KEY, DES.MODE_ECB)
s = socket.socket()
port = 12345

s.connect(("127.0.0.1", port))

print("Succesfully connected")

received_mesage = s.recv(1024)
decrypted_data = cipher.decrypt(received_mesage)

unpadded_data = decrypted_data[: -decrypted_data[-1]]
print("Decrypted Message: ", unpadded_data)
s.close()


# server.py
import socket
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

s = socket.socket()
print("Socket successfully created")

DES_KEY = b"K Ashish"
port = 12345

s.bind(("", port))
print("socket binded to %s" % (port))

s.listen(5)
print("socket is listening")

cipher = DES.new(DES_KEY, DES.MODE_ECB)
data = b"This is a secret message."

block_size = 8
padding_length = block_size - len(data) % block_size
padded_data = data + bytes([padding_length]) * padding_length

encrypted_data = cipher.encrypt(padded_data)

while True:
    c, addr = s.accept()
    print("Got connection from", addr)

    c.send(encrypted_data)

    c.close()

    break
