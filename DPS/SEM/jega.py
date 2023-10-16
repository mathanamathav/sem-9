# !pip install pycryptodome

from Crypto.Cipher import AES

# from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import hashlib
import ipaddress
import getpass
import rsa

"""**Password Authentication**"""


def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode("utf-8"))
    return sha256.hexdigest()


def register_user(username, password):
    hashed_password = hash_password(password)
    database[username] = hashed_password


def authenticate_user(username, password):
    hashed_password = hash_password(password)
    stored_password = database.get(username)
    if stored_password and stored_password == hashed_password:
        return True
    else:
        return False


"""**Maintaining DB**"""

database = {}
ip_policy = {
    ipaddress.ip_network("192.168.1.0/24"): "allow",
    ipaddress.ip_network("10.0.0.0/8"): "deny",
    ipaddress.ip_network("172.16.0.0/12"): "allow",
}

"""**FireWall**"""


def get_action(ip_address):
    ip = ipaddress.IPv4Address(ip_address)
    for ip_range, action in ip_policy.items():
        if ip in ip_range:
            return action
    return "default_action"


"""**RSA for Key Exchange**"""

publicKey, privateKey = rsa.newkeys(512)

"""**Sender Function**"""


def sender():
    print("\n")
    message = str(input("Enter your message: ")).encode()
    padded_message = pad(message, AES.block_size)

    ##Setting Key for AES
    key = "Jegadeesh_19PD15"
    print("Key for AES: ", key)
    iv = "DPSLABEXAM19PD15"

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())

    ##Encrypting Key using RSA
    key_encrypt = rsa.encrypt(key.encode(), publicKey)
    print("Encrypted Key using RSA: ", key_encrypt)
    iv_encrypt = rsa.encrypt(iv.encode(), publicKey)

    ##Encrypting Message using AES
    encrypted_message = cipher.encrypt(padded_message)
    print("The Encrypted Message is: ", encrypted_message)

    ##Registering User
    username = str(input("Enter your username: "))
    if username in database:
        print("You are an Existing User")
    else:
        pwd = getpass.getpass("Enter your password: ")
        register_user(username, pwd)
        print("You have been registered successfully")
    set_ip = "192.168.1.255"
    return encrypted_message, set_ip, username, key_encrypt, iv_encrypt


database

"""**Receiver Function**"""


def receiver(encrypted_msg, ip, username, key1, key2):
    print("\n")
    ## FireWall
    action = get_action(ip)
    if action == "deny":
        print("The given IP is not Authorized")
        return
    else:
        ## Authenticating User via SHA
        print("The given IP is Authorized")
        pwd = getpass.getpass("Enter your password: ")
        if authenticate_user(username, pwd):
            print("The User has been authenticated and receiving message")

            ##Decryping Key using RSA
            key = rsa.decrypt(key1, privateKey).decode()
            print("Decrypted key using RSA: ", key)
            iv = rsa.decrypt(key2, privateKey).decode()

            ##Decrypting Message using AES
            cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
            decrypted_message = cipher.decrypt(encrypted_msg)
            original_message = unpad(decrypted_message, AES.block_size)

            print("Decrypted Message: ", original_message.decode("utf-8"))
        else:
            print("The User is not authenticated")
            return


"""**Transporting Message**"""


def transport_message():
    print("------------Sender Sending Message-----------")
    encp_msg, ip, user_name, key1, key2 = sender()
    print("\n")
    print("------------Receiver Receiving Message-------")
    receiver(encp_msg, ip, user_name, key1, key2)


transport_message()
