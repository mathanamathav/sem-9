# !pip install pycryptodome

# imports
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA, ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHAKE128, SHA512
from Crypto.Signature import pkcs1_15
import ipaddress
from getpass import getpass


def AES_keygen():
    return get_random_bytes(16)


def AES_encrypt(plaintext, key, iv=None, is_bytes=False):
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    if is_bytes:
        padded_text = pad(plaintext, AES.block_size)
    else:
        padded_text = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    iv = cipher.iv
    return ciphertext, iv


def AES_decrypt(ciphertext, key, iv):
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    decrypted_text = cipher.decrypt(ciphertext)
    bytes_text = unpad(decrypted_text, AES.block_size)
    return bytes_text


def RSA_keygen(name):
    key = RSA.generate(2048)
    # signature
    private_key_der = key.export_key(format="DER")
    public_key_der = key.publickey().export_key(format="DER")
    with open(f"{name}_RSA_private.der", "wb") as fp:
        fp.write(private_key_der)
    with open(f"{name}_RSA_public.der", "wb") as fp:
        fp.write(public_key_der)

    # #encryption
    # key = RSA.generate(2048)
    # private_key = key.export_key()
    # public_key = key.publickey().export_key()
    # with open(f"{name}_RSA_private.pem", "wb") as fp:
    #   fp.write(private_key)
    # with open(f"{name}_RSA_public.pem","wb") as fp:
    #   fp.write(public_key)


def RSA_sign_digest(digest, sender_private_key_file):
    private_key = RSA.import_key(open(sender_private_key_file, "rb").read())
    signature = pkcs1_15.new(private_key).sign(digest)
    return signature


def RSA_verify_digest(digest, signature, sender_public_key_file):
    sender_key = RSA.import_key(open(sender_public_key_file, "rb").read())
    try:
        pkcs1_15.new(sender_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


# def RSA_encrypt(session_key, recipient_public_key_file):
#   recipient_key = RSA.import_key(open(recipient_public_key_file).read())
#   cipher_rsa = PKCS1_OAEP.new(recipient_key)
#   enc_session_key = cipher_rsa.encrypt(session_key)
#   return enc_session_key


# def RSA_decrypt(enc_session_key, recipient_private_key_file):
#   private_key = RSA.import_key(open(recipient_private_key_file).read())
#   cipher_rsa = PKCS1_OAEP.new(private_key)
#   session_key = cipher_rsa.decrypt(enc_session_key)
#   return session_key


def DH_ECC_keygen(name):
    key = ECC.generate(curve="P-256")
    private_key = key.export_key(format="PEM")
    public_key = key.public_key().export_key(format="PEM")
    with open(f"{name}_ECC_private.pem", "wt") as fp:
        fp.write(private_key)
    with open(f"{name}_ECC_public.pem", "wt") as fp:
        fp.write(public_key)


def DH_key_agreement(private_key_file, public_key_file):
    # This KDF has been agreed in advance
    kdf = lambda x: SHAKE128.new(x).read(32)
    priv_key = ECC.import_key(open(private_key_file).read())
    pub_key = ECC.import_key(open(public_key_file).read())
    session_key = key_agreement(static_priv=priv_key, static_pub=pub_key, kdf=kdf)
    return session_key


def SHA_512_hash(text):
    h = SHA512.new(text.encode())
    return h


ip_policy = {"next_id": 1, "default": "deny", "rules": {}}


def set_default(rule, ip_policy=ip_policy):
    ip_policy["default"] = rule


def add_rule(
    source_ip,
    dest_ip,
    source_port,
    dest_port,
    protocol,
    action,
    is_subnet=False,
    ip_policy=ip_policy,
):
    id = ip_policy["next_id"]
    rule = {
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "source_port": source_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "is_subnet": is_subnet,
        "action": action,
    }
    if rule not in ip_policy["rules"].values():
        ip_policy["rules"][id] = rule
        ip_policy["next_id"] += 1
        return id
    else:
        return -1


def remove_rule(id, ip_policy=ip_policy):
    ip_policy.pop(id, "ID not found")


def firewall_rules(ip_policy=ip_policy):
    print("ID\t\tPROTOCOL\tSOURCE_IP\t\tSOURCE_PORT\t\tDEST_IP\t\t\tDEST_PORT\tACTION")
    for id, policy in ip_policy["rules"].items():
        print(
            f"{id}\t\t{policy['protocol']}\t\t{policy['source_ip']}\t\t{policy['source_port']}\t\t\t{policy['dest_ip']}\t\t{policy['dest_port']}\t\t{policy['action']}"
        )


def firewall(source_ip, dest_ip, source_port, dest_port, protocol, ip_policy=ip_policy):
    for policy in ip_policy["rules"].values():
        match = True
        if policy["is_subnet"]:
            if not ipaddress.IPv4Address(source_ip) in ipaddress.ip_network(
                policy["source_ip"]
            ):
                match = False
        else:
            if not source_ip == policy["source_ip"]:
                match = False
        if not dest_ip == policy["dest_ip"]:
            match = False
        if not source_port == policy["source_port"]:
            match = False
        if not dest_port == policy["dest_port"]:
            match = False
        if not protocol == policy["protocol"]:
            match = False
        if match:
            return policy["action"]
    return ip_policy["default"]


shadow = {}


def register_user(shadow=shadow):
    print("Register User: ")
    hashed_user = SHA_512_hash(input("Username: ")).hexdigest()
    hashed_password = SHA_512_hash(getpass("Password: ")).hexdigest()
    shadow[hashed_user] = hashed_password


def authenticate_user(hashed_user, hashed_password, shadow=shadow):
    try:
        return hashed_password == shadow[hashed_user]
    except:
        return False


"""# End to End Implementation Example"""


def register_usr_pwd():
    # Setup
    register_user()
    RSA_keygen("sender")
    DH_ECC_keygen("sender")
    RSA_keygen("recv")
    DH_ECC_keygen("recv")


def sender(text):
    # Sender
    key = AES_keygen()
    digest = SHA_512_hash(text)
    signature = RSA_sign_digest(digest, "/content/sender_RSA_private.der")
    data = {"msg": text, "signature": signature}
    ciphertext, iv = AES_encrypt(str(data), key)
    session_key = DH_key_agreement(
        "/content/sender_ECC_private.pem", "/content/recv_ECC_public.pem"
    )
    enc_key, iv = AES_encrypt(key, session_key, iv, True)
    user = SHA_512_hash(input("username: ")).hexdigest()
    pwd = SHA_512_hash(getpass("password: ")).hexdigest()
    packet = {
        "header": {
            "source_ip": "192.168.9.2",
            "source_port": "80",
            "dest_ip": "10.1.10.0",
            "dest_port": "80",
            "protocol": "TCP",
        },
        "auth": {"usr": user, "pwd": pwd},
        "data": {
            "iv": iv,
            "ciphertext": ciphertext,
            "key": enc_key,
        },
    }
    return packet


def reciver(packet):
    # Reciver
    add_rule(
        source_ip=packet["header"]["source_ip"],
        dest_ip=packet["header"]["dest_ip"],
        source_port=packet["header"]["source_port"],
        dest_port=packet["header"]["dest_port"],
        protocol=packet["header"]["protocol"],
        action="allow",
        is_subnet=False,
        ip_policy=ip_policy,
    )
    firewall_rules()
    # firewall check
    if firewall(**packet["header"]) == "allow":
        # password check
        if authenticate_user(packet["auth"]["usr"], packet["auth"]["pwd"]):
            # code
            iv = packet["data"]["iv"]
            ciphertext = packet["data"]["ciphertext"]
            enc_key = packet["data"]["key"]
            session_key = DH_key_agreement(
                "/content/recv_ECC_private.pem", "/content/sender_ECC_public.pem"
            )
            key = AES_decrypt(enc_key, session_key, iv)

            data = eval(AES_decrypt(ciphertext, key, iv).decode())
            signature = data["signature"]
            digest = SHA_512_hash(data["msg"])

            if RSA_verify_digest(digest, signature, "/content/sender_RSA_public.der"):
                print(data["msg"])
            else:
                print("Message Authentication Failed")

        else:
            print("Password Authentication Failed")

    else:
        print("Firewall Blocked")


register_usr_pwd()

text = "Hope fully this works"

packet = sender(text)
reciver(packet)
