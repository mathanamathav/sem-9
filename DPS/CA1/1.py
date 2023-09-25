def additive_encoder(plain_text, key):
    res = ""
    for i in plain_text:
        if i.islower():
            res += chr((ord(i) + key - 97) % 26 + 97)
        elif i.isupper():
            res += chr((ord(i) + key - 65) % 26 + 65)
        else:
            res += " "
    return res


additive_encoder("The password is dontkill", 2)


def additive_decoder(cipher_text, key):
    res = ""
    for i in cipher_text:
        if i.islower():
            res += chr((ord(i) - key - 97) % 26 + 97)
        elif i.isupper():
            res += chr((ord(i) - key - 65) % 26 + 65)
        else:
            res += " "
    return res


additive_decoder("Vjg rcuuyqtf ku fqpvmknn", 2)


def multiplicative_encoder(plain_text, key):
    res = ""
    for i in plain_text:
        if i.islower():
            res += chr(((ord(i) - 97) * key) % 26 + 97)
        elif i.isupper():
            res += chr(((ord(i) - 65) * key) % 26 + 65)
        else:
            res += " "
    return res


multiplicative_encoder("The password is dontkill", 20)


def multiplicative_decoder(cipher_text, key):
    dkey = -1
    for i in range(26):
        if (key * i) % 26 == 1:
            dkey = i
            break
    if dkey == -1:
        return "Unable to decrypt"
    res = ""
    for i in cipher_text:
        if i.islower():
            res += chr(((ord(i) - 97) * dkey) % 26 + 97)
        elif i.isupper():
            res += chr(((ord(i) - 65) * dkey) % 26 + 65)
        else:
            res += " "
    return res


multiplicative_decoder("Qkc oawwyuci ew iuaqsemm", 20)

"""## Affine cipher"""


def affine_encoder(plain_text, a, b):
    res = ""
    for i in plain_text:
        if i.islower():
            res += chr(((ord(i) - 97) * a + b) % 26 + 97)
        elif i.isupper():
            res += chr(((ord(i) - 65) * a + b) % 26 + 65)
        else:
            res += " "
    return res


affine_encoder("The password is dontkill", 7, 3)


def affine_decoder(cipher_text, a, b):
    res = ""
    dkey = -1
    for i in range(26):
        if (a * i) % 26 == 1:
            dkey = i
            break
    if dkey == -1:
        return "Unable to decrypt"
    for i in cipher_text:
        if i.islower():
            res += chr((((ord(i) - 97) - b) * dkey) % 26 + 97)
        elif i.isupper():
            res += chr((((ord(i) - 65) - b) * dkey) % 26 + 65)
        else:
            res += " "
    return res


affine_decoder("Gaf edzzbxsy hz yxqgvhcc", 7, 3)

"""## Autokey Cipher"""


def autokey_encrpt(plain_text, key):
    get_key = lambda x, y: ord(x) - y
    keys = [key]
    for i in plain_text[:-1:]:
        if i.isupper():
            keys.append(get_key(i, 65))
        elif i.islower():
            keys.append(get_key(i, 97))
    res = ""
    for i in range(len(plain_text)):
        if plain_text[i].isupper():
            res += chr((get_key(plain_text[i], 65) + keys[i]) % 26 + 65)
        elif plain_text[i].islower():
            res += chr((get_key(plain_text[i], 97) + keys[i]) % 26 + 97)
    return res


autokey_encrpt("AtTackistoday", 12)


def autokey_decrypt(cipher_text, key):
    dkey = key
    res = ""
    for i in cipher_text:
        if i.islower():
            res += chr(((ord(i) - 97) - dkey) % 26 + 97)
            dkey = ((ord(i) - 97) - dkey) % 26
        if i.isupper():
            res += chr(((ord(i) - 65) - dkey) % 26 + 65)
            dkey = ((ord(i) - 65) - dkey) % 26
    return res


autokey_decrypt("MtMtcmsalhrdy", 12)

for i in range(1, 31):
    print(additive_decoder("NCJAEZRCLASJLYODEPRLYZRCLASJLCPEHZDTOPDZQLNZTY", i))

import numpy as np


def encrypt_trans(plain_text, key):
    extra = 0
    for i in range(0, len(key)):
        if (len(plain_text) + i) % len(key) == 0:
            extra = i
            break
    plain_text += extra * "z"
    matrix = np.zeros((len(key), len(key)))
    for i in range(len(matrix)):
        matrix[i][key[i] - 1] = 1
    matrix = matrix.T
    pt_matrix = np.array(list(plain_text)).reshape(-1, len(key))
    tmatrix = np.zeros_like(pt_matrix, dtype=int)
    for i in range(len(pt_matrix)):
        for j in range(len(pt_matrix[0])):
            tmatrix[i][j] = ord(pt_matrix[i][j])
    tmatrix = np.dot(tmatrix, matrix).T
    res = ""
    for i in range(len(tmatrix)):
        for j in range(len(tmatrix[0])):
            res += chr(int(tmatrix[i][j]))
    return res


cipher = encrypt_trans("enemyattackstonight", (3, 1, 4, 5, 2))
print(cipher)


def decrypt_trans(cipher_text, key):
    key = [(key[i - 1], i) for i in range(1, len(key) + 1)]
    key.sort()
    key = [i[1] for i in key]
    res = np.zeros((len(cipher_text) // len(key), len(key)))
    t = 0
    for i in range(len(res[0])):
        for j in range(len(res)):
            res[j][i] = ord(cipher_text[t])
            t += 1
    matrix = np.zeros((len(key), len(key)))
    for i in range(len(matrix)):
        matrix[i][key[i] - 1] = 1
    matrix = matrix.T
    tmatrix = np.dot(res, matrix)
    res = ""
    for i in range(len(tmatrix)):
        for j in range(len(tmatrix[0])):
            res += chr(int(tmatrix[i][j]))
    return res


decrypt_trans("etsize cotmt gzyathznaknz", (3, 1, 4, 5, 2))

temp1 = encrypt_trans("enemyattackstonight", (3, 1, 4, 5, 2))
cipher = encrypt_trans(temp1, (3, 1, 4, 5, 2))

temp2 = decrypt_trans(cipher, (3, 1, 4, 5, 2))
ans = decrypt_trans(temp2, (3, 1, 4, 5, 2))
print(ans)


# Q2

alphabet = "abcdefghijklmnopqrstuvwxyz"

# DECRYPT
def decrypt_shift(text, key):
    global alphabet
    for x in range(len(text)):
        # Find the index of the letter in alphabet
        ix = alphabet.index(text[x].lower())
        text[x] = alphabet[(ix - key) % 26]

    # Turn cipher back into a plain
    text = "".join(text)
    print("Plain text: ", text)


cipher = "NCJAEZRCLASJLYODEPRLYZRCLASJLCPEHZDTOPDZQLNZTY"

for i in range(10, 15):
    print("Key:", i)
    decrypt_shift(list(cipher), i)
