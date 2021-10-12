from base64 import b64encode, b64decode
import uuid
import time
import datetime
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# # Setting up aes-cbc encryption
# def encrypt(data, key):
#     cipher = AES.new(key, AES.MODE_CBC)
#     ct_bytes = cipher.encrypt(pad(data, AES.block_size))
#     iv = b64encode(cipher.iv).decode('utf-8')
#     ct = b64encode(ct_bytes).decode('utf-8')
#     key = b64encode(key).decode('utf-8')

#     result = json.dumps({'iv':iv, 'ciphertext':ct, 'key':key})
#     print(result)
#     return result

# def decrypt(json_input):
#     try:
#         b64 = json.loads(json_input)
#         iv = b64decode(b64['iv'])
#         ct = b64decode(b64['ciphertext'])
#         key = b64decode(b64['key'])

#         cipher = AES.new(key, AES.MODE_CBC, iv)
#         pt = unpad(cipher.decrypt(ct), AES.block_size)
#         return pt
#     except ValueError:
#         return "Incorrect decryption"

# def sendTGT(Kat, nonce, ts, lifetime, Kst, sender, Kas):
#     message = Kat + "," + str(nonce) + "," + str(ts) + "," + str(lifetime) + ",tgs"
#     print("printing plaintext at beginning...\n" + message)
#     message = message.encode()
#     # Kas = Kas.encode()

#     json_input = encrypt(message, Kas)
#     print(b64encode(Kas).decode('utf-8'))
#     # trying decrypt
#     # print("printing plaintext at end...\n")
#     # print(decrypt(json_input))
#     # print(message_encrypt)
#     # pass_key = Kat + "," + sender + "," + lifetime
#     # pass_key_encrypt = encrypt(pass_key, Kst)

#     # message_encrypt += "." + pass_key_encrypt
#     # print(message_encrypt)


# Kat = uuid.uuid4().hex
# ts = time.time()
# lifetime = 600 # seconds
# Kst = get_random_bytes(16)
# # print("Kst: " + str(Kst))
# Kas = get_random_bytes(16)
# # print("Kas: " + str(Kas))
# nonce = uuid.uuid4().hex
# sender = "a"

# sendTGT(Kat, nonce, ts, lifetime, Kst, sender, Kas)

# print(time.ctime(time.time()))
from datetime import datetime
now = datetime.now()

formatted_time = now.strftime('%H:%M:%S')
print(type(formatted_time))