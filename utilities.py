import datetime
import json
import json
from base64 import b64decode
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

# Check if a key is valid or not
def checkValidation(ts, lifetime):
    valid_until = datetime.datetime.strptime(ts, '%H:%M:%S')
    valid_until = valid_until + datetime.timedelta(seconds=int(lifetime))
    valid_until = valid_until.time()

    now = datetime.datetime.now()
    current_time = now.strftime('%H:%M:%S')
    current_time = datetime.datetime.strptime(current_time, '%H:%M:%S')

    if(current_time.time() < valid_until):
        # print("[*] Key still valid")
        return True
    else:
        # print("[*] Invalid key")
        return False

def decrypt(json_input):
    try:
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv_client'])
        ct = b64decode(b64['ciphertext_client'])
        key = b64decode(b64['key'])

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
    except ValueError:
        return "Incorrect decryption"