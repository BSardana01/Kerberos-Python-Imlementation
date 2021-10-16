import socket
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import json
from Crypto.Cipher import AES
from Crypto import Random
import datetime

# shared key with authServer (long term)
Kst = "m2ao3jabyAOswVJn6Fp4zA=="
Kbt = "tSJf8oFYd7LZkmhL+AGTog=="
# setting up socket
server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
LOCALHOST = '127.0.0.2'
port = 1556

server_socket.bind((LOCALHOST,port))
server_socket.listen(5)

print("[*] Ticket Granting Service started...")

client_sockets,addr=server_socket.accept()

# setting up aes
def encrypt(data, key, msg):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')

    if msg == "pass":
        result = json.dumps({'iv_pass': iv, 'ciphertext_pass': ct})
        return result
    else:
        result = json.dumps({'iv_client': iv, 'ciphertext_client': ct})
        return result

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

while(True):
    # Get request from client
    msg_received = client_sockets.recv(4096)
    msg_received = msg_received.decode()

    print("\n[*] Message received from client: \n", msg_received)

    b64 = json.loads(msg_received)
    # pass key
    iv_tgs = b64['iv_tgs']
    ciphertext_tgs = b64['ciphertext_tgs']
    # request from client
    iv_to_tgs = b64['iv_to_tgs']
    ciphertext_to_tgs = b64['ciphertext_to_tgs']

    message_to_decrypt = json.dumps({'iv_client':iv_tgs, 'ciphertext_client':ciphertext_tgs, 'key':Kst})
    message_recieved = decrypt(message_to_decrypt).decode()

    # Check if encryption was done with the right key
    if(message_recieved == "Incorrect decryption"):
        print("\n[*] Incorrect Kst")
        break

    Kat = message_recieved.split(',')[0]
    message_from_client = json.dumps({'iv_client': iv_to_tgs, 'ciphertext_client': ciphertext_to_tgs, 'key': Kat})
    message_from_client_decrypted = decrypt(message_from_client).decode()
    message_from_client_decrypted = json.loads(message_from_client_decrypted)

    # sending back to client
    # {Kab, n1, T, L, b}Kat and pass {Kab, a, L}Kbt
    Kab = Random.get_random_bytes(16)
    Kab_b64 = b64encode(Kab).decode('utf-8')
    nonce1 = message_from_client_decrypted['nonce']
    now = datetime.datetime.now()
    formatted_time = now.strftime('%H:%M:%S')
    lifetime = 600

    message_back_to_client = json.dumps({
        'Kab': Kab_b64,
        'formatted_time': formatted_time,
        'service': 'b',
        'nonce': nonce1,
        'lifetime': lifetime
    })
    message_back_to_client_encrypt = encrypt(message_back_to_client.encode(), b64decode(Kat), "")
    
    pass_key = json.dumps({
        'Kab': Kab_b64,
        'sender': message_from_client_decrypted['sender'],
        'formatted_time': formatted_time,
        'lifetime': 30
    })
    pass_key_encrypted = encrypt(pass_key.encode(), b64decode(Kbt), "pass")

    dictME = json.loads(message_back_to_client_encrypt)
    dictPE = json.loads(pass_key_encrypted)

    dictPE.update(dictME)

    final_message = json.dumps(dictPE)
    print("\n[*] Sending encrypted message to client", final_message)
    client_sockets.send(final_message.encode("ascii"))

