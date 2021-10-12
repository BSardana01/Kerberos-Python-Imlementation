'''
    Client sends message to authServer a, tgs, Na
    Client receives the message and pass key 
    Client decrypts the message with his key Kas and gets Kat
    Client takes the pass and sends it to tgs as it is
'''
import socket
from base64 import b64decode
from Crypto.Util.Padding import pad, unpad
import uuid
import json
from Crypto.Cipher import AES
import mysql.connector

# shared key with authServer (long term)
Kas = "AGsa0AIzNvVtAG1Az4FSdg=="

# setting up socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
LOCALHOST = '127.0.0.1'
port = 1555
s.connect((LOCALHOST,port))

# setting up db connection
mydb = mysql.connector.connect(
  host="localhost",
  user="police",
  password="6633",
  database="kerberos"
)

# setting up aes
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

while True:
    # send a request to auth server
    nonce = uuid.uuid4().hex
    message = "a,b," + nonce
    s.send(message.encode())

    msg_received = s.recv(4096)
    msg_received = msg_received.decode()
    # print(msg_received)

    # get pass and encrypted from authServer
    b64 = json.loads(msg_received)
    iv_client = b64["iv_client"]
    ciphertext_client = b64["ciphertext_client"]

    iv_tgs = b64["iv_tgs"]
    ciphertext_tgs = b64["ciphertext_tgs"]

    message_to_decrypt = json.dumps({'iv_client':iv_client, 'ciphertext_client':ciphertext_client, 'key':Kas})
    # print("decoded message: \n")
    message_recieved = decrypt(message_to_decrypt).decode()

    message_recieved_list = message_recieved.split(',')
    Kat_b64 = message_recieved_list[0]
    nonce = message_recieved_list[1]
    ts = message_recieved_list[2]
    lifetime = message_recieved_list[3]
    service = message_recieved_list[4]

    Kat = b64decode(Kat_b64) # bytes

    # send iv_tgs and ciphertext_tgs to tgs
    
    s.close()
    break
