'''
    Client sends message to authServer a, tgs, Na
    Client receives the message and pass key 
    Client decrypts the message with his key Kas and gets Kat
    Client takes the pass and sends it to tgs as it is
'''
import socket
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import uuid
import json
from Crypto.Cipher import AES
import mysql.connector
import datetime

# shared key with authServer (long term)
Kas = "AGsa0AIzNvVtAG1Az4FSdg=="

# setting up sockets
server_socket_AS = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket_TGS = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server_socket_FS = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

LOCALHOST = '127.0.0.1'
server_tgs = '127.0.0.2'
server_fs = '127.0.0.3'

port_AS = 1555
port_TGS = 1556
port_FS = 1557

print("[*] Starting client...")
server_socket_AS.connect((LOCALHOST,port_AS))
server_socket_TGS.connect((server_tgs,port_TGS))
server_socket_FS.connect((server_fs,port_FS))

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
        return "\n[*] Incorrect decryption"

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')

    result = json.dumps({'iv_to_tgs': iv, 'ciphertext_to_tgs': ct})

    return result

def killSockets():
    server_socket_AS.close()
    server_socket_TGS.close()
    server_socket_FS.close()

while True:
    # send a request to auth server
    nonce = uuid.uuid4().hex
    message = "a,b," + nonce

    print("\n[*] Sending message to authServer: ", message)
    server_socket_AS.send(message.encode())

    msg_received = server_socket_AS.recv(4096)
    msg_received = msg_received.decode()

    # get pass and encrypted message from authServer
    b64 = json.loads(msg_received)
    iv_client = b64["iv_client"]
    ciphertext_client = b64["ciphertext_client"]

    iv_tgs = b64["iv_tgs"]
    ciphertext_tgs = b64["ciphertext_tgs"]

    message_to_decrypt = json.dumps({'iv_client':iv_client, 'ciphertext_client':ciphertext_client, 'key':Kas})
    # print("decoded message: \n")
    message_recieved = decrypt(message_to_decrypt).decode()

    message_recieved_list = message_recieved.split(',')
    print("\n[*] Encrypted message received from authServer: \n", message_recieved_list)
    print("\n[*] Pass key received from authServer: \n", ciphertext_tgs)
    
    Kat_b64 = message_recieved_list[0]
    nonce = message_recieved_list[1]
    ts = message_recieved_list[2]
    lifetime = message_recieved_list[3]
    service = message_recieved_list[4]

    Kat = b64decode(Kat_b64) # bytes

    # Send {a, Ta, b, N1} and pass key to TGS
    now = datetime.datetime.now()
    formatted_time = now.strftime('%H:%M:%S')
    nonce1 = uuid.uuid4().hex

    request_to_tgs = json.dumps({
        'sender': 'a',
        'formatted_time': formatted_time,
        'service': 'b',
        'nonce': nonce1,
    })
    # print(request_to_tgs)
    request_to_tgs_encrypt = encrypt(request_to_tgs.encode(), Kat)
    final_request_to_tgs_encrypt = {
        'iv_tgs': iv_tgs,
        'ciphertext_tgs': ciphertext_tgs,
    }
    dictME = json.loads(request_to_tgs_encrypt)
    dictPE = final_request_to_tgs_encrypt

    dictPE.update(dictME)

    final_message = json.dumps(dictPE)
    print("\n[*] Sending encrypted message to TGS: ", final_message)

    server_socket_TGS.send(final_message.encode())

    # Get message: {Kab, n1, T, L, b}Kat and pass: {Kab, a, L}Kbt
    msg_received = server_socket_TGS.recv(4096)
    msg_received = msg_received.decode()

    # Get pass and encrypted from tgs for fileServer
    print("\n[*] Message received from TGS: \n", msg_received)
    b64 = json.loads(msg_received)

    iv_client = b64["iv_client"]
    ciphertext_client = b64["ciphertext_client"]

    iv_pass = b64["iv_pass"]
    ciphertext_pass = b64["ciphertext_pass"]

    message_to_decrypt = json.dumps({'iv_client':iv_client, 'ciphertext_client':ciphertext_client, 'key':Kat_b64})
    message_from_tgs_decrypted = decrypt(message_to_decrypt).decode()
    message_from_tgs_decrypted = json.loads(message_from_tgs_decrypted)

    Kab_b64 = message_from_tgs_decrypted['Kab']
    Kab_ts = message_from_tgs_decrypted['formatted_time']
    Kab_lifetime = message_from_tgs_decrypted['lifetime']

    print("\n[*] Kab received: ", Kab_b64)

    # sending request and pass to fileServer
    # {a, Tb}Kab and {iv_pas, ciphertext_pass}
    now = datetime.datetime.now()
    formatted_time = now.strftime('%H:%M:%S')

    request_to_FS = json.dumps({
        'sender': 'a',
        'formatted_time': formatted_time,
    })
    request_to_FS_encrypt = encrypt(request_to_FS.encode(), b64decode(Kab_b64))
    final_request_to_FS_encrypt = {
        'iv_pass': iv_pass,
        'ciphertext_pass': ciphertext_pass,
    }

    dictME = json.loads(request_to_FS_encrypt)
    dictPE = final_request_to_FS_encrypt

    dictPE.update(dictME)

    final_message = json.dumps(dictPE)
    server_socket_FS.send(final_message.encode())

    # get (Ta+1)Kab from fileserver and check it for local Kab
    # we can then use Kab to request secret
    msg_received = server_socket_FS.recv(4096)
    msg_received = msg_received.decode()

    print("\n[*] Attempting Time Check to prevent replay attack\n")
    
    b64 = json.loads(msg_received)
    iv_pass = b64["iv_pass"]
    ciphertext_pass = b64["ciphertext_pass"]
    message_to_decrypt = json.dumps({'iv_client':iv_pass, 'ciphertext_client':ciphertext_pass, 'key':Kab_b64})
    message_from_fs_decrypted = decrypt(message_to_decrypt).decode()

    if(message_from_fs_decrypted == "Incorrect decryption"):
        print("\n[*] Incorrect Kab")
        break

    msg_received = message_from_fs_decrypted
    print("\n[*] T received from FileServer: ", msg_received)

    new_time = datetime.datetime.strptime(formatted_time, '%H:%M:%S')
    new_time = new_time + datetime.timedelta(minutes=1)
    new_time = new_time.time().strftime('%H:%M')
    print("\n[*] Current time +1: ", new_time)

    TCheck = False
    if(new_time == msg_received):
        print("\n[*] Time check successfull")
        TCheck = True
    else:
        print("\n[*] Time check failed")
        break

    if TCheck == True:
        # request secret message
        while True:
            final_message = input("Enter request: (getSecretA, getSecretB): ")
            final_message_exit = final_message
            # final_message = "giveSecret"
            
            final_message = encrypt(final_message.encode(), b64decode(Kab_b64))
                
            print("\n[*] Requesting secret message from FileServer\n")
            server_socket_FS.send(final_message.encode())

            if(final_message_exit == "exit"):
                killSockets()
                break
            # get secret message
            msg_received = server_socket_FS.recv(4096)
            msg_received = msg_received.decode()

            b64 = json.loads(msg_received)
            iv_pass = b64["iv_pass"]
            ciphertext_pass = b64["ciphertext_pass"]
            message_to_decrypt = json.dumps({'iv_client':iv_pass, 'ciphertext_client':ciphertext_pass, 'key':Kab_b64})
            message_from_fs_decrypted = decrypt(message_to_decrypt).decode()

            print("\n[*] Secret received from fileServer: ", message_from_fs_decrypted)
    else:
        print("\n[*] Time check failed")
        killSockets()
        break

    # server_socket_AS.close()
    # server_socket_TGS.close()
    # server_socket_FS.close()
    killSockets()
    break
