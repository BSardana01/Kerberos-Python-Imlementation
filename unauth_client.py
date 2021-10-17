import socket
import uuid
from Crypto.Cipher import AES
import json

from utilities import decrypt

Kas = "don't know"
# setting up sockets
server_socket_AS = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
LOCALHOST = '127.0.0.1'
port_AS = 1555

print("[*] Starting client...")
server_socket_AS.connect((LOCALHOST,port_AS))

def checkWithAuthServer():
    nonce = uuid.uuid4().hex
    message = "d,b," + nonce

    print("\n[*] Sending message to authServer: ", message)
    server_socket_AS.send(message.encode())

    msg_received = server_socket_AS.recv(4096)
    msg_received = msg_received.decode()

    # exit if sender is not present in db
    if msg_received == "Unknown Client":
        print("\n[*] Sender not present in records, exiting...")
        server_socket_AS.send("exit".encode())
        server_socket_AS.close()
        exit()

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

    # return requestTGT(iv_tgs, ciphertext_tgs, message_recieved_list)

    return iv_tgs, ciphertext_tgs, message_recieved_list

while True:
    # first validate sender and requested service
    iv_tgs, ciphertext_tgs, message_recieved_list = checkWithAuthServer()