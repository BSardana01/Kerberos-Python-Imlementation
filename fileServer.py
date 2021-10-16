import socket
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import json
from Crypto.Cipher import AES
import datetime

Kbt = "tSJf8oFYd7LZkmhL+AGTog=="
secret_owned_by_fs_A = "$$$$Extremely Secret First Message$$$$"
secret_owned_by_fs_B = "###$$$SECRETB"

# setting up socket
server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
LOCALHOST = '127.0.0.3'
port = 1557

server_socket.bind((LOCALHOST,port))
server_socket.listen(5)

print("[*] File Server started...")
client_sockets,addr=server_socket.accept()

# setting up aes
def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')

    result = json.dumps({'iv_pass': iv, 'ciphertext_pass': ct})
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
        return "\n[*] Incorrect decryption"

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

while(True):
    # Get request from client
    msg_received = client_sockets.recv(4096)
    msg_received = msg_received.decode()

    b64 = json.loads(msg_received)
    # pass key
    iv_pass = b64['iv_pass']
    ciphertext_pass = b64['ciphertext_pass']
    # request from client
    iv_to_fs = b64['iv_to_tgs']
    ciphertext_to_fs = b64['ciphertext_to_tgs']

    # Decrypting message with Kbt to get Kab
    message_to_decrypt = json.dumps({'iv_client':iv_pass, 'ciphertext_client':ciphertext_pass, 'key':Kbt})
    message_recieved = decrypt(message_to_decrypt).decode()
    if(message_recieved == "Incorrect decryption"):
        print("\n[*] Incorrect pass key")
        break

    b64 = json.loads(message_recieved)
    Kab_b64 = b64["Kab"]
    Kab_ts = b64["formatted_time"]
    Kab_lifetime = b64["lifetime"]

    Kab = b64decode(Kab_b64)
    print("\n[*] Got Kab: ", Kab_b64)

    message_from_client = json.dumps({'iv_client': iv_to_fs, 'ciphertext_client': ciphertext_to_fs, 'key': Kab_b64})
    message_from_client_decrypted = decrypt(message_from_client).decode()
    message_from_client_decrypted = json.loads(message_from_client_decrypted)

    sender = message_from_client_decrypted["sender"]
    time_received = message_from_client_decrypted["formatted_time"]

    # To prove that fileServer is not malicious, 
    # it sends back Ta+1 which is confirmed by client

    # If this is done, Kab can then be used to exchange data
    new_time = datetime.datetime.strptime(time_received, '%H:%M:%S')
    new_time = new_time + datetime.timedelta(minutes=1)
    new_time = new_time.time().strftime('%H:%M')

    new_time_encrypt = encrypt(new_time.encode(), Kab)
    client_sockets.send(new_time_encrypt.encode("ascii"))

    while True:
        # sending secret to client if Kab is valid
        msg_received = client_sockets.recv(4096)
        msg_received = msg_received.decode()

        # if msg_received == "breakForNewKab":
        #     print("message received from client about new Kab, breaking from I/O while loop\n")
        #     break

        if(checkValidation(Kab_ts, Kab_lifetime) == False):
            final_message = encrypt("Session expired".encode(), Kab)
            
            client_sockets.send(final_message.encode())
            break

        b64 = json.loads(msg_received)
        iv_to_fs = b64['iv_to_tgs']
        ciphertext_to_fs = b64['ciphertext_to_tgs']

        message_from_client = json.dumps({'iv_client': iv_to_fs, 'ciphertext_client': ciphertext_to_fs, 'key': Kab_b64})
        message_from_client_decrypted = decrypt(message_from_client).decode()

        if(message_from_client_decrypted == "getSecretA"):
            # send secret
            final_message = secret_owned_by_fs_A
            final_message = encrypt(final_message.encode(), Kab)
            
            client_sockets.send(final_message.encode())
            print("\n[*] Sending encrypted secret to client\n")
        elif(message_from_client_decrypted == "getSecretB"):
            # send secret
            final_message = secret_owned_by_fs_B
            final_message = encrypt(final_message.encode(), Kab)
            
            client_sockets.send(final_message.encode())
            print("\n[*] Sending encrypted secret to client\n")
        elif(message_from_client_decrypted == "exit"):
            break
        else:
            # send response
            final_message = encrypt("Incorrect Request".encode(), Kab)
            
            client_sockets.send(final_message.encode())
            print("\n[*] Sending encrypted secret to client\n")



