'''
    Auth server just checks if the client is in mysql db
    A request is sent by the client (a) via socket to set communication b/w tgs
    Auth server sends back {Kat, Na, T, L, tgs}Kas and a pass {Kat, a, L}Kst
'''
import socket
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import json
from Crypto.Cipher import AES
from Crypto import Random
import mysql.connector
import datetime

# setting up socket
server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
LOCALHOST = '127.0.0.1'
port = 1555

server_socket.bind((LOCALHOST,port))
server_socket.listen(5)

print("AuthServer started...")

client_sockets,addr=server_socket.accept()

# setting up db connection
mydb = mysql.connector.connect(
  host="localhost",
  user="police",
  password="6633",
  database="kerberos"
)

# Setting up aes-cbc encryption
def encrypt(data, key, service):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')

    if(service == "client"):
        result = json.dumps({'iv_client':iv, 'ciphertext_client':ct})
        return result
    else:
        result = json.dumps({'iv_tgs':iv, 'ciphertext_tgs':ct})
        return result
 
def decrypt(json_input):
    try:
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        key = b64decode(b64['key'])

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt
    except ValueError:
        return "Incorrect decryption"

cursor = mydb.cursor()

def sendTGT(Kat, nonce, ts, lifetime, Kst, sender, Kas):
    message = Kat + "," + nonce + "," + str(ts) + "," + str(lifetime) + ",tgs"
    message = message.encode()

    message_encrypt = encrypt(message, Kas, "client")
    
    pass_key = Kat + "," + sender + "," + str(lifetime)
    pass_key = pass_key.encode()

    pass_key_encrypt = encrypt(pass_key, Kst, "tgs")

    dictME = json.loads(message_encrypt)
    dictPE = json.loads(pass_key_encrypt)

    dictPE.update(dictME)

    final_message = json.dumps(dictPE)
    print("my final message...\n" + final_message)
    client_sockets.send(final_message.encode("ascii"))
    print("sent key and pass to client\n")

def checkValidation(ts, lifetime):
    ts_check = datetime.datetime.strptime(ts, '%H:%M:%S')

    formatted_time = datetime.datetime.now()
    current_validation = datetime.timedelta(0, int(lifetime))
    print("current_validation: ")
    print(type(current_validation), type(ts_check))

    if((ts_check + current_validation) <= formatted_time):
        print("valid key\n")
        return True
    else:
        print("Invalid key\n")
        return False

while True:
    msg_received = client_sockets.recv(4096)
    msg_received = msg_received.decode()
    message = msg_received.split(',')

    isPreset = False
    sender = ''
    nonce = ''
    if len(message) == 0:
        print("Invalid request")
    else:
        # get request from client
        sender = message[0]
        requestedService = message[1]
        nonce = message[2]

        # check if sender and requestedService exists in db
        sql = ("SELECT * FROM client_server_relation WHERE csr_client=%s AND csr_server=%s"
        )
        sql_data = (sender, requestedService)

        try:
            cursor.execute(sql, sql_data)
            results = cursor.fetchall()

            if results == None:
                print("User doesn't exist")
                isPreset = False
            else:
                print("User and requested service exist\n")
                print("Creating and sending Kat to a...\n")
                isPreset = True
        except:
            mydb.rollback()
    
    if isPreset == False:
        continue
    
    # store Kat, ts and lifetime in db, check if the key is valid 
    sql_Kat_del = "DELETE FROM long_term_key WHERE ltk_client = %s"
    sql_Kat_del_data = [(sender)]

    try:
        cursor.execute(sql_Kat_del, sql_Kat_del_data)
        mydb.commit()
    except Exception as error:
        print("Exception thrown: {0}".format(error))
        mydb.rollback()
        print("\nrolling back on sql_Kat_del")

    Kat = Random.get_random_bytes(16)
    # storing Kat as base64 string in db
    Kat_b64 = b64encode(Kat).decode('utf-8')
    now = datetime.datetime.now()
    formatted_time = now.strftime('%H:%M:%S')
    lifetime = 600 # seconds

    # store Kat in db (as it is a long-term key)
    sql_Kat = ("INSERT INTO long_term_key(ltk_client, ltk_key, ltk_ts, ltk_lifetime, ltk_nonce) VALUES (%s, %s, %s, %s, %s)")
    sql_Kat_data = (sender, Kat_b64, formatted_time, lifetime, nonce)
        
    try:
        cursor.execute(sql_Kat, sql_Kat_data)
        mydb.commit()
    except Exception as error:
        print("Exception thrown: {0}".format(error))
        mydb.rollback()
        print("\nrolling back on sql_Kat")
    
    # get Kst from db
    sql_Kst = ("SELECT user_password FROM shared_keys WHERE user_name=%s")
    sql_Kst_data = [('tgs')]

    try:
        cursor.execute(sql_Kst, sql_Kst_data)
        results = cursor.fetchall()
        Kst_b64 = results[0][0]
    except Exception as error:
        print("Exception thrown: {0}".format(error))
        mydb.rollback()
        print("\nrolling back on Kst")
    
    # get Kas from db
    sql_get_Kas = ("SELECT user_password FROM shared_keys WHERE user_name=%s")
    sql_get_Kas_data = [(sender)]

    try:
        cursor.execute(sql_get_Kas, sql_get_Kas_data)
        results = cursor.fetchall()
        Kas_b64 = results[0][0]
    except Exception as error:
        print("Exception thrown: {0}".format(error))
        mydb.rollback()
        print("\nrolling back on kas")

    # send Kat back to client with
    Kas = b64decode(Kas_b64)
    Kst = b64decode(Kst_b64)
    sendTGT(Kat_b64, nonce, formatted_time, lifetime, Kst, sender, Kas)

    client_sockets.close()
    break

mydb.close()
