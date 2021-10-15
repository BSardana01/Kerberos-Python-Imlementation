'''
    Auth server just checks if the client is in mysql db
    A request is sent by the client (a) via socket to set communication b/w tgs
    Auth server sends back {Kat, Na, T, L, tgs}Kas and a pass {Kat, a, L}Kst
'''
import socket
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto import Random
import json
import mysql.connector
import datetime

# setting up socket
server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
LOCALHOST = '127.0.0.1'
port = 1555

server_socket.bind((LOCALHOST,port))
server_socket.listen(5)

print("[*] AuthServer started...")

client_sockets,addr=server_socket.accept()

# setting up db connection
mydb = mysql.connector.connect(
  host="localhost",
  user="police",
  password="6633",
  database="kerberos"
)
cursor = mydb.cursor()

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
        return "\n[*] Incorrect decryption"

# Send ticket granting ticket back to client
def sendTGT(Kat, nonce, ts, lifetime, Kst, sender, Kas):
    # Sncrypted message for tgs
    message = Kat + "," + nonce + "," + str(ts) + "," + str(lifetime) + ",tgs"
    message = message.encode()

    message_encrypt = encrypt(message, Kas, "client")
    
    # pass key the client passes to tgs
    pass_key = Kat + "," + sender + "," + str(lifetime)
    pass_key = pass_key.encode()

    pass_key_encrypt = encrypt(pass_key, Kst, "tgs")

    dictME = json.loads(message_encrypt)
    dictPE = json.loads(pass_key_encrypt)

    dictPE.update(dictME)

    final_message = json.dumps(dictPE)
    client_sockets.send(final_message.encode("ascii"))
    print("\n[*] Sent encrypted message: (Kat, N, T, L, TGS) and pass key: (Kat, a, L) to client\n")

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

while True:
    msg_received = client_sockets.recv(4096)
    msg_received = msg_received.decode()
    message = msg_received.split(',')

    isPreset = False
    sender = ''
    nonce = ''
    
    Kat_b64_db = ''
    ts_db = '' 
    lifetime_db = '' 
    nonce_db = ''
    if len(message) == 0:
        print("\n[*] Invalid request")
    else:
        # Get request from client
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
                print("\n[*] User doesn't exist")
                isPreset = False
            else:
                print("\n[*] User and requested service exist\n")
                print("\n[*] Creating and sending Kat to client...\n")
                isPreset = True
        except:
            mydb.rollback()
    
    if isPreset == False:
        break
    
    # Store Kat, ts and lifetime in db, check if the key is valid
    isKatPresent = False
    Kat_b64 = ''
    now = datetime.datetime.now()
    formatted_time = now.strftime('%H:%M:%S')
    lifetime = 600 # seconds

    sql_check_kat = "SELECT ltk_key, ltk_ts, ltk_lifetime, ltk_nonce FROM long_term_key WHERE ltk_client=%s"
    sql_check_kat_data = [(sender)]

    try:
        cursor.execute(sql_check_kat, sql_check_kat_data)
        row_count = cursor.rowcount
        results = cursor.fetchall()
        
        if(len(results) != 0):
            isKatPresent = True
            Kat_b64_db = results[0][0]
            ts_db = results[0][1]
            lifetime_db = results[0][2]
            nonce_db = results[0][3]

            # print("Kat_b64_db: ", Kat_b64_db)
            # print(type(Kat_b64_db), type(ts_db), type(lifetime_db), type(nonce_db))
    except Exception as error:
        print("Exception thrown: {0}".format(error))
        mydb.rollback()
        print("\nrolling back on sql_Kat_check")

    if isKatPresent == True:
        if checkValidation(ts_db, lifetime_db) == True:
            print("[*] Valid Kat found")
            Kat_b64 = Kat_b64_db
            lifetime = lifetime_db
            nonce = nonce_db
            formatted_time = ts_db
        else:
            print("[*] Kat is present but not valid\n")
            print("[*] Creating new Kat...")
            sql_Kat_del = "DELETE FROM long_term_key WHERE ltk_client=%s"
            sql_Kat_del_data = [(sender)]

            try:
                cursor.execute(sql_Kat_del, sql_Kat_del_data)
                mydb.commit()
            except Exception as error:
                print("Exception thrown: {0}".format(error))
                mydb.rollback()
                print("\nrolling back on sql_Kat_del")

            Kat = Random.get_random_bytes(16)
            # Storing Kat as base64 string in db
            Kat_b64 = b64encode(Kat).decode('utf-8')
            now = datetime.datetime.now()
            formatted_time = now.strftime('%H:%M:%S')
            lifetime = 600 # seconds

            # Store Kat in db (as it is a long-term key)
            sql_Kat = ("INSERT INTO long_term_key(ltk_client, ltk_key, ltk_ts, ltk_lifetime, ltk_nonce) VALUES (%s, %s, %s, %s, %s)")
            sql_Kat_data = (sender, Kat_b64, formatted_time, lifetime, nonce)
            print("\n[*] Storing Kat in db: ", Kat)

            try:
                cursor.execute(sql_Kat, sql_Kat_data)
                mydb.commit()
            except Exception as error:
                print("Exception thrown: {0}".format(error))
                mydb.rollback()
                print("\nrolling back on sql_Kat")
    else:
        Kat = Random.get_random_bytes(16)
        # Storing Kat as base64 string in db
        Kat_b64 = b64encode(Kat).decode('utf-8')
        now = datetime.datetime.now()
        formatted_time = now.strftime('%H:%M:%S')
        lifetime = 600 # second
        # Store Kat in db (as it is a long-term key)
        sql_Kat = ("INSERT INTO long_term_key(ltk_client, ltk_key, ltk_ts, ltk_lifetime, ltk_nonce) VALUES (%s, %s, %s, %s, %s)")
        sql_Kat_data = (sender, Kat_b64, formatted_time, lifetime, nonce)
        print("\n[*] Storing Kat in db: ", Kat_b64)
        try:
            cursor.execute(sql_Kat, sql_Kat_data)
            mydb.commit()
        except Exception as error:
            print("Exception thrown: {0}".format(error))
            mydb.rollback()
            print("\nrolling back on sql_Kat")

    # Get Kst from db
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

    print("\n[*] Got Kst from db: ", b64decode(Kst_b64))
    # Get Kas from db
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

    print("\n[*] Got Kas from db: ", b64decode(Kas_b64))
    # Send Kat back to client with
    Kas = b64decode(Kas_b64)
    Kst = b64decode(Kst_b64)
    sendTGT(Kat_b64, nonce, formatted_time, lifetime, Kst, sender, Kas)

    # Breaking for demo
    client_sockets.close()
    break

mydb.close()
