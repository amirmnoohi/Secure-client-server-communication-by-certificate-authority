import argparse
import os
import hashlib
import socket
from base64 import b64decode,b64encode

from Crypto.PublicKey import RSA

import functions

ca_server = functions.connection("127.0.0.1", 1104)
amazon_server = functions.connection("127.0.0.1", 1107)
ca_keys = functions.keys(None, None)
client_keys = functions.keys(None, None)
server_keys = functions.keys(None, None)
symmeyric_key = ""
parser = argparse.ArgumentParser()
parser.add_argument('-n', '--name', help='Name of Client', required=True)
username = parser.parse_args().name

# *******************GENERATE CLIENT RSA KEYS**********
p = functions.pstart("Generating RSA keys", 0.2)
public, private = functions.newkeys(1024)
client_keys.public = public
client_keys.private = private
directory = os.path.join(os.path.join(os.getcwd(), 'Client'), username)
if not os.path.exists(directory):
    os.makedirs(directory)
functions.file(directory, client_keys.public.exportKey("PEM")).write("public_key.PEM")
functions.file(directory, client_keys.private.exportKey("PEM")).write("private_key.PEM")
functions.pstop(p, 1.5)
print(functions.bcolors.OKGREEN + "[+] Rsa Keys Generated Successfully" + functions.bcolors.ENDC)
# ******************************************************

# *******************SEND INFO TO CA********************
s = socket.socket()
try:
    s.connect((ca_server.host, ca_server.port))
except ConnectionRefusedError:
    print(functions.bcolors.FAIL + "Can't Connect to CA\nMaybe CA is Down" + functions.bcolors.ENDC)
    exit(0)
s.send(username.encode("utf-8"))
functions.wait()
s.send(client_keys.public.exportKey("PEM"))
functions.wait()
# *******************************************************

# *******************GET INFO FROM CA********************
p = functions.pstart("Getting Certificate From CA", 0.2)
sign_sign = s.recv(1024)
ca_keys.public = s.recv(1024)
functions.file(directory, sign_sign).write("ca_sign.PEM")
functions.file(directory, ca_keys.public).write("ca_public_key.PEM")
s.close()
functions.pstop(p, 1)
functions.clean()
print(functions.bcolors.OKGREEN + "[+] Certificate Received Successfully" + functions.bcolors.ENDC)
# *******************************************************

# *******************SEND INFO TO AMAZON********************
s = socket.socket()
try:
    s.connect((amazon_server.host, amazon_server.port))
except ConnectionRefusedError:
    print(functions.bcolors.FAIL + "Can't Connect to Server\nMaybe Server is Down" + functions.bcolors.ENDC)
    exit(0)
s.send(username.encode("utf-8"))
functions.wait()
s.send(client_keys.public.exportKey("PEM"))
functions.wait()
s.send(sign_sign)
functions.wait()
# *********************************************************


# *******************GET INFO FROM AMAZON********************
try:
    server_name = s.recv(1024)
    server_keys.public = s.recv(1024)
    server_sign = s.recv(1024)
    verify = functions.verify(server_keys.public, b64decode(server_sign), RSA.importKey(ca_keys.public))
    if verify:
        print(functions.bcolors.OKGREEN + "[+] Server " + server_name.decode(
            "utf-8") + " Verified" + functions.bcolors.ENDC)
        symmeyric_key_encrypted = s.recv(1024)
        symmeyric_key = functions.decrypt(b64decode(symmeyric_key_encrypted), client_keys.private).decode("utf-8")
        aes = functions.AESCipher(symmeyric_key, 16)
        encrypt_nonce = s.recv(1024)
        nonce = functions.decrypt(b64decode(encrypt_nonce), client_keys.private).decode("utf-8")
        message = str(input("Enter Your Order : "))
        encrypt_message = aes.encrypt(message)
        s.send(encrypt_message.encode("utf-8"))
        functions.wait()
        encrypt_nonce = b64encode(functions.encrypt(nonce.encode("utf-8"), RSA.importKey(server_keys.public)))
        s.send(encrypt_nonce)
        functions.wait()
        hash_message = str(hashlib.sha256(message.encode("utf-8")).hexdigest())
        s.send(hash_message.encode("utf-8"))
        print(functions.bcolors.OKGREEN + "[+] Message Sent Successfully" + functions.bcolors.ENDC)
        functions.wait(2)
        s.close()
    else:
        s.close()
    s.close()
except KeyboardInterrupt:
    print(functions.bcolors.FAIL + "\nKeyboard Interrupt Pressed" + functions.bcolors.ENDC)
    exit(0)
except NameError:
    print(functions.bcolors.OKGREEN + "[-] Empty Message" + functions.bcolors.ENDC)
    exit(0)
# *******************************************************
