import hashlib
import os
import random
import socket
import threading
from base64 import b64decode, b64encode

from Crypto.PublicKey import RSA

import functions

username = "Amazon"
ca_server = functions.connection("127.0.0.1", 1104)
amazon_server = functions.connection("127.0.0.1", 1107)
ca_keys = functions.keys(None, None)
server_keys = functions.keys(None, None)
client_keys = functions.keys(None, None)
symmetric_key = ""

# *******************GENERATE SERVER RSA KEYS**********
p = functions.pstart("Generating RSA keys", 0.2)
public, private = functions.newkeys(1024)
server_keys.public = public
server_keys.private = private
directory = os.path.join(os.path.join(os.getcwd(), 'Server'), username)
if not os.path.exists(directory):
    os.makedirs(directory)
functions.file(directory, server_keys.public.exportKey("PEM")).write("public_key.PEM")
functions.file(directory, server_keys.private.exportKey("PEM")).write("private_key.PEM")
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
s.send(server_keys.public.exportKey("PEM"))
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


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
        except socket.error:
            print(
                functions.bcolors.FAIL + "Enabling the server has encountered a problem\nTry Another Time" + functions.bcolors.ENDC)
            exit(0)
        self.p = None

    def listen(self):
        p = functions.pstart("Waiting For Clients", 0.2)
        self.sock.listen(5)
        try:
            while True:
                client, address = self.sock.accept()
                functions.pstop(p, 0)
                client.settimeout(60)
                threading.Thread(target=self.listenToClient, args=(client, address)).start()
                p = functions.pstart("Waiting For Clients", 0.2)
        except KeyboardInterrupt:
            p.terminate()
            print(functions.bcolors.FAIL + "\nKeyboard Interrupt Pressed" + functions.bcolors.ENDC)
            exit(0)

    def listenToClient(self, conn, address):
        client_name = conn.recv(1024)
        client_keys.public = conn.recv(1024)
        sign = conn.recv(1024)
        functions.clean()
        print(functions.bcolors.OKGREEN + "[+] User " + client_name.decode(
            "utf-8") + " Connected" + functions.bcolors.ENDC)
        if client_name:
            ca_keys_public = RSA.importKey(ca_keys.public)
            verify = functions.verify(client_keys.public, b64decode(sign), ca_keys_public)
            if verify:
                functions.clean()
                print(functions.bcolors.OKGREEN + "[+] User " + client_name.decode(
                    "utf-8") + " Verified" + functions.bcolors.ENDC)
                # ***********************************SEND INFO TO CLIENT*****************
                conn.send(username.encode("utf-8"))
                functions.wait()
                conn.send(server_keys.public.exportKey("PEM"))
                functions.wait()
                conn.send(sign_sign)
                functions.wait()
                symmetric_key = functions.key_generator()
                symmetric_key_encrypted = b64encode(
                    functions.encrypt(symmetric_key.encode("utf-8"), RSA.importKey(client_keys.public)))
                conn.send(symmetric_key_encrypted)
                functions.wait()
                nonce = str(random.randint(1e9, 9e9))
                encrypt_nonce = b64encode(functions.encrypt(nonce.encode("utf-8"), RSA.importKey(client_keys.public)))
                conn.send(encrypt_nonce)
                functions.clean()
                print(functions.bcolors.OKGREEN + "        Symmetric Key Sent Successfully" + functions.bcolors.ENDC)
                # ************************************************************************
                # ***********************************GET ORDER FROM CLIENT*****************
                try:
                    encrypt_message = conn.recv(1024)
                    aes = functions.AESCipher(symmetric_key, 16)
                    message = aes.decrypt(encrypt_message)
                    encrypt_nonce = conn.recv(1024)
                    nonce_from_client = functions.decrypt(b64decode(encrypt_nonce), server_keys.private).decode("utf-8")
                    hash_message = conn.recv(1024).decode("utf-8")
                    if nonce == nonce_from_client:
                        functions.clean()
                        print(functions.bcolors.OKGREEN + "Valid Nonce" + functions.space + functions.bcolors.ENDC)
                        hash_message_gen = str(hashlib.sha256(message.encode("utf-8")).hexdigest())
                        if hash_message == hash_message_gen:
                            print(
                                functions.bcolors.OKGREEN + "Valid Checksum" + functions.space + functions.bcolors.ENDC)
                            functions.clean()
                            print("Client " + client_name.decode("utf-8") + " : " + message + functions.space)
                        else:
                            print(functions.bcolors.WARNING + "Message Integrity Problem" + functions.bcolors.ENDC)
                            conn.close()
                            return False
                    else:
                        print(
                            functions.bcolors.WARNING + "Reply Attack Detected Connection Will Close Shortly" + functions.bcolors.ENDC)
                        conn.close()
                        return False
                except NameError:
                    functions.clean()
                    print(functions.bcolors.WARNING + "[*] No Data Received from " + client_name.decode(
                        "utf-8") + functions.bcolors.ENDC)
                    return False
                except socket.timeout:
                    functions.clean()
                    print(functions.bcolors.WARNING + "[-] Connection to  " + client_name.decode(
                        "utf-8") + "  Closed Due to TimeOut" + functions.bcolors.ENDC)
                    return False
                # ************************************************************************
            else:
                conn.close()
        else:
            print(functions.bcolors.WARNING + "[-] Client disconnected" + functions.bcolors.ENDC)
            conn.close()
            exit(0)

    def terminate(self):
        p.terminate()


if __name__ == "__main__":
    T = ThreadedServer(amazon_server.host, amazon_server.port)
    try:
        T.listen()
    except KeyboardInterrupt:
        p.terminate()
        T.terminate()
        print(functions.bcolors.FAIL + "\nKeyboard Interrupt Pressed" + functions.bcolors.ENDC)
        exit(0)
