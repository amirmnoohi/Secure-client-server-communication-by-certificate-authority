import os
import socket
import threading
from base64 import b64encode

import functions

# *******************GENERATE CA RSA KEYS********************
p = functions.pstart("Generating RSA keys", 0.2)
public, private = functions.newkeys(1024)
ca_keys = functions.keys(public, private)  # as RSA Object
directory = os.path.join(os.getcwd(), 'CA')
if not os.path.exists(directory):
    os.makedirs(directory)
    os.makedirs(os.path.join(directory, "clients"))
functions.file(directory, ca_keys.public.exportKey("PEM")).write("public_key.PEM")  # Write client public key to file
functions.file(directory, ca_keys.private.exportKey("PEM")).write("private_key.PEM")  # Write client private key to file
functions.pstop(p, 1.5)
print(functions.bcolors.OKGREEN + "[+] RSA Keys Generated Successfully" + functions.bcolors.ENDC)
# ****************************************************************


class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
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

    def listenToClient(self, client, address):
        size = 1024
        data = client.recv(size)
        name = data
        data = client.recv(size)
        pub = data
        functions.clean()
        print(functions.bcolors.OKGREEN + "[+] User " + name.decode("utf-8") + " Connected" + functions.bcolors.ENDC)
        if name:
            dir = os.path.join(directory, "clients")
            functions.file(dir, pub).write(name.decode("utf-8") + ".PEM")
            sign = b64encode(functions.sign(pub, private))
            client.send(sign)
            functions.wait()
            client.send(ca_keys.public.exportKey("PEM"))
            functions.clean()
            print(functions.bcolors.OKGREEN + "        Certificate Sent Successfully" + functions.bcolors.ENDC)
        else:
            print(functions.bcolors.WARNING + "[-] Client disconnected" + functions.bcolors.ENDC)
            client.close()
            return False

    def terminate(self):
        p.terminate()


if __name__ == "__main__":
    while True:
        port_num = 1104
        try:
            port_num = int(port_num)
            break
        except ValueError:
            pass
    T = ThreadedServer('', port_num)
    try:
        T.listen()
    except KeyboardInterrupt:
        p.terminate()
        T.terminate()
        print(functions.bcolors.FAIL + "\nKeyboard Interrupt Pressed" + functions.bcolors.ENDC)
        exit(0)
