import base64
import os
import random
import re
import string
import sys
import time
from multiprocessing import Process

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

hash = "SHA-256"


def newkeys(keysize):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private


def sign(message, priv_key, hashalg=hash):
    global hash
    hash = hashalg
    signer = PKCS1_v1_5.new(priv_key)
    if hash == "SHA-512":
        digest = SHA512.new()
    elif hash == "SHA-384":
        digest = SHA384.new()
    elif hash == "SHA-256":
        digest = SHA256.new()
    elif hash == "SHA-1":
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.sign(digest)


def verify(message, signature, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
    if hash == "SHA-512":
        digest = SHA512.new()
    elif hash == "SHA-384":
        digest = SHA384.new()
    elif hash == "SHA-256":
        digest = SHA256.new()
    elif hash == "SHA-1":
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.verify(digest, signature)


def encrypt(message, pub_key):
    # RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)


def decrypt(ciphertext, priv_key):
    # RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)


class keys:
    def __init__(self, public_key, private_key):
        self.public = public_key
        self.private = private_key


class connection:
    def __init__(self, HOST, PORT):
        self.host = HOST
        self.port = PORT


class file:
    def __init__(self, directory, data):
        self.dir = directory
        self.data = data

    def write(self, name):
        f = open(os.path.join(self.dir, name), 'wb')
        f.write(self.data)
        f.close()

    def read(self):
        pass


def wait(length=0.1104):
    try:
        time.sleep(length)
    except KeyboardInterrupt:
        pass


def key_generator(size=16, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


class AESCipher:
    def __init__(self, key, blk_sz):
        self.key = key
        self.blk_sz = blk_sz

    def encrypt(self, raw):
        if raw is None or len(raw) == 0:
            raise NameError("No value given to encrypt")
        raw = raw + '\0' * (self.blk_sz - len(raw) % self.blk_sz)
        raw = raw.encode('utf-8')
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        if enc is None or len(enc) == 0:
            raise NameError("No value given to decrypt")
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CBC, iv)
        return re.sub(b'\x00*$', b'', cipher.decrypt(enc[16:])).decode('utf-8')


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def loading(text, speed):
    try:
        while True:
            sys.stdout.write(bcolors.OKBLUE + "\r" + "[-] " + text + bcolors.ENDC)
            wait(speed)
            sys.stdout.write(bcolors.OKBLUE + "\r" + "[\\] " + text + bcolors.ENDC)
            wait(speed)
            sys.stdout.write(bcolors.OKBLUE + "\r" + "[|] " + text + bcolors.ENDC)
            wait(speed)
            sys.stdout.write(bcolors.OKBLUE + "\r" + "[/] " + text + bcolors.ENDC)
            wait(speed)
    except KeyboardInterrupt:
        pass


def pstart(text, speed):
    p = Process(target=loading, args=(text, speed,))
    p.start()
    return p


def pstop(p, timeout=3):
    wait(timeout)
    sys.stdout.write("\r")
    p.terminate()


def clean():
    sys.stdout.write("\r\r\r\r")


space = "                     "
