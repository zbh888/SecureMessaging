import base64
import random
import string
import nacl.secret
import nacl.utils
import nacl.pwhash
import nacl.hash
from nacl.signing import SigningKey
from nacl.public import PrivateKey, Box
from nacl.encoding import Base64Encoder
from nacl.signing import VerifyKey
import json

def EncryptSP(message, password, salt, oplimit, memlimit, keylength):
    message = message.encode('utf-8')
    password = password.encode('utf-8')
    key = nacl.pwhash.scrypt.kdf(keylength, password, salt, oplimit, memlimit)
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(message, nonce)
    ctext = nonce + encrypted.ciphertext
    ctext = base64.b64encode(ctext)
    ctext = ctext.decode('utf-8')
    return ctext

def DecryptSP(cipher, password, salt, oplimit, memlimit, keylength):
    cipher = cipher.encode('utf-8')
    password = password.encode('utf-8')
    key = nacl.pwhash.scrypt.kdf(keylength, password, salt, oplimit, memlimit)
    box = nacl.secret.SecretBox(key)
    cipher = base64.b64decode(cipher)
    plaintext = box.decrypt(cipher)
    plaintext = plaintext.decode('utf-8')
    return plaintext