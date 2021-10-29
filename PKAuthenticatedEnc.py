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


# FingerPrint could be sent through one secure channel, 
# so it can be used to detect malicious server
def FingerPrint(PK):
    PKbytes = base64.b64decode(PK)
    hashing = nacl.hash.blake2b(PKbytes)
    return hashing.decode('utf-8')

def GenKeyPairAE():
    secret_key = PrivateKey.generate()
    public_key = secret_key.public_key
    my_public = public_key.encode(Base64Encoder)
    my_public = my_public.decode('utf-8')
    return (secret_key, my_public)

# Sender -> Receiver
# SK : Sender's private Key
# PK : Reveiver's Public Key
def EncryptAE(message, SK, PK):
    message = message.encode('utf-8')
    bob_box = Box(SK, nacl.public.PublicKey(base64.b64decode(PK)))
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    encrypted = bob_box.encrypt(message, nonce)
    ctext = nonce + encrypted.ciphertext
    ctext = base64.b64encode(ctext)
    return ctext.decode('utf-8')

def DecryptAE(cipher, SK, PK):
    bob_box = Box(SK, nacl.public.PublicKey(base64.b64decode(PK)))
    ctext = base64.b64decode(cipher)
    plain = bob_box.decrypt(ctext)
    return plain.decode('utf-8')