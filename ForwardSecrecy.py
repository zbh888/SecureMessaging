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

# Use the signkey, return preKeyPair
def GenPreKey(SignKey):
    sk = PrivateKey.generate()
    pk = sk.public_key
    my_pk = pk.encode(Base64Encoder)
    my_pk = base64.b64decode(my_pk)
    signed_b64 = SignKey.sign(my_pk, encoder=Base64Encoder)
    return sk, signed_b64.decode('utf-8')

def EncryptFS(message, preKeySK, verifyKey, preKeySigned):
    verify_key = VerifyKey(verifyKey.encode('utf-8'), encoder=Base64Encoder)
    PK = verify_key.verify(base64.b64decode(preKeySigned))
    bob_box = Box(preKeySK, nacl.public.PublicKey(PK))
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    encrypted = bob_box.encrypt(message.encode('utf-8'), nonce)
    ctext = nonce + encrypted.ciphertext
    ctext = base64.b64encode(ctext)
    return ctext.decode('utf-8')

def DecryptFS(cipher, preKeySK, verifyKey, preKeySigned):
    cipher = base64.b64decode(cipher)
    verify_key = VerifyKey(verifyKey.encode('utf-8'), encoder=Base64Encoder)
    PK = verify_key.verify(base64.b64decode(preKeySigned))
    bob_box = Box(preKeySK, nacl.public.PublicKey(PK))
    plain=bob_box.decrypt(cipher)
    return plain.decode('utf-8')