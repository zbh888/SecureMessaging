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

# returns (SK,PK) pair
def GenKeyPair():
    SK = SigningKey.generate()
    verify_key = SK.verify_key
    verify_key_b64 = verify_key.encode(encoder=Base64Encoder)
    PK=verify_key_b64.decode('utf-8')
    return (SK, PK)

def Sign(message, SK):
    message = message.encode('utf-8')
    signed_b64 = SK.sign(message, encoder=Base64Encoder)
    signature = signed_b64.decode('utf-8')
    return signature

def Verify(signature, PK):
    try:
        verify_key = VerifyKey(PK.encode('utf-8'), encoder=Base64Encoder)
        message = verify_key.verify(signature, encoder=Base64Encoder)
        return (True, message.decode('utf-8'))
    except:
        return (False, ' ')