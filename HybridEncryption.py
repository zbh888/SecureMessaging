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

def EncryptHybrid(message, SK, PK, PKgov):
    message = message.encode('utf-8')
    # symmetric encryption part
    message_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    message_nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    box = nacl.secret.SecretBox(message_key)
    encrypted = box.encrypt(message, message_nonce)
    message_ciphertext=encrypted.ciphertext
    
    # Encryption for receiver
    bob_box2 = Box(SK, nacl.public.PublicKey(base64.b64decode(PK)))
    recipient_nonce = nacl.utils.random(Box.NONCE_SIZE)
    encrypted2 = bob_box2.encrypt(message_key, recipient_nonce)
    recipient_ciphertext=encrypted2.ciphertext
    
    # Encryption for gov
    bob_box3 = Box(SK, nacl.public.PublicKey(base64.b64decode(PKgov)))
    government_nonce = nacl.utils.random(Box.NONCE_SIZE)
    encrypted3 = bob_box3.encrypt(message_key, government_nonce)
    government_ciphertext=encrypted3.ciphertext
    
    # findal cipher
    ciphertext=recipient_nonce+recipient_ciphertext+government_nonce+government_ciphertext+message_nonce+message_ciphertext
    ctext = base64.b64encode(ciphertext)
    return ctext.decode('utf-8')

def DecryptHybridReceive(ciphertext, SK, PK):
    cipher = base64.b64decode(ciphertext)
    message_key = cipher[0:72]
    ciphertext  = cipher[144:]
    bob_box = Box(SK, nacl.public.PublicKey(base64.b64decode(PK)))
    key = bob_box.decrypt(message_key)
    box = nacl.secret.SecretBox(key)
    plaintext = box.decrypt(ciphertext)
    return plaintext.decode('utf-8')
    
def DecryptHybridGov(ciphertext, SK, PK):
    cipher = base64.b64decode(ciphertext)
    message_key = cipher[72:144]
    ciphertext  = cipher[144:]
    bob_box = Box(SK, nacl.public.PublicKey(base64.b64decode(PK)))
    key = bob_box.decrypt(message_key)
    box = nacl.secret.SecretBox(key)
    plaintext = box.decrypt(ciphertext)
    return plaintext.decode('utf-8')