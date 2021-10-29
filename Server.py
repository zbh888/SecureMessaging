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

class Server:
    def __init__(self):
        self.name_list = []
        self.token_user = {}
        self.storage = {}
        self.verification_keys = {}
        self.pre_keys = {}

    
    def signup(self, name, verification_key, pre_key):
        if name not in self.name_list:
            token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(10))
            self.name_list.append(name)
            self.token_user[token] = name
            self.storage[name] = []
            self.verification_keys[name] = verification_key
            self.pre_keys[name] = pre_key
            return (True, token)
        return (False, "")
    
    def requirePK(self, name):
        try:
            PK = verification_keys[name]
            return (True, PK)
        except:
            return (False, '')
    
    def requirePrePK(self, name):
        try:
            PK = pre_keys[name]
            return (True, PK)
        except:
            return (False, '')
    
    def send(self, payload):
        try:
            message = payload['message']
            receiver= payload['to']
            sender  = self.token_user[payload['api_token']]
             
            json = {'id' : len(self.storage[receiver]),
                    'from' : sender,
                    'message' : message}
            self.storage[receiver].append(json)
            return True
            
        except:
            return False 
    
    
    def receive(self, payload):
        try:
            receiver  = self.token_user[payload['api_token']]
            messages = self.storage[receiver]
            self.storage[receiver] = []
            return (True, messages)
        except:
            return (False,[])