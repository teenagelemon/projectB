from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import random
import sys
from cryptography.hazmat.backends  import default_backend 
from cryptography.hazmat.primitives import hashes , hmac

def intkey_to_aeskey(key):
    key = int_to_bytes(key)
    hash_object = hashlib.sha256(key) 
    key = hash_object.hexdigest()
    return key[0:16]

def intkey_to_aesiv(key): 
    key = int_to_bytes(key)
    hash_object = hashlib.sha256(key)  
    key = hash_object.hexdigest()
    return key[16:32]

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def pad(message): 
    data = bytes(message, 'utf-8')
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return data

def depad(data):
    data = data[:-data[-1]]
    message = str(data, 'utf-8')
    return message

def encrypt(key, iv, msg):
    data = pad(msg)
    obj = AES.new(key, AES.MODE_CBC, iv)
    cipher = obj.encrypt(data)
    return cipher

def decrypt(key, iv, cipher):
    obj = AES.new(key, AES.MODE_CBC, iv)    
    cipher = obj.decrypt(cipher)
    message = depad(cipher)
    return message

def computeMAC(message , key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message) 
    return h.finalize()

def verifyMAC(message, MAC, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize() == MAC



