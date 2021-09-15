import random, binascii

def clientValues():
    val = random.randint(2, 999)
    return val

def serverValues():
    val = random.randint(2, 999)
    return val

def sharedValues(base, modulo):
    base = random.randint(2, 999)
    modulo = random.randint(2, 999)
    return base, modulo

def calc_dh(first, second, third):
    return int((first ** second) % third)

def encrypt_DH(self, message):
    print("hej")

def decrypt_DH(self, message):
    print("hej")