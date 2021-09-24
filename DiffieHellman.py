import random

# Generates client's private key
def client_key():
   return random.randint(1, 99999) 


# Generates the server's private key
def server_key():
    return random.randint(1, 99999)

# Generates server's and client's shared values
def shared_values():
    base = random.randint(1, 99999)
    mod = random.randint(1, 99999)
    return base, mod

# Generates the master key, by combining generator, prime number, private key. Maybe change function name?
def gen_master_key(g, p, private_key):
    return int((g ** private_key) % p)