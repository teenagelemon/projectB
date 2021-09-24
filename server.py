import socket
import pickle
from sys import meta_path
import DiffieHellman
import Encryptor

address_and_port = ("127.0.0.1", 8080)
buffer_size      = 1024
msg_from_server = "Recieved"

# Creates socket for server at specified address
UDP_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDP_server_socket.bind((address_and_port[0], address_and_port[1]))
print("UDP server up and listening.")

# Establishes the key exchange between server and client
def dh_handshake():
    
    # Random int used as the exponent in DH protocol 
    private_key = DiffieHellman.server_key()

    msg_from_client= UDP_server_socket.recvfrom(buffer_size)
    
    base_mod = pickle.loads(msg_from_client[0])
    base = base_mod[0] # Shared base 
    mod = base_mod[1]   # Shared modulus value

    # Computes server public key
    server_public_key = DiffieHellman.gen_master_key(base, mod, private_key)
    # Sends public key to client
    UDP_server_socket.sendto(pickle.dumps(server_public_key), msg_from_client[1])
    # Waits for response from client 
    msg_from_client = UDP_server_socket.recvfrom(buffer_size)
    # Gets public key from client
    client_public_key = pickle.loads(msg_from_client[0])
    # Genereates master key, unique for this session
    master_key = DiffieHellman.gen_master_key(client_public_key, mod, private_key,)

    return master_key
    

def start_session(master_key):
    while True:
        # Waits for message from client
        msg_from_client = UDP_server_socket.recvfrom(buffer_size)
        message = msg_from_client[0]
        address = msg_from_client[1]
        msg, mac = message[:16], message[16:]

        # Decrypts the message from client
        message = Encryptor.decrypt(Encryptor.intkey_to_aeskey(master_key), Encryptor.intkey_to_aesiv(master_key), message[:16])
        
        if not Encryptor.verifyMAC (str.encode(message), mac , master_key.to_bytes(32, byteorder ='big')):
           print ("Bad message")
           return 

        print("IP-address: {}".format(address))
        print (message)
        # Sends a encrypted message to the cleint

        MAC = Encryptor.computeMAC(str.encode(msg_from_server), master_key.to_bytes(32, byteorder ='big'))
        UDP_server_socket.sendto(Encryptor.encrypt(Encryptor.intkey_to_aeskey(master_key), Encryptor.intkey_to_aesiv(master_key), msg_from_server) + MAC, address)

key = dh_handshake()
start_session(key)