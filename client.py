import socket
import DiffieHellman
import pickle
import Encryptor

address = ("127.0.0.1", 8080)
buffer_size          = 1024

# Creates socket for client 
UDP_client_socket= socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Establishes the key exchange between client and server
def dh_handshake(): 

    # Random int used as the exponent in DH protocol 
    private_key = DiffieHellman.client_key()

    base_mod = DiffieHellman.shared_values()
    base = base_mod[0] # Shared base
    mod = base_mod[1] # Shared modulus value
    
    # Sends base and modulus value to server
    UDP_client_socket.sendto(pickle.dumps(base_mod), address)

    # Waits for response from server 
    msg_from_server = UDP_client_socket.recvfrom(buffer_size)
    # Gets public key from server
    server_public_key = pickle.loads(msg_from_server[0])
    # Computes client public key
    client_public_key = DiffieHellman.gen_master_key(base, mod, private_key)
    # Sends public key to server
    UDP_client_socket.sendto(pickle.dumps(client_public_key), address) 
    # Genereates master key, unique for this session
    master_key = DiffieHellman.gen_master_key(server_public_key, mod, private_key)
    return master_key

# Starts the secure connection between client and server
def start_session(master_key):
    while True:
        msg_from_client = input("Enter message ", )
      
        # Computes MAC
        MAC = Encryptor.computeMAC(str.encode(msg_from_client), master_key.to_bytes(32, byteorder ='big'))
        
        # Encrypts message from client and sends it to the servers
        UDP_client_socket.sendto(Encryptor.encrypt(Encryptor.intkey_to_aeskey(master_key), Encryptor.intkey_to_aesiv(master_key), msg_from_client) + MAC, address)

        # Waits for response from server
        msg_from_server = UDP_client_socket.recvfrom(buffer_size)
        msg_from_server = msg_from_server[0]
        msg, mac = msg_from_server[:16], msg_from_server[16:]
        # Decrypts messgage from server
        message = Encryptor.decrypt(Encryptor.intkey_to_aeskey(master_key), Encryptor.intkey_to_aesiv(master_key), msg[:16])
        
        if not Encryptor.verifyMAC (str.encode(message), mac , master_key.to_bytes(32, byteorder ='big')):
            print ("Bad message ")
            return        
        print(message)

key = dh_handshake()

start_session(key) 

