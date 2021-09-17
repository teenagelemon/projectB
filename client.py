import socket
import DiffieHellman
import pickle
import Encryptor

serverAddressPort   = ("127.0.0.1", 20001)
bufferSize          = 1024

# Create a UDP socket at client side
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

def key_exchange():
    # Diffie Hellman
    privatekey = DiffieHellman.clientValues()
    baseMod = (0,0)
    baseMod = DiffieHellman.sharedValues(baseMod[0], baseMod[1])
    #Sending public base and modulo
    UDPClientSocket.sendto(pickle.dumps(baseMod), serverAddressPort)
    #Recieving calculated value from server
    bytesAddressPair = UDPClientSocket.recvfrom(bufferSize)
    serverValue = pickle.loads(bytesAddressPair[0])
    #Sending clientside DH-value
    clientValue = DiffieHellman.calc_dh(baseMod[0], privatekey, baseMod[1])
    UDPClientSocket.sendto(pickle.dumps(clientValue), serverAddressPort) 
    #Calculating real DH-value
    dh_value = DiffieHellman.calc_dh(serverValue, privatekey, baseMod[1])

    print(dh_value)
    return dh_value

# Send to server using created UDP socket
def connection_phase(dh_value):
    while True:
        msgFromClient = input("What do you want to send? (Maximum 16 characters) ", )
        UDPClientSocket.sendto(Encryptor.aes_encrypt(Encryptor.intkey_to_aeskey(dh_value), Encryptor.intkey_to_aesiv(dh_value), msgFromClient), serverAddressPort)
        msgFromServer = UDPClientSocket.recvfrom(bufferSize)
        message = Encryptor.aes_decrypt(Encryptor.intkey_to_aeskey(dh_value), Encryptor.intkey_to_aesiv(dh_value), msgFromServer[0])
        print(message)

key = key_exchange()
print(key)
connection_phase(key)