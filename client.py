from diffiehellman.diffiehellman import DiffieHellman
import socket
from cypher import AESCipher 


# Generate keypair
alice = DiffieHellman()
alice.generate_public_key()    # automatically generates private key

# Init Socket
UDP_IP = "127.0.0.1"
UDP_PORT = 5005
address = (UDP_IP, UDP_PORT)
sock = socket.socket(
    socket.AF_INET, # Internet
    socket.SOCK_DGRAM # UDP
)




def init_handshake():
    handshake = "PUBLIC_KEY," + str(alice.public_key)
    msg = handshake.encode()
    sock.sendto(msg, address)

    bob_public_key, serv_addr = sock.recvfrom(4096)
    bob_public_key = int(bob_public_key.decode())

    alice.generate_shared_secret(bob_public_key, echo_return_key=True)

    print("sharedkey;", alice.shared_key)
    print("=======================")

init_handshake()





def send_message(message):
    if !hasattr(alice, 'shared_key'):
        print("Handshake not done")
    
      aesciph = AESCipher(alice.shared_key)






while True:
    message = input("Enter a message to send: ")
    encrypted = aesciph.encrypt(message)
    sock.sendto(encrypted, address)
    echo, serv_addr = sock.recvfrom(4096)
    print(echo.decode())
