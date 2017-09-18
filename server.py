from diffiehellman.diffiehellman import DiffieHellman
import socket
from cypher import AESCipher 

# Generate keypair
bob = DiffieHellman()
bob.generate_public_key()

# Set server url
UDP_IP = "127.0.0.1"
UDP_PORT = 5005

# Init socket
sock = socket.socket(
    socket.AF_INET, # Internet
    socket.SOCK_DGRAM # UDP
)
address = (UDP_IP, UDP_PORT)
sock.bind(address)



while True:
    data, client_addr = sock.recvfrom(4096) # buffer size is 4096 bytes
    msg = data.decode()

    if(msg.startswith("PUBLIC_KEY")):
        pbkey = msg.split(',')[1]
        pbkey = int(pbkey)
        
        bob.generate_shared_secret(pbkey, echo_return_key=True)
        bobkey = (str(bob.public_key)).encode()

        sock.sendto(bobkey, client_addr)
        
        print("shared key:", bob.shared_key)




    elif hasattr(bob, 'shared_key'):
        aesciph = AESCipher(bob.shared_key)
        decrypted = aesciph.decrypt(data)
        sock.sendto(decrypted.encode(), client_addr)
        print(decrypted)





    else:
        sock.sendto("No shared key exists".encode(), client_addr)
        print("No shared key exists")



