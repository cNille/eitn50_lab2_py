from diffiehellman.diffiehellman import DiffieHellman
import socket, hashlib
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

session = ''

sessiontable = {}

while True:
    data, client_addr = sock.recvfrom(4096) # buffer size is 4096 bytes
    msg = data.decode('utf-8')

    if(msg.startswith("PUBLIC_KEY")):
        pbkey = msg.split(',')[1]
        pbkey = int(pbkey)
        
        bob.generate_shared_secret(pbkey, echo_return_key=True)
        bobkey = (str(bob.public_key)).encode('utf-8')

        sock.sendto(bobkey, client_addr)
        
        print("shared key:", bob.shared_key)
        print("=======================")

    elif(msg.startswith("SESSION")):
        session = msg.split(',')[1]
        print("session:", session)
        print("=======================")

    elif session != '':

        # Decyphir
        aesciph = AESCipher(bob.shared_key)
        decrypted = aesciph.decrypt(data)

        # Extract hash
        complete_msg, hashvalue = decrypted.strip().split('%%%%%%')

        # Verify hash
        newhash = hashlib.sha256(complete_msg.encode('utf-8')).digest()

        aoeu = ('%s' % newhash)

        if aoeu != hashvalue:
            print(aoeu)
            print(type(aoeu))
            print(hashvalue)
            print(type(hashvalue))
            print(hashvalue == newhash)
            sock.sendto("Hash unverified".encode('utf-8'), client_addr)
            continue

        # Extract message
        message, session, sequence_number = complete_msg.split(':::::')

        print('Seq: ', sequence_number)

        # Respond
        sock.sendto(message.encode('utf-8'), client_addr)
        print(decrypted)





    else:
        sock.sendto("No shared key exists".encode('utf-8'), client_addr)
        print("No shared key exists")

