from diffiehellman.diffiehellman import DiffieHellman
import socket, hashlib, random, string
from cypher import AESCipher 

def random_string(N):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))

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
        
        sessiontable["sharedkey" + random_string(32)] = bob.shared_key

        print("shared key:", bob.shared_key)
        print("=======================")

    else:
        has_shared_key = False
        
        keyvalues = sessiontable.values()
        for masterkey in list(keyvalues):
            # Decyphir
            aesciph = AESCipher(masterkey)
            try:
                decrypted = aesciph.decrypt(data)
            except:
                continue

            # Extract hash
            decrypted = decrypted.strip().split('%%%%%%')
            if len(decrypted) != 4:
                continue
            start, complete_msg, hashvalue, end = decrypted

            # Verify start and end flags
            if start != 'START' or end != 'END':
                continue

            # Verify hash
            newhash = hashlib.sha256(complete_msg.encode('utf-8')).digest()

            # Convert newhash to string and check against hashvalue
            if ('%s' % newhash) != hashvalue:
                sock.sendto("Hash unverified".encode('utf-8'), client_addr)
                continue

            # Extract message
            message, session, sequence_number = complete_msg.split(':::::')

            if(message == "SESSION_SET" and sequence_number == '0'):
                has_shared_key = True
                sessiontable[masterkey] = session;
                print("session:", session)
                print("=======================")
                continue;

            # Respond
            has_shared_key = True
            sock.sendto(message.encode('utf-8'), client_addr)
            print(decrypted)

        if not has_shared_key:
            sock.sendto('==No shared key found'.encode('utf-8'), client_addr)
            
            

