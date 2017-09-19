from diffiehellman.diffiehellman import DiffieHellman
import socket, string, random, hashlib
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

session = ''

def random_string(N):
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))

def send_message(msg, session, sequence_number):
    # Create msg of msg,session and sequence
    complete_msg = ':::::'.join([msg, str(session), str(sequence_number)])

    # Create hash of msg
    hashvalue = hashlib.sha256(complete_msg.encode('utf-8')).digest()
    
    # append hash
    complete_msg = '%%%%%%'.join(['START', complete_msg, str(hashvalue), 'END'])

    # Encrypt
    encrypted = aesciph.encrypt(complete_msg)

    # Send to server
    sock.sendto(encrypted, address)

    # Increment sequence
    return sequence_number + 1

def recieve_response():
    echo, serv_addr = sock.recvfrom(4096)
    return echo.decode('utf-8')


# ===========================
# Here starts the handshake

#def init_handshake():
handshake = "PUBLIC_KEY," + str(alice.public_key)
msg = handshake.encode('utf-8')
sock.sendto(msg, address)

bob_public_key, serv_addr = sock.recvfrom(4096)
bob_public_key = int(bob_public_key.decode('utf-8'))

alice.generate_shared_secret(bob_public_key, echo_return_key=True)
aesciph = AESCipher(alice.shared_key)

print("sharedkey;", alice.shared_key)
print("=======================")

session = random.getrandbits(128)
sessionmsg = "SESSION_SET" 
print("session:", sessionmsg)
print("=======================")
#sock.sendto(sessionmsg.encode('utf-8'), address)
send_message(sessionmsg, session, 0)

#init_handshake()

sequence_number = 1

# ===========================
# Here starts the communication

# Use session as masterkey to encrypt instead
aesciph = AESCipher(str(session))

while True:
    message = input("Enter a message to send: ")

    sequence_number = send_message(message, session, sequence_number)
    resp = recieve_response()
    print(resp)
