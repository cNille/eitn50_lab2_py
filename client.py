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

#def init_handshake():
handshake = "PUBLIC_KEY," + str(alice.public_key)
msg = handshake.encode('utf-8')
sock.sendto(msg, address)

bob_public_key, serv_addr = sock.recvfrom(4096)
bob_public_key = int(bob_public_key.decode('utf-8'))

alice.generate_shared_secret(bob_public_key, echo_return_key=True)

print("sharedkey;", alice.shared_key)
print("=======================")

session = random_string(32)
sessionmsg = "SESSION," + session 
print("session:", sessionmsg)
print("=======================")
sock.sendto(sessionmsg.encode('utf-8'), address)


#init_handshake()

sequence_number = 0
def send_message(msg, session, sequence_number):
    # Increment sequence
    #sequence_number += 1  
    sequence_number = 1  

    # Create msg of msg,session and sequence
    complete_msg = ':::::'.join([msg, session, str(sequence_number)])

    # Create hash of msg
    hashvalue = hashlib.sha256(complete_msg.encode('utf-8')).digest()
    
    # append hash
    complete_msg = '%%%%%%'.join([complete_msg, str(hashvalue)])

    # Encrypt
    encrypted = aesciph.encrypt(complete_msg)

    # Send to server
    sock.sendto(encrypted, address)

def recieve_response():
    echo, serv_addr = sock.recvfrom(4096)
    return echo.decode('utf-8')




aesciph = AESCipher(alice.shared_key)
while True:
    message = input("Enter a message to send: ")

    send_message(message, session, sequence_number)
    resp = recieve_response()
    print(resp)
