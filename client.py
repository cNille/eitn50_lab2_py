from diffiehellman.diffiehellman import DiffieHellman
import socket, string, random, hashlib
from cypher import AESCipher 

# Generate keypair. Alice is nickname for the client
alice = DiffieHellman()
alice.generate_public_key()    # automatically generates private key

print("=======================")
print("Public key:", alice.public_key)
print("=======================")

# Init Socket
UDP_IP = "127.0.0.1"
UDP_PORT = 5005
address = (UDP_IP, UDP_PORT)
sock = socket.socket(
    socket.AF_INET, # Internet
    socket.SOCK_DGRAM # UDP
)

# The function used to send messages to the server
# The aesciph has to be initiated before this is called.
def send_message(msg, sequence_number):

    # Create msg of msg,session and sequence with ':::::' as seperator
    complete_msg = ':::::'.join([msg, str(sequence_number)])

    # Create hash of msg
    hashvalue = hashlib.sha256(complete_msg.encode('utf-8')).digest()
    
    # append hash with '%%%%%' as seperator
    # The msg syntax will be: 
    # START%%%%%MESSAGE:::::SESSION:::::SEQUENCENBRR%%%%%HASHVALUE%%%%%END
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
print("session:", session)
print("=======================")
send_message(str(session), 0)

sequence_number = 1

# ===========================
# Here starts the communication when the session is started

# Use session as masterkey to encrypt instead of shared_key
aesciph = AESCipher(str(session))

while True:
    message = input("Enter a message to send: ")
    sequence_number = send_message(message, sequence_number)
    resp = recieve_response()
    print('Server response:', resp)
