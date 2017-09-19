# Install dependencies

There are two dependencies to the project. Install by:

### Install for python < 3
```
pip install pycrypto
pip install diffiehellman
```

### Install for python3
```
pip3 install pycrypto
pip3 install diffiehellman
```

# About
You can run one server-instance and multiple client-instances. 
The clients will automatically connect to the server. And therefore the *server
needs to be started first*. 

The server has only one function, which is to decrypt the message and echo the
decrypted string back to the client.

The project is not able to handle åäöÅÄÖ in the
communication between server and client. So dont write those characters in
the chat. 



# Run server

When in the project folder. Run: 
```
python server.py
```

# Run client

When in the project folder. Run: 
```
python client.py
```
