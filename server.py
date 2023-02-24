import socket
import sys
sys.path.append('.')
import sympy


import rsa_keygen
from generate_primes import square_and_multiply
from hashlib import sha256

def RSA_encrypt(x, publicKey):
    e, n = publicKey
    assert x < n

    y = square_and_multiply(x, e, n)
    return y

def RSA_decrypt(y, privateKey):
    d, n = privateKey
    assert y < n

    x = square_and_multiply(y, d, n)
    return x

def hashFunction(message):
    hashed = sha256(message.encode("UTF-8")).hexdigest()
    return hashed


############################
def server_program():
    ########################################################################################################
    #public private key pair generation
    ########################################################################################################
    bitlength = 512
    e, n, d = rsa_keygen.RSA_keygen(n=bitlength)
    print("------------------------------")
    print('public Key of server: (e,n) = {}'.format((e, n)))
    print('Private Key (d) = {}'.format(d))
    file = open("pubser.txt", "w")
    file.write(str(e))
    file.close()
    file = open("pubsern.txt", "w")
    file.write(str(n))
    file.close()
    print("Public key of server save to pubser.txt file successfully ")
    print("------------------------------")
    ##########################################################################

    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024
    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together
    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    # store public key of client in recv.txt file
    file = open("recpubcli.txt", "w")
    print("public key of client is saved in recpubcli.txt file")
    recvData = conn.recv(2048)
    file.write(str(recvData.decode('utf-8')))
    file.close()
    file = open("pubser.txt", "rb")
    SendData2 = file.read(2048)
    while SendData2:
        # Now send the content of sample.txt to server
        conn.send(SendData2)
        SendData2 = file.read(2048)

    print("received public key of client :", recvData.decode('utf-8'))

    file = open("recpubclin.txt", "w")
    recvDatan = conn.recv(2048)
    file.write(str(recvDatan.decode('utf-8')))
    file.close()

    file = open("pubsern.txt", "rb")
    SendDatan2 = file.read(2048)
    while SendDatan2:
        # Now send the content of sample.txt to server
        conn.send(SendDatan2)
        SendDatan2 = file.read(2048)
    ##################################################################################

    while True:

        # receive data stream. it won't accept data packet greater than 1024 bytes
        dataq = conn.recv(2048).decode()
        datar = conn.recv(2048).decode()
        if not datar and dataq:
            # if data is not received break
            break
        print("------------------------------")
        print("From Bob: ")
        print("original msg: ", str(dataq))
        x = hashFunction(dataq)
        x = int(x, base=16)
        print("Msg to encrypt: ", x)
        data = RSA_decrypt(int(datar), (int(recvData.decode('utf-8')), int(recvDatan.decode('utf-8'))))
        if data == x:
            print("Signature Value: " + str(data))
            print("signature verified :)")
        else:
            break
        print("------------------------------")
        print("Enter Your message:")
        data2 = input(' -> ')
        x = hashFunction(data2)

        x = int(x, base=16)

        data = RSA_encrypt(x, (d, n))
        conn.send(str(data2).encode())  # send data to the client
        conn.send(str(data).encode())  # send data to the client

    conn.close()  # close the connection
############################


if __name__ == '__main__':
    server_program()


