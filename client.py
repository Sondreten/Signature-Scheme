
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

def client_program():
    bitlength = 512

    e, n, d = rsa_keygen.RSA_keygen(n=bitlength)
    print("------------------------------")
    print('Public Key of client (e, n) = {}'.format((e, n)))
    print('Private Key (d) = {}'.format(d))
    file = open("pubcli.txt", "w")
    file.write(str(e))
    file.close()
    file = open("pubclin.txt", "w")
    file.write(str(n))
    file.close()
    print("Public key of client save to pubcli.txt file successfully ")
    print("------------------------------")
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    file = open("pubcli.txt", "rb")
    SendData = file.read(2048)
    while SendData:
        # Now send the content of sample.txt to server
        client_socket.send(SendData)
        SendData = file.read(2048)

    file = open("recvserpub.txt", "w")
    print("public key of server is saved in recvserpub.txt file")
    recvData1 = client_socket.recv(2048)
    file.write(str(recvData1.decode('utf-8')))
    file.close()
    #print("received public key of server :", recvData1.decode('utf-8'))

    file = open("pubclin.txt", "rb")
    SendDatan = file.read(2048)
    while SendDatan:
        # Now send the content of sample.txt to server
        client_socket.send(SendDatan)
        SendDatan = file.read(2048)

    file = open("recvserpubn.txt", "w")
    print("public modulus of server is saved in recvserpub.txt file")
    print("------------------------------")
    recvDatan1 = client_socket.recv(2048)
    file.write(str(recvDatan1.decode('utf-8')))
    file.close()
    ###########################################################################################
    ####################################################################################
    print ("Enter your message")
    text = input(" -> ")  # take input
    x = hashFunction(text)
    #print('Plaintext x={}'.format(x))
    x = int(x, base=16)

    #print("value to encrypted: ", x)
    message = RSA_encrypt(x, (d, n))
    while text.lower().strip() != 'bye':
        client_socket.send(text.encode())
        client_socket.send(str(message).encode())  # send message
        datamsg = client_socket.recv(1024).decode()  # receive response
        datarec = client_socket.recv(1024).decode()  # receive response
        print("------------------------------")
        print("From Alice: ")
        print("original msg: ", str(datamsg))
        x = hashFunction(datamsg)
        x = int(x, base=16)
        print("Msg to encrypt: ", x)
        data = RSA_decrypt(int(datarec), (int(recvData1),int(recvDatan1)))
        #print('From Alice: ' + str(data))  # show in terminal
        if data == x:
            print("Signature Value: " + str(data))
            print("signature verified :)")
        else:
            break
        print ("Enter your message")
        text = input(" -> ")  # again take input
        x3 = hashFunction(text)
        #print('Plaintext x={}'.format(x3))
        x3 = int(x3, base=16)
        #print("value to encrypted: ", x3)
        message = RSA_encrypt(x3, (d, n))
    client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()
