# two works 
# first to generate a unique key
# protocol will be same as in INS project
    
import socket
import sys
import time
from _thread import *
import threading 
import struct
import select
from cryptography.fernet import Fernet

local  = socket.gethostname()	
Port = 8001

Keys = {}
# Make a Socket
for i in range(5):
	try:
		sock = socket.socket()
		sock.bind((local, Port))
		print("="*15)
		print("KDC socket open")
		print("="*15)
		break
	except Exception as e:
		time.sleep(5)
		if i == 4: 
			sys.exit("Exception {}".format(e))
    

# Helping function for send_msg function
def empty_socket(sock):
    """remove the data present on the socket"""
    input = [sock]
    while 1:
        inputready, o, e = select.select(input,[],[], 0.0)
        if len(inputready)==0: break
        for s in inputready: s.recv(1)

# Function to send message
def send_msg(sock, message):
    # Prefix each message with a 4-byte length (network byte order)
    # clean up buffer here
    empty_socket(sock)
    msg = message.encode()
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

#function to send message
def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    msg =  recvall(sock, msglen)
    return msg.decode()

#Helping function for recv_msg
def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def main():
	while True:
		sock.listen(15)
		c,addr = sock.accept()
		msg = None
		while msg is None:
			msg = recv_msg(c)
		print("="*15)
		print(msg)
		print("="*15)
		if 'saveKey' in msg:  #savekey 3002 eoineoncwoempqwomdpqodmpoiqnwdoi
			Keys[int(msg.split()[1])]=msg.split()[2];
			print("="*15)
			print('Key saved for ',int(msg.split()[1]))
			print("="*15)
		elif 'connect' in msg:   #connect 3002 4001 eoineoncwoempqwomdpqodmpoiqnwdoi
			port1=int(msg.split()[1])
			port2=int(msg.split()[2])
			nounce=msg.split()[3]
			if (Keys.get(port2,None) is not None) and (Keys.get(port1,None) is not None):
				sessionKey=(Fernet.generate_key())
				f = Fernet(Keys[port2].encode())
				#To encrypt session key in private key of B
				encrypted_message1 = (f.encrypt(sessionKey)).decode()      
				#To generate string with session key, encrypted message 1 and nounce of A
				response=sessionKey.decode()+" "+encrypted_message1+" "+nounce;
				f = Fernet(Keys[port1].encode())
				#Final string which is further encrypted
				encrypted_message2 = (f.encrypt(response.encode())).decode()
				send_msg(c,encrypted_message2)
				print("="*15)
				print('session key sent for connection {} {} with session key {}'.format(port1,port2,sessionKey.decode()))
				print("="*15)
			else:
				send_msg(c,'Failed: key of ports not present')
				print("="*15)
				print('Failed: key of ports not present')
				print("="*15)
		else:
			send_msg(c,'Failed: Incorrect command call')
			print("="*15)
			print('Failed: Incorrect command call')
			print("="*15)
		c.close()

if __name__ == '__main__':
	try:
		main()
	except Exception as e: 
		print("="*15)
		print('Interrupted',e)
		print("="*15)
		try:
			sock.close()
		except:
			pass


