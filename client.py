import socket
import sys
import time
import struct
import select
from cryptography.fernet import Fernet

try:
	local  = socket.gethostname()	
	serverPort = 4001
	kdcPort=8001
	clientPort = int(sys.argv[1])
	# Connect ot server's port
	for i in range(5):
		try:
			sock_srvr = socket.socket()
			sock_srvr.connect((local, serverPort))
			print("Server port connected")
			privateKey=(Fernet.generate_key()).decode();
			print("Private Key Generated",privateKey);
			break
		except Exception as e:
			time.sleep(5)
			if i == 4: 
				sys.exit("Exception: {}".format(e))


	# Make a new port for communication
	for i in range(5):
		try:
			sock_curr = socket.socket()
			sock_curr.bind((local, clientPort))
			print("Client port made")
			break
		except Exception as e:
			time.sleep(5)
			if i == 4: 
				sys.exit("Exception {}".format(e))

except :
	print('Interrupted')
	try:
		sock.close()
	except:
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


#Server class to handle server
class Server:
	def __init__(self):
		# connect to controller and get key
		send_msg(sock_srvr,"client {}".format(clientPort))
		sock_curr.listen(5)
		C, addr = sock_curr.accept()
		self.c = C
		# self.key = recv_msg(self.c)

	def encrypt(self, message):
		return message

	def decrypt(self, cipher):
		return cipher

	def sendMsg(self, message):
		cipher = self.encrypt(message)
		send_msg(self.c, cipher)

	def receiveMsg(self):
		cipher = recv_msg(self.c)
		message = self.decrypt(cipher)
		return message

	def connection(self):
		return self.c

	def __del__(self):
		self.sendMsg("Exit {}".format(clientPort))
		sock_curr.close()
		sock_srvr.close()	


#Handle class to handle session
class Session:
	def __init__(self,srvr):
		for i in range(5):  
			sock_kdc = socket.socket()
			sock_kdc.connect((local, kdcPort))
			nounce=(Fernet.generate_key()).decode();
			send_msg(sock_kdc,"connect "+str(clientPort)+" 4001 "+nounce)
			receive_msg=recv_msg(sock_kdc)
			f = Fernet(privateKey.encode())
			sessionstr = ((f.decrypt(receive_msg.encode())).decode()).split()
			print(nounce, sessionstr[2])
			if nounce==sessionstr[2]:
				self.sessionKey=sessionstr[0]
				srvr.sendMsg("StartSession {}".format(sessionstr[1]))
				# self.sessionKey = srvr.receiveMsg()
				self.c = srvr.connection()
				nounceb=self.receiveResponse()
				self.sendCommand(nounceb[:-1])
				break
		else:
			sys.exit("Exception Invalid nounce is returned")

	def encrypt(self, message):
		f = Fernet(self.sessionKey.encode())
		message = (f.encrypt(message.encode())).decode()
		return message

	def decrypt(self, cipher):
		f = Fernet(self.sessionKey.encode())
		cipher = (f.decrypt(cipher.encode())).decode()
		return cipher

	def sendCommand(self, cmd):
		cipher = self.encrypt(cmd)
		send_msg(self.c, cipher)

	def receiveResponse(self):
		cipher = recv_msg(self.c)
		message = self.decrypt(cipher)
		return message

	def __del__(self):
		self.sendCommand("EndSession {}".format(clientPort))

def main():
	obj = Server()
	for i in range(5):
		try:
			print("sending Key to KDC")
			sock_kdc = socket.socket()
			sock_kdc.connect((local, kdcPort))
			send_msg(sock_kdc,"saveKey "+str(clientPort)+" "+privateKey)
			print("Key sent to KDC")
			break
		except Exception as e:
			time.sleep(5)
			if i == 4: 
				sys.exit("Exception {}".format(e))
	while True:
		inp = input(">")
		if 'start' in inp:
			obj2 = Session(obj)
			while True:
				cmd = input(">>>")
				if "end" in cmd or "exit" in cmd:
					del(obj2)
					break
				obj2.sendCommand(cmd)
				print(obj2.receiveResponse())
		if "exit" in inp or "end" in inp:
			break
	del(obj)

if __name__ == '__main__':
	try:
		main()
	except Exception as e:
		print('Interrupted',e)
		try:
			sock.close()
			sys.exit()
		except:
			pass
