import socket
import sys
import time
from _thread import *
import threading 
import struct
import select
from cryptography.fernet import Fernet

local  = socket.gethostname()	
Port = 4001
kdcPort=8001

FileServers = []
# Make a Socket
for i in range(5):
	try:
		sock = socket.socket()
		sock.bind((local, Port))
		print("="*15)
		print("Controller socket open")
		print("="*15)
		privateKey=(Fernet.generate_key()).decode()
		print("="*15)
		print("Private Key Generated",privateKey)
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


class FileServer:
# Constructor function
	def __init__(self, port, name, message):
		# connect to and get key
		self.sock = socket.socket()
		self.sock.connect((local,port))
		f = Fernet(privateKey.encode())
		self.sessionKey = (f.decrypt(message.encode())).decode()
		print("="*15)
		print("sesion key for connection with file server saved")
		print("="*15)
		self.name = name
		print("="*15)
		print("File Server :{} connected at port:{}".format(name,port))
		print("="*15)
		# self.sock.send(self.key)

	def name(self):
		return self.name

	def encrypt(self, message):
		f = Fernet(self.sessionKey.encode())
		message = (f.encrypt(message.encode())).decode()
		return message

	def decrypt(self, cipher):
		f = Fernet(self.sessionKey.encode())
		cipher = (f.decrypt(cipher.encode())).decode()
		return cipher

	def sendMsg(self,message):
		cipher = self.encrypt(message)
		send_msg(self.sock,cipher)

	def receiveMsg(self):
		cipher = recv_msg(self.sock)
		message = self.decrypt(cipher)
		return message

	def __del__(self):
		print("="*15)
		print(" exited")
		print("="*15)
		FileServers.remove(self)
		self.sock.close()

class Client:
	def __init__(self, port):
		# connect and authenticate
		print("="*15)
		print("Client request {}".format(port))
		print("="*15)
		self.sock = socket.socket()
		self.port = port
		self.sock.connect((local,port))
		print("="*15)
		print("Client {} connected".format(port))
		print("="*15)
		# send_msg(self.sock,self.key)

	def encrypt(self, message):
		return message

	def decrypt(self, cipher):
		return cipher

	def sendMsg(self, message):
		cipher = self.encrypt(message)
		send_msg(self.sock,cipher)

	def receiveMsg(self):
		cipher = recv_msg(self.sock)
		message = self.decrypt(cipher)
		return message

	def Sock(self):
		return self.sock

	def Port(self):
		return self.port

	def __del__(self):
		print("="*15)
		print("Client {} exited".format(self.port))
		print("="*15)
		self.sock.close()

class Session:
	def __init__(self, client,msg):
		# start a session by sending key
		print("="*15)
		print("Session request Client {}".format(client.Port()))
		print("="*15)
		message=msg.split()[1]
		f = Fernet(privateKey.encode())
		self.sessionKey = (f.decrypt(message.encode())).decode()
		print("="*15)
		print("sesion key for connection with client saved")
		print("="*15)
		# client.sendMsg(self.key)
		self.sock = client.Sock()
		self.port = client.Port()
		nounceb=(Fernet.generate_key()).decode()
		self.sendResponse(nounceb)
		ack=self.receiveCmd()
		if(nounceb[:-1]==ack):
			print("="*15)
			print("same nounce received")
			print("="*15)
		else:
			print("="*15)
			print("diff nounce received")
			print("="*15)

	def encrypt(self, message):
		f = Fernet(self.sessionKey.encode())
		message = (f.encrypt(message.encode())).decode()
		return message

	def decrypt(self, cipher):
		f = Fernet(self.sessionKey.encode())
		cipher = (f.decrypt(cipher.encode())).decode()
		return cipher

	def sendResponse(self, message):
		cipher = self.encrypt(message)
		send_msg(self.sock,cipher)

	def receiveCmd(self):
		cipher = recv_msg(self.sock)
		message = self.decrypt(cipher)
		return message

	def __del__(self):
		print("="*15)
		print("Session ended for Client {}".format(self.port))
		print("="*15)

def handleSession(sess):
	# start a session
	pwd = ''
	fs = None
	while True:
		cmd = None
		while cmd is None:
			cmd = sess.receiveCmd()
		if fs is not None and fs not in FileServers:
			fs = None
			pwd=''
		if "pwd" in cmd:
			sess.sendResponse(pwd)

		if 'ls' in cmd:
			if pwd == '':
				resp = ''
				for server in FileServers:
					resp += server.name + ' '
			else:
				fs.sendMsg(pwd+"#"+"ls")
				resp = fs.receiveMsg()
			sess.sendResponse(resp)

		if 'cd' in cmd:
			if fs == None:
				for f in FileServers:
					if f.name in cmd:
						fs = f
						pwd = f.name
			else:
				if '..' in cmd:
					while len(pwd)>0 and pwd[-1] != '/':
						pwd = pwd[:-1]
					if len(pwd) > 0:
						pwd = pwd[:-1]
				else:
					fs.sendMsg(pwd + "#" + cmd)
					p = fs.receiveMsg()
					if p in 'failed':
						sess.sendResponse("failed")
						continue
					pwd = p
				if pwd == "":
					fs = None
			sess.sendResponse("Success")

		if 'cp' in cmd:
			if fs is not None:
				fs.sendMsg(pwd+"#"+cmd)
				sess.sendResponse(fs.receiveMsg())
			else:
				sess.sendResponse("No FileServer")

		if 'cat' in cmd:
			if fs is not None:
				fs.sendMsg(pwd+"#"+cmd)
				sess.sendResponse(fs.receiveMsg())
			else:
				sess.sendResponse("No FileServer")
                
		if 'mv' in cmd:
			if fs is not None:
				fs.sendMsg(pwd+"#"+cmd)
				sess.sendResponse(fs.receiveMsg())
			else:
				sess.sendResponse("No FileServer")
                
		if 'rm' in cmd:
			if fs is not None:
				fs.sendMsg(pwd+"#"+cmd)
				sess.sendResponse(fs.receiveMsg())
			else:
				sess.sendResponse("No FileServer")

		if 'EndSession' in cmd:
			sess.__del__()
			return

		if not cmd in ['cp', 'cd', 'ls', 'cat', 'EndSession', 'pwd', 'mv']:
			sess.sendResponse("Invalid command")


def handleClient(obj):
	while True:
		msg = None
		while msg is None:
			msg = obj.receiveMsg()
		if 'StartSession' in msg:
			sess = Session(obj,msg)
			handleSession(sess)
		if 'Exit' in msg:
			obj.__del__()
			return

def main():
	for i in range(5):
		try:
			sock_kdc = socket.socket()
			sock_kdc.connect((local, kdcPort))
			send_msg(sock_kdc,"saveKey"+" "+str(Port)+" "+privateKey)
			print("="*15)
			print("Key sent to KDC")
			print("="*15)
			break
		except Exception as e:
			time.sleep(5)
			if i == 4: 
				sys.exit("Exception {}".format(e))
	while True:
		sock.listen(5)
		c,addr = sock.accept()
		msg = None
		while msg is None:
			msg = recv_msg(c)
		if 'client' in msg:
			# create a thread for client
			client = Client(int(msg.split()[1]))
			start_new_thread(handleClient, (client,))
			c.close()

		if 'fileserver' in msg:
			# connect and add file server to list
			fs = FileServer(int(msg.split()[1]), msg.split()[2],msg.split()[3])
			FileServers.append(fs)
			c.close()
            
		if 'exit' in msg[:5]:
			fsName = msg.split()[1]
			for f in FileServers:
				if f.name == fsName:
					f.__del__()
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
