import socket
import sys
import os
import time
import struct
import shutil
import select
from cryptography.fernet import Fernet

# Code To connect with the server and acquire self port connection
try:
	local  = socket.gethostname()	
	serverPort = 4001
	kdcPort=8001
	fsPort = int(sys.argv[1])
	# Connect ot server's port
	for i in range(5):
		try:
			sock_srvr = socket.socket()
			sock_srvr.connect((local, serverPort))
			print("="*15)
			print("Server port connected")
			print("="*15)
			privateKey=Fernet.generate_key().decode();
			print("="*15)
			print("Private Key Generated",privateKey)
			print("="*15)
			break
		except Exception as e:
			time.sleep(5)
			if i == 4: 
				sys.exit("Exception {}".format(e))


	# Make a new port for communication
	for i in range(5):
		try:
			sock_curr = socket.socket()
			sock_curr.bind((local, fsPort))
			print("="*15)
			print("fsPort started")
			print("="*15)
			break
		except Exception as e:
			time.sleep(5)
			if i == 4: 
				sys.exit("Exception {}".format(e))

except :
	print("="*15)
	print('Interrupted')
	print("="*15)
	try:
		sock.close()
	except:
		pass
	
    
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


#Class to handle connection with server
class Server:
	def __init__(self, folder_name):                 #constructor function for server class
		self.name=folder_name
		for i in range(5):  
			sock_kdc = socket.socket()
			sock_kdc.connect((local, kdcPort))
			nounce=(Fernet.generate_key()).decode();
			send_msg(sock_kdc,"connect "+str(fsPort)+" 4001 "+nounce)
			receive_msg=recv_msg(sock_kdc)
			f = Fernet(privateKey.encode())
			sessionstr = ((f.decrypt(receive_msg.encode())).decode()).split()
			print("="*15)
			print(nounce, sessionstr[2])
			print("="*15)
			if nounce==sessionstr[2]:
				self.sessionKey=sessionstr[0]
				print("="*15)
				print(self.sessionKey)
				print("="*15)
				send_msg(sock_srvr,"fileserver {} {} {}".format(fsPort, folder_name,sessionstr[1]))
				sock_curr.listen(5)
				C, addr = sock_curr.accept()
				self.c = C
				break
		else:
			sys.exit("Exception Invalid nounce is returned")
		# connect to controller and get key
# 		sock_kdc = socket.socket()
# 		sock_kdc.connect((local, kdcPort))
# 		send_msg(sock_kdc,"connect "+str(fsPort)+" 4001")
# 		self.sessionKey=recv_msg(sock_kdc)
# 		print(self.sessionKey)
# 		self.key = recv_msg(self.c)

#function for encrypting message with server key
	def encrypt(self, message):
		f = Fernet(self.sessionKey.encode())
		message = (f.encrypt(message.encode())).decode()
		return message

#function for encrypting message with server key
	def decrypt(self, cipher):            
		f = Fernet(self.sessionKey.encode())
		cipher = (f.decrypt(cipher.encode())).decode()
		return cipher

#function for sending message to the server
	def sendMsg(self, message):
		cipher = self.encrypt(message)
		send_msg(self.c, cipher)

#function for receiving message from the server
	def receiveMsg(self):
		cipher = recv_msg(self.c)
		message = self.decrypt(cipher)
		return message

#destructor function
	def __del__(self):
		conn=socket.socket()
		for i in range(5):
			try:
				conn.connect((local, serverPort))
				break
			except Exception as e:
				time.sleep(5)
				if i == 4: 
					sys.exit("Exception {}".format(e))
		send_msg(conn, "exit {}".format(self.name))
		sock_curr.close()
		sock_srvr.close()



def main():
#Code to send the private key to the KDC
	for i in range(5):
		try:
			print("="*15)
			print("sending Key to KDC")
			print("="*15)
			sock_kdc = socket.socket()
			sock_kdc.connect((local, kdcPort))
			send_msg(sock_kdc,"saveKey "+str(fsPort)+" "+privateKey)
			print("="*15)
			print("Key sent to KDC")
			print("="*15)
			break
		except Exception as e:
			time.sleep(5)
			if i == 4: 
				sys.exit("Exception {}".format(e))
	# have to get name of folder for FS
	folder_name = sys.argv[2]
	global srvr
	srvr = Server(folder_name)
	current_dir = os.getcwd()
	while True:
		os.chdir(current_dir)
		msg = None
		while msg is None:
			msg = srvr.receiveMsg()
		print("="*15)
		print(msg)
		print("="*15)
		vwd, cmd = msg.split("#")
		print("="*15)
		print(vwd,cmd)
		print("="*15)
		os.chdir(os.path.join(current_dir,vwd))
		print("="*15)
		print(os.getcwd())
		print("="*15)
		if 'ls' in cmd:    #ls filename
			resp = ""
			for files in os.listdir(os.getcwd()):
				resp += files + " "
			srvr.sendMsg(resp)
		if 'cat' in cmd:    #cat filename
			filename = cmd[4:]
			print("="*15)
			print(filename)
			print("="*15)
			try:
				with open(filename,'r') as fp:
					srvr.sendMsg(fp.read())
			except :
				srvr.sendMsg("File Not Found")

		if 'cp' in cmd:    #cp filename
			filename = cmd.split()[1]
			print("="*15)
			print("filename",filename)
			print("="*15)
			try:
				if('.' in filename):
					shutil.copyfile(os.path.join(os.getcwd(), filename),os.path.join(os.getcwd(), "copyof" + filename))
				else:
					shutil.copytree(os.path.join(os.getcwd(), filename),os.path.join(os.getcwd(),filename+  "(1)"),copy_function = shutil.copy)    
				srvr.sendMsg("success")
			except Exception as e:
				print("="*15)
				print(e)
				print("="*15)
				srvr.sendMsg("failed")

		if 'cd' in cmd: #cd foldername
			nw_dir = cmd[3:]
			print("="*15)
			print("nw_dir '{}'".format(nw_dir))
			print("="*15)
			try:
				os.chdir(os.path.join(os.getcwd(),nw_dir))
				srvr.sendMsg(os.path.join(vwd,nw_dir))
			except Exception as e:
				print("="*15)
				print(e)
				print("="*15)
				srvr.sendMsg("failed")
                
		if 'mv' in cmd:  #mv source_file_location dest_location
			filesrc = cmd.split()[1]
			filedst = cmd.split()[2]
			print("="*15)
			print("filename",filename)
			print("="*15)
			try:
				shutil.move(os.path.join(os.getcwd(), filesrc),os.path.join(os.getcwd(), filedst), copy_function = shutil.copytree)
				srvr.sendMsg("success")
			except Exception as e:
				print("="*15)
				print(e)
				print("="*15)
				srvr.sendMsg("failed")
		if 'rm' in cmd:   #rm filename/folderName
			filesrc = cmd.split()[1]
			print("="*15)
			print("Removing",filesrc)
			print("="*15)
			try:
				if('.' in cmd):
					os.remove(filesrc)
				else:
					shutil.rmtree(os.path.join(os.getcwd(), filesrc))                  
				srvr.sendMsg("success")
			except Exception as e:
				print("="*15)
				print(e)
				print("="*15)
				srvr.sendMsg("failed")

if __name__ == '__main__':
	try:
		main()
	except :
		print("="*15)
		print('Interrupted')
		print("="*15)
		# try:
		srvr.__del__()
		sys.exit()
		# except:
		# 	pass






