import socket
from DES import desModes,sendMAC
from Crypto.Cipher import DES

blockSize = 64
    

class client():

    def __init__(self, portNum=50000):
        self.s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 50000))
        return
    
    # Read plain text from user
    def getMsg(self):
        msg = input("Type the message you want to send\n")
        return msg
    def sendMsg(self,msg):
        msg = str(msg)
        self.s.sendall(msg.encode())
        return 

    def connectToPort(self, portNum=50000):
        self.s.connect(('localhost', portNum))
        return
    
    def closeConn(self):
        self.s.close()
        return


clien = client()
#clien.connectToPort()
plainMsg = clien.getMsg()
# Display plaintext msg inputed from user
print("Message taken from user  "+plainMsg)
dataMAC = sendMAC(str(plainMsg))
print("MAC to be sent  "+dataMAC)
encryptedData = "Hallo"
clien.sendMsg(encryptedData+ ' '+ dataMAC)
# Display the Encypted Data
print("Message after encryption  "+encryptedData)
