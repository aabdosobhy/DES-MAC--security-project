import socket
from DES import desModes,sendMAC
from Crypto.Cipher import DES

blockSize = 8
    

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
        self.s.sendall(msg)
        return 

    
    def closeConn(self):
        self.s.close()
        return


clien = client()
des = desModes()
#clien.connectToPort()
plainMsg = clien.getMsg()
# Display plaintext msg inputed from user
print("Message taken from user  "+plainMsg)
encryptedData = des.desECB_Enc(plainMsg)
# Display MAC data
dataMAC = sendMAC(plainMsg)
print("MAC to be sent  "+dataMAC)

clien.sendMsg(encryptedData+ b'_'+ dataMAC.encode("utf-8"))
# Display the Encypted Data
print("Message after encryption  "+str(encryptedData))
