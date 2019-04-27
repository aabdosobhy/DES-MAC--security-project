import socket
from keys import keyMAC
from DES import desModes
from Crypto.Cipher import DES

blockSize = 64

# MAC sender data processing
def sendMAC(msg):

    # encrypt msg with keyMAC
    encryptMACkey=""
    # hash msg with keyMAC
    hashedMAC = hash(encryptMACkey)
    return hashedMAC
    

class client():

    # Read plain text from user and sent it to client
    def sendMsg(self, sock):
        msg = input("Type the message you want to send\n")
        sock.sendall(msg.encode())
        return msg

    def connectToPort(self, portNum=50000):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', portNum))
        data = self.sendMsg(s)
        s.close()
        return data


clien = client()
plainMsg = clien.connectToPort()
# Display plaintext msg inputed from user
print(plainMsg)
encryptedData = "Hallelujia"

# Display the Encypted Data
print(encryptedData)
