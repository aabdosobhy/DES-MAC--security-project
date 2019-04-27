import socket
from perms import keyMAC

blockSize = 64

# MAC sender data processing
def sendMAC(msg):
    # encrypt msg with keyMAC
    encryptMACkey=""
    # hash msg with keyMAC
    hashedMAC = hash(encryptMACkey)
    return hashedMAC
    


# Read plain text from user and sent it to client
def sendMsg(sock):
    msg = input("Type the message you want to send\n")
    sock.sendall(msg.encode())
    return msg

def connectToPort(portNum=50000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', portNum))
    data = sendMsg(s)
    s.close()
    return data

plainMsg = connectToPort()
# Display plaintext msg inputed from user
print(plainMsg)
encryptedData = "Hallelujia"

# Display the Encypted Data
print(encryptedData)