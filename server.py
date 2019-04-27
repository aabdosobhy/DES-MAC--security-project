import socket
from perms import keyMAC

blockSize=64

# MAC receiver data processing
def recvMAC(msg):
    # encrypt msg with keyMAC
    encryptMACkey=""
    # hash msg with keyMAC
    hashedMAC = hash(encryptMACkey)
    return hashedMAC

def checkMAC(msg, MAC):
    calcMAC = recvMAC(msg)
    return calcMAC == MAC

def createConn(prtNum=50000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', prtNum))
    s.listen(1)
    conn, addr = s.accept()
    while 1:
        data = conn.recv(blockSize)
        if not data:
            break
        #conn.sendall(data)
        strn = data.decode("utf-8") 
    conn.close()
    MAC = ""
    return strn,MAC

cipheredMsg, MAC = createConn()
# Display the Encypted Data
print(cipheredMsg)
# Decrypt the recieved msg
decryptedMsg = ""
print(decryptedMsg)
# Check for the MAC
checkMAC(decryptedMsg, MAC)