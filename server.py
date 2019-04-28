import socket
from keys import keyMAC
from DES import desModes, sendMAC

blockSize=64

def checkMAC(msg, MAC):
    calcMAC = sendMAC(msg)
    print(calcMAC+' '+ MAC)
    return calcMAC == MAC
class server():

    def createConn(self, prtNum=50000):
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
        # MAC = ""
        return strn

serv = server()
cipheredMsg = serv.createConn()
# Display the Encypted Data
print(cipheredMsg)
receieved = cipheredMsg.split(" ")
MAC = receieved[1]
# Decrypt the recieved msg
decryptedMsg = "Hallo"
print(decryptedMsg)
sendMAC(decryptedMsg)
# Check for the MAC
if checkMAC(decryptedMsg, MAC):
    print("Message is Authenticated")
else:
    print("Message is NOT Authenticated.\n 3yate")
