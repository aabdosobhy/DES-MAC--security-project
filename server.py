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
        strn=""
        while 1:
            data = conn.recv(blockSize)
            if not data:
                break
            #conn.sendall(data)
            strn += data.decode("utf-8") 
        conn.close()
        # MAC = ""
        return strn


serv = server()
des = desModes()
cipheredMsg = serv.createConn()
receieved = cipheredMsg.split(" ")
try:
    MAC = receieved[1]
except:
    print("Wrong message format")
msg = receieved[0]
msg= msg[2:-1]
# Display the Encypted Data
print("Recieved encyprted message  "+msg)
# Decrypt the recieved msg
decryptedMsg = des.desECB_Dec(msg)
#print(decryptedMsg)
print("Decrypted message \n")
print(decryptedMsg)
sendMAC(decryptedMsg)
# Check for the MAC
if checkMAC(decryptedMsg, MAC):
    print("Message is Authenticated")
else:
    print("Message is NOT Authenticated.\n 3yate")
