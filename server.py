import socket
from keys import keyMAC
from DES import desModes, sendMAC

blockSize=8

def checkMAC(msg, MAC):
    calcMAC = sendMAC(msg)
    print(calcMAC+' '+ str(MAC))
    return calcMAC == MAC
class server():

    def createConn(self, prtNum=50000):

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(('localhost', prtNum))
        self.s.listen(1)
        self.conn, addr = self.s.accept()

    def sendMsg(self,msg):
        self.s.sendall(msg)
        return 

    def recvMsg(self):
        strn=b""
        while 1:
            data = self.conn.recv(blockSize)
            if not data:
                break
            strn += data
        return strn
    
    def closeConn(self):
        self.s.close()
        return


serv = server()
des = desModes()
serv.createConn()
cipheredMsg = serv.recvMsg()
serv.closeConn()

msg = cipheredMsg[:-33]
MAC = cipheredMsg[-33:-1].decode()
mode = desModes.modes[cipheredMsg[-1:].decode()]
print("DES mode used is " + mode + ".")
# Display the Encypted Data
print("Recieved encyprted message  ")
print(cipheredMsg)
# print(MAC)
# Decrypt the recieved msg
decryptedMsg = des.decMode(msg, mode)

print("\nDecrypted message \n")
print(decryptedMsg)
sendMAC(decryptedMsg.decode("utf-8"))
# Check for the MAC
if checkMAC(decryptedMsg.decode("utf-8"), MAC):
    print("Message is Authenticated")
else:
    print("Message is NOT Authenticated.\n 3yate")
