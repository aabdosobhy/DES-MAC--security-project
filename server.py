import socket
from keys import keyMAC
from DES import desModes, sendMAC

blockSize=8

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
        strn=b""
        while 1:
            data = conn.recv(blockSize)
            if not data:
                break
            #conn.sendall(data)
            strn += data
        conn.close()
        # MAC = ""
        return strn


serv = server()
des = desModes()
cipheredMsg = serv.createConn()
# receieved = str(cipheredMsg).split(" ")
# try:
#     MAC = receieved[1]
# except:
#     print("Wrong message format")
msg = cipheredMsg #receieved[0]
# Display the Encypted Data
print("Recieved encyprted message  ")
print(msg)
# Decrypt the recieved msg
decryptedMsg = des.desECB_Dec(msg)
#print(decryptedMsg)
print("\nDecrypted message \n")
print(decryptedMsg)
# sendMAC(decryptedMsg)
# # Check for the MAC
# if checkMAC(decryptedMsg, MAC):
#     print("Message is Authenticated")
# else:
#     print("Message is NOT Authenticated.\n 3yate")
