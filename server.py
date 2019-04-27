import socket

blockSize=64

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
    return strn

cipheredMsg = createConn()
# Display the Encypted Data
print(cipheredMsg)