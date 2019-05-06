from Crypto.Cipher import DES
from keys import keyMAC, keyDES, IV, Nonce
import hashlib

blockSize = 8
blockMAC = 8
STR = 1
BYTE = 0
# MAC sender data processing
def sendMAC(msg):
    obj = DES.new(keyMAC, DES.MODE_ECB)
    padLen = blockMAC - (len(msg) % blockMAC)
    if len(msg) % blockMAC > 0 and padLen > 0:
        msg += padLen * '.'
    # encrypt msg with keyMAC
    encryptMACkey = obj.encrypt(msg)
    # hash msg with keyMAC
    hashedMAC = hashlib.md5(encryptMACkey).hexdigest()
    return hashedMAC

class desModes():
    modes = {"1":"ECB", "2":"CBC", "3":"CFB", "4":"OFB", "5":"CNT"}
    def __init__(self):
        self.key = keyDES
        self.iv = IV
        self.nonce = Nonce
    
    #Split a list into sublists of size blocksize
    def splitMessage(self, plainText, bkSize = blockSize):
        return [plainText[k : k + bkSize] for k in range(0, len(plainText), bkSize)]
    
    def padBlock(self, block, bkSize = blockSize):
        padLen = bkSize - (len(block) % bkSize)
        block += padLen * '.'
        return block

    def xor(self, s1, s2, s1Str, s2Str, outFormat = 0):
        if s1Str == 1:
            s1 = bytes(s1, 'utf-8')
        if s2Str == 1:
            s2 = bytes(s2, 'utf-8')
        
        xorRes = bytes(a ^ b for a, b in zip(s1, s2))
        if outFormat == 1:
            return xorRes.decode('utf-8')
        else:
            return xorRes 
        
    def incCount (self, count):
        countstr = str(count)
        i = len(countstr)
        comp = ""
        for j in range (0, 8 - i):
            comp += "0"
        return comp + countstr
        
    def desECB_Enc(self, plainText):
        result = b''
        desECB = DES.new(self.key, DES.MODE_ECB)
        textBlocks = self.splitMessage(plainText)
        
        for block in textBlocks:
            if len(block) < blockSize:
                block = self.padBlock(block)
            ciph = desECB.encrypt(block)
            result += ciph
            # print(ciph)
        return result

    def desECB_Dec(self, plainText):
        result = b''
        desECB = DES.new(self.key, DES.MODE_ECB)  
        textBlocks = self.splitMessage(plainText)
        
        for block in textBlocks:
            dciph = desECB.decrypt(block)
            result += dciph
        return result

    def desCBC_Enc(self, plainText, IV=IV):
        result = b''
        desECB = DES.new(self.key, DES.MODE_ECB)         
        textBlocks = self.splitMessage(plainText)
        prevFeed = bytes(IV, 'utf-8')
        
        for block in textBlocks: #Loop over all the blocks of data               
            if len(block) < blockSize:
                block = self.padBlock(block)
            block = self.xor(prevFeed, block, BYTE, STR, BYTE)
            ciph = desECB.encrypt(block)
            print(str(ciph))
            result += ciph
            prevFeed = ciph
            print(ciph)
        return result

    def desCBC_Dec(self, plainText, IV=IV):
        result = b''
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        
        for i in range (0, len(textBlocks)):
            block = textBlocks[i]
            if len(block) < blockSize:
                block = self.padBlock(block)
            dciph = desECB.decrypt(block)
            if i == 0:
                dciph = self.xor(IV, dciph, STR, BYTE, BYTE)
            else:
                dciph = self.xor(dciph, textBlocks[i-1], BYTE, BYTE, BYTE)
            result += dciph
        return result

    def desCFB_Enc(self, plainText, IV=IV, S=blockSize):
        result = b''
        IV = bytes(IV, 'utf-8')
        desECB = DES.new(self.key, DES.MODE_ECB)
        textBlocks = self.splitMessage(plainText, S)
        
        for block in textBlocks:
            if len(block) < S:
                block = self.padBlock(block, S)
            ciph = desECB.encrypt(IV)
            sSelect = ciph[0 : S]
            block = self.xor(sSelect, block, BYTE, STR, BYTE)
            IV = IV[S : len(IV)] + block
            
            result += block 
        return result

    def desCFB_Dec(self, plainText, IV= IV, S=blockSize):
        result = b''
        IV = bytes(IV, 'utf-8')
        desECB = DES.new(self.key, DES.MODE_ECB)
        textBlocks = self.splitMessage(plainText, S)
        
        for block in textBlocks:
            ciph = desECB.encrypt(IV)
            sSelect = ciph[0 : S]
            IV = IV[S : len(IV)] + block
            block = self.xor(sSelect, block, BYTE, BYTE, BYTE)
            result += block
        return result

    def desOFB_Enc(self, plainText, Nonce=Nonce):
        result = b''
        nonceCurr = bytes(Nonce, 'utf-8')
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        
        for block in textBlocks: #Loop over all the blocks of data               
            if len(block) < blockSize:
                block = self.padBlock(block)
            ciph = desECB.encrypt(nonceCurr)
            nonceCurr = ciph            
            ciph = self.xor(ciph, block, BYTE, STR, BYTE)
            result += ciph
        return result

    def desOFB_Dec(self, plainText, Nonce=Nonce):
        result = b''
        nonceCurr = bytes(Nonce, 'utf-8')
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        
        for block in textBlocks: #Loop over all the blocks of data               
            if len(block) < blockSize:
                block = self.padBlock(block)
            dciph = desECB.encrypt(nonceCurr)
            nonceCurr = dciph
            dciph = self.xor(dciph, block, BYTE, BYTE, BYTE)
            result += dciph
        return result
    
    def desCNT_Enc(self, plainText, count =0):
        result = b''
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        
        for block in textBlocks: #Loop over all the blocks of data               
            if len(block) < blockSize:
                block = self.padBlock(block)
            countCurr = self.incCount(count)
            ciph = desECB.encrypt(countCurr)
            ciph = self.xor(ciph, block, BYTE, STR, BYTE)
            result += ciph
            count += 1
        return result
    
    def desCNT_Dec(self, plainText, count =0):
        result = b''
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        
        for block in textBlocks: #Loop over all the blocks of data 
            countCurr = self.incCount(count)              
            dciph = desECB.encrypt(countCurr)
            dciph = self.xor(dciph, block, BYTE, BYTE, BYTE)
            result += dciph
            count += 1
        return result

    def chooseEncMode(self, plainMsg, modeNum):
        # print ("Enter 1 fot ECB, 2 for CBC, 3 for CFB, 4 for OFB, 5 for CNT")
        # modeNum = input("Choose DES mode number:\n")
        mode = desModes.modes[modeNum]
        print("You chose " + mode + " mode.")
        if(mode == "ECB" ):
            encryptedMsg = self.desECB_Enc(plainMsg)
        elif(mode == "CBC" ):
            encryptedMsg = self.desCBC_Enc(plainMsg, self.iv)
        elif(mode == "CFB" ):
            s=blockSize
            encryptedMsg = self.desCFB_Enc(plainMsg, self.iv,s)
        elif(mode == "OFB" ):
            encryptedMsg = self.desOFB_Enc(plainMsg, self.nonce)
        elif(mode == "CNT" ):
            encryptedMsg = self.desCNT_Enc(plainMsg)
        else:
            print ("Your choice is invalid")
            return  b'-1'
        return encryptedMsg, modeNum

    def decMode(self, cipheredMsg, modeNum):
        mode = desModes.modes[modeNum]
        if(mode == "ECB" ):
            decryptedMsg = self.desECB_Dec(cipheredMsg,)
        elif(mode == "CBC" ):
            decryptedMsg = self.desCBC_Dec(cipheredMsg, self.iv)
        elif(mode == "CFB" ):
            s=blockSize
            decryptedMsg = self.desCFB_Dec(cipheredMsg, self.iv,s)
        elif(mode == "OFB" ):
            decryptedMsg = self.desOFB_Dec(cipheredMsg,self.nonce)
        elif(mode == "CNT" ):
            decryptedMsg = self.desCNT_Dec(cipheredMsg)
        return decryptedMsg


if __name__ == "__main__":
    text= "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"
    d = desModes()
    while (blockSize<8*16):
        r, t = d.chooseEncMode(text, "1")
        print("Ciphered: %r" % str(r))
        dec = d.decMode(r,"1")
        print("Deciphered: ", dec)
        blockSize+=8