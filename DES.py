from Crypto.Cipher import DES
from keys import keyMAC, keyDES
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
    def __init__(self):
        # For testing purposes
        self.key = keyDES
    
    #Split a list into sublists of size blocksize
    def splitMessage(self, plainText, bkSize = blockSize):
        return [plainText[k : k + bkSize] for k in range(0, len(plainText), bkSize)]
    
    def padBlock(self, block, bkSize = blockSize):
        padLen = bkSize - (len(block) % bkSize)
        block += padLen * '.'
        return block
    
    def stringToBits(self, text):#Convert a string into a list of bits
        array = list()
        for char in text:
            binval = self.binvalue(char, 8)#Get the char value on one byte
            array.extend([int(x) for x in list(binval)]) #Add the bits to the final list
        return array

    def bitsToString(self, array): #Recreate the string from the bit array
        res = ''.join([chr(int(y , 2)) for y in 
            [''.join([str(x) for x in _bytes]) for _bytes in  self.splitMessage(array)]])   
        return res
    
    def binvalue(self, val, bitsize): #Return the binary value as a string of the given size 
        binval = bin(val)[2 : ] if isinstance(val, int) else bin(ord(val))[2 : ]
        if len(binval) > bitsize:
            raise "binary value larger than the expected size"
        while len(binval) < bitsize:
            binval = "0" + binval #Add as many 0 as needed to get the wanted size
        return binval
    
    #def xor(self, t1, t2):#Apply a xor and return the resulting list
    #    return [x^y for x,y in zip(t1,t2)]
    
    def change_to_be_hex(self, str1):
        return int(str1, base = 16)

    '''
    # xor operation on two bytes and return the value in two possible forms string or byte
    #
    # inputs:
    #   s1:         first byte can be in bytes or string format 
    #   s2:         second byte can be in bytes or string format 
    #   s1Str:      first byte flag 0: byte, 1: string
    #   s2Str:      second byte flag 0: byte, 1: string
    #   outFormat:  output result format select 0: byte, 1: string
    #   
    # output:
    #   xor of two bytes in the selected format (bytes or string)
    #
    '''
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
            print(ciph)
        return result

    def desECB_Dec(self, plainText):
        result = b''
        desECB = DES.new(self.key, DES.MODE_ECB)  
        textBlocks = self.splitMessage(plainText)
        
        for block in textBlocks:
            dciph = desECB.decrypt(block)
            result += dciph
        return result

    def desCBC_Enc(self, plainText, IV):
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

    def desCBC_Dec(self, plainText, IV):
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

    def desCFB_Enc(self, plainText, IV, S):
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

    def desCFB_Dec(self, plainText, IV, S):
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

    def desOFB_Enc(self, plainText, Nonce):
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

    def desOFB_Dec(self, plainText, Nonce):
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