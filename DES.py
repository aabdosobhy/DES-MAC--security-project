from Crypto.Cipher import DES, DES3, AES
from keys import keyMAC, keyDES
import hashlib

blockSize = 16
blockMAC = 8
# MAC sender data processing
def sendMAC(msg):
    obj=DES.new(keyMAC, DES.MODE_ECB)
    padLen = blockMAC - (len(msg) % blockMAC)
    if len(msg) % blockMAC > 0 and padLen > 0:
        msg += padLen * '.'
    # encrypt msg with keyMAC
    encryptMACkey=obj.encrypt(msg)
    # hash msg with keyMAC
    hashedMAC = hashlib.md5(encryptMACkey).hexdigest()
    return hashedMAC

class desModes():
    def __init__(self):
        # For testing purposes
        self.key = keyDES
    
    #Split a list into sublists of size blocksize
    def splitMessage(self, plainText):
        return [plainText[k:k+blockSize] for k in range(0, len(plainText), blockSize)]
    
    def padBlock(self, block):
        padLen = blockSize - (len(block) % blockSize)
        block += padLen * '.'
        return block
    
    def stringToBits(self, text):#Convert a string into a list of bits
        array = list()
        for char in text:
            binval = self.binvalue(char, 8)#Get the char value on one byte
            array.extend([int(x) for x in list(binval)]) #Add the bits to the final list
        return array

    def bitsToString(self, array): #Recreate the string from the bit array
        res = ''.join([chr(int(y,2)) for y in 
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
    
    def change_to_be_hex(str):
        return int(str, base = 16)

    def xor(str1, str2):
        return hex(int(str1, base = 16) ^ int(str1, base = 16))
    
    #print xor_two_str("12ef","abcd")
    
    

    def desECB_Enc(self, plainText):
        result = b''
        des3ECB = DES3.new(self.key, DES3.MODE_ECB)  
        desECB = DES.new(self.key, DES.MODE_ECB)  
        cipher = AES.new(self.key, AES.MODE_ECB)
        textBlocks = self.splitMessage(plainText)
        for block in textBlocks:
            print(block)
            if len(block) < blockSize:
                block = self.padBlock(block)
            ciph = cipher.encrypt(block)
            result += ciph
            print(ciph)
        return result

    def desECB_Dec(self, plainText):
        result = b''
        #key = get_random_bytes(16)
        
        des3ECB = DES3.new(self.key, DES3.MODE_ECB)  
        desECB = DES.new(self.key, DES.MODE_ECB)  
        cipher = AES.new(self.key, AES.MODE_ECB)  
        textBlocks = self.splitMessage(plainText)
        for block in textBlocks:
            # if len(block) < blockSize:
            #     block = self.padBlock(block)
            dciph = cipher.decrypt(block)
            result += dciph
        # print(desECB.decrypt(plainText))
        return result
    
    
    def des_CFB_Enc(self):
        #TODO: 
        return
    
    def des_CFB_Dec(self):
        #TODO: 
        return
    
    def des_OFB_Enc(self, plainText, Nonce):
        result = b''
        nonceList = list()
        Nonce = self.stringToBits(Nonce)
        nonceList.append(Nonce)
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        b_no = 1
        for block in textBlocks: #Loop over all the blocks of data               
            block = self.stringToBits(block)#Convert the block in bit array
            if len(block) < blockSize:
                block = self.padBlock(block)
            ciph=desECB.encrypt(nonceList[b_no-1])
            nonceList.append(ciph)
            ciph = self.xor(ciph,block)
            result.append(ciph)
            b_no += 1
        return result

    def des_OFB_Dec(self, plainText, Nonce):
        result = b''
        nonceList = list()
        Nonce = self.stringToBits(Nonce)
        nonceList.append(Nonce)
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        b_no = 1
        for block in textBlocks: #Loop over all the blocks of data               
            if len(block) < blockSize:
                block = self.padBlock(block)
            dciph=desECB.decrypt(nonceList[b_no -1])
            nonceList.append(dciph)
            dciph = self.xor(dciph, block)
            result.append(dciph)
            b_no += 1
        return result
    
    
    def des_CNT_Enc(self, plainText, count=0):
        result = b''
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        for block in textBlocks: #Loop over all the blocks of data               
            block = self.stringToBits(block)#Convert the block in bit array
            if len(block) < blockSize:
                block = self.padBlock(block)
            ciph=desECB.encrypt(count)
            ciph = self.xor(ciph,block)
            result.append(ciph)
            count+=1
        return result 
    
    def des_CNT_Dec(self, plainText, count=0):
        result = b''
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        for block in textBlocks: #Loop over all the blocks of data               
            if len(block) < blockSize:
                block = self.padBlock(block)
            dciph = desECB.decrypt(count)
            dciph = self.xor(dciph, block)
            result.append(dciph)
            count+=1
        return result 


if __name__ == '__main__':
    print(DES3.block_size)
    text= "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
    d = desModes()
    r = d.desECB_Enc(text)
    #r2 = d.desECB_Dec(r)
    print("Ciphered: %r" % r)
    #print("Deciphered: ", r2)
