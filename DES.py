from Crypto.Cipher import DES
from keys import keyMAC,keyDES
import hashlib
#from des import DesKey

blockSize = 64
blockMAC = 8
# MAC sender data processing
def sendMAC(msg):
    obj=DES.new(keyMAC, DES.MODE_ECB)
    padLen = blockMAC - (len(msg) % blockMAC)
    msg += padLen * 'X'
    # encrypt msg with keyMAC
    encryptMACkey=obj.encrypt(msg)
    # hash msg with keyMAC
    hashedMAC = hashlib.md5(encryptMACkey).hexdigest()
    return str(hashedMAC)

class desModes():
    def __init__(self):
        # For testing purposes
        self.key = keyDES
        #self.key = DesKey(b"some key")
    
    #Split a list into sublists of size blocksize
    def splitMessage(self, plainText):
        return [plainText[k:k+blockSize] for k in range(0, len(plainText), blockSize)]
    
    def padBlock(self, block):
        padLen = blockSize - (len(block) % blockSize)
        block += padLen * chr(padLen)
        return block
    
    def stringToBits(text):#Convert a string into a list of bits
        array = list()
        for char in text:
            binval = binvalue(char, 8)#Get the char value on one byte
            array.extend([int(x) for x in list(binval)]) #Add the bits to the final list
        return array

    def bitsToString(array): #Recreate the string from the bit array
        res = ''.join([chr(int(y,2)) for y in 
            [''.join([str(x) for x in _bytes]) for _bytes in  nsplit(array,8)]])   
        return res
        
    def desECB_Enc(self, plainText):
        result = list()
        plainText = self.stringToBits(plainText)
        desECB=DES.new(self.key, DES.MODE_ECB)   
        textBlocks = self.splitMessage(plainText)
        for block in textBlocks:
            if len(block) < blockSize:
                block = self.padBlock(block)
            ciph=desECB.encrypt(block)
            result.append(ciph)
        return result

    def desECB_Dec(self, plainText):
        result = list()
        desECB=DES.new(self.key, DES.MODE_ECB)   
        textBlocks = self.splitMessage(plainText)
        for block in textBlocks:
            if len(block) < blockSize:
                block = self.padBlock(block)
            dciph=desECB.decrypt(block)
            result.append(dciph)
        return result
       

    def desCBC_Enc(self, plainText, IV):
        result = list()
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        b_no=0
        for block in textBlocks: #Loop over all the blocks of data               
            block = self.stringToBits(block)#Convert the block in bit array
            if len(block) < blockSize:
                block = self.padBlock(block)
            if b_no == 0:
                block = self.xor(IV, block)
            else:
                block = self.xor(result[b_no-1], block)
            ciph = desECB.encrypt(block)
            result.append(ciph)
        b_no += 1
        return result

    def desCBC_Dec(self, plainText, IV):
        result = list()
        desECB=DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        for i in range (0 , len(textBlocks))
        #for block in textBlocks: #Loop over all the blocks of data
            block = textBlocks[i]
            if len(block) < blockSize:
                block = self.padBlock(block)
            dciph = desECB.decrypt(block)
            if i == 0:
                dciph = self.xor(IV, dciph)
            else:
                dciph = self.xor(dciph, textBlocks[i-1])
            result.append(dciph)

        return result
    
    def des_CFB_Enc(self):
        #TODO: 
        return
    
    def des_CFB_Dec(self):
        #TODO: 
        return
    
    def des_OFB_Enc(self, plainText, Nonce):
        result = list()
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
        result = list()
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
    
    
    def des_CNT_Enc(self, plainText, Count=0):
        result = list()
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        for block in textBlocks: #Loop over all the blocks of data               
            block = self.stringToBits(block)#Convert the block in bit array
            if len(block) < blockSize:
                block = self.padBlock(block)
            ciph=desECB.encrypt(Count)
            ciph = self.xor(ciph,block)
            result.append(ciph)
            count+=1
        return result 
    
    def des_CNT_Dec(self, plainText, Count=0):
        result = list()
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        for block in textBlocks: #Loop over all the blocks of data               
            if len(block) < blockSize:
                block = self.padBlock(block)
            dciph = desECB.decrypt(Count)
            dciph = self.xor(dciph, block)
            result.append(dciph)
            count+=1
        return result 
        
'''       
if __name__ == '__main__':
    key = "secret_k"
    text= "Hello wolldldldxxxx"
    d = des()
    r = d.encrypt(key,text, True)
    r2 = d.decrypt(key, r, True)
    print("Ciphered: %r" % r)
    print("Deciphered: ", r2)
'''
