from Crypto.Cipher import DES
#from des import DesKey

blockSize = 64

class desModes():
    def __init__(self):
        # For testing purposes
        self.key = "0E329232EA6D0D73"
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
        res = ''.join([chr(int(y,2)) for y in [''.join([str(x) for x in _bytes]) for _bytes in  nsplit(array,8)]])   
        return res
        
    def desECB(self, plainText):
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
    

    def desCBC(self, plainText, IV):
        result = list()
        plainText = self.stringToBits(plainText)
        desECB=DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        b_no=0
        for block in textBlocks: #Loop over all the blocks of data               
            block = self.stringToBits(block)#Convert the block in bit array
            if len(block) < blockSize:
                block = self.padBlock(block)
            if b_no == 0:
                block = self.xor(IV,block)
            else:
                block = self.xor(result[b_no-1],block)
            ciph=desECB.encrypt(block)
            result.append(ciph)

        return result
    
    def des_CFB(self):
        # TODO
        return
    
    def des_OFB(self, plainText, Nonce):
        result = list()
        nonceList = list()
        plainText = self.stringToBits(plainText)
        Nonce = self.stringToBits(Nonce)
        nonceList.append(Nonce)
        desECB = DES.new(self.key, DES.MODE_ECB)        
        textBlocks = self.splitMessage(plainText)
        b_no=1
        for block in textBlocks: #Loop over all the blocks of data               
            block = self.stringToBits(block)#Convert the block in bit array
            if len(block) < blockSize:
                block = self.padBlock(block)
            ciph=desECB.encrypt(nonceList[b_no-1])
            nonceList.append(ciph)
            ciph = self.xor(ciph,block)
            result.append(ciph)
        return result
    
    
    def des_CNT(self):
        # TODO
        return
        
        
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
