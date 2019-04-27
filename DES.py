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
    
    def desECB(self, plainText):
        result = list()
        desECB=DES.new(plainText, DES.MODE_ECB)
        textBlocks = self.splitMessage(plainText)
        for block in textBlocks:
            if len(block) < blockSize:
                block = self.padBlock(block)
            ciph=desECB.encrypt(block)
            result.append(ciph)
        return result
 
    def desCBC(self, text_blocks, action, IV):
        result = list()
        b_no=0
        if action == ENCRYPT:
            for block in text_blocks: #Loop over all the blocks of data               
                block = string_to_bit_array(block)#Convert the block in bit array
                if b_no == 0:
                    block = self.xor(IV,block)
                else:
                    block = self.xor(result[b_no-1],block)
                d, g = self.desCalc(block)
                b_no+=1
                result += self.permut(d+g, PI_1) #Do the last permut and append the result to result

        else:
            for block in text_blocks:#Loop over all the blocks of data
                block = string_to_bit_array(block)#Convert the block in bit array
                d, g = self.desCalc(block)
                if b_no == 0:
                    block = self.xor(IV,block)
                else:
                    block = self.xor(result[b_no-1],block)
                b_no+=1
                result += self.permut(d+g, PI_1) #Do the last permut and append the result to result
       
        return result
    
    def des_CFB(self):
        # TODO
        return
    def des_OFB(self):
        # TODO
        return
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
