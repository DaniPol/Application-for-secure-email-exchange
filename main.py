import os
import TwofishOFB as MTF

from ecc.curve import Curve25519
from ecc.key import gen_keypair
from ecc.cipher import ElGamal
import dsa

def CreateRandomTwoFishKey():
    return os.urandom(16)

def CreateRandomInizVec():
    return os.urandom(16)

def TwoFishEncryptMessage(cipherKey,iniz_vec, Ptext):
    twoFishObj = MTF.TwofishOFB(cipherKey,iniz_vec)
    Ptext = twoFishObj.encrypt(bytes(Ptext, 'utf-8'))
    return Ptext


def TwoFishDecryptMessage(decKey,iniz_vec, cipher):
    twoFishObj = MTF.TwofishOFB(decKey,iniz_vec)
    cipher = twoFishObj.encrypt(cipher)
    return cipher.decode()

class Person:
        def __init__(self,name):
            self.name = name
            self.DSA_p = -1
            self.DSA_q = -1
            self.DSA_g = -1
            self.DSA_y = -1
            self.DSA_x = -1
            self.DSA_r = -1
            self.DSA_s = -1
            self.ecc_eg_pri_key = -1
            self.ecc_eg_pub_key = -1
            
            

alice = Person("Alice")
bob = Person("Bob")

#DSA Signture - alice signs

N = 160
L = 1024
    
p, q, g = dsa.generate_params(L, N)
alice.DSA_p = p
alice.DSA_q = q
alice.DSA_g = g
alice.DSA_x, alice.DSA_y = dsa.generate_keys(g, p, q)

#Message to encrypt
message = input("Please enter message to encrypt\n")
print("Message alice encrypts: ", message)

#Message to encrypt

message_DSA = str.encode(message, "ascii")

alice.DSA_r, alice.DSA_s = dsa.sign(message_DSA, p, q, g, alice.DSA_x)

while alice.DSA_r == 0 or alice.DSA_s == 0:
    alice.DSA_r, alice.DSA_s = dsa.sign(message_DSA, p, q, g, alice.DSA_x)


#DSA Signture - alice end signing

#EC El-Gamal , key encryption , alice encrypts the key

message_key = CreateRandomTwoFishKey()

print("Key Alice Wants Bob to get after decyrption: ", message_key)


iniz_vec = CreateRandomInizVec()

bob.ecc_eg_pri_key, bob.ecc_eg_pub_key = gen_keypair(Curve25519)

cipher_elg = ElGamal(Curve25519)
C1, C2 = cipher_elg.encrypt(message_key, bob.ecc_eg_pub_key)

message_key_dec = cipher_elg.decrypt(bob.ecc_eg_pri_key, C1, C2)

print("Key Bob got after decyrption: ", message_key_dec)

#EC El-Gamal , key decyrption , bob decrypts the key


#Message encyrption , alice encyrpts the message

encryptedMessage = TwoFishEncryptMessage(message_key,iniz_vec, message)

decryptedMessage = TwoFishDecryptMessage(message_key_dec,iniz_vec, encryptedMessage)

print("Message Bob got after decyrption: ", decryptedMessage)

#Message decyrption , bob decrypts the message


verfication = dsa.verify(message_DSA, alice.DSA_r, alice.DSA_s, p, q, g, alice.DSA_y)

print("Did alice send the message? " , verfication)