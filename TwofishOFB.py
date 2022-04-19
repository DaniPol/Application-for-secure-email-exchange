#
# Loxodo -- Password Safe V3 compatible Password Vault
# Copyright (C) 2008 Christoph Sommer <mail@christoph-sommer.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#TODO check how to import python file
#original import from . import twofish
import twofish
import operator

import six

class TwofishOFB:
    """
    Cipher-block chaining (CBC) Twofish operation mode.
    """
    def __init__(self, key, init_vec=0):
        """
        Set the key to be used for en-/de-cryption and optionally specify an initialization vector (aka seed/salt).
        """
        self.twofish = twofish.Twofish()
        self.twofish.set_key(key)
        self.state = init_vec
        self.org_init_vec = init_vec
       
    def encrypt(self, plaintext):
        """
        Encrypt the given string using Twofish OFB.
        """
        if len(plaintext) <= 0:
            raise RuntimeError("Twofish ciphertext length must be greater than zero")
        ciphertext = b""
        while len(plaintext) > 0:
            #Enc - IV with Key#
            encIV = self.twofish.encrypt(self.state)
            envIV_bytearray = bytearray(encIV)
            state_bytearray = bytearray(self.state)


            ##############
            len_plaintext = len(plaintext[0:16])
            PText_bytearray = bytearray(plaintext[0:16])
            if (len_plaintext < 16):
                for x in range(16 - len_plaintext):
                    PText_bytearray.append(0)
            PtextBytes = bytes(PText_bytearray)

            block = self._xor_block(PtextBytes, encIV)
            self.state = bytes(state_bytearray[1:] + envIV_bytearray[0:1])

            block_first_bit = bytearray(block)
            block_first_bit = block_first_bit[0:1]
            block_first_bit = bytes(block_first_bit)
            ciphertext += block_first_bit

            #end
            plaintext = plaintext[1:]
            #TODO create temp value so i wont lose self.state
        return ciphertext

    def decrypt(self, ciphertext):
        """
        Decrypt the given string using Twofish OFB.
        """
        #restore org init vec #
        self.state = self.org_init_vec
        if len(ciphertext) <= 0:
            raise RuntimeError("Twofish ciphertext length must be greater than zero")
        plaintext = b""
        while len(ciphertext) > 0:
             #Enc - IV with Key#
            decIV = self.twofish.decrypt(self.state)
            decIV_bytearray = bytearray(decIV)
            state_bytearray = bytearray(self.state)


            ##############
            len_ciphertext = len(ciphertext[0:16])
            CText_bytearray = bytearray(ciphertext[0:16])
            if (len_ciphertext < 16):
                for x in range(16 - len_ciphertext):
                    CText_bytearray.append(0)
            CtextBytes = bytes(CText_bytearray)

            block = self._xor_block(CtextBytes, decIV)
            self.state = bytes(state_bytearray[1:] + decIV_bytearray[0:1])

            block_first_bit = bytearray(block)
            block_first_bit = block_first_bit[0:1]
            block_first_bit = bytes(block_first_bit)
            plaintext += block_first_bit

            #end
            ciphertext = ciphertext[1:]
           
        return plaintext

    @staticmethod
    def _xor_block(text1, text2):
        """
        Return the bitwise xor of two arbitrary-length blocks of data
        """
        return b"".join(
                       map(
                           lambda c1, c2: six.int2byte(operator.xor(six.byte2int([c1]), six.byte2int([c2]))),
                           text1,
                           text2
                           )
                       )
    
 


