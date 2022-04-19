The project topic: An Application for secure email exchange: encryption-decryption with Twofish in OFB mode, secret key delivery with EC EL-Gamal + DSA signature


The project flow: 

1.	Preparation - EC-El Gamal / DSA:

•	Alice and Bob send each-other their public keys for their DSA digital signature using a secure channel.
•	Alice generates an EC-El Gamal system and sends Bob her public key (EC-El Gamal).
•	Bob receives Alice’s message, validates that it’s from Alice and generates a symmetric key “M” of 128 bits and an IV of 128 bits. Bob then encrypts it with the public EC-El Gamal key, signs with DSA and sends the message to Alice
•	Alice receives Bob’s message, decrypts the key using her private EC-El Gamal key and validates the signature using DSA.
•	If everything worked, Alice and Bob now agree on the same symmetric key (M) and IV for them to use in the Encryption/Decryption process (Twofish OFB).

2.	Encryption/Decryption:

•	Bob writes an E-Mail to Alice, encrypts it with the symmetric key M and initial vector IV using Twofish in OFB mode. Bob then signs on the original E-Mail (Using DSA) and sends both the encrypted E-Mail and the signature to Alice.
•	Alice received the message, decrypts the E-Mail (the encrypted message) and verifies that Bob is the sender of the E-Mail.
•	If everything worked, Bob and Alice exchanged E-Mails. If Oscar/Eve Cause any interruption in the process, Bob and Alice will figure it out in the verification stage of the Digital Signature.



Weaknesses: 

The preparation stage of the process is crucial for the scheme, Asymmetric algorithms are vulnerable to Man in the Middle attack, The preparation stage main goal is to exchange the symmetric key using secure way.
 


Run Example:
![image](https://user-images.githubusercontent.com/73639212/163991274-21cb7ab3-49cd-449b-b6d1-9f67ea4a4658.png)

 






References:

•	https://en.wikipedia.org/wiki/Twofish
•	https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
•	https://www.schneier.com/academic/twofish/
•	https://www.youtube.com/watch?v=SpaXSMkJLs0
•	https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
•	https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
•	https://medium.com/asecuritysite-when-bob-met-alice/elgamal-and-elliptic-curve-cryptography-ecc-8b72c3c3555e



