"""
Author: Laura Pickens
File: ios7decrypt.py
DescriptioN: cisco type 7 password decryptor
Usage: python ios7decrypt.py <pass>
	   where <pass> is the type 7 password on cisco switch

Based on Daren Matthews perl script found at http://mccltd.net/blog/?p=1034 and
https://www.question-defense.com/2011/08/17/perl-script-to-decode-cisco-type-7-password-hash

Do not use for any malicous activities please and thank you
"""

import sys

"""
Vigenere translation table
"""
global xlat
xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 
		0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 
		0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 0x38, 0x33, 0x34,  
		0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b, 
		0x3b, 0x66, 0x67, 0x38, 0x37]

"""
Decryption Algorithm
"""
def decrypt(password):

	# Break Cipher into Hex Values
	password_hex = []
	for i in range(0,len(password),2):
		password_hex.append(password[i:i+2])

	# Look Up Hex Values in Vigenere translation table
	password_chars = []
	index = int(password_hex[0],16)
	for i in range(1,len(password_hex)):
		password_chars.append(chr(int(password_hex[i],16) ^ xlat[index]))
		index = index + 1 % 53 # wrap around if necessary

	plaintext = ''.join(password_chars)

	return plaintext

"""
Main
"""
if len(sys.argv) == 2:
	ciphertext = sys.argv[1]
	print ("Cipher Text is %s" % ciphertext)

	print ("Plain Text is %s" % decrypt(ciphertext))
else:
	print ("Error - Incorrect # of args")
	print ("Example Usage: python ios7decrypt.py 002D01090A681B0F0B245E")
