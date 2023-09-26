# https://asecuritysite.com/encryption/ecc_blind
import hashlib

import binascii
import sys

from ecc import make_keypair, point_add, scalar_mult, curve

r1=-10
r2=15
v1=5
v2=7

r3=r1+r2
v3=v1+v2

#aliceSecretKey, alicePublicKey = make_keypair()
#bobSecretKey, bobPublicKey = make_keypair()


#print ("\nAlice\'s secret key:\t", aliceSecretKey)
#print ("Alice\'s public key:\t", alicePublicKey)

#print ("\n==========================")

va = point_add(scalar_mult(r1,curve.g),scalar_mult(v1,curve.g)) # we sould not be using the same curve ,e.g, curve G for m and curve H for r, this probably for illustration only !
vb = point_add(scalar_mult(r2 ,curve.g),scalar_mult(v2 ,curve.g))
vr1 = point_add(va,vb)
print("This the type", type(vr1))
print ("Transaction (r1*G + v1*G) + (r2*G +v2*G): ",vr1)

vr2 = point_add(scalar_mult(r3 ,curve.g),scalar_mult(v3,curve.g))
print ("Transaction (r3*G + v3*G): ",vr2)

print ("\nNow let's compare...")
if (vr1[0]==vr2[0]):
	print ("Success!")
else:
	print ("Failure!")
