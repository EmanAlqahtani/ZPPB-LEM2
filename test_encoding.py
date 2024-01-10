
import os,sys

import random
from fhipe.fhipe import ipe

sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(1, os.path.abspath('..'))
# Number of Vector's Elements ( one extra element for encoding the number zero)
D = 7

# Number of vectors and Number of bits representing the decmilal number to be encoded
N = D-1

Y=5
# VectorY encoding
VectorY = [[0]*D for _ in range(N)]
# now convert to string of 1s and 0s
byteY = bin(Y)[2:].rjust(N, '0')
# now byte contains a string with 0s and 1s
print(byteY)
counter = 0
for bit in byteY:
    if(bit=='0'):
        VectorY[counter][0]=1
    else:
        VectorY[counter][N-counter]=1
    counter = counter + 1
print(VectorY)
X=6
#  VectorXl encoding
VectorXl = [[0]*D for _ in range(N)]
byteX = bin(X)[2:].rjust(N, '0')
print(byteX)
counter = 0
for bit in byteX:
    if(bit=='0'):
        VectorXl[counter][0]=1
    else:
        for i in range(N-counter+1):
            VectorXl[counter][i]=1
    counter = counter + 1
print(VectorXl)
#  VectorXR encoding
VectorXR = [[0]*D for _ in range(N)]
byteX = bin(X)[2:].rjust(N, '0')

counter = 0
for bit in byteX:
    if(bit=='0'):
        for i in range(0,D):
            VectorXR[counter][i]=1
    else:
        for i in range(N-counter,D):
            VectorXR[counter][i]=1
    counter = counter + 1
print(VectorXR)
(pp, sk) = ipe.setup(D)
Result=0
sky= [[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]
ctxL=[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]
ctxR=[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]


for i in range(N):
    sky[i] = ipe.keygen(sk, VectorY[i])
    #print(skx[i])
    ctxL[i] = ipe.encrypt(sk, VectorXl[i])
    #print(ctyL[i])
    ctxR[i] = ipe.encrypt(sk, VectorXR[i])
    #print(ctyR[i])

def comp():
    # Less than comparision
    for i in range(N):
        Result = ipe.decrypt(pp, sky[i], ctxL[i], D)
        if Result==0:
            return 0
    # Greater than comparision
        Result = ipe.decrypt(pp, sky[i], ctxR[i], D)
        if Result==0:
            return 1
    return 2

if comp()==0:
    print("X value(",X,") is less than Y Value(",Y,")")
elif comp()==1:
    print("X value(",X,") is greater than Y Value(",Y,")")
elif comp()==2:
    print("X value(",X,") is equal to Y Value(",Y,")")
