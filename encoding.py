
import os
import random

# D = Number of Vector's Elements ( one extra element for encoding the number zero)

# N = Number of vectors and Number of bits representing the decmilal number to be encoded

def VectorYEncoding(Y,D):
    N = D-1
    # VectorY encoding
    VectorY = [[0]*D for _ in range(N)]
    # now convert to string of 1s and 0s
    byteY = bin(Y)[2:].rjust(N, '0')
    # now byte contains a string with 0s and 1s

    counter = 0
    for bit in byteY:
        if(bit=='0'):
            VectorY[counter][0]=1
        else:
            VectorY[counter][N-counter]=1
        counter = counter + 1
    return VectorY

def VectorXLEncoding(X,D):
    N = D-1
    #  VectorXl encoding
    VectorXl = [[0]*D for _ in range(N)]
    byteX = bin(X)[2:].rjust(N, '0')

    counter = 0
    for bit in byteX:
        if(bit=='0'):
            VectorXl[counter][0]=1
        else:
            for i in range(N-counter+1):
                VectorXl[counter][i]=1
        counter = counter + 1
    return VectorXl

def VectorXREncoding(X,D):
    N = D-1
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
    return VectorXR
