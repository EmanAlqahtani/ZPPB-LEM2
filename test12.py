import os
n = int.from_bytes(os.urandom(16), byteorder="big")
l=100
k = 98 # key, must be less than l
k2 = 70
x = 9 # value
x2 = 10 # vlaue 2
price1 = 5
price2 = 6
encrypted = ( x + k ) % l
bill = (encrypted * price1)
encrypted2 = (x2 + k2 ) % l
bill += (encrypted2 * price2)

decryption_key = ((k * price1) + (k2 * price2)) % l

print("the bill after decryption: ",(bill-decryption_key)% l)
