# Change randoms
# Add zones, then evaluate
# correct deviation share according to my values
import random
import os
import hashlib
import binascii
import sys
import encoding
from ecc import point_add, scalar_mult, curve
# Path hack
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(1, os.path.abspath('..'))
from fhipe.fhipe import ipe

# variables necassary for functional encryption and encoding
# 1- Number of Vector's Elements ( one extra element for encoding the number zero)
D = 12
# 2- Number of vectors and Number of bits representing the decmilal number to be encoded
N = D-1

class KeyAuthority:
  readingsKeys,pTypeKeys,cTypeKeys = [],[],[]
  DecKey,pTypeDecKey,cTypeDecKey,rDecKey = 0 ,0, 0, 0
  pp, sk = 0, 0
  def getReadingsEncryptionKeys(self):
    for i in range(0,2): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.readingsKeys.append(n)
    print("Secret meater reading keys are: ",KeyAuthority.readingsKeys)
    return KeyAuthority.readingsKeys

  def getDecryptionKey(self,decPKeyHelper,decCKeyHelper):
    KeyAuthority.DecKey = self.getReadingsDecryptionKey() + self.getPTypeDecryptionKey(decPKeyHelper) + self.getCTypeDecryptionKey(decCKeyHelper)
    return KeyAuthority.DecKey

  def getReadingsDecryptionKey(self):
    for i in range(0,2):
      KeyAuthority.rDecKey += KeyAuthority.readingsKeys[i] * tradingPrices[i]
      KeyAuthority.rDecKey = KeyAuthority.rDecKey % pow(2,23)
    print("Decryption key is: ", KeyAuthority.rDecKey)
    return KeyAuthority.rDecKey

  def getPTypeEncryptionKeys(self):
    for i in range(0,2): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.pTypeKeys.append(n)
    print("Secret type keys are: ",KeyAuthority.pTypeKeys)
    return KeyAuthority.pTypeKeys

  def getPTypeDecryptionKey(self,decPKeyHelper):
    for i in range(0,2):
      KeyAuthority.pTypeDecKey += decPKeyHelper[i] * KeyAuthority.pTypeKeys[i] * (FiT[i] - tradingPrices[i]) * vs[i]
      KeyAuthority.pTypeDecKey = KeyAuthority.pTypeDecKey % pow(2,23)
    print("Decryption key is: ", KeyAuthority.pTypeDecKey)
    return KeyAuthority.pTypeDecKey

  def getCTypeEncryptionKeys(self):
    for i in range(0,2): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.cTypeKeys.append(n)
    print("Secret type keys are: ",KeyAuthority.cTypeKeys)
    return KeyAuthority.cTypeKeys

  def getCTypeDecryptionKey(self,decCKeyHelper):
    for i in range(0,2):
      KeyAuthority.cTypeDecKey += decCKeyHelper[i] * KeyAuthority.cTypeKeys[i] * (RP[i] - tradingPrices[i]) * vs[i]
      KeyAuthority.cTypeDecKey = KeyAuthority.cTypeDecKey % pow(2,23)
    print("Decryption key is: ", KeyAuthority.cTypeDecKey)
    return KeyAuthority.cTypeDecKey

  def ipeSetup(self):
    (KeyAuthority.pp, KeyAuthority.sk) = ipe.setup(D)

  def getSecretKey(self):
    return KeyAuthority.sk

  def getPublicParameters(self):
     return KeyAuthority.pp

class SmartMeter:
  def __init__(self):
    self.KAuth = KeyAuthority()
    self.MaskedReadings,self.ComittedReadings= [],[]
#    self.EncodedReadings = [[0]*D for _ in range(N)]
    self.sky = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]

  def getMaskedReadings(self,u):
    randomKeys = self.KAuth.getReadingsEncryptionKeys()
    for i in range(0,2):
      self.MaskedReadings.append(usersTupples[u][i][0] + randomKeys[i])
    print("Masked Readings", self.MaskedReadings)
    return self.MaskedReadings

  # Pedersen Commitment
  def getCommitedReadings(self):
    for i in range(0,3):
      self.ComittedReadings.append(point_add(scalar_mult(-1 * meterReadings[i],curve.g),scalar_mult(3,curve.g)))
    return self.ComittedReadings

  # InnerProducts functionl encryption (meater readings)
  def getIpfeEncryptedReading(self,u):
      for i in range(2): # 10 meter readings for each of the 10 periods
          for j in range(N): # N vectors per meter reading
              self.sky[i][j]= ipe.keygen(self.KAuth.getSecretKey(), encoding.VectorYEncoding(usersTupples[u][i][0],D)[j])
      return self.sky
      '''self.EncodedReadings = encoding.VectorYEncoding(meterReadings[0],D)
      for i in range(N):
          self.sky[i]= ipe.keygen(self.KAuth.getSecretKey(), self.EncodedReadings[i])
      print("Second",self.sky[0])
      return self.sky'''

class MarketOperator:
  def __init__(self):
      self.ComittedAmounts = []
      self.KAuth = KeyAuthority()
      self.MaskedPTypes, self.MaskedCTypes = [],[]
#      self.EncodedVolumesL = self.EncodedVolumesR = [[0]*D for _ in range(N)]
      self.skxL = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
      self.skxR = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]

  # mask prosumer vector
  def getMaskedPTypes(self,u):
    randomKeys = self.KAuth.getPTypeEncryptionKeys()
    for i in range(0,2):
      self.MaskedPTypes.append(usersTupples[u][i][2] + randomKeys[i])
    print("Masked prosumer vector", self.MaskedPTypes)
    return self.MaskedPTypes

  # mask consumer type vector
  def getMaskedCTypes(self,u):
    randomKeys = self.KAuth.getCTypeEncryptionKeys()
    for i in range(0,2):
      self.MaskedCTypes.append(1 + randomKeys[i])
    print("Masked consumer vector", self.MaskedCTypes)
    return self.MaskedCTypes

  def getComittedAmounts(self):
    for i in range(0,3):
       self.ComittedAmounts.append(point_add(scalar_mult(tradingVolumes[i],curve.g),scalar_mult(4,curve.g)))
    return self.ComittedAmounts

  # InnerProducts functionl encryption (trading volumes)
  def getIpfeEncryptedVolume(self,u):
#      self.EncodedVolumesL,self.EncodedVolumesR = encoding.VectorXLEncoding(5,D),encoding.VectorXREncoding(5,D)
      for i in range(2):
          for j in range(N):
              self.skxL[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXLEncoding(usersTupples[u][i][1],D)[j])
              self.skxR[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXREncoding(usersTupples[u][i][1],D)[j])
      return self.skxL,self.skxR

class Supplier:
  def __init__(self):
        self.BillCT = [numberOfUsers]
        self.EncryptedReading = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.EncryptedVolumeL = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.EncryptedVolumeLR = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.decPKeyHelper, self.decCKeyHelper= [[0 for _ in range(2)] for _ in range(numberOfUsers)],[[0 for _ in range(2)]for _ in range(numberOfUsers)]
        self.SM = SmartMeter()
        self.KAuth = KeyAuthority()
        self.MO = MarketOperator()

  # Check if user has deviated using IPFE
  def checkDeviations(self,i,u):
      self.EncryptedReading = self.SM.getIpfeEncryptedReading(u)
      self.EncryptedVolumeL,self.EncryptedVolumeR = self.MO.getIpfeEncryptedVolume(u)

      for j in range(N): # i: period number,  self.EncryptedReading[i] to retreive the encrypted reading of period i.
          #j: every meter reading is represented using N number of encdoed vectors , each is encrypted using IPFE
      # Less than comparision , check if trading volume is less than the actual meter reading (positive deviation)
          prod = ipe.decrypt(self.KAuth.getPublicParameters(), self.EncryptedReading[i][j] , self.EncryptedVolumeL[i][j], D)
          if prod==0:return 1 # indicate positive deviation
      # Greater than comparision , check if trading volume is more than the actual meter reading (negative deviation)
          prod = ipe.decrypt(self.KAuth.getPublicParameters(),self.EncryptedReading[i][j],  self.EncryptedVolumeR[i][j], D)
          if prod==0:return -1 # indicate negative deviation
      return 0 # No deviation, trading volume is equal to meater reading

  def ComputeBill(self,u):
    maskedReadings, maskedPTypes, maskedCTypes =self.SM.getMaskedReadings(u), self.MO.getMaskedPTypes(u), self.MO.getMaskedCTypes(u)
    for i in range(0,2):
#      self.BillCT += ((maskedReadings[i] * tradingPrices[i]) + ((vs[i]>0) * (self.checkDeviations(i)>0) * maskedPTypes[i] * vs[i] *(FiT[i] - tradingPrices[i])) + ((vs[i]<0) * (self.checkDeviations(i)<0) * maskedCTypes[i] * vs[i] *(RP[i] - tradingPrices[i])))
        self.BillCT[u] += (maskedReadings[i] * tradingPrices[i])
        if (vs[i]>0) * (self.checkDeviations(i,u)>0):
            self.decPKeyHelper[u][i]=1
            self.BillCT[u] += maskedPTypes[i] * vs[i] *(FiT[i] - tradingPrices[i])
        elif (vs[i]<0) * (self.checkDeviations(i,u)<0):
            self.decCKeyHelper[u][i]=1
            self.BillCT[u] += maskedCTypes[i] * vs[i] *(RP[i] - tradingPrices[i])
        self.BillCT[u] = self.BillCT[u] % pow(2,23)
    print("Encrypted bill is: ", self.BillCT[u])

  def getCorrectBills(self,u):
    DecKey = self.KAuth.getDecryptionKey(self.decPKeyHelper[u], self.decCKeyHelper[u])
    Bill = (self.BillCT[u] - DecKey) % pow(2,23)
    print("The bill after decryption is: ", Bill/1000)

  def aggregIVCommitments(self): #Compute individual deviations commitmements and aggregate them
    ComittedReadings = self.SM.getCommitedReadings()
    ComittedAmounts = self.MO.getComittedAmounts()
    IV = point_add(ComittedAmounts[0],ComittedReadings[0])

    #checkDeviationsCorrectness(self):
    Result = tradingVolumes[0] - meterReadings[0]
    #R = randomKeys[0] + randomKeys[0]
    IV2 = point_add(scalar_mult(Result ,curve.g),scalar_mult(7,curve.g))
    print ("\nComparsision result...")
    if (IV[0]==IV2[0]):
    	print ("Success. Individual deviations are correct.")
    else:
    	print ("Failure!")

tradingPrices = [156,201,233,160,247,210,195,262,187,143] #300 pounds per Watt is the average retail price in UK
FiT = [100,90,95,100,100,99,97,95,98,99]
RP = [290,300,295,285,305,290,295,300,310,320]
meterReadings = [700,500,900,600,400,500,800,900,700,600]
tradingVolumes = [650,400,850,550,390,490,777,888,650,500]
vs = [-45,50,37.6,-10,-23,44,-31,39,41,-18] # Deviation share for each period (total deviation (per watt)/number of prosumers or consumers), we should get these values from MPC
prosumerEncoding = [0,1,1,1,1,1,1,1,1,0] # 1 for prosumer and 0 for conumer
consumerEncoding = [1,0,0,0,0,0,0,0,0,1] # 0 for consumer and 1 prosumer
numberOfUsers = 10
usersTupples = [[[0 for _ in range(3)] for _ in range(2)] for _ in range(numberOfUsers)] # Three values (mr, tv and type) , two periods and 10 users
# Inner-product functional encryption keysSetup
KAuth = KeyAuthority()
KAuth.ipeSetup()
supplier = Supplier()

# Setting users data
try:
    with open("/Users/emanahmed/Documents/GitHub/ZPPB-LEM2/data/input-P0-0.txt", 'r') as file:
        u,p,v=0,0,0
        n=0
        for line in file:
            numbers = line.split()
            for i in range(numberOfUsers*6):
                usersTupples[u][p][v]= int(numbers[i]) # u is the user ID , p is the period number , v is the value ( mr,tv or type)
                v+=1
                n+=1
                if n==3: v,p=0,1
                elif n==6:
                    v,p,n=0,0,0
                    u+=1

except FileNotFoundError:
    print(f"The file '{file_path}' was not found.")

print(usersTupples)

supplier.ComputeBill(0) #Encrypted
supplier.getCorrectBills(0)
supplier.aggregIVCommitments()

# For testing
Bill =0
for i in range(0,2): #10 periods
    Bill += usersTupples[0][i][0] * tradingPrices[i]
    if (supplier.checkDeviations(i,0)>0) * (vs[i]>0):
        Bill += vs[i] * (FiT[i] - tradingPrices[i]) * usersTupples[u][i][2]
    elif (supplier.checkDeviations(i,0)<0) * (vs[i]<0):
        Bill += vs[i] * (RP[i] - tradingPrices[i]) * 1
Bill = Bill % pow(2,23)
print("Bill computation in clear (for testing) is: ", Bill/1000)

Bill=0
for i in range(0,22): #10 periods
    Bill += usersTupples[0][i][0] * tradingPrices[i]
Bill = Bill % pow(2,23)
print("Bill computation without deviations in clear (for testing) is: ", Bill/1000)
