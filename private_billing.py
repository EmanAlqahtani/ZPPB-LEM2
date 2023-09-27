# Change randoms
# Add zones, then evaluate
# Integrate with MPC
# Did not think about hiding whether consumer or prosumer ?
# Change the decryption to one time decryption with one decryption key
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

tradingPrices = [156,201,233,160,247,210,195,262,187,143] #300 pounds per Watt is the average retail price in UK
FiT = [100,90,95,100,100,99,97,95,98,99]
RP = [290,300,295,285,305,290,295,300,310,320]
meterReadings = [700,500,900,600,400,500,800,900,700,600]
tradingVolumes = [650,400,850,550,390,490,777,888,650,500]
vs = [45,50,37.6,-10,-23,44,-31,39,41,-18] # Deviation share for each period (total deviation (per watt)/number of prosumers or consumers), we should get these values from MPC
prosumerEncoding = [0,1,1,1,1,1,1,1,1,0] # 1 for prosumer and 0 for conumer
consumerEncoding = [1,0,0,0,0,0,0,0,0,1] # 0 for consumer and 1 prosumer
# variables necassary for functional encryption and encoding
# 1- Number of Vector's Elements ( one extra element for encoding the number zero)
D = 12
# 2- Number of vectors and Number of bits representing the decmilal number to be encoded
N = D-1

class KeyAuthority:
  readingsKeys,pTypeKeys,cTypeKeys = [],[],[]
  DecKey,pTypeDecKey,cTypeDecKey = 0 ,0 , 0
  pp, sk = 0, 0
  def getReadingsEncryptionKeys(self):
    for i in range(0,3): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.readingsKeys.append(n)
    print("Secret meater reading keys are: ",KeyAuthority.readingsKeys)
    return KeyAuthority.readingsKeys

  def getDecryptionKey(self):
    for i in range(0,3):
      KeyAuthority.DecKey += KeyAuthority.readingsKeys[i] * tradingPrices[i]
      KeyAuthority.DecKey = KeyAuthority.DecKey % pow(2,23)
    print("Decryption key is: ", KeyAuthority.DecKey)
    return KeyAuthority.DecKey

  def getPTypeEncryptionKeys(self):
    for i in range(0,3): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.pTypeKeys.append(n)
    print("Secret type keys are: ",KeyAuthority.pTypeKeys)
    return KeyAuthority.pTypeKeys

  def getPTypeDecryptionKey(self):
    for i in range(0,3):
      KeyAuthority.pTypeDecKey += KeyAuthority.pTypeKeys[i] * (FiT[i] - tradingPrices[i]) * vs[i]
      KeyAuthority.pTypeDecKey = KeyAuthority.pTypeDecKey % pow(2,23)
    print("Decryption key is: ", KeyAuthority.pTypeDecKey)
    return KeyAuthority.pTypeDecKey

  def getCTypeEncryptionKeys(self):
    for i in range(0,3): #10 periods
      n = int.from_bytes(os.urandom(4), byteorder="big")
      KeyAuthority.cTypeKeys.append(n)
    print("Secret type keys are: ",KeyAuthority.cTypeKeys)
    return KeyAuthority.cTypeKeys

  def getCTypeDecryptionKey(self):
    for i in range(0,3):
      KeyAuthority.cTypeDecKey += KeyAuthority.cTypeKeys[i] * (RP[i] - tradingPrices[i]) * vs[i]
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

  def getMaskedReadings(self):
    randomKeys = self.KAuth.getReadingsEncryptionKeys()
    for i in range(0,3):
      self.MaskedReadings.append(meterReadings[i] + randomKeys[i])
    print("Masked Readings", self.MaskedReadings)
    return self.MaskedReadings

  # Pedersen Commitment
  def getCommitedReadings(self):
    for i in range(0,3):
      self.ComittedReadings.append(point_add(scalar_mult(-1 * meterReadings[i],curve.g),scalar_mult(3,curve.g)))
    return self.ComittedReadings

  # InnerProducts functionl encryption (meater readings)
  def getIpfeEncryptedReading(self):
      for i in range(3): # 10 meter readings for each of the 10 periods
          for j in range(N): # N vectors per meter reading
              self.sky[i][j]= ipe.keygen(self.KAuth.getSecretKey(), encoding.VectorYEncoding(meterReadings[i],D)[j])
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
  def getMaskedPTypes(self):
    randomKeys = self.KAuth.getPTypeEncryptionKeys()
    for i in range(0,3):
      self.MaskedPTypes.append(prosumerEncoding[i] + randomKeys[i])
    print("Masked prosumer vector", self.MaskedPTypes)
    return self.MaskedPTypes

  # mask consumer type vector
  def getMaskedCTypes(self):
    randomKeys = self.KAuth.getCTypeEncryptionKeys()
    for i in range(0,3):
      self.MaskedCTypes.append(consumerEncoding[i] + randomKeys[i])
    print("Masked consumer vector", self.MaskedCTypes)
    return self.MaskedCTypes

  def getComittedAmounts(self):
    for i in range(0,3):
       self.ComittedAmounts.append(point_add(scalar_mult(tradingVolumes[i],curve.g),scalar_mult(4,curve.g)))
    return self.ComittedAmounts

  # InnerProducts functionl encryption (trading volumes)
  def getIpfeEncryptedVolume(self):
#      self.EncodedVolumesL,self.EncodedVolumesR = encoding.VectorXLEncoding(5,D),encoding.VectorXREncoding(5,D)
      for i in range(3):
          for j in range(N):
              self.skxL[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXLEncoding(tradingVolumes[i],D)[j])
              self.skxR[i][j]= ipe.encrypt(self.KAuth.getSecretKey(), encoding.VectorXREncoding(tradingVolumes[i],D)[j])
      return self.skxL,self.skxR

class Supplier:
  def __init__(self):
        self.BillCT = 0
        self.EncryptedReading = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.EncryptedVolumeL = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.EncryptedVolumeLR = [[[[0 for _ in range(2)] for _ in range(D+1)] for _ in range(N)]for _ in range(3)]
        self.SM = SmartMeter()
        self.KAuth = KeyAuthority()
        self.MO = MarketOperator()

  # Check if user has deviated using IPFE
  def checkDeviations(self,i):
      self.EncryptedReading = self.SM.getIpfeEncryptedReading()
      self.EncryptedVolumeL,self.EncryptedVolumeR = self.MO.getIpfeEncryptedVolume()

      for j in range(N): # i: period number,  self.EncryptedReading[i] to retreive the encrypted reading of period i.
          #j: every meter reading is represented using N number of encdoed vectors , each is encrypted using IPFE
      # Less than comparision , check if trading volume is less than the actual meter reading (positive deviation)
          prod = ipe.decrypt(self.KAuth.getPublicParameters(), self.EncryptedReading[i][j] , self.EncryptedVolumeL[i][j], D)
          if prod==0:return 1 # indicate positive deviation
      # Greater than comparision , check if trading volume is more than the actual meter reading (negative deviation)
          prod = ipe.decrypt(self.KAuth.getPublicParameters(),self.EncryptedReading[i][j],  self.EncryptedVolumeR[i][j], D)
          if prod==0:return -1 # indicate negative deviation
      return 0 # No deviation, trading volume is equal to meater reading

  def ComputeBill(self):
    maskedReadings, maskedPTypes, maskedCTypes =self.SM.getMaskedReadings(), self.MO.getMaskedPTypes(), self.MO.getMaskedCTypes()
    for i in range(0,3):
#      self.BillCT += ((maskedReadings[i] * tradingPrices[i]) + ((vs[i]>0) * (self.checkDeviations(i)>0) * maskedPTypes[i] * vs[i] *(FiT[i] - tradingPrices[i])) + ((vs[i]<0) * (self.checkDeviations(i)<0) * maskedCTypes[i] * vs[i] *(RP[i] - tradingPrices[i])))
        self.BillCT += (maskedReadings[i] * tradingPrices[i])
        if (vs[i]>0) * (self.checkDeviations(i)>0):
            self.BillCT += maskedPTypes[i] * vs[i] *(FiT[i] - tradingPrices[i])
        elif (vs[i]<0) * (self.checkDeviations(i)<0):
            self.BillCT += maskedCTypes[i] * vs[i] *(RP[i] - tradingPrices[i])
        self.BillCT = self.BillCT % pow(2,23)
    print("Encrypted bill is: ", self.BillCT)

  def getCorrectBills(self):
    DecKey = self.KAuth.getDecryptionKey()
    pTypeDecKey = self.KAuth.getPTypeDecryptionKey()
    print("from supplier:", DecKey)
    cTypeDecKey = self.KAuth.getCTypeDecryptionKey()
    Bill = (self.BillCT - DecKey - pTypeDecKey) % pow(2,23)
#      Bill = (Bill- cTypeDecKey) % pow(2,23)
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

# Inner-product functional encryption keysSetup
KAuth = KeyAuthority()
KAuth.ipeSetup()
supplier = Supplier()
# For testing
Bill =0
for i in range(0,3): #10 periods
    Bill += meterReadings[i] * tradingPrices[i]
    if (supplier.checkDeviations(i)>0) * (vs[i]>0):
        Bill += vs[i] * (FiT[i] - tradingPrices[i]) * prosumerEncoding[i]
    elif (supplier.checkDeviations(i)<0) * (vs[i]<0):
        Bill += vs[i] * (RP[i] - tradingPrices[i]) * consumerEncoding[i]
Bill = Bill % pow(2,23)
print("Bill computation in clear (for testing) is: ", Bill/1000)
Bill=0
for i in range(0,3): #10 periods
    Bill += meterReadings[i] * tradingPrices[i]
Bill = Bill % pow(2,23)
print("Bill computation without deviations in clear (for testing) is: ", Bill/1000)
supplier.ComputeBill() #Encrypted
supplier.getCorrectBills()
supplier.aggregIVCommitments()
