import scrypt
import os
import base64

salt = os.urandom(64)
hashed_pass = scrypt.encrypt('secret',salt,maxtime=0.5)
hash2 = scrypt.encrypt('x',salt,maxtime=0.5)

x = base64.b64encode(hashed_pass).decode('utf-8')
y = base64.b64encode(hash2).decode('utf-8')

print("TYPE: ")
print(type(x))

z = x.encode('utf-8')
z = base64.b64decode(z)
decoded = scrypt.decrypt(z,salt,maxtime=0.5)
print(decoded)

if x == y:
	print ('OK')
else:
	print('NOT OK')

'''
print(type(hashed_pass))
decoded = scrypt.decrypt(hashed_pass,salt,maxtime=0.5)	
print("Decoded :")
print(decoded)
print (hashed_pass)
print ("BASE 64 : ")
a = base64.b64encode(hashed_pass)
print("a : ")
print (a)

b = a.decode('utf-8')

print("b: ")
print (b)

c = b.encode('utf-8')
print("c: ")
print (c)

print("Decoded 2:")
decoded = scrypt.decrypt(c,salt,maxtime=0.5)   
print(decoded)
'''