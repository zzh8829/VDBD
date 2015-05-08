from ctypes import *



f = open("../samples/helloworld/helloworld.exe", "rb")
data = f.read()

print(len(data))
print(data)