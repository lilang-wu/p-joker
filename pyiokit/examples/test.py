from iokitconnection import IOKitConnection
import numpy as np
import ctypes
iokit_instance = IOKitConnection("IOUSBInterface")
connection = iokit_instance.fuzz_IOServiceOpen("IOUSBInterface", 0)
print connection



"""
arr = np.array([1,2,3],dtype = np.float32)

#a= ctypes.pointer(ctypes.c_uint32(1))
a = 0

iokit_instance.add_arr_1(arr,1,3, a)

print arr
print a

"""

#input_scalar = np.array([0xe38340d99444cc1,0x49,0xfffffffffffffff, 0x0, 0x8, 0x41, 0xc9585027d463be01],dtype = np.uint64)
input_scalar = np.array([0xc1,0x49,0xf, 0x0, 0x8, 0x41, 0x01],dtype = np.uint64)

print input_scalar



ret = iokit_instance.fuzz_IOConnectCallMethod(0x11, input_scalar, 7, 0, 0);

output = iokit_instance.getfuzz_output()
#outputStruct = iokit_instance.getfuzz_outputStruct()
print output
#print outputStruct

