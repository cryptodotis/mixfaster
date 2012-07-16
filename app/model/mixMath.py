import struct, time

def mixTimestampFromBinary(binstr):
    """
    Timestamp: A timestamp is introduced with the byte sequence (48, 48, 48,
    48, 0). The following two bytes specify the number of days since Jan 1,
    1970, given in little-endian byte order. 
    """
    ba = binaryToByteArray(binstr)
    if len(ba) != 7 or ba[0] != 48 or ba[1] != 48 or ba[2] != 48 or ba[3] != 48 or ba[4] != 0:
        raise Exception("Invalid string given to mixTimestampFromBinary " + str(ba))
    days = littleEndian(ba[5:7])
    result = time.ctime(days * (24 * 60 * 60))
    return result
def hexpad(str, len):
    return hex(str)[2:-1].zfill(len)
def binaryToByteArray(str):
    a = struct.unpack("B" * len(str), str)
    return list(a)
def byteArrayToBinary(arr):
    str=""
    for b in arr:
        str += chr(b)
    return str
def arrayLeftPad(arr, desiredLen, char):
    while len(arr) < desiredLen:
        arr.insert(0, char)
    return arr
def bigEndian(param):
    if isinstance(param, list) or isinstance(param, tuple):
        #Convert an array of bytes to an int
        x = 0
        for b in param:
            x = (x << 8) + b
        return x
    elif isinstance(param, long) or isinstance(param, int):
        #Convert a long to a big-endian array of bytes
        result = []
        while param:
            result.append(param & 0xFF)
            param >>= 8
        result.reverse()
        return result
    else:
        raise Exception("Called bigEndian with an unknown type:", type(param))
        
def littleEndian(arr):
    arr.reverse()
    return bigEndian(arr)
def modinv(u, v):
	""" Computes the inverse of u, mod v:  u^-1 mod v """
	u1 = 1
	u3 = u
	v1 = 0
	v3 = v
	iter = 1;
	while v3 != 0:
		q = u3 / v3
		t3 = u3 % v3
		t1 = u1 + q * v1
		
		u1 = v1
		v1 = t1
		u3 = v3
		v3 = t3
		
		iter = -iter
		
	if u3 != 1:
		raise Exception("Error getting modular inverse")
		return 0
		
	if iter < 0:
		return v - u1
	else:
		return u1
def modpow(base, exponent, modulus):
	result = 1
	while exponent > 0:
		if exponent & 1 == 1:
			result = (result * base) % modulus
		exponent = exponent >> 1
		base = (base * base) % modulus
	return result

def splitToNPerLine(data, wrapat=40):
    output = ""
    while len(data) > wrapat:
        output += data[:wrapat] + "\n"
        data = data[wrapat:]
    output += data
    return output
