#!/usr/bin/env python
"""
NEM hardware wallet preprocessing script.
"""
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct
import base64

KEY_HEADER = "ecdsa-sha2-nistp256"
CURVE_NAME = "nistp256"
KEY_HEADER_ED25519 = "ssh-ed25519"

def parse_bip32_path(path):
	if len(path) == 0:
		return ""
	result = ""
	elements = path.split('/')
	for pathElement in elements:
		element = pathElement.split('\'')
		if len(element) == 1:
			result = result + struct.pack(">I", int(element[0]))			
		else:
			result = result + struct.pack(">I", 0x80000000 | int(element[0]))
	return result

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to retrieve")
parser.add_argument("--ed25519", help="Use Ed25519 curve", action='store_true')
args = parser.parse_args()

if args.path == None:
	args.path = "44'/535348'/0'/0/0"

if args.ed25519:
	p2 = "02"
	keyHeader = KEY_HEADER_ED25519
else:
	p2 = "01" 
	keyHeader = KEY_HEADER

donglePath = parse_bip32_path(args.path)
apdu = "800200" + p2 
apdu = apdu.decode('hex') + chr(len(donglePath) + 1) + chr(len(donglePath) / 4) + donglePath

dongle = getDongle(True)
result = dongle.exchange(bytes(apdu))
key = str(result[1:])
blob = struct.pack(">I", len(KEY_HEADER)) + keyHeader 
if args.ed25519:
	keyX = bytearray(key[0:32])
	keyY = bytearray(key[32:][::-1])
	if ((keyX[31] & 1)<>0):
		keyY[31] |= 0x80
	key = str(keyY)
else:
	blob += struct.pack(">I", len(CURVE_NAME)) + CURVE_NAME
	
blob += struct.pack(">I", len(key)) + key
print keyHeader + " " + base64.b64encode(blob)

