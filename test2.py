from flask import Flask, request, jsonify, Response
import json
import base64
from cryptography.hazmat.primitives.serialization import  load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import time
import requests

token = "eyJwYXlsb2FkIjp7InVzZXJJZCI6ImQ2NWM5YTRlZmEzNzRlNDI4OGI5ZTg3ODgwYzY5OTM5IiwicHJvZHVjdElkIjoiVEdTSElOSU5HTElHSFRTMiIsImV4cGlyeSI6MTc0MDM3ODg1NDU5Nn0sInNpZ25hdHVyZSI6IkNPZjBucHFKY1hiZFV1VXhrWXhHeWlxcnVpNGpuOWQ1OThndXJlSGZLN3k0VHZHNVNHVzlkeWlHWjBFUFlRRGlVT1ZwbDRVemROUG9yeHAwTmlQeUh6ZmI5ak04b0F3R0szY3R1Rm5Wa3BGOVRTWWppK3c2cXlpYVZVQnl4ZnZqVDJPUmhQYXhCSkd1QXBKYlNSV292aHNWbUFHbzlnMFc5aHJWOGk5MkZtZmwvS1R0MmFjQ1dYVGRmR0Rqc1g5Q05BUCsvUDRTVXFOYUVnUWxKRDhrWnRHTUVJSkYrRmVVL1ZnbkVxdDVtTlVBMlpteFlmZ3hoQklnTjg0eVpDNjZwTDYvdjZsWkt6UlFtM3VpS0xyZVRMSXJlcVo0NlNnSmRQblBWekRvdTAyVkQyU1c5STB5ZWczRDNaVFpYcEN4cURFUjI0U2JZa1dkSVdmcmMvSjRhQT09In0="

decoded_data = base64.b64decode(token)

publicKey = 'LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQXoyMys1YklCT2J1cUZDL25pRlpUbnIyMFRaS0YwYWVKcnNGdEd3QkwzSjB5Tys0YnVMWkgKQ2E5aXNMYmV6KzRUT1pSV2VwaGVsYXMrVFM1SU0wMWVGanFBQ3FtZ1VraFBWSzlGallVN0k5aGlvdG9PdGN0RwpQZDVnOUZIL1YxT1MyNkhCci9Bd3pHTit4TDZTUy9VbmNCR1FIempuZHJEU3FtNFRrQXNNZU0wWnIvWmh1cmdYCjlMYmZoYkZRRytYQVprcUpzbU44V2JUZjM4dVE4TVgxWmVQZk1xeVdaczFhTXlkUzNvNXRUMTNvWGpVcG03S2oKd3dLbHY3ZlVRNG5yeDFrd015U1ZPdXZlbENKL1VVK1BGK2gyKzRBTFhvWXRsZDNrN1gyNUtmVElMMlFSdC9aYgpGWWYwMUtOTXFXZ2diRnhCU3ZPczc0bFlTaXZsYUhCbFl3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K'

# Decode the public key
public_key_pem = base64.b64decode(publicKey)

# Load public key in the pem format 
public_key = load_pem_public_key(public_key_pem)

print ('public_key', public_key)
print('------------------------')

# Get the payload and signature from decoded token
data = json.loads(decoded_data)
payload = data["payload"]
signature = data["signature"]

print ('payload', payload)
print('------------------------')

print ('signature', signature)
print('------------------------')

print ('base64.b64decode(signature)', base64.b64decode(signature))
print('------------------------')

# Convert the payload json to string to verify it
message = json.dumps(payload, separators=(',', ':')).encode()
try:

    # Verify using the public key if the payload and signature match
    isVerified = public_key.verify(
        base64.b64decode(signature),
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature verification successful!")
except Exception as e:
    print("Signature verification failed!", e)

    
print ('isVerified', isVerified)
print('------------------------')    