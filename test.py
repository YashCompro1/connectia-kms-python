import json
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Private key (Base64-decoded)
private_key_pem = base64.b64decode("""LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBejIzKzViSUJPYnVxRkMvbmlGWlRucjIwVFpLRjBhZUpyc0Z0R3dCTDNKMHlPKzRiCnVMWkhDYTlpc0xiZXorNFRPWlJXZXBoZWxhcytUUzVJTTAxZUZqcUFDcW1nVWtoUFZLOUZqWVU3STloaW90b08KdGN0R1BkNWc5RkgvVjFPUzI2SEJyL0F3ekdOK3hMNlNTL1VuY0JHUUh6am5kckRTcW00VGtBc01lTTBaci9aaAp1cmdYOUxiZmhiRlFHK1hBWmtxSnNtTjhXYlRmMzh1UThNWDFaZVBmTXF5V1pzMWFNeWRTM281dFQxM29YalVwCm03S2p3d0tsdjdmVVE0bnJ4MWt3TXlTVk91dmVsQ0ovVVUrUEYraDIrNEFMWG9ZdGxkM2s3WDI1S2ZUSUwyUVIKdC9aYkZZZjAxS05NcVdnZ2JGeEJTdk9zNzRsWVNpdmxhSEJsWXdJREFRQUJBb0lCQUZiTlgrcDlGL2d4NlJWegppbjlLS01uMzl0aXpaUjU3N3FqYnRxMmk3UndRQ0RKK0RNbTZOWFgvRjl4OVdqWkhHWEp4K2RKcHFzTVZHd2d2ClF2VjgvYzl0Z2FGMHBHdHFhUkEySEhRQmVlTWhMUDJiSkthOHZ0TXJHUVdFdnNhcmFYeFJiMzBSbFVvaXBLenUKVnNoRWVkRnkrQTJvd1d1d3lTZWEwc0xuYkx1cnp0R0cwVGJXOUlZWjNSbjA0bWk2UCtDSUpWMWlrdkpJMTAvNwp4bUI0UVNFUGI0K0hLdUorWDVhUEJ0NEgrNE55K2xaUTlvRW5NZm9aVVJ5dmJCdmxSdjA2MUJnQjgydUc0NkwwCjNmODgxQVZzNzlCanUxZDErd2R6dFNyUlIyYmF1TUpQa0p0QTBVUzh3VW95UTdZNFRBMElORWovK0RoTjVweHMKY3NOU0t3a0NnWUVBL0xVNVBHSEtkN3hwT3Bnb2xySGw4L0RlaUtXVUxXdE8xT20zSTVwdFB5bERKT1dSRkl1VQpKdGpRZklCUHBCckJyTmgwMkxUalZSbzhmOUwzM1pvRDVOdTdjZEtyQTJkV1hJVVZRcVhTNDM3TFNaTnB2ejI1CmVSOHU4YXAyQ2ZLaTNXTzAxQ2kvOUhZTjc1cHJGWG9kUVFKakdTTENORHNkK0RUNTU3OGlyNThDZ1lFQTBpSEYKSHJrWnVtdm1yRWFkSXJGV1J4SHN1bjZibkVtNGNWRHphRTIrVjBFK1FIVXFIdzJsY1htVjVjbk1vUEVLejhMKwpEbkJEaWpPZEJLV3BpenBZY0N3SkhhOGkvejNhM3gzSlNDdEhVaWxTNVR6M09hVFgySWM4YXp2Z0pvdzNjRXhOCllMbHdJN2VSb3ZhTVc2amRsTThsNTFyTElCNEo2Z0hPanJqdUk3MENnWUVBc2ZuQUViS2RzYTVVUGh3am1kNDQKb1pFbWFQNlVXVmlWOElXWm9jMkUyMUxvSXZnN01Va01VaitvdGNaNFVJODNqOC95bXh6cWJtbEg2bzVlV3dlNQpibGtDcnFzOEhlMk5lU09SVVpzUDU0REpFMHhxMFhGYlN0NlhaVVEwVmRVNHRzc2Q4NzJ2VXpCQnFGb015TmR6Cit2RC9jaGgweGV4TXN4NDhVdWJlT3VrQ2dZQTNJRWJmVlg0TGF3MDcrdFowYUlPUzUzL3NPUlRIdm90VnB3QUUKU0FqOFNSQjB4b2dEVjRna3Fkb0tTNU9VVVVnZDB6RGxSc3hoTUVNc0dlM05xY1BUd2FtdWtPaWtmMnl4QmRadApTWFZQZDZuWW05TGIyNFFJdVFtL3RCaU01RklTOHVHRjA0QTR6b3ExYnVySmpSWjhXSS9BRHhDazMxeUllR3JoCkJHRHRIUUtCZ0hIWWNNcWIwb3FmS2dWZTI5RWoxc0w0NjQ3M1doS0tCa1gyUVN6VmVGN2I4bkF2M0hPWm4vZ3cKandlc0VENEd1RWtmQU0yRjh4elBCbjJCUDkvYVo5eWFwdlFGZVlHeE9LbTRETUJSb3lHNG1GOHkwMWg5RTBxUwpqSW5BY3dFUjFrVGg4ZWV2T0FuQUF2YzdXRGdtMFNZT29waVB6TXV1RklOdlJKT2hjZ01PCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==""")

private_key = load_pem_private_key(private_key_pem, password=None)

payload = {
    "userId": "d65c9a4efa374e4288b9e87880c69939",
    "productId": "TGSHININGLIGHTS2",
    "expiry": 1740371646954
}

message = json.dumps(payload, separators=(', ', ': ')).encode()

signature = private_key.sign(
    message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# Encode signature in Base64
signature = base64.b64encode(signature).decode()

# Create token object
token = {"payload": payload, "signature": signature}
token = json.dumps(token)


# Encode token in Base64
token = base64.b64encode(token.encode()).decode()  # FIXED HERE

token1 = 'eyJwYXlsb2FkIjp7InVzZXJJZCI6ImQ2NWM5YTRlZmEzNzRlNDI4OGI5ZTg3ODgwYzY5OTM5IiwicHJvZHVjdElkIjoiVEdTSElOSU5HTElHSFRTMiIsImV4cGlyeSI6MTc0MDM3MTY0Njk1NH0sInNpZ25hdHVyZSI6Ik1uYTVvU2hqSlZ6YW0yOE94QmxwMEZSWEhkUVE3ckhmU0w3LzlrRlV5elpBK2JPQlJqaTRyc3NvbnQ5blNCd3k4c1JJNWFWVElUejJPditUMWs4eEh3cERMN3lMYVhwdE80bXBMZUI3ck0zSGhGdHQ1TWFPZWVJUFRjM0hOblpBNTNzeDloeEJabVBRYnZScTJ5K0JGVUo3MXpMZzNCSW0yS21YdHBtWXc0S2x5NFpXMlFOdFFWRHkzTVVsalhrUWNXMlU4MDR4N0FMdy9FdWJOcTlIZjdPQmtNbGtZVFUzRHNtWW9CVjlUOGxHR25tWUtCSW5BbSs3b1VSQzVlTUZsZGVpV0dTWnVXRWRvbForSFRWM2JKR2xqUnk1NWNVUDBaZ042Tm4vZkRySnhFM0srVG5iRFd2NzlIYWs4aERuVTE5QlNHUmQ4ZUY2OUFOeEZHOFZVUT09In0='


# Decode token from Base64
decoded_data = base64.b64decode(token).decode()
decoded_data1 = base64.b64decode(token1).decode()

print('------------')
print ('decoded_data', decoded_data)
print('------------')

print('------------')
print ('decoded_data1', decoded_data1)
print('------------')

# Parse JSON data
data = json.loads(decoded_data1)
payload = data["payload"]
signature = data["signature"]

# Public Key (Base64-encoded)
publicKey = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQXoyMys1YklCT2J1cUZDL25pRlpUbnIyMFRaS0YwYWVKcnNGdEd3QkwzSjB5Tys0YnVMWkgKQ2E5aXNMYmV6KzRUT1pSV2VwaGVsYXMrVFM1SU0wMWVGanFBQ3FtZ1VraFBWSzlGallVN0k5aGlvdG9PdGN0RwpQZDVnOUZIL1YxT1MyNkhCci9Bd3pHTit4TDZTUy9VbmNCR1FIempuZHJEU3FtNFRrQXNNZU0wWnIvWmh1cmdYCjlMYmZoYkZRRytYQVprcUpzbU44V2JUZjM4dVE4TVgxWmVQZk1xeVdaczFhTXlkUzNvNXRUMTNvWGpVcG03S2oKd3dLbHY3ZlVRNG5yeDFrd015U1ZPdXZlbENKL1VVK1BGK2gyKzRBTFhvWXRsZDNrN1gyNUtmVElMMlFSdC9aYgpGWWYwMUtOTXFXZ2diRnhCU3ZPczc0bFlTaXZsYUhCbFl3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K"  
# Your public key

# Decode Public Key from Base64
public_key_pem = base64.b64decode(publicKey)
public_key = load_pem_public_key(public_key_pem)

# Serialize payload with consistent formatting
message = json.dumps(payload, separators=(',', ':')).encode()

print ('message', message)

# Decode signature from Base64
decoded_signature = base64.b64decode(signature)  # FIXED HERE

# Verify Signature
try:
    public_key.verify(
        decoded_signature,
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