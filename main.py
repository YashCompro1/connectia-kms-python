from flask import Flask, request, jsonify, Response
import json
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import time
import requests
import os
from typing import TypedDict

class Payload(TypedDict):
    userId: str
    productId: str
    env: str
    expiry: int


class Data(TypedDict):
    payload: Payload
    signature: str


# Temp key to launch TG using current implementation. This may not be required in final implementation.
# This is the secret key given to Cambridge from Connectia.
CONNECTIA_KEY = os.environ.get("CONNECTIA_KEY", "default_secret_key")

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'working'})

# Create a map for env variables and correspoding public keys
key_maps = {
    'thor': 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUFybkRtd3lVaUZJcWQvSGhjTzl0KwpoVlI4RVlNOXFVamE4VzNRdGlKeHlQUkJaNjhtWmtDNDU4TGQzZTY3QS9DR1dSeStOb1g5WHBZN2FmOXg5ZVA2CnYzWjlCai9uaVZzTHkrdTQ0UGo1WWVBVkZwUHU2RnVuekZBZy9tSDJaalZCMFRUbDRoVmVScTNUQU04ZTloalgKb2o2N3hHSzNqVEM4Z3BNMzdXZXN0Q0o2cmhoVFk0anB2VytJalZkVjBhTWNLdXdUR0VJOWVxUnlzdS90djhzVwptZFRLVTVqZmswS3JBd1hMQjB5YnhNM2N5bGJNMDkzMEdHMmZaQisxZEdndkU0Y0xyNkorZm5YSnpoVUVlRkdxCko2REQzT25WbVBjZVBPQVJXVkNmTzN2SWpLc0JjUVhiUjdRWUVGRlR2UGg0cDcrZXVvcXVjWjBIbFpoYWllT0gKWHgrWTNwSERVcDZ0NmIza0ZVWG1EQ3NWa1lMaUdIMWttcERVRkJOSThub05JU3R6MHNVOXRLbmx6TmFFYjNsVAp6ZmtzNVo5OVQwc2xURk44UXdReHp4L2k1cWVPSll1U0Mwdjdud1QxL2xPN3VPM2paRTQyQTdGQTJwV1JqWDlKCmV1MjVvL2xpa2lGK3FocEI2N0JTT1J2bnFDRW9hanNZUitaZ3lwR0dQQm1ZOFpkcHlTbzhmc1JEbUhIdDJYdzAKVld6R0gyRDhDa1U5UWttQk02bDI1S0pPdHBveWRmV3hUNVhabzFJWk9URVd6SlFYU3BTTEUzekFwZ1FVSzRxQworcWdIY0ZCb0IrMmY1RDNyTnBJQUxCbXRIbEJVUFZwUi9QdndNN2FLQmZEeXVROEVDenVjdndmTmltL2VrMjNmCkpZVzZmc2xZdnNpaFF3WDI3QnQ3bEUwQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==',
    'qa': 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUFybkRtd3lVaUZJcWQvSGhjTzl0KwpoVlI4RVlNOXFVamE4VzNRdGlKeHlQUkJaNjhtWmtDNDU4TGQzZTY3QS9DR1dSeStOb1g5WHBZN2FmOXg5ZVA2CnYzWjlCai9uaVZzTHkrdTQ0UGo1WWVBVkZwUHU2RnVuekZBZy9tSDJaalZCMFRUbDRoVmVScTNUQU04ZTloalgKb2o2N3hHSzNqVEM4Z3BNMzdXZXN0Q0o2cmhoVFk0anB2VytJalZkVjBhTWNLdXdUR0VJOWVxUnlzdS90djhzVwptZFRLVTVqZmswS3JBd1hMQjB5YnhNM2N5bGJNMDkzMEdHMmZaQisxZEdndkU0Y0xyNkorZm5YSnpoVUVlRkdxCko2REQzT25WbVBjZVBPQVJXVkNmTzN2SWpLc0JjUVhiUjdRWUVGRlR2UGg0cDcrZXVvcXVjWjBIbFpoYWllT0gKWHgrWTNwSERVcDZ0NmIza0ZVWG1EQ3NWa1lMaUdIMWttcERVRkJOSThub05JU3R6MHNVOXRLbmx6TmFFYjNsVAp6ZmtzNVo5OVQwc2xURk44UXdReHp4L2k1cWVPSll1U0Mwdjdud1QxL2xPN3VPM2paRTQyQTdGQTJwV1JqWDlKCmV1MjVvL2xpa2lGK3FocEI2N0JTT1J2bnFDRW9hanNZUitaZ3lwR0dQQm1ZOFpkcHlTbzhmc1JEbUhIdDJYdzAKVld6R0gyRDhDa1U5UWttQk02bDI1S0pPdHBveWRmV3hUNVhabzFJWk9URVd6SlFYU3BTTEUzekFwZ1FVSzRxQworcWdIY0ZCb0IrMmY1RDNyTnBJQUxCbXRIbEJVUFZwUi9QdndNN2FLQmZEeXVROEVDenVjdndmTmltL2VrMjNmCkpZVzZmc2xZdnNpaFF3WDI3QnQ3bEUwQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==',
    'rel': 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUFybkRtd3lVaUZJcWQvSGhjTzl0KwpoVlI4RVlNOXFVamE4VzNRdGlKeHlQUkJaNjhtWmtDNDU4TGQzZTY3QS9DR1dSeStOb1g5WHBZN2FmOXg5ZVA2CnYzWjlCai9uaVZzTHkrdTQ0UGo1WWVBVkZwUHU2RnVuekZBZy9tSDJaalZCMFRUbDRoVmVScTNUQU04ZTloalgKb2o2N3hHSzNqVEM4Z3BNMzdXZXN0Q0o2cmhoVFk0anB2VytJalZkVjBhTWNLdXdUR0VJOWVxUnlzdS90djhzVwptZFRLVTVqZmswS3JBd1hMQjB5YnhNM2N5bGJNMDkzMEdHMmZaQisxZEdndkU0Y0xyNkorZm5YSnpoVUVlRkdxCko2REQzT25WbVBjZVBPQVJXVkNmTzN2SWpLc0JjUVhiUjdRWUVGRlR2UGg0cDcrZXVvcXVjWjBIbFpoYWllT0gKWHgrWTNwSERVcDZ0NmIza0ZVWG1EQ3NWa1lMaUdIMWttcERVRkJOSThub05JU3R6MHNVOXRLbmx6TmFFYjNsVAp6ZmtzNVo5OVQwc2xURk44UXdReHp4L2k1cWVPSll1U0Mwdjdud1QxL2xPN3VPM2paRTQyQTdGQTJwV1JqWDlKCmV1MjVvL2xpa2lGK3FocEI2N0JTT1J2bnFDRW9hanNZUitaZ3lwR0dQQm1ZOFpkcHlTbzhmc1JEbUhIdDJYdzAKVld6R0gyRDhDa1U5UWttQk02bDI1S0pPdHBveWRmV3hUNVhabzFJWk9URVd6SlFYU3BTTEUzekFwZ1FVSzRxQworcWdIY0ZCb0IrMmY1RDNyTnBJQUxCbXRIbEJVUFZwUi9QdndNN2FLQmZEeXVROEVDenVjdndmTmltL2VrMjNmCkpZVzZmc2xZdnNpaFF3WDI3QnQ3bEUwQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==',
    'prod1': 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUFybkRtd3lVaUZJcWQvSGhjTzl0KwpoVlI4RVlNOXFVamE4VzNRdGlKeHlQUkJaNjhtWmtDNDU4TGQzZTY3QS9DR1dSeStOb1g5WHBZN2FmOXg5ZVA2CnYzWjlCai9uaVZzTHkrdTQ0UGo1WWVBVkZwUHU2RnVuekZBZy9tSDJaalZCMFRUbDRoVmVScTNUQU04ZTloalgKb2o2N3hHSzNqVEM4Z3BNMzdXZXN0Q0o2cmhoVFk0anB2VytJalZkVjBhTWNLdXdUR0VJOWVxUnlzdS90djhzVwptZFRLVTVqZmswS3JBd1hMQjB5YnhNM2N5bGJNMDkzMEdHMmZaQisxZEdndkU0Y0xyNkorZm5YSnpoVUVlRkdxCko2REQzT25WbVBjZVBPQVJXVkNmTzN2SWpLc0JjUVhiUjdRWUVGRlR2UGg0cDcrZXVvcXVjWjBIbFpoYWllT0gKWHgrWTNwSERVcDZ0NmIza0ZVWG1EQ3NWa1lMaUdIMWttcERVRkJOSThub05JU3R6MHNVOXRLbmx6TmFFYjNsVAp6ZmtzNVo5OVQwc2xURk44UXdReHp4L2k1cWVPSll1U0Mwdjdud1QxL2xPN3VPM2paRTQyQTdGQTJwV1JqWDlKCmV1MjVvL2xpa2lGK3FocEI2N0JTT1J2bnFDRW9hanNZUitaZ3lwR0dQQm1ZOFpkcHlTbzhmc1JEbUhIdDJYdzAKVld6R0gyRDhDa1U5UWttQk02bDI1S0pPdHBveWRmV3hUNVhabzFJWk9URVd6SlFYU3BTTEUzekFwZ1FVSzRxQworcWdIY0ZCb0IrMmY1RDNyTnBJQUxCbXRIbEJVUFZwUi9QdndNN2FLQmZEeXVROEVDenVjdndmTmltL2VrMjNmCkpZVzZmc2xZdnNpaFF3WDI3QnQ3bEUwQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==',
    'alpha': 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUFybkRtd3lVaUZJcWQvSGhjTzl0KwpoVlI4RVlNOXFVamE4VzNRdGlKeHlQUkJaNjhtWmtDNDU4TGQzZTY3QS9DR1dSeStOb1g5WHBZN2FmOXg5ZVA2CnYzWjlCai9uaVZzTHkrdTQ0UGo1WWVBVkZwUHU2RnVuekZBZy9tSDJaalZCMFRUbDRoVmVScTNUQU04ZTloalgKb2o2N3hHSzNqVEM4Z3BNMzdXZXN0Q0o2cmhoVFk0anB2VytJalZkVjBhTWNLdXdUR0VJOWVxUnlzdS90djhzVwptZFRLVTVqZmswS3JBd1hMQjB5YnhNM2N5bGJNMDkzMEdHMmZaQisxZEdndkU0Y0xyNkorZm5YSnpoVUVlRkdxCko2REQzT25WbVBjZVBPQVJXVkNmTzN2SWpLc0JjUVhiUjdRWUVGRlR2UGg0cDcrZXVvcXVjWjBIbFpoYWllT0gKWHgrWTNwSERVcDZ0NmIza0ZVWG1EQ3NWa1lMaUdIMWttcERVRkJOSThub05JU3R6MHNVOXRLbmx6TmFFYjNsVAp6ZmtzNVo5OVQwc2xURk44UXdReHp4L2k1cWVPSll1U0Mwdjdud1QxL2xPN3VPM2paRTQyQTdGQTJwV1JqWDlKCmV1MjVvL2xpa2lGK3FocEI2N0JTT1J2bnFDRW9hanNZUitaZ3lwR0dQQm1ZOFpkcHlTbzhmc1JEbUhIdDJYdzAKVld6R0gyRDhDa1U5UWttQk02bDI1S0pPdHBveWRmV3hUNVhabzFJWk9URVd6SlFYU3BTTEUzekFwZ1FVSzRxQworcWdIY0ZCb0IrMmY1RDNyTnBJQUxCbXRIbEJVUFZwUi9QdndNN2FLQmZEeXVROEVDenVjdndmTmltL2VrMjNmCkpZVzZmc2xZdnNpaFF3WDI3QnQ3bEUwQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==',
    'hotfix': 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUFybkRtd3lVaUZJcWQvSGhjTzl0KwpoVlI4RVlNOXFVamE4VzNRdGlKeHlQUkJaNjhtWmtDNDU4TGQzZTY3QS9DR1dSeStOb1g5WHBZN2FmOXg5ZVA2CnYzWjlCai9uaVZzTHkrdTQ0UGo1WWVBVkZwUHU2RnVuekZBZy9tSDJaalZCMFRUbDRoVmVScTNUQU04ZTloalgKb2o2N3hHSzNqVEM4Z3BNMzdXZXN0Q0o2cmhoVFk0anB2VytJalZkVjBhTWNLdXdUR0VJOWVxUnlzdS90djhzVwptZFRLVTVqZmswS3JBd1hMQjB5YnhNM2N5bGJNMDkzMEdHMmZaQisxZEdndkU0Y0xyNkorZm5YSnpoVUVlRkdxCko2REQzT25WbVBjZVBPQVJXVkNmTzN2SWpLc0JjUVhiUjdRWUVGRlR2UGg0cDcrZXVvcXVjWjBIbFpoYWllT0gKWHgrWTNwSERVcDZ0NmIza0ZVWG1EQ3NWa1lMaUdIMWttcERVRkJOSThub05JU3R6MHNVOXRLbmx6TmFFYjNsVAp6ZmtzNVo5OVQwc2xURk44UXdReHp4L2k1cWVPSll1U0Mwdjdud1QxL2xPN3VPM2paRTQyQTdGQTJwV1JqWDlKCmV1MjVvL2xpa2lGK3FocEI2N0JTT1J2bnFDRW9hanNZUitaZ3lwR0dQQm1ZOFpkcHlTbzhmc1JEbUhIdDJYdzAKVld6R0gyRDhDa1U5UWttQk02bDI1S0pPdHBveWRmV3hUNVhabzFJWk9URVd6SlFYU3BTTEUzekFwZ1FVSzRxQworcWdIY0ZCb0IrMmY1RDNyTnBJQUxCbXRIbEJVUFZwUi9QdndNN2FLQmZEeXVROEVDenVjdndmTmltL2VrMjNmCkpZVzZmc2xZdnNpaFF3WDI3QnQ3bEUwQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ=='
}

@app.route('/connectia', methods=['POST'])
def connectia():

    # Get token from request
    # Cambridge will be submitting a form with a base64 encoded token that contains payload and signature
    token: str = request.form.get('token')

    # Decode the base64 encoded token.
    decoded_data = base64.b64decode(token)

    # Get the payload and signature from decoded token
    data: Data = json.loads(decoded_data)
    payload = data["payload"]
    signature = data["signature"]

    # Get Public key from env vars
    # Public key will be generated and provided by cambridge
    # Public key will be base64 encoded
    publicKey = key_maps.get(payload.get('env'))

    # Decode the public key
    public_key_pem = base64.b64decode(publicKey)

    # Load public key in the pem format
    public_key = load_pem_public_key(public_key_pem)

    # Convert the payload json to string to verify it
    message = json.dumps(payload, separators=(',', ':')).encode()

    try:
        # Verify using the public key if the payload and signature match
        public_key.verify(
            base64.b64decode(signature),
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Get the payload data
        expiry = payload['expiry']
        userId = payload['userId']
        productId = payload['productId']

        # expiry from cambridge is recieved in ms, whilst time.time() returns timestamp in seconds.
        # Use correct conversion and logic to return error incase expiry is passed.
        if time.time()*1000 > expiry:
            return jsonify({"error": "time expired"}), 401

        # If everything is correct, then launch connectia test generator
        url = "https://c1.conectia.es/login.php"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = request.form.to_dict()  # Forward form data from client

        data.update({
            "user": userId,
            "product": productId,
            "key": CONNECTIA_KEY
        })

        response = requests.post(url, headers=headers, data=data)
        return Response(response.text, status=response.status_code, content_type=response.headers.get("Content-Type", "text/plain"))

    except Exception as e:
        print(e)
        return jsonify({"error": "token invalid"}), 401

if __name__ == '__main__':
    app.run()
