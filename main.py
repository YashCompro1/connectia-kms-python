from flask import Flask, request, jsonify, Response
import json
import base64
from cryptography.hazmat.primitives.serialization import  load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import time
import requests
import os

CONNECTIA_KEY = os.environ.get("CONNECTIA_KEY", "default_secret_key")

app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    common()
    return jsonify({'message': 'working'})

@app.route('/connectia', methods=['POST'])
def connectia():

    common()

    # Get token from request
    # Cambridge will be submitting a form with a base64 encoded token that contains payload and signature
    token = request.form.get('token')

    # Decode the base64 encoded token.
    decoded_data = base64.b64decode(token)

    # Get Public key from env vars
    # Public key will be generated and provided by cambridge
    # Public key will be base64 encoded
    publicKey = 'LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQXoyMys1YklCT2J1cUZDL25pRlpUbnIyMFRaS0YwYWVKcnNGdEd3QkwzSjB5Tys0YnVMWkgKQ2E5aXNMYmV6KzRUT1pSV2VwaGVsYXMrVFM1SU0wMWVGanFBQ3FtZ1VraFBWSzlGallVN0k5aGlvdG9PdGN0RwpQZDVnOUZIL1YxT1MyNkhCci9Bd3pHTit4TDZTUy9VbmNCR1FIempuZHJEU3FtNFRrQXNNZU0wWnIvWmh1cmdYCjlMYmZoYkZRRytYQVprcUpzbU44V2JUZjM4dVE4TVgxWmVQZk1xeVdaczFhTXlkUzNvNXRUMTNvWGpVcG03S2oKd3dLbHY3ZlVRNG5yeDFrd015U1ZPdXZlbENKL1VVK1BGK2gyKzRBTFhvWXRsZDNrN1gyNUtmVElMMlFSdC9aYgpGWWYwMUtOTXFXZ2diRnhCU3ZPczc0bFlTaXZsYUhCbFl3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K'
    
    # Decode the public key
    public_key_pem = base64.b64decode(publicKey)

    # Load public key in the pem format 
    public_key = load_pem_public_key(public_key_pem)

    # Get the payload and signature from decoded token
    data = json.loads(decoded_data)
    payload = data["payload"]
    signature = data["signature"]

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
        if time.time()*1000>expiry :
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
        return jsonify({"error": "token invalid"}), 401


def common():
    print ('-'*40)
    headers = dict(request.headers)

    print ('origin', request.origin, request.headers.get('origin'))
    
    # Get query parameters (GET requests)
    query_params = request.args.to_dict()

    # Get form data (POST requests)
    form_data = request.form.to_dict()

    # Get JSON data (POST requests with application/json)
    json_data = request.get_json(silent=True)

    # Get raw body (if needed)
    raw_body = request.data.decode("utf-8")

    # Get request method and remote address
    method = request.method
    ip_address = request.remote_addr

    # Print everything in the console
    print(f"Headers: {headers}")
    print(f"Query Params: {query_params}")
    print(f"Form Data: {form_data}")
    print(f"JSON Data: {json_data}")
    print(f"Raw Body: {raw_body}")
    print(f"Method: {method}")
    print(f"IP Address: {ip_address}")
    print ('-'*40)


if __name__ == '__main__':
    app.run()


        