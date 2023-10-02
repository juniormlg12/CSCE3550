import http.server
import json
from http import HTTPStatus
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import jwt
import time


def generate_RSA_key_pair():
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
            )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

current_time = int(time.time())
keys = [{'kid': 'key1', 'private_key': generate_rsa_key_pair()[0], 'public_key': generate_rsa_key_pair()[1], 'exp': current_time + 3600},
        {'kid': 'key2', 'private_key': generate_rsa_key_pair()[0], 'public_key': generate_rsa_key_pair()[1], 'exp': current_time + 7200}]


class JWKSHandler(http.server.BaseHTTPRequestHandler):
    def POST(self):
        if self.path == "/jwks":
            jwks = {
                    "keys": [key for key in keys if key['exp'] > int(time.time())]
                }
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(jwks).encode())
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()
            self.wfile.write("Not Found".encode())


class AuthHandler(http.server.BaseHTTPRequestHandler):
    def POST(self):
        if self.path == "/auth":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            credentials = base64.b64decode(post_data.decode('utf-8').split(' ')[-1]).decode('utf-8').split(':')
            username, password = credentials[0], credentials[1]

            if username == 'user' and password == 'password':
                kid = 'key1' if 'expired=true' in self.path else 'key2'
                private_key = next((key['private_key'] for key in keys if key['kid'] == kid), None)
                if private_key:
                    token = jwt.encode({'sub':username, 'exp': keys[0]['exp'], 'iss': 'your_issuer'}, private_key, algorithm='RS256', headers={'kid': kid})
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-type", "application/jwt")
                    self.end_headers()
                    self.wfile.write(token.encode())
                else:
                    self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                    self.end_headers()
                    self.wfile.write("Internal Server Error".encode())
            else:
                self.send_response(HTTPStatus.UNAUTHORIZED)
                self.send_header("WWW-Authenticate", "Basic realm='Authentication required'")
                self.end_headers()
                self.wfile.write("Unauthorized".encode())
        else:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()
            self.wfile.write("Not Found".encode())


    def run_server():
        jwks_port = 8080
        auth_port = 8081


        jwks_server_address = ("", jwks_port)
        auth_server_address = ("", auth_port)

        jwks_httpd = http.server.HTTPServer(jwks_server_address, JWKSHandler)
        auth_httpd = http.server.HTTPServer(auth_server_address, AuthHandler)

        print(f"JWKS server is running on port {jwks_port}")
        print(f"Auth server is running on port {auth_port}")

        jwks_httpd.serve_forever()
        auth_httpd.serve_forever()
    if __name__ == "__main__":

        run_server()




