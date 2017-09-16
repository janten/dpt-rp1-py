#!/usr/local/bin/python3
import requests
import httpsig
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DigitalPaper(object):
    """docstring for DigitalPaper"""
    def __init__(self, ip_address, client_id):
        super(DigitalPaper, self).__init__()
        self.client_id = client_id
        self.ip_address = ip_address
        self.cookies = {}
        
    @property
    def base_url(self):
        return f"https://{self.ip_address}:8443"    
    
    def get_nonce(self):
        url = f"{self.base_url}/auth/nonce/{self.client_id}"
        r = requests.get(url, verify=False)
        return r.json()["nonce"]

    def authenticate(self, path_to_private_key='certs/key.pem'):
        secret = open(path_to_private_key, 'rb').read()
        sig_maker = httpsig.Signer(secret=secret, algorithm='rsa-sha256')
        nonce = self.get_nonce()
        signed_nonce = sig_maker._sign(nonce)
        url = f"{self.base_url}/auth"
        data = {
            "client_id": self.client_id,
            "nonce_signed": signed_nonce
        }
        r = requests.put(url, json=data, verify=False)
        print(r.headers["Set-Cookie"])
        _, credentials = r.headers["Set-Cookie"].split("; ")[0].split("=")
        self.cookies["Credentials"] = credentials

    def get_endpoint(self, endpoint=""):
        url = f"{self.base_url}{endpoint}"
        return requests.get(url, verify=False, cookies=self.cookies).json()
        
dp = DigitalPaper(ip_address = "10.0.1.17", client_id="5d8cdd57-d496-459d-bd06-4774223e6707")
dp.authenticate()
print(dp.get_endpoint("/api_version"))
print(dp.get_endpoint("/system/status"))
print(dp.get_endpoint("/folders/root/entries"))
