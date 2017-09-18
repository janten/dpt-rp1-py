#!/usr/local/bin/python3
import requests
import httpsig
import urllib3
from urllib.parse import quote_plus
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DigitalPaper(object):
    """docstring for DigitalPaper"""
    def __init__(self, client_id):
        super(DigitalPaper, self).__init__()
        self.client_id = client_id
        self.cookies = {}
        
    @property
    def base_url(self):
        return f"https://digitalpaper.local:8443"    
    
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
        _, credentials = r.headers["Set-Cookie"].split("; ")[0].split("=")
        self.cookies["Credentials"] = credentials

    def get_endpoint(self, endpoint=""):
        url = f"{self.base_url}{endpoint}"
        return requests.get(url, verify=False, cookies=self.cookies)

    def put_endpoint(self, endpoint="", data={}, files=None):
        url = f"{self.base_url}{endpoint}"
        return requests.put(url, verify=False, cookies=self.cookies, json=data, files=files)

    def post_endpoint(self, endpoint="", data={}):
        url = f"{self.base_url}{endpoint}"
        return requests.post(url, verify=False, cookies=self.cookies, json=data)
    
    def upload_document(self, local_path, remote_path):
        filename = os.path.basename(remote_path)
        remote_directory = os.path.dirname(remote_path)
        encoded_directory = quote_plus(remote_directory)
        directory_entry = dp.get_endpoint(f"/resolve/entry/{encoded_directory}").json()
        directory_id = directory_entry["entry_id"]
        info = {
            "file_name": filename,
            "parent_folder_id": directory_id,
            "document_source": ""
        }
        r = dp.post_endpoint("/documents", data=info)
        doc = r.json()
        doc_id = doc["document_id"]
        with open(local_path, 'rb') as local_file:
            files = {
                'file': ("altair.pdf", local_file, 'rb')
            }
            self.put_endpoint(f"/documents/{doc_id}/file", files=files)
        
    def take_screenshot(self):
        url = f"{self.base_url}/system/controls/screen_shot"
        r = requests.get(url, verify=False, cookies=self.cookies)
        with open("screenshot.png", 'wb') as f:
            f.write(r.content)
        
if __name__ == "__main__":
    dp = DigitalPaper(client_id="5d8cdd57-d496-459d-bd06-4774223e6707")
    dp.authenticate()
    
    endpoints = [
        '/documents',
        '/documents/{}',
        '/documents/{}/file',
        '/documents/{}/copy',

        '/folders',
        '/folders/{}',
        '/folders/{}/entries',

        '/viewer/configs/note_templates',
        '/viewer/configs/note_templates/{}',
        '/viewer/configs/note_templates/{}/file',

        '/viewer/status/preset_marks',
        '/viewer/controls/open',

        '/system/configs',
        '/system/configs/timezone',
        '/system/configs/datetime',
        '/system/configs/date_format',
        '/system/configs/time_format',
        '/system/configs/initialized_flag',
        '/system/configs/timeout_to_standby',
        '/system/configs/owner',

        '/system/status/storage',
        '/system/status/firmware_version',
        '/system/status/mac_address',

        '/system/controls/screen_shot',
        '/system/controls/update_firmware/precheck',
        '/system/controls/update_firmware',
        '/system/controls/update_firmware/file',

        '/system/configs/wifi',
        '/system/configs/wifi_accesspoints',
        '/system/configs/wifi_accesspoints/{}/{}',
        '/system/configs/certificates',
        '/system/configs/certificates/ca',
        '/system/configs/certificates/client',

        '/system/status/wifi_state',
        '/system/status/wps_state',

        '/system/controls/wifi_accesspoints/scan',
        '/system/controls/wifi_accesspoints/register',
        '/system/controls/wps_start/button',
        '/system/controls/wps_start/pin',
        '/system/controls/wps_cancel',

        '/register/serial_number',
        '/register/information',
        '/register/pin',
        '/register/hash',
        '/register/ca',
        '/register',
        '/register/cleanup',

        '/auth/nonce/{}',
        '/auth',

        '/extensions/status',
        '/extensions/status/{}',
        '/extensions/configs',
        '/extensions/configs/{}',

        '/testmode/auth/nonce',
        '/testmode/auth',
        '/testmode/launch',
        '/testmode/recovery_mode',
        '/testmode/assets/{}',

        '/resolve/entry/{}',
        '/api_version',
        '/ping'
    ]

