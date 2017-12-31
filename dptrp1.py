#!/usr/local/bin/python3
import requests
import httpsig
import urllib3
from urllib.parse import quote_plus
import os
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DigitalPaper():
    def __init__(self, client_id, key, addr = None):
        self.client_id = client_id
        self.key = key
        if addr is None:
            self.addr = "https://digitalpaper.local:8443"
        else:
            if ":" in addr:
                port = ""
            else:
                port = ":8443"
            self.addr = "https://" + addr + port
        self.cookies = {}

    @property
    def base_url(self):
        return self.addr

    ### Authentication

    def authenticate(self, path_to_private_key='privs/key.pem'):
        sig_maker = httpsig.Signer(secret=self.key, algorithm='rsa-sha256')
        nonce = self._get_nonce()
        signed_nonce = sig_maker._sign(nonce)
        url = "{base_url}/auth".format(base_url = self.base_url)
        data = {
            "client_id": self.client_id,
            "nonce_signed": signed_nonce
        }
        r = requests.put(url, json=data, verify=False)
        _, credentials = r.headers["Set-Cookie"].split("; ")[0].split("=")
        self.cookies["Credentials"] = credentials


    ### File management

    def list_documents(self):
        data = self._get_endpoint('/documents2').json()
        return data['entry_list']

    def download(self, remote_path):
        encoded_remote_path = quote_plus(remote_path)
        url = "/resolve/entry/path/{enc_path}".format(enc_path = encoded_remote_path)
        remote_entry = self._get_endpoint(url).json()
        remote_id = remote_entry['entry_id']

        url = "{base_url}/documents/{remote_id}/file".format(
                base_url = self.base_url,
                remote_id = remote_id)
        response = requests.get(url, verify=False, cookies=self.cookies)
        return response.content

    def upload(self, fh, remote_path):
        filename = os.path.basename(remote_path)
        remote_directory = os.path.dirname(remote_path)
        encoded_directory = quote_plus(remote_directory)
        url = "/resolve/entry/path/{enc_dir}".format(enc_dir = encoded_directory)
        directory_entry = self._get_endpoint(url).json()

        directory_id = directory_entry["entry_id"]
        info = {
            "file_name": filename,
            "parent_folder_id": directory_id,
            "document_source": ""
        }
        r = self._post_endpoint("/documents2", data=info)
        doc = r.json()
        doc_id = doc["document_id"]
        doc_url = "/documents/{doc_id}/file".format(doc_id = doc_id)

        files = {
            'file': (filename, fh, 'rb')
        }
        self._put_endpoint(doc_url, files=files)

    def new_folder(self, remote_path):
        folder_name = os.path.basename(remote_path)
        remote_directory = os.path.dirname(remote_path)
        encoded_directory = quote_plus(remote_directory)
        url = "/resolve/entry/path/{enc_dir}".format(enc_dir = encoded_directory)
        directory_entry = self._get_endpoint(url).json()

        directory_id = directory_entry["entry_id"]
        info = {
            "folder_name": folder_name,
            "parent_folder_id": directory_id
        }

        r = self._post_endpoint("/folders2", data=info)

    ### Wifi 
    def wifi_list(self):
        data = self._get_endpoint('/system/configs/wifi_accesspoints').json()
        for ap in data['aplist']:
            ap['ssid'] = base64.b64decode(ap['ssid']).decode('utf-8', errors='replace')
        return data['aplist']

    def wifi_scan(self):
        data = self._post_endpoint('/system/controls/wifi_accesspoints/scan').json()
        for ap in data['aplist']:
            ap['ssid'] = base64.b64decode(ap['ssid']).decode('utf-8', errors='replace')
        return data['aplist']

    def configure_wifi(self, ssid, security, passwd, dhcp, static_address,
                       gateway, network_mask, dns1, dns2, proxy):
                       
        #    cnf = {
        #        "ssid": base64.b64encode(b'YYY').decode('utf-8'),
        #        "security": "nonsec", # psk, nonsec, XXX
        #        # "passwd": "XXX",
        #        "dhcp": "false",
        #        "static_address": "172.20.123.4",
        #        "gateway": "172.20.123.160",
        #        "network_mask": "24",
        #        "dns1": "172.20.123.160",
        #        "dns2": "",
        #        "proxy": "false"
        #    }

        #print(kwargs['ssid'])
        conf = dict(ssid = base64.b64encode(ssid.encode()).decode('utf-8'),
                    security = security,
                    passwd = passwd,
                    dhcp = dhcp,
                    static_address = static_address,
                    gateway = gateway,
                    network_mask = network_mask,
                    dns1 = dns1,
                    dns2 = dns2,
                    proxy = proxy)

        return self._put_endpoint('/system/controls/wifi_accesspoints/register', data=conf)

    def delete_wifi(self, ssid, security):
        url = "/system/configs/wifi_accesspoints/{ssid}/{security}" \
                .format(ssid = ssid,
                        security = security)
                #.format(ssid = base64.b64encode(ssid.encode()).decode('utf-8'),
        return self._delete_endpoint(url)

    def wifi_enabled(self):
        return self._get_endpoint('/system/configs/wifi').json()

    def enable_wifi(self):
        return self._put_endpoint('/system/configs/wifi', data = {'value' : 'on'})

    def disable_wifi(self):
        return self._put_endpoint('/system/configs/wifi', data = {'value' : 'off'})

    ### Etc

    def take_screenshot(self):
        url = "{base_url}/system/controls/screen_shot" \
                .format(base_url = self.base_url)
        r = requests.get(url, verify=False, cookies=self.cookies)
        return r.content

    ### Utility

    def _get_endpoint(self, endpoint=""):
        url = "{base_url}{endpoint}" \
                .format(base_url = self.base_url,
                        endpoint = endpoint)
        return requests.get(url, verify=False, cookies=self.cookies)

    def _put_endpoint(self, endpoint="", data={}, files=None):
        url = "{base_url}{endpoint}" \
                .format(base_url = self.base_url,
                        endpoint = endpoint)
        return requests.put(url, verify=False, cookies=self.cookies, json=data, files=files)

    def _post_endpoint(self, endpoint="", data={}):
        url = "{base_url}{endpoint}" \
                .format(base_url = self.base_url,
                        endpoint = endpoint)
        return requests.post(url, verify=False, cookies=self.cookies, json=data)

    def _delete_endpoint(self, endpoint="", data={}):
        url = "{base_url}{endpoint}" \
                .format(base_url = self.base_url,
                        endpoint = endpoint)
        return requests.delete(url, verify=False, cookies=self.cookies, json=data)

    def _get_nonce(self):
        url = "{base_url}/auth/nonce/{client_id}" \
                .format(base_url = self.base_url,
                        client_id = self.client_id)

        r = requests.get(url, verify=False)
        return r.json()["nonce"]





