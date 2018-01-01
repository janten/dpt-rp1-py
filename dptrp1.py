#!/usr/local/bin/python3
import requests
import httpsig
import urllib3
from urllib.parse import quote_plus
import os
import base64
from pyDH import DiffieHellman
from pbkdf2 import PBKDF2
from Crypto.Hash import SHA256 
from Crypto.Hash.HMAC import HMAC
#from diffiehellman.diffiehellman import DiffieHellman


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DigitalPaper():
    def __init__(self, client_id, key, addr = None):
        self.reg_addr = addr
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

    def register(self):
        reg_url = "http://{addr}:8080".format(addr = self.reg_addr)
        print(reg_url)
        register_pin_url = '{base_url}/register/pin'.format(base_url = reg_url)
        print(register_pin_url)
        register_hash_url = '{base_url}/register/hash'.format(base_url = reg_url)
        register_ca_url = '{base_url}/register/ca'.format(base_url = reg_url)
        register_cleanup_url = '{base_url}/register/cleanup'.format(base_url = reg_url)

        r = requests.post(register_pin_url, verify = False)
        m1 = r.json()

        n1 = base64.b64decode(m1['a'])
        mac = base64.b64decode(m1['b'])
        yb = base64.b64decode(m1['c'])
        yb = int.from_bytes(yb, 'big')
        #n2 = os.urandom(16)  # random nonce
        n2 = base64.b64decode('G3/TBqzaWD9cZen8rqJngQ==')

        dh = DiffieHellman()
        #print(dir(dh))
        #dh._DiffieHellman__a = int.from_bytes(base64.b64decode('f0thp5CROJvF2excmobSTJruG1eFyYjefiMWYrSklItgUbqAo1CFk6RI1knMewQUtDgKzR8CJAft/jDE+6izQI0sS1FDjCPG3JHbXBUiRnNhSKz2+Eh43vDGKju74b6IcfNiuQT5Sq1rthluMknmx6JwnED5JvhkOL3yS7ol0dscsfUQPcZjHLLr7CVjXGXerKF95vtjfDZzV69/LGYCZ3zxN6UsIpmLYOAec9Ls1G+OfcCut4u4mqmNZpjoBSD9AfIlnvhqjaOpcfkbL6IPdRSRxvjay0Mm4vh5Ok2A7AmupFXEXd7dA/W+3P0S0hmNVM90tNPUogSB7FpAgHeqiQ=='), 'big')
        ya = dh.gen_public_key()
        ya = b'\x00' + ya.to_bytes(256, 'big')

        zz = dh.gen_shared_key(yb)
        yb = yb.to_bytes(256, 'big')

        derivedKey = PBKDF2(passphrase = zz, 
                            salt = n1 + mac + n2, 
                            iterations = 10000,
                            digestmodule = SHA256).read(48)
        authKey = derivedKey[:32]
        keyWrapKey = derivedKey[32:]

        hmac = HMAC(authKey, digestmod = SHA256)
        hmac.update(n1 + mac + yb + n1 + n2 + mac + ya)
        m2hmac = hmac.digest()

        m2 = dict(a = base64.b64encode(n1).decode('utf-8'),
                  b = base64.b64encode(n2).decode('utf-8'),
                  c = base64.b64encode(mac).decode('utf-8'),
                  d = base64.b64encode(ya).decode('utf-8'),
                  e = base64.b64encode(m2hmac).decode('utf-8'))

        print(m2)

        r = requests.post(register_hash_url, json = m2)
        print(r)
        print(r.json())


        print("Cleaning up...")
        r = requests.put(register_cleanup_url, verify = False)
        print(r)

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





