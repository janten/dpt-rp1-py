#!/usr/local/bin/python3
import requests
import httpsig
import urllib3
from urllib.parse import quote_plus
import os
import base64
from dptrp1.pyDH import DiffieHellman
from pbkdf2 import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Hash.HMAC import HMAC
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import uuid
import functools
#from diffiehellman.diffiehellman import DiffieHellman

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DigitalPaper():
    def __init__(self, addr = None):

        if addr is None:
            self.addr = "digitalpaper.local"
        else:
            self.addr = addr

        self.cookies = {}

    @property
    def base_url(self):
        if ":" in self.addr and self.addr[0] != "[":
            port = ""
        else:
            port = ":8443"

        return "https://" + self.addr + port

    ### Authentication

    def register(self):
        """
        Gets authentication info from a DPT-RP1.  You can call this BEFORE
        DigitalPaper.authenticate()

        Returns (ca, priv_key, client_id):
            - ca: a PEM-encoded X.509 server certificate, issued by the CA
                  on the device
            - priv_key: a PEM-encoded 2048-bit RSA private key
            - client_id: the client id
        """

        reg_url = "http://{addr}:8080".format(addr = self.addr)
        register_pin_url = '{base_url}/register/pin'.format(base_url = reg_url)
        register_hash_url = '{base_url}/register/hash'.format(base_url = reg_url)
        register_ca_url = '{base_url}/register/ca'.format(base_url = reg_url)
        register_url = '{base_url}/register'.format(base_url = reg_url)
        register_cleanup_url = '{base_url}/register/cleanup'.format(base_url = reg_url)

        print("Cleaning up...")
        r = requests.put(register_cleanup_url, verify = False)
        print(r)

        print("Requesting PIN...")
        r = requests.post(register_pin_url, verify = False)
        print(r)
        m1 = r.json()

        n1 = base64.b64decode(m1['a'])
        mac = base64.b64decode(m1['b'])
        yb = base64.b64decode(m1['c'])
        yb = int.from_bytes(yb, 'big')
        n2 = os.urandom(16)  # random nonce

        dh = DiffieHellman()
        ya = dh.gen_public_key()
        ya = b'\x00' + ya.to_bytes(256, 'big')

        zz = dh.gen_shared_key(yb)
        zz = zz.to_bytes(256, 'big')
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


        print("Encoding nonce...")
        r = requests.post(register_hash_url, json = m2)
        print(r)

        m3 = r.json()

        if(base64.b64decode(m3['a']) != n2):
            print("Nonce N2 doesn't match")
            return

        eHash = base64.b64decode(m3['b'])
        m3hmac = base64.b64decode(m3['e'])
        hmac = HMAC(authKey, digestmod = SHA256)
        hmac.update(n1 + n2 + mac + ya + m2hmac + n2 + eHash)
        if m3hmac != hmac.digest():
            print("M3 HMAC doesn't match")
            return

        pin = input("Please enter the PIN shown on the DPT-RP1: ")

        hmac = HMAC(authKey, digestmod = SHA256)
        hmac.update(pin.encode())
        psk = hmac.digest()

        rs = os.urandom(16)  # random nonce
        hmac = HMAC(authKey, digestmod = SHA256)
        hmac.update(rs + psk + yb + ya)
        rHash = hmac.digest()

        wrappedRs = wrap(rs, authKey, keyWrapKey)

        hmac = HMAC(authKey, digestmod = SHA256)
        hmac.update(n2 + eHash + m3hmac + n1 + rHash + wrappedRs)
        m4hmac = hmac.digest()

        m4 = dict(a = base64.b64encode(n1).decode('utf-8'),
                  b = base64.b64encode(rHash).decode('utf-8'),
                  d = base64.b64encode(wrappedRs).decode('utf-8'),
                  e = base64.b64encode(m4hmac).decode('utf-8'))

        print("Getting certificate from device CA...")
        r = requests.post(register_ca_url, json = m4)
        print(r)

        m5 = r.json()

        if(base64.b64decode(m5['a']) != n2):
            print("Nonce N2 doesn't match")
            return

        wrappedEsCert = base64.b64decode(m5['d'])
        m5hmac = base64.b64decode(m5['e'])

        hmac = HMAC(authKey, digestmod = SHA256)
        hmac.update(n1 + rHash + wrappedRs + m4hmac + n2 + wrappedEsCert)
        if hmac.digest() != m5hmac:
            print("HMAC doesn't match!")
            return

        esCert = unwrap(wrappedEsCert, authKey, keyWrapKey)
        es = esCert[:16]
        cert = esCert[16:]

        hmac = HMAC(authKey, digestmod = SHA256)
        hmac.update(es + psk + yb + ya)
        if hmac.digest() != eHash:
            print("eHash does not match!")
            return

        #print("Certificate: ")
        #print(cert)

        print("Generating RSA2048 keys")
        new_key = RSA.generate(2048, e=65537)

        #with open("key.pem", 'wb') as f:
        #    f.write(new_key.exportKey("PEM"))

        keyPubC = new_key.publickey().exportKey("PEM")

        selfDeviceId = str(uuid.uuid4())
        print("Device ID: " + selfDeviceId)
        selfDeviceId = selfDeviceId.encode()

        #with open("client_id.txt", 'wb') as f:
        #    f.write(selfDeviceId)

        wrappedDIDKPUBC = wrap(selfDeviceId + keyPubC, authKey, keyWrapKey)

        hmac = HMAC(authKey, digestmod = SHA256)
        hmac.update(n2 + wrappedEsCert + m5hmac + n1 + wrappedDIDKPUBC)
        m6hmac = hmac.digest()

        m6 = dict(a = base64.b64encode(n1).decode('utf-8'),
                  d = base64.b64encode(wrappedDIDKPUBC).decode('utf-8'),
                  e = base64.b64encode(m6hmac).decode('utf-8'))

        print("Registering device...")
        r = requests.post(register_url, json = m6, verify = False)
        print(r)

        print("Cleaning up...")
        r = requests.put(register_cleanup_url, verify = False)
        print(r)

        return (cert.decode('utf-8'),
                new_key.exportKey("PEM").decode('utf-8'),
                selfDeviceId.decode('utf-8'))

    def authenticate(self, client_id, key):
        sig_maker = httpsig.Signer(secret=key, algorithm='rsa-sha256')
        nonce = self._get_nonce(client_id)
        signed_nonce = sig_maker.sign(nonce)
        url = "{base_url}/auth".format(base_url = self.base_url)
        data = {
            "client_id": client_id,
            "nonce_signed": signed_nonce
        }
        r = requests.put(url, json=data, verify=False)
        _, credentials = r.headers["Set-Cookie"].split("; ")[0].split("=")
        self.cookies["Credentials"] = credentials

    ### File management

    def list_documents(self):
        data = self._get_endpoint('/documents2').json()
        return data['entry_list']

    def list_all(self):
        data = self._get_endpoint('/documents2?entry_type=all').json()
        return data['entry_list']

    def list_objects_in_folder(self, remote_path):
        remote_id = self._resolve_object_by_path(remote_path).json()['entry_id']
        response = self._get_endpoint("/folders/{remote_id}/entries2".format(remote_id = remote_id))
        return response.json()['entry_list']

    def traverse_folder(self, remote_path):
        def traverse(obj):
            if obj['entry_type'] == 'document':
                return [obj]
            else:
                children = self \
                  ._get_endpoint("/folders/{remote_id}/entries2".format(remote_id = obj['entry_id'])) \
                  .json()['entry_list']
                return [obj] + functools.reduce(lambda acc, c: traverse(c) + acc, children[::-1], [])
        return traverse(self._resolve_object_by_path(remote_path).json())

    def list_document_info(self, remote_path):
        remote_info = self._resolve_object_by_path(remote_path).json()
        return remote_info

    def download(self, remote_path):
        remote_id = self._resolve_object_by_path(remote_path).json()['entry_id']

        url = "{base_url}/documents/{remote_id}/file".format(
                base_url = self.base_url,
                remote_id = remote_id)
        response = requests.get(url, verify=False, cookies=self.cookies)
        return response.content

    def delete_document(self, remote_path):
        remote_id = self._resolve_object_by_path(remote_path).json()['entry_id']
        url = "/documents/{remote_id}".format(remote_id = remote_id)
        self._delete_endpoint(url)

    def upload(self, fh, remote_path):
        filename = os.path.basename(remote_path)
        remote_directory = os.path.dirname(remote_path)

        directory_id = self._resolve_object_by_path(remote_directory).json()['entry_id']
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
            'file': (quote_plus(filename), fh, 'rb')
        }
        self._put_endpoint(doc_url, files=files)

    def new_folder(self, remote_path):
        folder_name = os.path.basename(remote_path)
        remote_directory = os.path.dirname(remote_path)

        directory_id = self._resolve_object_by_path(remote_directory).json()['entry_id']
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

    ### Configuration

    def get_timeout(self):
        data = self._get_endpoint('/system/configs/timeout_to_standby').json()
        return(data['value'])

    def set_timeout(self, value):
        data = self._put_endpoint('/system/configs/timeout_to_standby', data={'value': value})

    def get_date_format(self):
        data = self._get_endpoint('/system/configs/date_format').json()
        return(data['value'])

    def set_date_format(self, value):
        data = self._put_endpoint('/system/configs/date_format', data={'value': value})

    def get_time_format(self):
        data = self._get_endpoint('/system/configs/time_format').json()
        return(data['value'])

    def set_time_format(self, value):
        data = self._put_endpoint('/system/configs/time_format', data={'value': value})

    def get_timezone(self):
        data = self._get_endpoint('/system/configs/timezone').json()
        return(data['value'])

    def set_timezone(self, value):
        data = self._put_endpoint('/system/configs/timezone', data={'value': value})

    def get_owner(self):
        data = self._get_endpoint('/system/configs/owner').json()
        return(data['value'])

    def set_owner(self, value):
        data = self._put_endpoint('/system/configs/owner', data={'value': value})

    ### System info

    def get_storage(self):
        data = self._get_endpoint('/system/status/storage').json()
        return(data)

    def get_firmware_version(self):
        data = self._get_endpoint('/system/status/firmware_version').json()
        return(data['value'])

    def get_mac_address(self):
        data = self._get_endpoint('/system/status/mac_address').json()
        return(data['value'])

    def get_battery(self):
        data = self._get_endpoint('/system/status/battery').json()
        return(data)

    def get_info(self):
        data = self._get_endpoint('/register/information').json()
        return(data)

    ### Etc

    def take_screenshot(self):
        url = "{base_url}/system/controls/screen_shot" \
                .format(base_url = self.base_url)
        r = requests.get(url, verify=False, cookies=self.cookies)
        return r.content


    ## Update firmware

    def update_firmware(self, fwfh):
        filename = 'FwUpdater.pkg'
        fw_url = "/system/controls/update_firmware/file"\
            .format(base_url=self.base_url)
        files = {
            'file': (quote_plus(filename), fwfh, 'rb')
        }
        # TODO: add file transferring feedback
        self._put_endpoint(fw_url, files=files)

        precheck_msg = self._get_endpoint(
            '/system/controls/update_firmware/precheck').json()
        battery_check = precheck_msg.get('battery', 'not ok')
        uploaded_image_check = precheck_msg.get('image_file', 'not ok')

        print('* battery check: {}'.format(battery_check))
        print('* uploaded image check: {}'.format(uploaded_image_check))

        for key in precheck_msg:
            if not (key == 'battery' or key == 'image_file'):
                print('! Find unrecognized key-value pair: ({0}, {1})'
                      .format(key, precheck_msg[key]))

        if battery_check == 'ok' and uploaded_image_check == 'ok':
            # TODO: add check if status is 204
            self._put_endpoint('/system/controls/update_firmware')


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

    def _get_nonce(self, client_id):
        url = "{base_url}/auth/nonce/{client_id}" \
                .format(base_url = self.base_url,
                        client_id = client_id)

        r = requests.get(url, verify=False)
        return r.json()["nonce"]

    def _resolve_object_by_path(self, path):
        enc_path = quote_plus(path)
        url = "/resolve/entry/path/{enc_path}".format(enc_path = enc_path)
        return self._get_endpoint(url)


# crypto helpers
def wrap(data, authKey, keyWrapKey):
    hmac = HMAC(authKey, digestmod = SHA256)
    hmac.update(data)
    kwa = hmac.digest()[:8]
    iv = os.urandom(16)
    cipher = AES.new(keyWrapKey, AES.MODE_CBC, iv)

    wrapped = cipher.encrypt(pad(data + kwa))
    wrapped = wrapped + iv
    return wrapped

# from https://gist.github.com/adoc/8550490
def pad(bytestring, k=16):
    """
    Pad an input bytestring according to PKCS#7

    """
    l = len(bytestring)
    val = k - (l % k)
    return bytestring + bytearray([val] * val)

def unwrap(data, authKey, keyWrapKey):
    iv = data[-16:]
    cipher = AES.new(keyWrapKey, AES.MODE_CBC, iv)
    unwrapped = cipher.decrypt(data[:-16])
    unwrapped = unpad(unwrapped)

    kwa = unwrapped[-8:]
    unwrapped = unwrapped[:-8]

    hmac = HMAC(authKey, digestmod = SHA256)
    hmac.update(unwrapped)
    local_kwa = hmac.digest()[:8]

    if(kwa != local_kwa):
        print("Unwrapped kwa does not match")

    return unwrapped

def unpad(bytestring, k=16):
    """
    Remove the PKCS#7 padding from a text bytestring.
    """

    val = bytestring[-1]
    if val > k:
        raise ValueError('Input is not padded or padding is corrupt')
    l = len(bytestring) - val
    return bytestring[:l]
