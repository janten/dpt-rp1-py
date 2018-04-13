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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # @UndefinedVariable

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

    def register(self, callback = None):
        """
        Gets authentication info from a DPT-RP1.  You can call this BEFORE
        DigitalPaper.authenticate()

        Returns:
            ca: a PEM-encoded X.509 server certificate, issued by the CA
                  on the device
            priv_key: a PEM-encoded 2048-bit RSA private key
            client_id: the client id
        """

        reg_url = "http://{addr}:8080".format(addr = self.addr)
        register_pin_url = '{base_url}/register/pin'.format(base_url = reg_url)
        register_hash_url = '{base_url}/register/hash'.format(base_url = reg_url)
        register_ca_url = '{base_url}/register/ca'.format(base_url = reg_url)
        register_url = '{base_url}/register'.format(base_url = reg_url)
        register_cleanup_url = '{base_url}/register/cleanup'.format(base_url = reg_url)
        try:
            print("Requesting PIN...")
            r = requests.post(register_pin_url, verify = False)
            r.raise_for_status()
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
            r.raise_for_status()
    
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

            if callback is not None:
                pin = callback()
            else:
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
            r.raise_for_status()
    
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
    
            print("Generating RSA2048 keys")
            new_key = RSA.generate(2048, e=65537)
    
            keyPubC = new_key.publickey().exportKey("PEM")
    
            selfDeviceId = str(uuid.uuid4())
            print("Device ID: " + selfDeviceId)
            selfDeviceId = selfDeviceId.encode()
    
            wrappedDIDKPUBC = wrap(selfDeviceId + keyPubC, authKey, keyWrapKey)
    
            hmac = HMAC(authKey, digestmod = SHA256)
            hmac.update(n2 + wrappedEsCert + m5hmac + n1 + wrappedDIDKPUBC)
            m6hmac = hmac.digest()
    
            m6 = dict(a = base64.b64encode(n1).decode('utf-8'),
                      d = base64.b64encode(wrappedDIDKPUBC).decode('utf-8'),
                      e = base64.b64encode(m6hmac).decode('utf-8'))
    
            print("Registering device...")
            r = requests.post(register_url, json = m6, verify = False)
            r.raise_for_status()

            return (cert.decode('utf-8'), 
                    new_key.exportKey("PEM").decode('utf-8'), 
                    selfDeviceId.decode('utf-8'))

        except Exception as e:
            raise e


        finally:
            print("Cleaning up...")
            r = requests.put(register_cleanup_url, verify = False)
            r.raise_for_status()

    def authenticate(self, client_id, key):
        """
        Set up an authenticated session with a device.
        
        Args:
            client_id (string): The client UUID
            key (string): PEM-formated RSA private key
        """
        
        sig_maker = httpsig.Signer(secret=key, algorithm='rsa-sha256')
        nonce = self._get_nonce(client_id)
        signed_nonce = sig_maker._sign(nonce)
        url = "{base_url}/auth".format(base_url = self.base_url)
        data = {
            "client_id": client_id,
            "nonce_signed": signed_nonce
        }
        r = requests.put(url, json=data, verify=False)
        r.raise_for_status()
        _, credentials = r.headers["Set-Cookie"].split("; ")[0].split("=")
        self.cookies["Credentials"] = credentials
        
    def device_information(self):
        """
        Gets the device information (serial#, hardware revision, etc.)
        
        Returns:
            dict: The document info.
        """
        
        data = self._get_endpoint('/register/information').json()
        return data
        
    ### File management

    def list_documents(self):
        """
        Gets a list of all of the documents (files and folders) on the device.
        
        Returns:
            list of dict : Information for all the documents.
        """
        
        params = {
                'entry_type' : 'all'
                }
        data = self._get_endpoint('/documents2', params = params).json()
        return data['entry_list']
    
    def get_document_info(self, document_id):
        """
        Gets the document info for a single document.
        
        Args:
            document_id (int): The document id
            
        Returns:
            dict: A dictionary with the document info
        """
        
        url = '/documents2/{document_id}'.format(document_id = document_id)
        data = self._get_endpoint(url).json()
        return data
         
    
    def get_document_id(self, remote_path):
        """
        Gets the document id for a given path (file or folder).
        
        Args:
            remote_path (string): The document path
            
        Returns:
            string: the document id
        """
        
        encoded_remote_path = quote_plus(remote_path)
        url = "/resolve/entry/path/{enc_path}".format(enc_path = encoded_remote_path)
        remote_entry = self._get_endpoint(url).json()
        return remote_entry['entry_id']
        

    def download(self, document_id):
        """
        Downloads a document from the device.
        
        Args:
            document_id (string) : The document ID
            
        Returns:
            bytes: the document.
        """


        url = "/documents/{document_id}/file".format(document_id = document_id)
        response = self._get_endpoint(url)
        return response.content

    def upload(self, parent_folder_id, file_name, fh):
        """
        Uploads a document to the device.
        
        Args:
            remote_folder_id (str): The id of a folder on the remote device
            file_name (str): The name of the new file
            fh (file handle): An open file handle to the document to upload
            
        Returns:
            string: The remote id of the new document
        """

        info = {
            "file_name": file_name,
            "parent_folder_id": parent_folder_id,
            "document_source": ""
        }
        r = self._post_endpoint("/documents2", data=info)
        doc = r.json()
        document_id = doc["document_id"]
        document_url = "/documents/{document_id}/file".format(document_id = document_id)

        files = {
            'file': (file_name, fh, 'rb')
        }
        self._put_endpoint(document_url, files=files)
        
        return document_id

    def delete(self, document_id):
        """
        Deletes a document
        
        Args:
            document_id (string): The document id
        """

        url = "/documents/{document_id}".format(document_id = document_id)
        return self._delete_endpoint(url).json()

    def new_folder(self, parent_folder_id, folder_name):
        """
        Make a new folder
        
        Args:
            parent_folder_id (string): The id of the parent folder
            folder_name (string): The name of the new folder
            
        Returns:
            string: The id of the new folder
        """

        info = {
            "folder_name": folder_name,
            "parent_folder_id": parent_folder_id
        }

        r = self._post_endpoint("/folders2", data=info)
        doc = r.json()
        return doc['folder_id']
    
    def delete_folder(self, folder_id):
        """
        Deletes a folder.
        
        WARNING: The folder does not have to be empty!
        
        Args:
            folder_id (string): The ID of the folder to delete
        """
        
        url = "/folders/{folder_id}".format(folder_id = folder_id)
        return self._delete_endpoint(url)

    def list_templates(self):
        """
        List the note templates on the device.
        
        Returns:
            list of string: the names of the templates
        """
        
        data = self._get_endpoint('/viewer/configs/note_templates').json()
        return data['template_list']
    
    def get_template_id(self, template_name):
        """
        Get a template's id
        
        Args:
            template_name (string): the name of a template to get
            
        Returns:
            string: The template id
        
        Raises:
            StopIteration: If the template can't be found
        """
        
        # there doesn't appear to be a 'resolve' endpoint for templates.  so get all and iterate
        templates = self.list_templates()
        return next(t['note_template_id'] for t in templates if t['template_name'] == template_name)


    def upload_template(self, fh, template_name):
        """
        Upload a new template
        
        Args:
            fh (file handle): a file handle to the open template file
            template_name (string): the new template's name
            
        Returns:
            string: the new template's id
        """
            
        params = {
                "template_name" : template_name
                }

        data = self._post_endpoint('/viewer/configs/note_templates', data = params)
        template_id = data.json()['note_template_id']

        url = "/viewer/configs/note_templates/{template_id}/file" \
                .format(template_id = template_id)

        files = {
                'file' : (template_name, fh, 'rb')
                }
        self._put_endpoint(url, files = files).json()
        
        return template_id

    def delete_template(self, template_id):
        """
        Delete a template
        
        Args:
            template_id (string): The ID of the template to delete
        """


        url = '/viewer/configs/note_templates/{template_id}' \
                .format(template_id = template_id)
        return self._delete_endpoint(url).json()
                
    def get_configuration(self):
        url = '/system/configs'
        return self._get_endpoint(url).json()
    
    def set_timeformat(self, fmt):
        """
        Sets the clock's time format
        
        Args:
            fmt (string): Must be "12hour" or "24hour"
        """
        
        if fmt != '12hour' and fmt != '24hour':
            raise RuntimeError('format must be "12hour" or "24hour"')
        
        url = '/system/configs/time_format'
        info = {'value' : fmt}
        
        self._put_endpoint(url, data = info)
    
    def update_datetime(self):
        """
        Sets the device date and time to the host date and time
        """
        
        # value = YYYY-MM-DDTHH:mm
        from datetime import datetime
        url = '/system/configs/datetime'
        info = {'value' : datetime.now().isoformat()[0:19] + 'Z'}
        
        self._put_endpoint(url, data = info)

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
        r = self._get_endpoint('/system/controls/screen_shot') 
        return r.content

#     def status(self):
#         r = self._get_endpoint('/extensions/configs') 
#         return r.json()
# 
#     def test_mode(self):
#         r = self._put_endpoint('/testmode/launch') 
#         return r.json()
# 
# 

    ### Utility

    def _get_endpoint(self, endpoint="", params = None):
        url = "{base_url}{endpoint}" \
                .format(base_url = self.base_url,
                        endpoint = endpoint)
        r = requests.get(url, params=params, verify=False, cookies=self.cookies)
        r.raise_for_status()
        return r

    def _put_endpoint(self, endpoint="", data={}, files=None):
        url = "{base_url}{endpoint}" \
                .format(base_url = self.base_url,
                        endpoint = endpoint)
        r = requests.put(url, verify=False, cookies=self.cookies, json=data, files=files)
        r.raise_for_status()
        return r

    def _post_endpoint(self, endpoint="", data={}):
        url = "{base_url}{endpoint}" \
                .format(base_url = self.base_url,
                        endpoint = endpoint)
        r = requests.post(url, verify=False, cookies=self.cookies, json=data)
        r.raise_for_status()
        return r

    def _delete_endpoint(self, endpoint="", data={}):
        url = "{base_url}{endpoint}" \
                .format(base_url = self.base_url,
                        endpoint = endpoint)
        r = requests.delete(url, verify=False, cookies=self.cookies, json=data)
        r.raise_for_status()
        return r

    def _get_nonce(self, client_id):
        url = "{base_url}/auth/nonce/{client_id}" \
                .format(base_url = self.base_url,
                        client_id = client_id)

        r = requests.get(url, verify=False)
        r.raise_for_status()
        return r.json()["nonce"]


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
