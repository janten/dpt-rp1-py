#!/usr/bin/env python3
import os
import sys
import uuid
import time
import base64
import httpsig
import urllib3
import requests
import functools
import unicodedata
import pickle
import shutil
from glob import glob
from urllib.parse import quote_plus
from dptrp1.pyDH import DiffieHellman
from datetime import datetime, timezone
from pbkdf2 import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Hash.HMAC import HMAC
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_default_auth_files():
    """Get the default path where the authentication files for connecting to DPT-RP1 are stored"""
    config_path = os.path.join(os.path.expanduser('~'), ".dpapp")
    os.makedirs(config_path, exist_ok=True)
    deviceid = os.path.join(config_path, "deviceid.dat")
    privatekey = os.path.join(config_path, "privatekey.dat")

    return deviceid, privatekey

def find_auth_files():
    """Search for authentication files for connecting to DPT-RP1, both in default path and in paths from Sony's Digital Paper App"""
    deviceid, privatekey = get_default_auth_files()

    if not os.path.exists(deviceid) or not os.path.exists(privatekey):
        # Could not find our own auth-files. Let's see if we can find any auth files created by Sony's Digital Paper App
        search_paths = [
            os.path.join(os.path.expanduser('~'), "Library/Application Support/Sony Corporation/Digital Paper App"), # Mac
            os.path.join(os.path.expanduser('~'), "AppData/Roaming/Sony Corporation/Digital Paper App") # Windows
        ]

        for path in search_paths:
            # Recursively look for deviceid.dat and privatekey.dat in any sub-folders of the search paths
            deviceid_matches = glob(os.path.join(path, "**/deviceid.dat"), recursive=True)
            privatekey_matches = glob(os.path.join(path, "**/privatekey.dat"), recursive=True)

            if deviceid_matches and privatekey_matches:
                # Found a match. Selecting the first file from each for now.
                # This might not be correct if the user has several devices with their own keys. Should ideally be configurable
                deviceid = deviceid_matches[0]
                privatekey = privatekey_matches[0]
                break

    return deviceid, privatekey

class DigitalPaperException(Exception):
    pass

class ResolveObjectFailed(DigitalPaperException):
    pass

class LookUpDPT:
    def __init__(self):
        import threading
        self.addr = None
        self.id = None
        self.lock = threading.Lock()

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        import ipaddress
        addr = ipaddress.IPv4Address(info.addresses[0])
        info = requests.get("http://{}:{}/register/information".format(addr, info.port)).json()
        if not self.id:
            self.id = info['serial_number']
            print("Found Digital Paper with serial number {}".format(self.id))
            print("To discover only this specific device, call:")
            print()
            print("    {} --serial {} {}".format(sys.argv[0], self.id, " ".join(sys.argv[1:])))
            print()
        if info['serial_number'] == self.id:
            self.addr = str(addr)
            self.lock.release()

    def find(self, id, timeout=30):
        from zeroconf import ServiceBrowser, Zeroconf
        print("Discovering Digital Paper for {} seconds…".format(timeout))
        sys.stdout.flush()
        self.id = id
        zc = Zeroconf()
        self.lock.acquire()
        ServiceBrowser(zc, "_digitalpaper._tcp.local.", self)
        wait = self.lock.acquire(timeout=timeout) or (self.addr is not None)
        zc.close()
        if not wait:
            print("Failed".format(timeout))
            return None
        else:
            print("Found digital paper at", self.addr)
            print("To skip the discovery process (and this message), call:")
            print()
            print("    {} --addr {} {}".format(sys.argv[0], self.addr, " ".join(sys.argv[1:])))
            print()
            return self.addr

class DigitalPaper():
    def __init__(self, addr=None, id=None):
        if addr:
            self.addr = addr
            if id:
                print("Ignoring serial number since address is set. Remove --serial {} from call to silence this message.".format(id))
        else:
            lookup = LookUpDPT()
            self.addr = lookup.find(id)

        self.session = requests.Session()
        self.session.verify = False # disable ssl certificate verification

    @property
    def base_url(self):
        if self.addr and ":" in self.addr and self.addr[0] != "[":
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
        r = self.session.put(register_cleanup_url)
        print(r)

        print("Requesting PIN...")
        r = self.session.post(register_pin_url)
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
        r = self.session.post(register_hash_url, json = m2)
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
        r = self.session.post(register_ca_url, json = m4)
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
        r = self.session.post(register_url, json = m6)
        print(r)

        print("Cleaning up...")
        r = self.session.put(register_cleanup_url)
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
        r = self.session.put(url, json=data)
        # cookiejar cannot parse the cookie format used by the tablet,
        # so we have to set it manually.
        _, credentials = r.headers["Set-Cookie"].split("; ")[0].split("=")
        self.session.cookies["Credentials"] = credentials
        return r

    ### File management
    def list_documents(self):
        data = self._get_endpoint('/documents2').json()
        return data['entry_list']

    def list_all(self):
        data = self._get_endpoint('/documents2?entry_type=all').json()
        return data['entry_list']

    def list_objects_in_folder(self, remote_path):
        remote_id = self._get_object_id(remote_path)
        entries = self.list_folder_entries_by_id(remote_id)
        return entries

    def list_folder_entries_by_id(self, folder_id):
        response = self._get_endpoint(f"/folders/{folder_id}/entries")
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
        return traverse(self._resolve_object_by_path(remote_path))

    def list_document_info(self, remote_path):
        remote_info = self._resolve_object_by_path(remote_path)
        return remote_info

    def download(self, remote_path):
        remote_id = self._get_object_id(remote_path)

        url = "{base_url}/documents/{remote_id}/file".format(
                base_url = self.base_url,
                remote_id = remote_id)
        response = self.session.get(url)
        return response.content

    def delete_document(self, remote_path):
        try:
            remote_id = self._get_object_id(remote_path)
        except ResolveObjectFailed as e:
            # Path not found
            return
        self.delete_document_by_id(remote_id)

    def delete_folder(self, remote_path):
        try:
            remote_id = self._get_object_id(remote_path)
        except ResolveObjectFailed as e:
            # Path not found
            return
        self.delete_folder_by_id(remote_id)

    def delete_document_by_id(self, doc_id):
        self._delete_endpoint(f"/documents/{doc_id}")

    def delete_folder_by_id(self, folder_id):
        self._delete_endpoint(f"/folders/{folder_id}")

    def upload(self, fh, remote_path):
        # Uploading a document should replace the existing document
        self.delete_document(remote_path)
        filename = os.path.basename(remote_path)
        remote_directory = os.path.dirname(remote_path)
        self.new_folder(remote_directory)
        directory_id = self._get_object_id(remote_directory)
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
        if not remote_directory:
            return
        if not self.path_exists(remote_directory):
            self.new_folder(remote_directory)
        directory_id = self._get_object_id(remote_directory)
        info = {
            "folder_name": folder_name,
            "parent_folder_id": directory_id
        }

        r = self._post_endpoint("/folders2", data=info)

    def list_folders(self):
        if not self.folder_list:
            data = self.list_all()
            for d in data:
                if d['entry_type'] == 'folder':
                    self.folder_list.append(d['entry_path'])
        return self.folder_list

    def download_file(self, remote_path, local_path):
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        data = self.download(remote_path)
        with open(local_path, 'wb') as f:
            f.write(data)

    def upload_file(self, local_path, remote_path):
        if self.path_is_folder(remote_path):
            local_filename = os.path.basename(local_path)
            remote_path = os.path.join(remote_path, local_filename)
        with open(local_path, 'rb') as f:
            self.upload(f, remote_path)

    def path_is_folder(self, remote_path):
        remote_filename = os.path.basename(remote_path)
        if not remote_filename:
            # Always a folder if path ends in slash.
            # Folder may not exist in this case!
            return True
        try:
            remote_obj = self._resolve_object_by_path(remote_path)
            if remote_obj["entry_type"] == "folder":
                return True;
        except ResolveObjectFailed:
            pass
        return False

    def path_exists(self, remote_path):
        try:
            remote_id = self._get_object_id(remote_path)
        except ResolveObjectFailed as e:
            return False
        return True

    def sync(self, local_folder, remote_folder):
        checkpoint_info = self.load_checkpoint(local_folder)
        self.set_datetime()
        self.new_folder(remote_folder)
        remote_info = self.traverse_folder(remote_folder)

        # Lists for applying remote changes to local
        to_download = []
        to_delete_local = []
        # Prepare download list
        for r in remote_info:
            r_path = unicodedata.normalize("NFC", r['entry_path'])
            if r['entry_type'] == 'document':
                r_date = datetime.strptime(r['modified_date'], '%Y-%m-%dT%H:%M:%SZ')
            found = False
            for c in checkpoint_info:
                c_path = unicodedata.normalize("NFC", c['entry_path'])
                date_difference = 0
                if c['entry_type'] == 'document':
                    c_date = datetime.strptime(c['modified_date'], '%Y-%m-%dT%H:%M:%SZ')
                    if r['entry_type'] == 'document':
                        date_difference = (r_date - c_date).total_seconds()
                if c_path == r_path:
                    found = True
                    if date_difference > 0:  # Remote modified after checkpoint
                        to_download.append(r)
                        break
            if not found:
                to_download.append(r)

        # Prepare local delete list
        for c in checkpoint_info:
            c_path = unicodedata.normalize("NFC", c['entry_path'])
            found = False
            for r in remote_info:
                r_path = unicodedata.normalize("NFC", r['entry_path'])
                if c_path == r_path:
                    found = True
                    break
            if not found:
                to_delete_local.append(c)

        # Lists for applying local change to remote
        to_upload = []
        to_delete_remote = []
        local_files = glob(os.path.join(local_folder, "**/*.pdf"), recursive=True)

        # Prepare upload list
        for local_path in local_files:
            relative_path = os.path.relpath(local_path, local_folder)
            remote_path = os.path.join(remote_folder, relative_path)
            r_path = unicodedata.normalize("NFC", remote_path)
            local_date = datetime.utcfromtimestamp(os.path.getmtime(local_path))
            found = False
            for c in checkpoint_info:
                if c['entry_type'] == 'folder':
                    continue
                c_path = unicodedata.normalize("NFC", c['entry_path'])
                c_date = datetime.strptime(c['modified_date'], '%Y-%m-%dT%H:%M:%SZ')
                date_difference = (local_date - c_date).total_seconds()
                if r_path == c_path:
                    found = True
                    if date_difference > 0: # Local is newer
                        to_upload.append(local_path)
            if not found:
                to_upload.append(local_path)

        # Prepare remote delete list
        for c in checkpoint_info:
            remote_path = os.path.relpath(c['entry_path'], remote_folder)
            local_path = os.path.join(local_folder, remote_path)
            if not os.path.exists(unicodedata.normalize("NFC", local_path)):
                to_delete_remote.append(c)

        # Apply changes in remote to local
        for file_info in to_download:
            remote_path = os.path.relpath(file_info['entry_path'], remote_folder)
            local_path = os.path.join(local_folder, remote_path)
            if file_info['entry_type'] == 'folder':
                os.makedirs(local_path, exist_ok = True)
                continue
            print("⇣ " + file_info['entry_path'])
            self.download_file(file_info['entry_path'], local_path)
            remote_date = datetime.strptime(file_info['modified_date'], '%Y-%m-%dT%H:%M:%SZ')
            remote_date = remote_date.replace(tzinfo=timezone.utc).astimezone(tz=None)
            mod_time = time.mktime(remote_date.timetuple())
            os.utime(local_path, (mod_time, mod_time))
            # If both remote and local have changes, remote wins.
            if file_info in to_delete_remote:
                to_delete_remote.remove(file_info)
            if unicodedata.normalize("NFC", local_path) in to_upload:
                to_upload.remove(local_path)

        for file_info in to_delete_local:
            remote_path = os.path.relpath(file_info['entry_path'], remote_folder)
            local_path = os.path.join(local_folder, remote_path)
            entry_type = file_info['entry_type']
            if os.path.exists(local_path):
                print("X " + local_path)
                if entry_type == 'folder':
                    shutil.rmtree(local_path)
                else:
                    os.remove(local_path)
            if file_info in to_delete_remote:
                to_delete_remote.remove(file_info)
            if unicodedata.normalize("NFC", local_path) in to_upload:
                to_upload.remove(local_path)

        # Apply changes in local to remote
        for remote_file in to_delete_remote:
            remote_path = unicodedata.normalize("NFC", remote_file['entry_path'])
            if self.path_exists(remote_path):
                print("X " + remote_path)
                if remote_file['entry_type'] == 'folder':
                    self.delete_folder(remote_path)
                else:
                    self.delete_document(remote_path)

        for local_file in to_upload:
            local_path = local_file
            relative_path = os.path.relpath(local_path, local_folder)
            remote_path = os.path.join(remote_folder, relative_path)
            print("⇡ " + local_path)
            self.upload_file(local_path, remote_path)

        remote_info = self.traverse_folder(remote_folder)
        self.sync_checkpoint(local_folder, remote_info)

    def load_checkpoint(self, local_folder):
        checkpoint_file = os.path.join(local_folder, ".sync")
        if not os.path.exists(checkpoint_file):
            return []
        with open(checkpoint_file, "rb") as f:
            return pickle.load(f)

    def sync_checkpoint(self, local_folder, doclist):
        checkpoint_file = os.path.join(local_folder, ".sync")
        with open(checkpoint_file, "wb") as f:
            pickle.dump(doclist, f)

    def _copy_move_data(self, file_id, folder_id,
            new_filename=None):
        data = {"parent_folder_id": folder_id}
        if new_filename is not None:
            data["file_name"] = new_filename
        return data

    def copy_file_to_folder_by_id(self, file_id, folder_id,
            new_filename=None):
        """
        Copies a file with given file_id to a folder with given folder_id.
        If new_filename is given, rename the file.
        """
        data = self._copy_move_data(file_id, folder_id, new_filename)
        return self._post_endpoint(f"/documents/{file_id}/copy", data=data)

    def move_file_to_folder_by_id(self, file_id, folder_id,
            new_filename=None):
        """
        Moves a file with given file_id to a folder with given folder_id.
        If new_filename is given, rename the file.
        """
        data = self._copy_move_data(file_id, folder_id, new_filename)
        return self._put_endpoint(f"/documents/{file_id}", data=data)

    def _copy_move_find_ids(self, old_path, new_path):
        old_id = self._get_object_id(old_path)
        new_filename = None

        try: # find out whether new_path is a filename or folder
            new_folder_id = self._get_object_id(new_path)
        except ResolveObjectFailed:
            new_filename = os.path.basename(new_path)
            new_folder = os.path.dirname(new_path)
            new_folder_id = self._get_object_id(new_folder)

        return old_id, new_folder_id, new_filename

    def copy_file(self, old_path, new_path):
        """
        Copies a file with given path to a new path.
        """
        old_id, new_folder_id, new_filename = self._copy_move_find_ids(
                old_path, new_path)
        self.copy_file_to_folder_by_id(old_id, new_folder_id,
                new_filename)

    def move_file(self, old_path, new_path):
        """
        Moves a file with given path to a new path.
        """
        old_id, new_folder_id, new_filename = self._copy_move_find_ids(
                old_path, new_path)
        return self.move_file_to_folder_by_id(old_id, new_folder_id,
                new_filename)


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

    def get_api_version(self):
        url = f"http://{self.addr}:8080/api_version"
        resp = self.session.get(url)
        return resp.json()["value"]

    def get_mac_address(self):
        data = self._get_endpoint('/system/status/mac_address').json()
        return(data['value'])

    def get_battery(self):
        data = self._get_endpoint('/system/status/battery').json()
        return(data)

    def get_info(self):
        data = self._get_endpoint('/register/information').json()
        return(data)

    def set_datetime(self):
        now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        self._put_endpoint('/system/configs/datetime', data={"value": now})

    ### Etc

    def take_screenshot(self):
        url = "{base_url}/system/controls/screen_shot" \
                .format(base_url = self.base_url)
        r = self.session.get(url)
        return r.content

    def ping(self):
        """
        Returns True if we are authenticated.
        """
        url = f"{self.base_url}/ping"
        r = self.session.get(url)
        return r.ok


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
    def _endpoint_request(self, method, endpoint, data=None, files=None):
        req = requests.Request(method, self.base_url, json=data, files=files)
        prep = self.session.prepare_request(req)
        # modifying the prepared request, so that the "endpoint" part of
        # the URL will not be modified by urllib.
        prep.url += endpoint.lstrip("/")
        return self.session.send(prep)

    def _get_endpoint(self, endpoint=""):
        return self._endpoint_request("GET", endpoint)

    def _put_endpoint(self, endpoint="", data={}, files=None):
        return self._endpoint_request("PUT", endpoint, data, files)

    def _post_endpoint(self, endpoint="", data={}):
        return self._endpoint_request("POST", endpoint, data)

    def _delete_endpoint(self, endpoint="", data={}):
        return self._endpoint_request("DELETE", endpoint, data)

    def _get_nonce(self, client_id):
        r = self._get_endpoint(f"/auth/nonce/{client_id}")
        return r.json()["nonce"]

    def _resolve_object_by_path(self, path):
        enc_path = quote_plus(path)
        url = f"/resolve/entry/path/{enc_path}"
        resp = self._get_endpoint(url)
        if not resp.ok:
            raise ResolveObjectFailed(path, resp.json()["message"])
        return resp.json()

    def _get_object_id(self, path):
        return self._resolve_object_by_path(path)["entry_id"]


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
