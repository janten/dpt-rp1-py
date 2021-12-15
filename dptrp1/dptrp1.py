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
from tqdm import tqdm
from glob import glob
from urllib.parse import quote_plus
from dptrp1.pyDH import DiffieHellman
from datetime import datetime, timezone
from pbkdf2 import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Hash.HMAC import HMAC
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from pathlib import Path
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_default_auth_files():
    """Get the default path where the authentication files for connecting to DPT-RP1 are stored"""
    config_path = os.path.join(os.path.expanduser("~"), ".dpapp")
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
            os.path.join(
                os.path.expanduser("~"),
                "Library/Application Support/Sony Corporation/Digital Paper App",
            ),  # Mac
            os.path.join(
                os.path.expanduser("~"),
                "AppData/Roaming/Sony Corporation/Digital Paper App",
            ),  # Windows
        ]

        for path in search_paths:
            # Recursively look for deviceid.dat and privatekey.dat in any sub-folders of the search paths
            deviceid_matches = glob(
                os.path.join(path, "**/deviceid.dat"), recursive=True
            )
            privatekey_matches = glob(
                os.path.join(path, "**/privatekey.dat"), recursive=True
            )

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
    def __init__(self, quiet=False):
        import threading

        self.addr = None
        self.id = None
        self.lock = threading.Lock()
        self.quiet = quiet

    def update_service(self, zeroconf, service_type, name):
        pass

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        import ipaddress

        addr = ipaddress.IPv4Address(info.addresses[0])
        info = requests.get(
            "http://{}:{}/register/information".format(addr, info.port)
        ).json()
        if not self.id:
            self.id = info["serial_number"]
            if not self.quiet:
                print("Found Digital Paper with serial number {}".format(self.id))
                print("To discover only this specific device, call:")
                print()
                print(
                    "    {} --serial {} {}".format(
                        sys.argv[0], self.id, " ".join(sys.argv[1:])
                    )
                )
                print()
        if info["serial_number"] == self.id:
            self.addr = str(addr)
            self.lock.release()

    def find(self, id, timeout=30):
        from zeroconf import ServiceBrowser, Zeroconf

        if not self.quiet:
            print("Discovering Digital Paper for {} seconds…".format(timeout))
        sys.stdout.flush()
        self.id = id
        zc = Zeroconf()
        self.lock.acquire()
        ServiceBrowser(zc, ["_digitalpaper._tcp.local.", "_dp_fujitsu._tcp.local."], self)
        wait = self.lock.acquire(timeout=timeout) or (self.addr is not None)
        zc.close()
        if not wait:
            print("Failed".format(timeout))
            return None
        else:
            if not self.quiet:
                print("Found digital paper at", self.addr)
                print("To skip the discovery process (and this message), call:")
                print()
                print(
                    "    {} --addr {} {}".format(
                        sys.argv[0], self.addr, " ".join(sys.argv[1:])
                    )
                )
                print()
            return self.addr


class DigitalPaper:
    def __init__(self, addr=None, id=None, assume_yes=False, quiet=False):
        if addr:
            self.addr = addr
            if id:
                print(
                    "Ignoring serial number since address is set. Remove --serial {} from call to silence this message.".format(
                        id
                    )
                )
        else:
            lookup = LookUpDPT(quiet=quiet)
            self.addr = lookup.find(id)

        self.session = requests.Session()
        self.session.verify = False  # disable ssl certificate verification
        self.assume_yes = assume_yes  # Whether to disable interactive prompts (currently only in sync())

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

        reg_url = "http://{addr}:8080".format(addr=self.addr)
        register_pin_url = "{base_url}/register/pin".format(base_url=reg_url)
        register_hash_url = "{base_url}/register/hash".format(base_url=reg_url)
        register_ca_url = "{base_url}/register/ca".format(base_url=reg_url)
        register_url = "{base_url}/register".format(base_url=reg_url)
        register_cleanup_url = "{base_url}/register/cleanup".format(base_url=reg_url)

        print("Cleaning up...")
        r = self.session.put(register_cleanup_url)
        print(r)

        print("Requesting PIN...")
        r = self.session.post(register_pin_url)
        m1 = r.json()

        n1 = base64.b64decode(m1["a"])
        mac = base64.b64decode(m1["b"])
        yb = base64.b64decode(m1["c"])
        yb = int.from_bytes(yb, "big")
        n2 = os.urandom(16)  # random nonce

        dh = DiffieHellman()
        ya = dh.gen_public_key()
        ya = b"\x00" + ya.to_bytes(256, "big")

        zz = dh.gen_shared_key(yb)
        zz = zz.to_bytes(256, "big")
        yb = yb.to_bytes(256, "big")

        derivedKey = PBKDF2(
            passphrase=zz, salt=n1 + mac + n2, iterations=10000, digestmodule=SHA256
        ).read(48)

        authKey = derivedKey[:32]
        keyWrapKey = derivedKey[32:]

        hmac = HMAC(authKey, digestmod=SHA256)
        hmac.update(n1 + mac + yb + n1 + n2 + mac + ya)
        m2hmac = hmac.digest()

        m2 = dict(
            a=base64.b64encode(n1).decode("utf-8"),
            b=base64.b64encode(n2).decode("utf-8"),
            c=base64.b64encode(mac).decode("utf-8"),
            d=base64.b64encode(ya).decode("utf-8"),
            e=base64.b64encode(m2hmac).decode("utf-8"),
        )

        print("Encoding nonce...")
        r = self.session.post(register_hash_url, json=m2)
        m3 = r.json()

        if base64.b64decode(m3["a"]) != n2:
            print("Nonce N2 doesn't match")
            return

        eHash = base64.b64decode(m3["b"])
        m3hmac = base64.b64decode(m3["e"])
        hmac = HMAC(authKey, digestmod=SHA256)
        hmac.update(n1 + n2 + mac + ya + m2hmac + n2 + eHash)
        if m3hmac != hmac.digest():
            print("M3 HMAC doesn't match")
            return

        pin = input("Please enter the PIN shown on the DPT-RP1: ")

        hmac = HMAC(authKey, digestmod=SHA256)
        hmac.update(pin.encode())
        psk = hmac.digest()

        rs = os.urandom(16)  # random nonce
        hmac = HMAC(authKey, digestmod=SHA256)
        hmac.update(rs + psk + yb + ya)
        rHash = hmac.digest()

        wrappedRs = wrap(rs, authKey, keyWrapKey)

        hmac = HMAC(authKey, digestmod=SHA256)
        hmac.update(n2 + eHash + m3hmac + n1 + rHash + wrappedRs)
        m4hmac = hmac.digest()

        m4 = dict(
            a=base64.b64encode(n1).decode("utf-8"),
            b=base64.b64encode(rHash).decode("utf-8"),
            d=base64.b64encode(wrappedRs).decode("utf-8"),
            e=base64.b64encode(m4hmac).decode("utf-8"),
        )

        print("Getting certificate from device CA...")
        r = self.session.post(register_ca_url, json=m4)
        print(r)

        m5 = r.json()

        if base64.b64decode(m5["a"]) != n2:
            print("Nonce N2 doesn't match")
            return

        wrappedEsCert = base64.b64decode(m5["d"])
        m5hmac = base64.b64decode(m5["e"])

        hmac = HMAC(authKey, digestmod=SHA256)
        hmac.update(n1 + rHash + wrappedRs + m4hmac + n2 + wrappedEsCert)
        if hmac.digest() != m5hmac:
            print("HMAC doesn't match!")
            return

        esCert = unwrap(wrappedEsCert, authKey, keyWrapKey)
        es = esCert[:16]
        cert = esCert[16:]

        hmac = HMAC(authKey, digestmod=SHA256)
        hmac.update(es + psk + yb + ya)
        if hmac.digest() != eHash:
            print("eHash does not match!")
            return

        # print("Certificate: ")
        # print(cert)

        print("Generating RSA2048 keys")
        new_key = RSA.generate(2048, e=65537)

        # with open("key.pem", 'wb') as f:
        #    f.write(new_key.exportKey("PEM"))

        keyPubC = new_key.publickey().exportKey("PEM")

        selfDeviceId = str(uuid.uuid4())
        print("Device ID: " + selfDeviceId)
        selfDeviceId = selfDeviceId.encode()

        # with open("client_id.txt", 'wb') as f:
        #    f.write(selfDeviceId)

        wrappedDIDKPUBC = wrap(selfDeviceId + keyPubC, authKey, keyWrapKey)

        hmac = HMAC(authKey, digestmod=SHA256)
        hmac.update(n2 + wrappedEsCert + m5hmac + n1 + wrappedDIDKPUBC)
        m6hmac = hmac.digest()

        m6 = dict(
            a=base64.b64encode(n1).decode("utf-8"),
            d=base64.b64encode(wrappedDIDKPUBC).decode("utf-8"),
            e=base64.b64encode(m6hmac).decode("utf-8"),
        )

        print("Registering device...")
        r = self.session.post(register_url, json=m6)
        print(r)

        print("Cleaning up...")
        r = self.session.put(register_cleanup_url)
        print(r)

        return (
            cert.decode("utf-8"),
            new_key.exportKey("PEM").decode("utf-8"),
            selfDeviceId.decode("utf-8"),
        )

    def authenticate(self, client_id, key):
        sig_maker = httpsig.Signer(secret=key, algorithm="rsa-sha256")
        nonce = self._get_nonce(client_id)
        signed_nonce = sig_maker.sign(nonce)
        url = "{base_url}/auth".format(base_url=self.base_url)
        data = {"client_id": client_id, "nonce_signed": signed_nonce}
        r = self.session.put(url, json=data)
        # cookiejar cannot parse the cookie format used by the tablet,
        # so we have to set it manually.
        _, credentials = r.headers["Set-Cookie"].split("; ")[0].split("=")
        self.session.cookies["Credentials"] = credentials
        return r

    ### File management
    def list_templates(self):
        data = self._get_endpoint('/viewer/configs/note_templates').json()
        return data['template_list']

    def list_documents(self):
        data = self._get_endpoint("/documents2").json()
        return data["entry_list"]

    def list_all(self):
        data = self._get_endpoint("/documents2?entry_type=all").json()
        return data["entry_list"]

    def list_objects_in_folder(self, remote_path):
        remote_id = self._get_object_id(remote_path)
        entries = self.list_folder_entries_by_id(remote_id)
        return entries

    def list_folder_entries_by_id(self, folder_id):
        response = self._get_endpoint(f"/folders/{folder_id}/entries")
        return response.json()["entry_list"]

    def traverse_folder(self, remote_path, fields=[]):
        # In most cases, the request overhead of traversing folders is larger than the overhead of
        # requesting all info. So let's just request all info and filter for remote_path on our side
        if fields:
            field_query = "&fields=" + ",".join(fields)
        else:
            field_query = ""
        entry_data = self._get_endpoint(
            f"/documents2?entry_type=all" + field_query
        ).json()

        if entry_data.get("count") != len(entry_data.get("entry_list", [])):
            # The device seems to not want to return more than 1300 items in the entry_list, meaning that we will miss entries if the device
            # has more files/folders than this. Luckly, it can easily be detected by comparing the number of entries with the count.
            # Perhaps there is some way to request the remaining entries from the same endpoint through some form of pagination,
            # but we do not know how. Let's fall back to the slower recursive traversal
            print("Warning: Fast folder traversal did not work. Falling back to slower, recursive folder traversal.")
            return self.traverse_folder_recursively(remote_path)
        
        all_entries = entry_data["entry_list"]

        return list(
            filter(lambda e: e["entry_path"].startswith(remote_path), all_entries)
        )
    
    def traverse_folder_recursively(self, remote_path):
        # This is the old recursive implementation of traverse_folder.
        # It is slower because the main overhead when communicating with the DPT-RP1 is the request latency,
        # and this recursive implementation makes one request per folder. However, the faster implementation
        # above fails when there are more than 1300 items, in which case we fall back to this older implementation
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
            base_url=self.base_url, remote_id=remote_id
        )
        response = self.session.get(url)
        return response.content

    def delete_document(self, remote_path):
        try:
            remote_id = self._get_object_id(remote_path)
        except ResolveObjectFailed as e:
            # Path not found
            return
        self.delete_document_by_id(remote_id)
    
    def delete_template(self,template_name):
        template_list = self.list_templates()
        for t in template_list:
            if t['template_name']==template_name:
                remote_id = t['note_template_id']
                self.delete_template_by_id(remote_id)

    def display_document(self, document_id, page=1):
        info = {"document_id": document_id, "page": page}
        r = self._put_endpoint("/viewer/controls/open2", data=info)

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
    
    def delete_template_by_id(self, template_id):
        self._delete_endpoint(f"/viewer/configs/note_templates/{template_id}")

    def upload_template(self, fh, remote_path):
        filename = os.path.basename(remote_path)
        info = {
            "templateName": filename,
            "document_source": ""
        }
        r = self._post_endpoint("/viewer/configs/note_templates", data=info)
        doc = r.json()
        doc_url = "/viewer/configs/note_templates/{}/file".format(doc["note_template_id"])
        
        files = { 'file': (quote_plus(filename), fh, 'rb') }
        self._put_endpoint(doc_url, files=files)

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
            "document_source": "",
        }
        r = self._post_endpoint("/documents2", data=info)
        doc = r.json()
        doc_id = doc["document_id"]
        doc_url = "/documents/{doc_id}/file".format(doc_id=doc_id)

        files = {"file": (quote_plus(filename), fh, "rb")}
        self._put_endpoint(doc_url, files=files)

    def new_folder(self, remote_path):
        folder_name = os.path.basename(remote_path)
        remote_directory = os.path.dirname(remote_path)
        if not remote_directory:
            return
        if not self.path_exists(remote_directory):
            self.new_folder(remote_directory)
        directory_id = self._get_object_id(remote_directory)
        info = {"folder_name": folder_name, "parent_folder_id": directory_id}

        r = self._post_endpoint("/folders2", data=info)

    def list_folders(self):
        if not self.folder_list:
            data = self.list_all()
            for d in data:
                if d["entry_type"] == "folder":
                    self.folder_list.append(d["entry_path"])
        return self.folder_list

    def download_file(self, remote_path, local_path):
        local_folder = os.path.dirname(local_path)
        # Make sure that local_folder exists so that we can write data there.
        # If local_path is just a filename, local_folder will be '', and
        # we won't need to create any directories.
        if local_folder != "":
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
        data = self.download(remote_path)
        with open(local_path, "wb") as f:
            f.write(data)

    def upload_file(self, local_path, remote_path):
        if self.path_is_folder(remote_path):
            local_filename = os.path.basename(local_path)
            remote_path = os.path.join(remote_path, local_filename)
        with open(local_path, "rb") as f:
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
                return True
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
        print("Looking for changes on device... ", end="", flush=True)
        remote_info = self.traverse_folder(
            remote_folder, fields=["entry_path", "modified_date", "entry_type"]
        )
        print("done")

        # Syncing will require different comparions between local and remote paths.
        # Let's normalize them to ensure stable comparisions,
        # both with respect to unicode normalization and with respect to
        # directory separator symbols.
        def normalize_path(path):
            return unicodedata.normalize("NFC", path).replace(os.sep, "/")

        # Create a defaultdict of defaultdict
        # so that we can save data to it with two indexes, without having to manually create
        # nested dictionaries.
        # Will contain:
        # file_data[<filename>][<checkpoint/remote/local>_time] = <timestamp>
        file_data = defaultdict(lambda: defaultdict(lambda: None))

        # When it comes to folders, we want to handle them separately and not care about creation/deletion.
        # We therefore use a slightly different data structure:
        # folder_data[<filename>][checkpoint/remote/local_exists] = True/False
        folder_data = defaultdict(lambda: defaultdict(lambda: False))

        # Then we will go changes locally, remotely, and in checkpoint, and save all modificaiton times to the same
        # data structure for easy comparison, and the same with folders.

        # The checkpoint and remote_info contain the same data-structure, because the checkpoint is simply a dump of
        # remote_info at a previous point in time. Therefore, we use the same code to look through both of them:
        for location_info, location in [
            (checkpoint_info, "checkpoint"),
            (remote_info, "remote"),
        ]:
            for f in location_info:
                path = normalize_path(f["entry_path"])
                if path.startswith(remote_folder):
                    if f["entry_type"] == "document":
                        modification_time = datetime.strptime(
                            f["modified_date"], "%Y-%m-%dT%H:%M:%SZ"
                        )
                        file_data[path][f"{location}_time"] = modification_time
                    elif f["entry_type"] == "folder":
                        folder_data[path][f"{location}_exists"] = True

        print("Looking for local changes... ", end="", flush=True)
        # Recursively traverse the local path looking for PDF files.
        # Use relatively low-level os.scandir()-api instead of a higher-level api such as glob.glob()
        # because os.scandir() gives access to mtime without having to perform an additional syscall on Windows,
        # leading to much faster scanning times on Windows
        def traverse_local_folder(path):
            # Let's store to folder_data that this folder exists
            relative_path = Path(path).relative_to(local_folder)
            remote_path = normalize_path(
                (Path(remote_folder) / relative_path).as_posix()
            )
            folder_data[remote_path]["local_exists"] = True
            # And recursively go through all items inside of the folder
            for entry in os.scandir(path):
                if entry.is_dir():
                    traverse_local_folder(entry.path)
                # Only handle PDF files, ignore files starting with a dot.
                elif entry.name.lower().endswith(".pdf") and not entry.name.startswith(
                    "."
                ):
                    relative_path = Path(entry.path).relative_to(local_folder)
                    remote_path = normalize_path(
                        (Path(remote_folder) / relative_path).as_posix()
                    )
                    modification_time = datetime.utcfromtimestamp(entry.stat().st_mtime)
                    file_data[remote_path]["local_time"] = modification_time

        traverse_local_folder(local_folder)
        print("done")

        # Let's loop through the data structure
        # to create list of actions to take
        to_download = []
        to_delete_local = []
        to_upload = []
        to_delete_remote = []

        missing_checkpoint_files = []

        for filename, data in file_data.items():
            if data["checkpoint_time"] is None:
                if data["remote_time"] and data["local_time"]:
                    # File exists both on device and locally, but not in checkpoint.
                    # Corrupt or missing checkpoint?
                    # The safest bet is to assume that the two files are identical, and not sync in either directions.
                    missing_checkpoint_files.append(filename)
                    continue

                if data["remote_time"]:
                    # File only exists on remote, so it's new and should be downloaded
                    to_download.append(filename)
                    continue
                if data["local_time"]:
                    # File only exists locally, sot it's new and should be uploaded
                    to_upload.append(filename)
                    continue

            # If we get to here, file exists in checkpoint
            modified_local = (
                data["local_time"] and data["local_time"] > data["checkpoint_time"]
            )
            modified_remote = (
                data["remote_time"] and data["remote_time"] > data["checkpoint_time"]
            )
            deleted_local = data["local_time"] is None
            deleted_remote = data["remote_time"] is None

            if modified_local and modified_remote:
                print(
                    f"Warning, sync conflict!  {filename} is changed both locally and remotely."
                )
                if data["local_time"] > data["remote_time"]:
                    print("Local change is newer and will take precedence.")
                    to_upload.append(filename)
                else:
                    print("Remote change is newer and will take precedence.")
                    to_download.append(filename)
            elif modified_local:
                to_upload.append(filename)
            elif modified_remote:
                to_download.append(filename)
            elif deleted_local:
                to_delete_remote.append(filename)
            elif deleted_remote:
                to_delete_local.append(filename)

        if missing_checkpoint_files:
            print(
                "\nWarning: The following files exist both locally and on the DPT, but do not seem to have been synchronized using this tool:"
            )

            max_print = 20  # Let's only print the first max_print filenames to avoid completely flooding
            # stdout with unusable information if missing metadata means that this happens
            # to all files in the user's library
            print("\t" + "\n\t".join(missing_checkpoint_files[:max_print]))
            if len(missing_checkpoint_files) > max_print:
                print(
                    f"\t... and {len(missing_checkpoint_files)-max_print} additional files"
                )
            print("The files will be assumed to be identical.\n")

        # Just syncing the files will automatically create the necessary folders to store the given files, but it won't sync empty folders,
        # or folder deletion. Therefore, let's go through the folder_data as well, to see which additional folder operations need to be performed:
        folders_to_delete_remote = []
        folders_to_delete_local = []
        folders_to_create_remote = []
        folders_to_create_local = []
        for foldername, data in folder_data.items():
            # data contains information about whether the given foldername exists locally, remotely, and in the checkpoint.
            # In addition, we plan to upload/download some files, in which case we won't need to manually create the folders.
            # So let's updte data to describe the expected situation after uploading/downloding those files, to decide which additional
            # folder operations need to be performed.
            data["remote_exists"] = data["remote_exists"] or any(
                [f.startswith(foldername) for f in to_upload]
            )
            data["local_exists"] = data["local_exists"] or any(
                [f.startswith(foldername) for f in to_download]
            )

            # Depending on whether the folder exists is remote/local/checkpoint, let's decide whether to create/delete the folder from remote/local.
            create_remote = (
                data["local_exists"]
                and (not data["checkpoint_exists"])
                and (not data["remote_exists"])
            )
            create_local = (
                data["remote_exists"]
                and (not data["checkpoint_exists"])
                and (not data["local_exists"])
            )
            delete_remote = (
                (not data["local_exists"])
                and data["checkpoint_exists"]
                and data["remote_exists"]
            )
            delete_local = (
                (not data["remote_exists"])
                and data["checkpoint_exists"]
                and data["local_exists"]
            )

            if create_remote:
                folders_to_create_remote.append(foldername)
            if create_local:
                folders_to_create_local.append(foldername)
            if delete_remote:
                folders_to_delete_remote.append(foldername)
            if delete_local:
                folders_to_delete_local.append(foldername)

        # If a folder structure is deleted, let's sort the deletion so that we always select the innermost, empty, folder first.
        folders_to_delete_remote.sort(reverse=True)
        folders_to_delete_local.sort(reverse=True)

        print("")
        print("Ready to sync")
        print("")
        actions = [
            (to_delete_local + folders_to_delete_local, "DELETED locally"),
            (to_delete_remote + folders_to_delete_remote, "DELETED from device"),
            (to_upload + folders_to_create_remote, "UPLOADED to device"),
            (to_download + folders_to_create_local, "DOWNLOADED from device"),
        ]
        for file_list, description in actions:
            if file_list:
                print(f"{len(file_list):4d} files will be {description}")

        if not (
            to_delete_local
            or to_delete_remote
            or to_upload
            or to_download
            or folders_to_delete_local
            or folders_to_delete_remote
            or folders_to_create_local
            or folders_to_create_remote
        ):
            print("All files are in sync. Exiting.")
            return

        # Conferm that the user actually wants to perform the actions that
        # have been prepared.
        print("")
        confirm = ""
        while not (confirm in ("y", "yes") or self.assume_yes):
            confirm = input(f"Proceed (y/n/?)? ")
            if confirm in ("n", "no"):
                return
            if confirm in ("?", "list", "l"):
                for file_list, description in actions:
                    if file_list:
                        print("")
                        print(f"The following files will be {description}:")
                        print("\t" + "\n\t".join(file_list))
                        print("")

        # Syncing can potentially take some time, so let's display a progress bar
        # to give the user some idea about the progress.
        # Calling print() will interfere with the progress bar, so all print calls
        # are replaced by tqdm.write() while the progress bar is in use
        progress_bar = tqdm(
            total=len(to_delete_local)
            + len(to_delete_remote)
            + len(to_upload)
            + len(to_download),
            desc="Synchronizing",
            unit="files",
        )

        # Apply changes in remote to local
        for remote_path in to_download:
            relative_path = Path(remote_path).relative_to(remote_folder)
            local_path = Path(local_folder) / relative_path
            tqdm.write("⇣ " + str(remote_path))
            self.download_file(remote_path, local_path)
            remote_time = (
                file_data[remote_path]["remote_time"]
                .replace(tzinfo=timezone.utc)
                .astimezone(tz=None)
            )
            mod_time = time.mktime(remote_time.timetuple())
            os.utime(local_path, (mod_time, mod_time))
            progress_bar.update()

        for remote_path in to_delete_local:
            relative_path = Path(remote_path).relative_to(remote_folder)
            local_path = Path(local_folder) / relative_path
            if os.path.exists(local_path):
                tqdm.write("X " + str(local_path))
                os.remove(local_path)
            progress_bar.update()

        for remote_path in folders_to_delete_local:
            relative_path = Path(remote_path).relative_to(remote_folder)
            local_path = Path(local_folder) / relative_path
            if os.path.exists(local_path):
                tqdm.write("X " + str(local_path))
                try:
                    os.rmdir(local_path)
                except OSError as e:
                    if e.errno == 39:
                        tqdm.write(
                            f"WARNING: The folder {local_path} is not empty and will not be deleted."
                        )
                    else:
                        raise
            progress_bar.update()

        for remote_path in folders_to_create_local:
            relative_path = Path(remote_path).relative_to(remote_folder)
            local_path = Path(local_folder) / relative_path
            tqdm.write("⇣ " + str(remote_path))
            os.makedirs(local_path, exist_ok=True)
            progress_bar.update()

        # Apply changes in local to remote
        for remote_file in to_delete_remote:
            if self.path_exists(remote_file):
                tqdm.write("X " + str(remote_file))
                self.delete_document(remote_file)
            progress_bar.update()

        for remote_deletion_folder in folders_to_delete_remote:
            if self.path_exists(remote_deletion_folder):
                tqdm.write("X " + str(remote_deletion_folder))
                self.delete_folder(remote_deletion_folder)
            progress_bar.update()

        for remote_path in to_upload:
            relative_path = Path(remote_path).relative_to(remote_folder)
            local_path = Path(local_folder) / relative_path
            tqdm.write("⇡ " + str(local_path))
            self.upload_file(local_path, remote_path)
            progress_bar.update()

        for remote_path in folders_to_create_remote:
            relative_path = Path(remote_path).relative_to(remote_folder)
            local_path = Path(local_folder) / relative_path
            tqdm.write("⇡ " + str(local_path))
            self.new_folder(remote_path)
            progress_bar.update()

        progress_bar.close()

        print("Refreshing file information... ", end="", flush=True)
        remote_info = self.traverse_folder(
            remote_folder, fields=["entry_path", "modified_date", "entry_type"]
        )
        self.sync_checkpoint(local_folder, remote_info)
        print("done")

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

    def _copy_move_data(self, file_id, folder_id, new_filename=None):
        data = {"parent_folder_id": folder_id}
        if new_filename is not None:
            data["file_name"] = new_filename
        return data

    def copy_file_to_folder_by_id(self, file_id, folder_id, new_filename=None):
        """
        Copies a file with given file_id to a folder with given folder_id.
        If new_filename is given, rename the file.
        """
        data = self._copy_move_data(file_id, folder_id, new_filename)
        return self._post_endpoint(f"/documents/{file_id}/copy", data=data)

    def move_file_to_folder_by_id(self, file_id, folder_id, new_filename=None):
        """
        Moves a file with given file_id to a folder with given folder_id.
        If new_filename is given, rename the file.
        """
        data = self._copy_move_data(file_id, folder_id, new_filename)
        return self._put_endpoint(f"/documents/{file_id}", data=data)

    def _copy_move_find_ids(self, old_path, new_path):
        old_id = self._get_object_id(old_path)
        new_filename = None

        try:  # find out whether new_path is a filename or folder
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
            old_path, new_path
        )
        self.copy_file_to_folder_by_id(old_id, new_folder_id, new_filename)

    def move_file(self, old_path, new_path):
        """
        Moves a file with given path to a new path.
        """
        old_id, new_folder_id, new_filename = self._copy_move_find_ids(
            old_path, new_path
        )
        return self.move_file_to_folder_by_id(old_id, new_folder_id, new_filename)

    ### Wifi
    def wifi_list(self):
        data = self._get_endpoint("/system/configs/wifi_accesspoints").json()
        for ap in data["aplist"]:
            ap["ssid"] = base64.b64decode(ap["ssid"]).decode("utf-8", errors="replace")
        return data["aplist"]

    def wifi_scan(self):
        data = self._post_endpoint("/system/controls/wifi_accesspoints/scan").json()
        for ap in data["aplist"]:
            ap["ssid"] = base64.b64decode(ap["ssid"]).decode("utf-8", errors="replace")
        return data["aplist"]

    def configure_wifi(
        self,
        ssid,
        security,
        passwd,
        dhcp,
        static_address,
        gateway,
        network_mask,
        dns1,
        dns2,
        proxy,
    ):

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

        # print(kwargs['ssid'])
        conf = dict(
            ssid=base64.b64encode(ssid.encode()).decode("utf-8"),
            security=security,
            passwd=passwd,
            dhcp=dhcp,
            static_address=static_address,
            gateway=gateway,
            network_mask=network_mask,
            dns1=dns1,
            dns2=dns2,
            proxy=proxy,
        )

        return self._put_endpoint(
            "/system/controls/wifi_accesspoints/register", data=conf
        )

    def delete_wifi(self, ssid, security):
        url = "/system/configs/wifi_accesspoints/{ssid}/{security}".format(
            ssid=ssid, security=security
        )
        # .format(ssid = base64.b64encode(ssid.encode()).decode('utf-8'),
        return self._delete_endpoint(url)

    def wifi_enabled(self):
        return self._get_endpoint("/system/configs/wifi").json()

    def enable_wifi(self):
        return self._put_endpoint("/system/configs/wifi", data={"value": "on"})

    def disable_wifi(self):
        return self._put_endpoint("/system/configs/wifi", data={"value": "off"})

    ### Configuration

    def get_config(self):
        """
        Returns the current configuration.
        Return value will be a dictionary of dictionaries.
        """
        data = self._get_endpoint("/system/configs/").json()
        return data

    def set_config(self, config):
        """
        Update the device configuration.
        Input uses the same format that get_config() returns.
        """
        for key, setting in config.items():
            data = self._put_endpoint("/system/configs/" + key, data=setting)

    def get_timeout(self):
        data = self._get_endpoint("/system/configs/timeout_to_standby").json()
        return data["value"]

    def set_timeout(self, value):
        data = self._put_endpoint(
            "/system/configs/timeout_to_standby", data={"value": value}
        )

    def get_date_format(self):
        data = self._get_endpoint("/system/configs/date_format").json()
        return data["value"]

    def set_date_format(self, value):
        data = self._put_endpoint("/system/configs/date_format", data={"value": value})

    def get_time_format(self):
        data = self._get_endpoint("/system/configs/time_format").json()
        return data["value"]

    def set_time_format(self, value):
        data = self._put_endpoint("/system/configs/time_format", data={"value": value})

    def get_timezone(self):
        data = self._get_endpoint("/system/configs/timezone").json()
        return data["value"]

    def set_timezone(self, value):
        data = self._put_endpoint("/system/configs/timezone", data={"value": value})

    def get_owner(self):
        data = self._get_endpoint("/system/configs/owner").json()
        return data["value"]

    def set_owner(self, value):
        data = self._put_endpoint("/system/configs/owner", data={"value": value})

    ### System info

    def get_storage(self):
        data = self._get_endpoint("/system/status/storage").json()
        return data

    def get_firmware_version(self):
        data = self._get_endpoint("/system/status/firmware_version").json()
        return data["value"]

    def get_api_version(self):
        url = f"http://{self.addr}:8080/api_version"
        resp = self.session.get(url)
        return resp.json()["value"]

    def get_mac_address(self):
        data = self._get_endpoint("/system/status/mac_address").json()
        return data["value"]

    def get_battery(self):
        data = self._get_endpoint("/system/status/battery").json()
        return data

    def get_info(self):
        data = self._get_endpoint("/register/information").json()
        return data

    def set_datetime(self):
        now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        self._put_endpoint("/system/configs/datetime", data={"value": now})

    ### Etc

    def take_screenshot(self):
        # Or "{base_url}/system/controls/screen_shot" for a PNG image.
        url = "{base_url}/system/controls/screen_shot2".format(base_url=self.base_url)
        r = self.session.get(url, params={"query": "jpeg"})
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
        filename = "FwUpdater.pkg"
        fw_url = "/system/controls/update_firmware/file".format(base_url=self.base_url)
        files = {"file": (quote_plus(filename), fwfh, "rb")}
        # TODO: add file transferring feedback
        self._put_endpoint(fw_url, files=files)

        precheck_msg = self._get_endpoint(
            "/system/controls/update_firmware/precheck"
        ).json()
        battery_check = precheck_msg.get("battery", "not ok")
        uploaded_image_check = precheck_msg.get("image_file", "not ok")

        print("* battery check: {}".format(battery_check))
        print("* uploaded image check: {}".format(uploaded_image_check))

        for key in precheck_msg:
            if not (key == "battery" or key == "image_file"):
                print(
                    "! Find unrecognized key-value pair: ({0}, {1})".format(
                        key, precheck_msg[key]
                    )
                )

        if battery_check == "ok" and uploaded_image_check == "ok":
            # TODO: add check if status is 204
            self._put_endpoint("/system/controls/update_firmware")

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
    hmac = HMAC(authKey, digestmod=SHA256)
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

    hmac = HMAC(authKey, digestmod=SHA256)
    hmac.update(unwrapped)
    local_kwa = hmac.digest()[:8]

    if kwa != local_kwa:
        print("Unwrapped kwa does not match")

    return unwrapped


def unpad(bytestring, k=16):
    """
    Remove the PKCS#7 padding from a text bytestring.
    """

    val = bytestring[-1]
    if val > k:
        raise ValueError("Input is not padded or padding is corrupt")
    l = len(bytestring) - val
    return bytestring[:l]
