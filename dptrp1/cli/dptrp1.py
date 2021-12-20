#!/usr/bin/env python3
# coding=utf-8

import argparse
import inspect
import json
import sys
import os
import re

from pathlib import Path
from dptrp1.dptrp1 import DigitalPaper, find_auth_files, get_default_auth_files

ROOT_FOLDER = 'Document'

def do_screenshot(d, filename):
    """
    Take a screenshot of the device's screen and save it to the given local path.
    """
    pic = d.take_screenshot()
    with open(filename, "wb") as f:
        f.write(pic)

def do_list_templates(d):
    data = d.list_templates()
    for d in data:
        print(d["template_name"])

def do_list_documents(d):
    data = d.list_documents()
    for d in data:
        print(d["entry_path"])


def do_list_folders(d, *remote_paths):
    data = d.list_all()
    for d in data:
        if d["entry_type"] == "folder":
            print(d["entry_path"] + "/")


def do_move_document(d, old_path, new_path):
    d.move_file(old_path, new_path)


def do_copy_document(d, old_path, new_path):
    d.copy_file(old_path, new_path)


def do_upload(d, local_path, remote_path=""):
    """
    Upload a local document to the reader.
    Will upload to Document/ if only the local path is specified.
    """
    if not remote_path:
        remote_path = ROOT_FOLDER + "/" + os.path.basename(local_path)
    d.upload_file(local_path, add_prefix(remote_path))

def do_upload_template(d, local_path, template_name=''):
    """
    Upload a local document as a template for the reader.
    The template name will be set as the file name if
    only the local path is specified.
    """
    if not template_name:
        template_name = os.path.basename(local_path)
    with open(local_path, 'rb') as f:
        d.upload_template(f, template_name)

def do_download(d, remote_path, local_path):
    """
    Download a document from the reader to your computer.
    """
    data = d.download(remote_path)

    if os.path.isdir(local_path):
        re.sub("/?$", "/", local_path)
        local_path += os.path.basename(remote_path)

    with open(local_path, "wb") as f:
        f.write(data)


def do_list_document_info(d, remote_path=''):
    """
    Print metadata about a document on the device.
    If no path is given, information is printed for every document on the device.
    """
    if not remote_path:
        infos = d.list_all()
        for info in infos:
            print(info["entry_path"])
            for key in info:
                print("    - " + key + ": " + info[key])
    else:
        info = d.list_document_info(add_prefix(remote_path))
        print(info["entry_path"])
        for key in info:
            print("    - " + key + ": " + info[key])


def do_display_document(d, remote_path, page=1):
    """
    Displays the given document on the reader.
    The path must be a valid path on the device.
    To display a local document, upload it first.
    Optionally pass a page number to open a specific page, number 1 being the front page.
    Will show the first page if the page parameter is omitted.
    
    Example: dptrp1 display-document Document/Magazines/Comic.pdf 5
    """
    info = d.list_document_info(add_prefix(remote_path))
    d.display_document(info["entry_id"], page)


def do_update_firmware(d, local_path):
    with open(local_path, "rb") as fwfh:
        d.update_firmware(fwfh)

def add_prefix(remote_path: str) -> str:
    return remote_path if remote_path.startswith(ROOT_FOLDER) else f'{ROOT_FOLDER}/{remote_path}'

def do_delete_document(d, remote_path):
    d.delete_document(add_prefix(remote_path))

def do_delete_template(d,remote_path):
    d.delete_template(remote_path)

def do_delete_folder(d, remote_path):
    d.delete_folder(add_prefix(remote_path))


def do_sync(d, local_path, remote_path="Document"):
    """
    Synchronize all PDF documents between a local path (on your PC) and a
    remote path (on the DPT). Older documents will be overwritten by newer ones
    without any additional warning. Also synchronizes the time and date on the
    reader to the computer's time and date.

    Example: dptrp1 sync ~/Dropbox/Papers Document/Papers
    """
    d.sync(local_path, remote_path)


def do_new_folder(d, remote_path):
    d.new_folder(add_prefix(remote_path))


def do_wifi_list(d):
    data = d.wifi_list()
    print(json.dumps(data, indent=2))


def do_wifi_scan(d):
    data = d.wifi_scan()
    print(json.dumps(data, indent=2))


def do_wifi(d):
    print(d.wifi_enabled()["value"])


def do_wifi_enable(d):
    print(d.enable_wifi())


def do_wifi_disable(d):
    print(d.disable_wifi())


def do_add_wifi(d, cfg_file=""):
    try:
        cfg = json.load(open(cfg_file))
    except JSONDecodeError:
        quit("JSONDecodeError: Check the contents of %s" % cfg_file)
    except FileNotFoundError:
        quit("File Not Found: %s" % cfg_file)
    if not cfg:
        print(
            d.configure_wifi(
                ssid="vecna2",
                security="psk",
                passwd="elijah is a cat",
                dhcp="true",
                static_address="",
                gateway="",
                network_mask="",
                dns1="",
                dns2="",
                proxy="false",
            )
        )
    else:
        print(d.configure_wifi(**cfg))


def do_delete_wifi(d, cfg_file=""):
    try:
        cfg = json.load(open(cfg_file))
    except ValueError:
        quit("JSONDecodeError: Check the contents of %s" % cfg_file)
    except FileNotFoundError:
        quit("File Not Found: %s" % cfg_file)
    if not cfg:
        print(d.delete_wifi(ssid="vecna2", security="psk"))
    else:
        print(d.delete_wifi(**cfg))


def do_register(d, key_file, id_file):
    _, key, device_id = d.register()

    with open(key_file, "w") as f:
        f.write(key)

    with open(id_file, "w") as f:
        f.write(device_id)


def format_parameter(parameter):
    desc = ""
    if parameter.default != inspect.Parameter.empty:
        desc += "["
    desc += "<{}>".format(parameter.name)
    if parameter.default != inspect.Parameter.empty:
        desc += " = " + str(parameter.default) + "]"
    return desc


def do_help(command):
    """
    Print additional information about a command, if available.
    """
    try:
        args = list(inspect.signature(commands[command]).parameters.values())
        args = [format_parameter(x) for x in args[1:]]
        print()
        print("    Usage:", sys.argv[0], command, *args)
    except:
        pass
    print(commands[command].__doc__)


def do_get_config(d, path):
    """
    Saves the current device configuration to the given path.
    The configuration will be saved as a JSON file compatible with the set-configuration command.
    """
    config = d.get_config()
    with open(path, "w") as file:
        json.dump(config, file, indent=4, sort_keys=True)


def do_set_config(d, path):
    """
    Reads the JSON-encoded configuration file and applies the configuration to the device.
    Use get-configuration first to read the current configuration.
    """
    with open(path) as file:
        config = json.load(file)
    d.set_config(config)


commands = {
    "screenshot": do_screenshot,
    "list-documents": do_list_documents,
    "list-templates" : do_list_templates,
    "document-info": do_list_document_info,
    "upload": do_upload,
    "upload-template" : do_upload_template,
    "download": do_download,
    "delete": do_delete_document,
    "delete-folder": do_delete_folder,
    "delete-template": do_delete_template,
    "new-folder": do_new_folder,
    "move-document": do_move_document,
    "copy-document": do_copy_document,
    "list-folders": do_list_folders,
    "wifi-list": do_wifi_list,
    "wifi-scan": do_wifi_scan,
    "wifi-add": do_add_wifi,
    "wifi-del": do_delete_wifi,
    "wifi": do_wifi,
    "wifi-enable": do_wifi_enable,
    "wifi-disable": do_wifi_disable,
    "register": do_register,
    "update-firmware": do_update_firmware,
    "sync": do_sync,
    "help": do_help,
    "display-document": do_display_document,
    "get-configuration": do_get_config,
    "set-configuration": do_set_config,
}


def build_parser():
    p = argparse.ArgumentParser(description="Remote control for Sony DPT-RP1")
    p.add_argument(
        "--client-id", help="File containing the device's client id", default=None
    )
    p.add_argument(
        "--key", help="File containing the device's private key", default=None
    )
    p.add_argument(
        "--addr",
        help="Hostname or IP address of the device. Disables auto discovery.",
        default=None,
    )
    p.add_argument(
        "--serial",
        help="Device serial number for auto discovery. Auto discovery only works for some minutes after the Digital Paper's Wi-Fi setting is switched on.",
        default=None,
    )
    p.add_argument(
        "--yes",
        "-y",
        help="Automatically answer yes to confirmation prompts, for running non-interactively.",
        action="store_true",
        dest="assume_yes",
        default=False,
    )
    p.add_argument(
        "--quiet",
        "-q",
        help="Suppress informative messages.",
        action="store_true",
        dest="quiet",
        default=False,
    )
    p.add_argument("command", help="Command to run", choices=sorted(commands.keys()))
    p.add_argument("command_args", help="Arguments for the command", nargs="*")
    return p


def main():
    args = build_parser().parse_args()
    if args.command in ["help", "command-help"]:
        # Help is available without a device
        commands[args.command](*args.command_args)
        return

    dp = DigitalPaper(
        addr=args.addr, id=args.serial, assume_yes=args.assume_yes, quiet=args.quiet
    )
    if args.command == "register":
        # When registering the device, we default to storing auth files in our own configuration directory
        default_deviceid, default_privatekey = get_default_auth_files()
        do_register(
            dp, args.key or default_privatekey, args.client_id or default_deviceid
        )
        return

    # When connecting to a device, we default to looking for auth files in
    # both our own configuration directory and in Sony's paths
    found_deviceid, found_privatekey = find_auth_files()
    if not args.key:
        args.key = found_privatekey
    if not args.client_id:
        args.client_id = found_deviceid

    if not os.path.exists(args.key) or not os.path.exists(args.client_id):
        print("Could not read device identifier and private key.")
        print("Please use command 'register' first:")
        print()
        print("    {} register".format(sys.argv[0]))
        print()
        exit(1)
    with open(args.client_id) as fh:
        client_id = fh.readline().strip()
    with open(args.key, "rb") as fh:
        key = fh.read()
    dp.authenticate(client_id, key)

    try:
        commands[args.command](dp, *args.command_args)
    except Exception as e:
        print("An error occured:", e, file=sys.stderr)
        print("For help, call:", sys.argv[0], "help", args.command)
        sys.exit(1)


if __name__ == "__main__":
    main()
