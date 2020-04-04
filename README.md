# dpt-rp1-py
Python script to manage Sony DPT-RP1 without the Digital Paper App. This repository includes a Python library and a command line utility to manage documents on the DPT-RP1. Tested on Windows, Linux, and macOS. Should also work for Sony's other digital paper readers.

## Installation
We now have a proper Python package, so you may just run:

```
pip3 install dpt-rp1-py
```

Installing the package also installs the command line utilities `dptrp1` and `dptmount`.


### From Source
To install the library from the sources, clone this repository, then run `python3 setup.py install` or `pip3 install .` from the root directory. To install as a developer use `python3 setup.py develop` (see [the setuptools docs](http://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode)) and work on the source as usual.

## Using the command line utility
```
dptrp1 command [arguments]
```

To see if you can successfully connect to the reader, try the command `dptrp1 list-documents`. If you have Sony's Digital Paper App installed, this should work without any further configuration. If this fails, register your reader with the app using `dptrp1  register`.

### Supported commands
You can get a list of the implemented commands by running `dptrp1` with no additional arguments. Supported commands include _help_, _copy-document_, _delete_, _delete-folder_, _download_, _list-documents_, _list-folders_, _move-document_, _new-folder_, _register_, _screenshot_, _sync_, _update-firmware_, _upload_, _wifi_, _wifi-add_, _wifi-del_, _wifi-disable_, _wifi-enable_, _wifi-list_, and _wifi-scan_.

For some commands, you can get additional help by calling `dptrp1 help <command>`, e.g. `dptrp1 help sync`.

Note that the root path for DPT-RP1 is `Document/`. Example command to download a document `file.pdf` from the root folder ("System Storage") of DPT-RP1: `dptrp1 download Document/file.pdf ./file.pdf`. Example command to upload a document `file.pdf` to a folder named `Articles` on DPT-RP1: `dptrp1 upload ./file.pdf Document/Articles/file.pdf`

### Registering the DPT-RP1
The DPT-RP1 uses SSL encryption to communicate with the computer.  This requires registering the DPT-RP1 with the computer, which results in two pieces of information -- the client ID and the key file -- that you'll need to run the script. You can get this information in three ways.

#### Registering without the Digital Paper App
This method requires your DPT-RP1 and your computer to be on the same network segment via WiFi, Bluetooth or a USB connection. The USB connection works on Windows and macOS but may not work on a Linux machine. If your WiFi network is not part of the "Saved Network List" (for example if you don't have the app), you can still use the DPT-RP1 as a WiFi access point and connect your computer to it.

```
dptrp1 register
```

The tool can generally figure out the correct IP address of the device automatically, but you may also specify it with the `--addr <address>` option. If you're on WiFi, go to _Wi-Fi Settings_ on the device and tap the connected network to see the device's address. If you use a Bluetooth connection, it's likely _172.25.47.1_. You can also try the hostname _digitalpaper.local_. Use the _register_ command like seen below, substituting the IP address of the device.

```
dptrp1 --addr 10.0.0.1 register
```

If you get an error, wait a few seconds and try again. Sometimes it takes two or three tries to work.

## Mounting as a file system
This Repository contains a `dptmount` script to mount the Digital Paper as a userspace mount. This tool has additional requirements.

- On macOS, install osxfuse (e.g. with `brew cask install osxfuse`). 
- On Linux, you may need to install libfuse.

### How to use 
Create a yaml file with configuration details at _~/.config/dpt-rp1.conf_. You must specify either an address (with `addr`) or a Device ID (with `serial`). All entries must be strings, the serial number must be wrapped in quotation marks.

```
dptrp1:
  addr: 192.168.0.200
  serial: "50040222"
  client-id: ~/.config/dpt/deviceid.dat
  key: ~/.config/dpt/privatekey.dat
```
If you register with `dptrp1 register` command, the client-id shall be $HOME/.dpapp/deviceid.dat, and key shall be $HOME/.dpapp/privatekey.dat.
Mount the Digital Paper to a directory with `dptmount --config ~/.config/dpt-rp1.conf /mnt/mountpoint`

#### Finding the private key and client ID on Windows

If you have already registered on Windows, the Digital Paper app stores the files in _Users/{username}/AppData/Roaming/Sony Corporation/Digital Paper App/_. You'll need the files _deviceid.dat_ and _privatekey.dat_.

#### Finding the private key and client ID on macOS

If you have already registered on macOS, the Digital Paper app stores the files in _$HOME/Library/Application Support/Sony Corporation/Digital Paper App/_. You'll need the files _deviceid.dat_ and _privatekey.dat_.

#### What works
* Reading files
* Moving files (both rename and move to different folder)
* Uploading new files
* Deleting files and folders 

#### What does not work
* Currently there is no caching, therefore operations can be slow as they require uploading or downloading from the 
device. However, this avoids having to resolve conflicts if a document has been changed both on the Digital Paper and
the caching directory.

## Usage

If paired over bluetooth, use `172.25.47.1` (double check IP from bluetooth connection network access point)

Else, over Wifi:

```
# Try multiple times
dptrp1 --addr 192.168.0.107 register

dptrp1 --addr 192.168.0.107 list-folders

dptrp1 --addr 192.168.0.107 wifi-add ./samples/wifi_2.5G.json

dptrp1 --addr 192.168.0.107 wifi-del ./samples/wifi_del_2.5G.json
```
