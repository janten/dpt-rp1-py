# dpt-rp1-py
Python script to manage Sony DPT-RP1 without Digital Paper App. This repository includes a Python library and a command line utility to manage documents on the DPT-RP1. Tested on Windows, Linux, and macOS. 

## Install

To install the library run `python3 setup.py install` or `pip3 install .` from the root directory. To install as a developer use `python3 setup.py develop` (see [the setuptools docs](http://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode)) and work on the source as usual.

Installing the package also installs the command line utility called `dptrp1`.

## Using the command line utility
```
dptrp1 --addr <DPT-RP1 hostname or IP address> command [arguments]
```

To see if you can successfully connect to the reader, try the command `dptrp1 --addr <address> list-documents`. If you have Sony's Digital Paper App installed, this should work without any further configuration. If this fails, register your reader with the app using `dptrp1 --addr <address> register`.

### Supported commands
You can get a list of the implemented commands by running `dptrp1` with no additional arguments. Supported commands include _command-help_, _copy-document_, _delete_, _delete-folder_, _download_, _list-documents_, _list-folders_, _move-document_, _new-folder_, _register_, _screenshot_, _sync_, _update-firmware_, _upload_, _wifi_, _wifi-add_, _wifi-del_, _wifi-disable_, _wifi-enable_, _wifi-list_, and _wifi-scan_.

For some command, you can get additional help by calling `dptrp1 command-help <command>`, e.g. `dptrp1 command-help sync`.

Note that the root path for DPT-RP1 is `Document/`. Example command to download a document `file.pdf` from the root folder ("System Storage") of DPT-RP1: `dptrp1 --addr 10.0.0.4 download Document/file.pdf ./file.pdf`. Example command to upload a document `file.pdf` to a folder named `Articles` on DPT-RP1: `dptrp1 --addr 10.0.0.4 upload ./file.pdf Document/Articles/file.pdf`

### Registering the DPT-RP1

The DPT-RP1 uses SSL encryption to communicate with the computer.  This requires registering the DPT-RP1 with the computer, which results in two pieces of information -- the client ID and the key file -- that you'll need to run the script. You can get this information in three ways.

#### Registering without the Digital Paper App
This method requires your DPT-RP1 and your computer to be on the same network segment via WiFi, Bluetooth or a USB connection. The USB connection works on Windows and macOS but may not work on a Linux machine. If the USB connection does not work for you, perform the initial setup on a different PC to connect the reader to your WiFi network.

Second, find the DPT-RP1's IP address. If you're on WiFi, go to _Wi-Fi Settings_ on the device and tap the connected network. If you're on Bluetooth, it's likely _172.25.47.1_. You can also try the hostname _digitalpaper.local_.

Finally, use the _register_ command, substituting the IP address of the device:

```
dptrp1 --client-id <client_id file> register
```

If you get an error, wait a few seconds and try again.  Sometimes it takes two or three tries to work.

## FUSE mount

This Repository contains a script to mount the Digital Paper as a userspace mount. The work was originally started by @jgrigera
who did most of the work, but did not implement write delete and create methods. I have extended this work to also implement 
write and upload methods. 

### How to use 

Create a yaml file with configuration details like the below:

```
dptrp1:
  client-id: ~/.config/dpt/deviceid.dat
  key: ~/.config/dpt/privatekey.dat
  addr: 192.168.0.200
```

Mount the Digital Paper to a directory with `dptmount /my/mountpoint/`. 

#### Finding the private key and client ID on Windows

If you have already registered on Windows, the Digital Paper app stores the files in _Users/{username}/AppData/Roaming/Sony Corporation/Digital Paper App/_. You'll need the files _deviceid.dat_ and _privatekey.dat_.

#### Finding the private key and client ID on macOS

If you have already registered on macOS, the Digital Paper app stores the files in _$HOME/Library/Application Support/Sony Corporation/Digital Paper App/_. You'll need the files _deviceid.dat_ and _privatekey.dat_.

#### What works

* reading files
* moving files (both rename and move to different folder)
* uploading new files
* deleting files and folders 

#### What does not work

* currently there is no caching, therefore operations can be slow as they require uploading or downloading from the 
device. However, this avoids having to resolve conflicts if a document has been changed both on the Digital Paper and
the caching directory.
