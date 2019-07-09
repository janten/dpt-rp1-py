# dpt-rp1-py
Python script to manage Sony DPT-RP1 without Digital Paper App. This repository includes a Python library and a command line utility to manage documents on the DPT-RP1. Tested on Windows, Linux, and macOS. 

## Install

To install the library run `python3 setup.py install` or `pip3 install .` from the root directory. To install as a developer use `python3 setup.py develop` (see [the setuptools docs](http://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode)) and work on the source as usual.

Installing the package also installs the command line utility called `dptrp1`.

## Using the command line utility
```
dptrp1 \
	--addr <DPT-RP1 hostname or IP address> \
	command [arguments]
```

To see if you can successfully connect to the reader, try the command `dptrp1 --addr <address> list-documents`. If you have Sony's Digital Paper App installed, this should work without any further configuration. If this fails, register your reader with the app using `dptrp1 --addr <address> register`.

### Supported commands
You can get a list of the implemented commands by running `dptrp1` with no additional arguments. Supported commands include _register_, _list-documents_, _download <remote path> [<local path>]_, _upload <local path> <remote path>_, _new-folder <new folder path>_, _delete <remote_path>_, _wifi-list_, _wifi-scan_, _wifi-enable_, and _wifi-disable_.

Note that the root path for DPT-RP1 is `Document/`.
- Example command to download a document `file.pdf` from the root folder ("System Storage") of DPT-RP1: `dptrp1 --addr 10.0.0.4 download Document/file.pdf ./file.pdf`
- Example command to upload a document `file.pdf` to a folder named `Articles` on DPT-RP1: `dptrp1 --addr 10.0.0.4 upload ./file.pdf Document/Articles/file.pdf`

### Registering the DPT-RP1

The DPT-RP1 uses SSL encryption to communicate with the computer.  This requires registering the DPT-RP1 with the computer, which results in two pieces of information -- the client ID and the key file -- that you'll need to run the script. You can get this information in three ways.

#### Registering without the Digital Paper App
This method requires your DPT-RP1 and your computer to be on the same network segment via WiFi, Bluetooth or a USB connection. The USB connection works on Windows on macOS but may not work on a Linux machine. If you the USB connection does not work for you, perform the initial setup on a different PC to connect the reader to your WiFi network.

Second, find the DPT-RP1's IP address. If you're on WiFi, go to 
_Wi-Fi Settings_ on the device and tap the connected network. If you're
on Bluetooth, it's likely _172.25.47.1_. You can also try the hostname _digitalpaper.local_.

Finally, use the _register_ command, substituting the files you want the client ID and key written to, and the IP address of the device:

```
dptrp1 \
	--client-id <client_id file> \
	register
```

If you get an error, wait a few seconds and try again.  Sometimes it takes two or three tries to work.
