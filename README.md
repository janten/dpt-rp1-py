# dpt-rp1-py
Python script to manage electronic paper devices made by Sony (Digital Paper, DPT-RP1, DPT-CP1) or Fujitsu (Quaderno) without the Digital Paper App. This repository includes a Python library and a command line utility to manage documents on the reader. Tested on Windows, Linux, and macOS. Should also work for Sony's other digital paper readers.

Throughout this document, _reader_ or _device_ refers to your Digital Paper device.

## Installation
We now have a proper Python package, so you may just run:

```
pip3 install dpt-rp1-py
```

Installing the package also installs the command line utilities `dptrp1` and `dptmount`. To install the library from the sources, clone this repository, then run `python3 setup.py install` or `pip3 install .` from the root directory. To install as a developer use `python3 setup.py develop` (see [the setuptools docs](http://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode)) and work on the source as usual.

## Using the command line utility
The command line utility requires a connection to the reader via WiFi, Bluetooth, or USB. The USB connection works on Windows and MacOS but may not work on a Linux machine.

To see if you can successfully connect to the reader, try the command `dptrp1 list-documents`. If you have Sony's Digital Paper App installed, this should work without any further configuration. If this fails, register your reader with the app using `dptrp1 register`.

### Basic usage
Here you see some basic usage examples for the utility. Text following a dollar sign is the command as entered on the command line on MacOS or Linux. Your paths may look slightly different on Windows.

#### Registering the device
This command pairs the command line utility to your reader. You only need to run this once. Keep the device nearby, you will need to read a code from the display and enter it.

```
$ dptrp1 register                                                                                 
Discovering Digital Paper for 30 seconds…
Found Digital Paper with serial number 500XXXX
Cleaning up...
<Response [204]>
Requesting PIN...
Encoding nonce...
Please enter the PIN shown on the DPT-RP1: 
```


#### Listing all documents on the device
```
$ dptrp1 list-documents                                                                                 
Document/Note/Graph_20171022.pdf
Document/Work/Scans/Contract.pdf
Document/Papers/svetachov2010.pdf
Document/Papers/sporns2012.pdf
```

#### Getting general usage instructions
```
$ dptrp1 -h
usage: dptrp1 [-h] [--client-id CLIENT_ID] [--key KEY] [--addr ADDR]
              [--serial SERIAL] [--yes] [--quiet]
              {copy-document,[...],wifi-scan}
              [command_args [command_args ...]]

Remote control for Sony DPT-RP1

positional arguments:
  {copy-document,[...],wifi-scan}
                        Command to run
  command_args          Arguments for the command

optional arguments:
  -h, --help            show this help message and exit
  --client-id CLIENT_ID
                        File containing the device's client id
  --key KEY             File containing the device's private key
  --addr ADDR           Hostname or IP address of the device. Disables auto
                        discovery.
  --serial SERIAL       Device serial number for auto discovery. Auto
                        discovery only works for some minutes after the
                        Digital Paper's Wi-Fi setting is switched on.
  --yes, -y             Automatically answer yes to confirmation prompts, for
                        running non-interactively.
  --quiet, -q           Suppress informative messages.

```

#### Getting help for the upload command
```
$ dptrp1 help upload

    Usage: dptrp1 upload <local_path> [<remote_path>]

    Upload a local document to the reader.
    Will upload to Document/ if only the local path is specified.
```
    
#### Uploading a document to the reader
```
$ dptrp1 upload ~/Desktop/scan.pdf
```

#### Opening the second page of a document on the reader
```
$ dptrp1 display-document Document/scan.pdf 2
```

#### Connecting to a WiFi network
This command requires the path to a WiFi configuration file as a parameter. Look at the [sample configuration](https://github.com/janten/dpt-rp1-py/blob/master/samples/wifi_2.5G.json) file and put your network name in the _ssid_ field and your password into the _passwd_ field. You can generally leave the other fields unchanged.

```
$ dptrp1 wifi-add config.json
```

### Supported commands
You can get a list of the implemented commands by running `dptrp1` with no additional arguments. The most important commands for everyday use are _register_, _help_, _upload_, _download_, and _sync_.

You can get additional information about a specific command by calling `dptrp1 help <command>`, e.g. `dptrp1 help sync`.

Note that the root path for DPT-RP1 is always `Document/`, which is misleadingly displayed as "System Storage" on the device. To download a document called _file.pdf_ from a folder called _Articles_ of the DPT-RP1, the correct command is `dptrp1 download Document/Articles/file.pdf`.

### Registering the DPT-RP1
The DPT-RP1 uses SSL encryption to communicate with the computer.  This requires registering the DPT-RP1 with the computer, which results in two pieces of information, the client ID and the private key. If you have used Sony's Digital Paper App on the same computer, the utility will automatically try to use the existing credentials. If you do not have the Digital Paper App, use the _register_ command.

#### Registering without the Digital Paper App
If you want to use a WiFi connection, make sure that the reader and your computer are connected to the same WiFi network. Some versions of the DPT-RP1 do not allow you to connect to a WiFi network from the device itself. In this case, use Bluetooth or USB first to configure the WiFi network (using the _wifi-add_ command) or update the firmware (using _update-firmware_).

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

If you register with `dptrp1 register` command, the client-id shall be $HOME/.dpapp/deviceid.dat, and key shall be $HOME/.dpapp/privatekey.dat. Mount the Digital Paper to a directory with `dptmount --config ~/.config/dpt-rp1.conf /mnt/mountpoint`

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
