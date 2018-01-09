# dpt-rp1-py
Python script to manage Sony DPT-RP1 without Digital Paper App. This repository includes a Python library and a command line utility to manage documents on the DTP-RP1. Tested on Windows, Linux, and macOS. 

## Install

To install the library run `python3 setup.py install` or `pip3 install .` from the root directory. To install as a developer use `python3 setup.py develop` (see [the setuptools docs](http://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode)) and work on the source as usual.

Installing the package also installs the command line utility called `dptrp1`.

## Using the command line utility
```
dptrp1 \
	--addr <DPT-RP1 hostname or IP address> \
	--client-id <client_id file> \
	--key <key file> \
	command [arguments]
```
The required files for the client ID and private key will be created when you first register the reader. The files can also be extracted from the original Digital Paper App.

### Supported commands
You can get a list of the implemented commands by running `dptrp1` with no additional arguments. Supported commands include _register_, _list-documents_, _download <remote path> <local path>_, _upload <local path> <remote path>_, _new-folder <new folder path>_, _delete <remote_path>_, _wifi-list_, _wifi-scan_, _wifi-enable_, and _wifi-disable_.


### Registering the DPT-RP1

The DPT-RP1 uses SSL encryption to communicate with the computer.  This
requires registering the DPT-RP1 with the computer, which results in 
two pieces of information -- the client ID and the key file -- that you'll need to run the script.  You can get this information in three ways.

#### Registering without the Digital Paper App
This method requires your DPT-RP1 and your computer to be on the same network segment via WiFi, Bluetooth or a USB connection. The USB connection works on Windows on macOS but may not work on a Linux machine. If you the USB connection does not work for you, perform the initial setup on a different PC to connect the reader to your WiFi network.

Second, find the DPT-RP1's IP address. If you're on WiFi, go to 
_Wi-Fi Settings_ on the device and tap the connected network. If you're
on Bluetooth, it's likely _172.25.47.1_. You can also try the hostname _digitalpaper.local_.

Finally, use the _register_ command, substituting the files you want the client ID and key written to, and the IP address of the device:

```
dptrp1 \
	--client-id <client_id file> \
	--key <key file> \
	--addr <address> \
	register
```

If you get an error, wait a few seconds and try again.  Sometimes it takes two or three tries to work.

#### Finding the private key and client ID on Windows

If you have already registered on Windows, the Digital Paper app stores the files in _Users/{username}/AppData/Roaming/Sony Corporation/Digital Paper App/_. You'll need the files _deviceid.dat_ and _privatekey.dat_.

#### Extracting the private key and client ID on macOS
You can also modify the Digital Paper App to write your files to the desktop.

First, [download](https://esupport.sony.com/info/1667/US/EN/) the Digital Paper App. I am going to use the macOS version here but the process should be similar on Windows as the Digital Paper App is just an Electron wrapper around some JavaScript code. You will need to manipulate the application to extract the client identifier (_client\_id_) and the certificate that the application receives from the device upon pairing. 

The main application logic resides in a file called _app.asar_, which can be found at _/Applications/Digital Paper App.app/Contents/Resources/app.asar_ after the installation. Extract this archive to a folder called _dpt_ on your desktop using the [asar](https://github.com/electron/asar) command line utility, which can be installed using [homebrew](https://brew.sh) and npm.

```
brew install npm
npm install --global asar
cd "/Applications/Digital Paper App.app/Contents/Resources"
asar e app.asar ~/Desktop/dpt 
```

Surprisingly, the application is nicely organised into different modules that even come with source code comments and readme files. Those modules can be found in _node\_modules/mw-*_ within the _dpt_ folder. To extract the _client\_id_ and the certificate to handle communication with the DPT-RP1, make just one change in _/node\_modules/mw-auth-ctrl/authctrl.js_ by adding a few statements after line 189:

```javascript
// console.log('attempt to put /auth');
// console.log(JSON.stringify(authInfo, null, "  "));
var fs = require('fs');
var os = require('os');
var certPath = os.homedir() + '/Desktop/key.pem';
var clientPath = os.homedir() + '/Desktop/client_id.txt';
fs.writeFileSync(certPath, data, 'utf-8');
fs.writeFileSync(clientPath, deviceId, 'utf-8');
console.log(data);
console.log(deviceId);
```

Then use the _asar_ utility again to archive the changes and implement them into the Digital Paper App.

```
cd "/Applications/Digital Paper App.app"
sudo asar p ~/Desktop/dpt ./Contents/Resources/app.asar
```

Now run the Digital Paper App and it will create two files, _client\_id.txt_ and _key.pem_, on the desktop once the pairing is complete.
