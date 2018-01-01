# dpt-rp1-py
Python script to manage Sony DPT-RP1 without Digital Paper App.  To run
the command-line client:

`python3 cli.py --client-d {client-id file} --key {key file} --addr {host or ip address} COMMAND arg1 [arg2 ...]`

Commands and arguments:
```
list-documents
download {remote path} {local path}
upload {local path} {remote path}
new-folder {new folder path}
wifi-list
wifi-scan
wifi-enable
wifi-disable
```

...more coming soon!

## Registering the DPT-RP1

The DPT-RP1 uses SSL encryption to communicate with the computer.  This
requires "registering" the DPT-RP1 with the computer, which results in 
two pieces of information -- the client ID and the key file -- that you'll
need to run the script.  You can get this information in three ways.

### NEW: Registering works from the command line!

First, get your GNU/Linux box and your DPT-RP1 on the same network segment.
You can either register it on Windows or MacOS with the Digital Paper App
and then setup WiFi from there, or connect via Bluetooth networking.
(For whatever reason, the DPT-RP1 does not show up as a USB network
device on my Linux machine.  Maybe it works under newer distributions?)

Second, find the DPT-RP1's IP address.  If you're on WiFi, go to 
"Wi-Fi Settings" on the device and tap the connected network.  If you're
on Bluetooth, it's likely 172.25.47.1.

Finally, say ``python3 cli.py --client-id {client_id file} --key {key file} --addr {addr} register``, substituting the files you want the client id
and key written to, and the IP address of the device.

If you get an error, wait a few seconds and try again.  Sometimes it takes
two or three tries to work.

### Finding the private key and clientid on Windows

If you have already registered on Windows, the Digital Paper app stores the
files in ``Users/{username}/AppData/Roaming/Sony Corporation/Digital Paper App/``.
You'll need the files deviceid.dat and privatekey.dat.

### FIXME: Where are they stored on MacOS?

### Extracting the Private Key and ClientID
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
