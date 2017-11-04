# dpt-rp1-py
Python script to manage Sony DPT-RP1 without Digital Paper App

## Extracting the Private Key and ClientID
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
var certPath = os.homedir() + '/Desktop/cert.pem';
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

Now run the Digital Paper App and it will create two files, _client\_id.txt_ and _cert.pem_, on the desktop once the pairing is complete.
