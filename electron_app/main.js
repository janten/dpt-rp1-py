/*
    main.js
    created:    [2016-07-05 21:24:36+09:00]
    modified:   [2016-11-25 01:59:55+09:00]
    description:
*/

const DEVBUILD = require('./lib/config').DEVBUILD;

///////////////////////////////////
/// Requires
///////////////////////////////////

const electron = require('electron');

// アプリの生存期間をコントロールするモジュール
const app = electron.app;

// ネイティブのブラウザウィンドウを作るためのモジュール
const BrowserWindow = electron.BrowserWindow;

// renderプロセスとの通信用のモジュール
const ipc = electron.ipcMain
// const ipc = require('electron').ipcMain

const Menu = electron.Menu;
// const {Menu} = require('electron');

const winston = require('winston');

const fs = require('fs');

const os = require('os');

const AutoBtPanConnector = require('mw-auto-bt-pan-connector');
const autoBtPanConnector = AutoBtPanConnector.getInstance();
autoBtPanConnector.startScanDevice(function (err) {});

// クラッシュレポートを送る
// require('crash-reporter').start();

///////////////////////////////////
/// Statics
///////////////////////////////////

var windowMap = {
    'init_setup': 'app/index_init_setup.html',
    'software_update': 'app/index_software_update.html',
    'setting' : 'app/index_setting.html',
    'explorer' : 'app/index_explorer.html',
    'about' : 'app/index_about.html'
};

var windowOptionMap = {
    'init_setup': {
        width: 1024,
        height: 768,
        minimizable: false,
        maximizable: false,
    },
    'software_update': {
    },
    'setting': {
        width: 800,
        height: 800,
        minimizable: false,
        maximizable: false,
    },
    'explorer': {
        width: 1300,
        height: 800,
        minWidth: 925,
        minHeight: 600,
        title: 'Digital Paper App', // ここで設定しないとpackage.jsonのnameがタイトルになる
        // [2016-09-14 16:33:11+09:00] kan.k: このicon設定をした状態で、
        // electron packagerで、exeにパッケージすると、アプリケーショ
        // ンが落ちるという事が分かったため、コメントアウト
        // icon: appIcon,
    },
    'about': {}
};

const MW_PATH_PREFIX =              '/Sony Corporation/Digital Paper App';
const MW_PATH_PREFIX_ELECTRON =     '/Sony Corporation/Digital Paper App/electron';
const MW_PATH_PREFIX_UPDATER =      '/Sony Corporation/Digital Paper App/updater';

const LOG_SIZE_LIMIT = 1024 * 1024 * 10;
const LOG_COUNT_LIMIT = 10;

///////////////////////////////////
/// Command Line Switches Handling
///////////////////////////////////

// var debuggable = false;
var debuggable = DEVBUILD;

const DEBUGKEY =
      '-----BEGIN PUBLIC KEY-----\n' +
      'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4U/mMHLLAt2rXKHCoziy\n' +
      'VYbuXewac4TClWnWRHMT77NabJesoH/0KSqxO8a5743cNFPE7jl/ooJ+avyKvEbr\n' +
      'rrlopdUhywyc/S5Os30hJKtu3rsRWKVqUvQ/UcZs0UN3GhX6Mm+zvhJudVLxMAHK\n' + 
      'F8eNGPGpdqDSqtLlWrWobEUwhuqHB9SzV7KIekpm7NtltwH1Eo84g8yKbOwPzBYR\n' +
      'Kulwh6fQr9x6yRY9Ha/PDAviqSLJ/QeVsWbHi0C0jus0dmUhuoKXeKvQoTrT75jY\n' +
      'AEeGCrog5q9f3HTLyM/OfFfpMfsZbJhu/k+k52/wxuoYJcB3f6OIdcV9EcHB71ZT\n' + 
      'IQIDAQAB\n' +
      '-----END PUBLIC KEY-----\n';

try {
    const debugPhrase = fs.readFileSync(__dirname + '/debug');
    const userInfo = os.userInfo();
    // console.log('HOGE');
    const crypto = require('crypto');
    const userId = userInfo.username + '@' + os.hostname();
    // console.log(userId);
    // console.log(crypto.publicDecrypt(DEBUGKEY, debugPhrase).toString());
    if ( crypto.publicDecrypt(DEBUGKEY, debugPhrase).toString() === userId ) {
        console.log('Debuggable');
        debuggable = true;
    }
} catch (e) {
    // nothing
}

// Default values.
var appOpts = {
    deviceId: null,
    windowId: 'explorer',
    debug: false,
    resizable: false,
    ignoreCertErrors: false,
    waitDevice: 0,
    // waitDevice: 20000,
    waitBeforeAction: 10000,
    printDocumentPath: null,
    version: null,
    supportDpApiVersionRange: null,
    supportDpApiReauth: true,
    supportDpApiRetry: true,
    supportDpApiStrictSizeCheck: false,
    supportDpApiStrictJsonCheck: false,
    stderrUncaughtException: true,
    // logToFile: true,
    logToFile: DEVBUILD,
    logToConsole: DEVBUILD,
    logLevel: 'warn',
    // logLevel: 'error',
    errorLogging: true,
    // errorLogging: true,
    errorRawFormat: false,
    // errorRawFormat: false,
    closeApp: false,
    forceCloseApp: false,
};

function processArguments(argv, appOpts) {
    // let argv = require('electron').remote.process.argv;
    let len = argv.length;
    for (var i = 0; i < len; i++) {
        let arg = argv[i];
        if ( debuggable && arg === '--deviceid') {
            /**
             * --deviceid {deviceid}
             *   Debug purpose options. Initialize the app for
             *   designated opponent device.
             */
            if (i + 1 >= len) {
                // alert('deviceid is not set. Please add --deviceid <device id> to command line option.');
                throw new Error('Device Id is not specified. Please add --deviceid <device id> to command line option.');
                app.quit();
            }
            i++;
            appOpts.deviceId = argv[i];
            continue;
        } else if ( debuggable && arg === '--windowid') {
            /**
             * --windowid {windowid} Debug purpose options. Open
             *   designated window immediately. This option usually
             *   require --deviceid option.
             */
            if (i + 1 >= len) {
                // alert('windowid is not set. Please add --windowid <window id> to command line option.');
                throw new Error('window Id is not specified. Please add --windowid <window id> to command line option.');
                app.quit();
            }
            i++;
            appOpts.windowId = argv[i];
            continue;
        } else if ( arg === '--print') {
            /**
             * --print Indicates the app to invoke printing to device
             *   procedure. This is prepared to be called from
             *   printing service.
             */
            if (i + 1 >= len) {
                // alert('windowid is not set. Please add --windowid <window id> to command line option.');
                throw new Error('designated file path is not specified. Please add --print <path/to/document> to command line option.');
                app.quit();
            }
            i++;
            appOpts.printDocumentPath = argv[i];
            continue;
        } else if (arg === '--close') {
            /**
             * --close が指定された場合には、ユーザーがアプリを終了した場合と同様の方法で
             * アプリの終了を試みる。具体的には、転送中断の確認ダイアログを表示した上で
             * 転送を中断し、アプリを終了させる。
             * 
             * アップデートインストールなどの際に、インストーラーから呼び出されることを
             * 想定している。
             * 
             * ※RC直前の仕様変更による追加対応のため、--close/--force-closeのフラグで両実装を保持
             */
            appOpts.closeApp = true;
            continue;
        } else if (arg === '--force-close') {
            /**
             * --force-close が指定された場合には、ユーザーに確認ダイアログを表示せずに
             * アプリの終了を行った上で、アプリを終了させる。
             * 
             * アップデートインストールなどの際に、インストーラーから呼び出されることを
             * 想定している。
             * 
             * ※RC直前の仕様変更による追加対応のため、--close/--force-closeのフラグで両実装を保持
             */
            appOpts.forceCloseApp = true;
            continue;
        } else if ( debuggable && arg === '--waitdevice') {
            /**
             * --waitdevice {mili-sec} Debug purpose options. Wait
             *   designated period before launch designated window.
             */
            if (i + 1 >= len) {
                // alert('windowid is not set. Please add --windowid <window id> to command line option.');
                throw new Error('waitdevice number is not specified. Please add --waitdevice <wait millisecond-sec> to command line option.');
                app.quit();
            }
            i++;
            appOpts.waitDevice = parseInt(argv[i]);
            if ( isNaN(appOpts.waitDevice) ) {
                throw new Error('waitdevice argument must be a number');
                app.quit();
            }

            // console.log(appOpts.waitDevice);
            continue;
        } else if ( debuggable && arg === '--waitbeforeaction') {
            /**
             * --waitdevice {mili-sec} Debug purpose options. Wait
             *   designated period before launch designated window.
             */
            if (i + 1 >= len) {
                // alert('windowid is not set. Please add --windowid <window id> to command line option.');
                throw new Error('waitbeforeaction number is not specified. Please add --waitdevice <wait millisecond-sec> to command line option.');
                app.quit();
            }
            i++;
            appOpts.waitBeforeAction = parseInt(argv[i]);
            if ( isNaN(appOpts.waitBeforeAction ) ) {
                throw new Error('waitdevice argument must be a number');
                app.quit();
            }

            // console.log(appOpts.waitDevice);
            continue;
        } else if ( debuggable && arg === '--dpapi-reauth' ) {
            appOpts.supportDpApiReauth = true;
            continue;
        } else if ( debuggable && arg === '--dpapi-retry' ) {
            appOpts.supportDpApiRetry = true;
            continue;
        } else if ( debuggable && arg === '--dpapi-no-reauth' ) {
            appOpts.supportDpApiReauth = false;
            continue;
        } else if ( debuggable && arg === '--dpapi-no-retry' ) {
            appOpts.supportDpApiRetry = false;
            continue;
        } else if ( debuggable && arg === '--dpapi-strict-size-check' ) {
            appOpts.supportDpApiStrictSizeCheck = true;
            continue;
        } else if ( debuggable && arg === '--dpapi-strict-json-check' ) {
            appOpts.supportDpApiStrictJsonCheck = true;
            continue;
        } else if ( debuggable && arg === '--dpapi-strict' ) {
            appOpts.supportDpApiReauth = false;
            appOpts.supportDpApiRetry = false;
            appOpts.supportDpApiStrictSizeCheck = true;
            appOpts.supportDpApiStrictJsonCheck = true;
            continue;
        } else if ( debuggable && arg === '--error-raw' ) {
            appOpts.errorRawFormat = true;
            continue;
        } else if ( debuggable && arg === '--popup-exception' ) {
            appOpts.stderrUncaughtException = false;
            continue;
        } else if ( debuggable && arg === '--no-popup-exception' ) {
            appOpts.stderrUncaughtException = true;
            continue;
        } else if ( arg === '--log-file' ) {
            appOpts.logToFile = true;
            continue;
        } else if ( arg === '--log-console' ) {
            appOpts.logToConsole = true;
            // appOpts.logToFile = false;
            continue;
            // log levels:
            // { error: 0, warn: 1, info: 2, verbose: 3, debug: 4, silly: 5 }
        } else if ( debuggable && arg === '--log-level-error' ) {
            appOpts.logLevel = 'error';
            continue;
        } else if ( debuggable && arg === '--log-level-warn' ) {
            appOpts.logLevel = 'warn';
            continue;
        } else if ( debuggable && arg === '--log-level-info' ) {
            appOpts.logLevel = 'info';
            continue;
        } else if ( debuggable && arg === '--log-level-verbose' ) {
            appOpts.logLevel = 'verbose';
            continue;
        } else if ( debuggable && arg === '--log-level-debug' ) {
            appOpts.logLevel = 'debug';
            continue;
        } else if ( debuggable && arg === '--log-level-silly' ) {
            appOpts.logLevel = 'silly';
            continue;
        } else if ( debuggable && arg === '--debug' ) {
            /**
             * @param {string} waitdevice Debug purpose options. Open
             *   developer tool immediately after launching
             *   application.
             */
            appOpts.debug = true;
            continue;
        } else if ( debuggable && arg === '--experimental' ) {
            /**
             * @param {string} waitdevice Debug purpose options. Open
             *   developer tool immediately after launching
             *   application.
             */
            appOpts.experimental = true;
            continue;
        } else if (debuggable && arg === '--ignore-certificate-errors') {
            /**
             * @param {boolean} ignore-certificate-errors Debug
             * purpose options. Ignore certificate errors.
             */
            appOpts.ignoreCertError = true;
            continue;
        }
    }
    return appOpts;
}
// console.log(process.argv);
var appOpts = processArguments(process.argv, appOpts);


if (typeof appOpts.windowId !== 'string') {
    // alert('windowId is not set. Please add --windowid <window id> to command line option.');
    throw new Error('Window Id is not specified. Please add --windowid <window id> to command line option.');
    app.quit();
}

if (typeof windowMap[appOpts.windowId] !== 'string') {
    // alert('windowId "' + appOpts.windowId + '" can not be recognized.');
    throw new Error('Window Id "' + appOpts.windowId + '" can not be recognized.');
    app.quit();
}

// var fs = require('fs');
// if (fs.existsSync('debug')) {
//     appOpts.debug = true;
//     // mainWindow.openDevTools();
// }


///////////////////////////////////
/// Read application version
///////////////////////////////////

const MW_APP_VERSION_FILEPATH = __dirname + '/version.txt';
const MW_SUPPORT_DPAPI_VERSION_RANGE_FILEPATH = __dirname + '/dpapiversion.txt';
const MW_APP_LICENSES_FILEPATH = __dirname + '/LICENSES.txt';
const MW_APP_LICENSE_US_FILEPATH = __dirname + '/LICENSE.US.txt';
const MW_APP_LICENSE_JP_FILEPATH = __dirname + '/LICENSE.JP.txt';

try {
    var version = fs.readFileSync(MW_APP_VERSION_FILEPATH);
    appOpts.version = version.toString().trim();
} catch (e) {
    appOpts.version = app.getVersion();
    // appOpts.version = version.toString().trim();
}

try {
    var version = fs.readFileSync(MW_SUPPORT_DPAPI_VERSION_RANGE_FILEPATH);
    appOpts.supportDpApiVersionRange = version.toString().trim();
} catch (e) {
    // appOpts.version = app.getVersion();
    // appOpts.version = version.toString().trim();
}

///////////////////////////////////
/// Setup app global as env variable
///////////////////////////////////

if ( ! debuggable ) {
    process.env.DEBUG = '';
}

process.env.MW_APP_VERSION = appOpts.version;

process.env.MW_SUPPORT_DPAPI_VERSION_RANGE = appOpts.supportDpApiVersionRange;

process.env.MW_SUPPORT_DPAPI_REAUTH = ( appOpts.supportDpApiReauth ? "true" : "");
process.env.MW_SUPPORT_DPAPI_RETRY = ( appOpts.supportDpApiRetry ? "true" : "");

process.env.MW_SUPPORT_DPAPI_STRICT_SIZE_CHECK = (appOpts.supportDpApiStrictSizeCheck ? "true" : "");
process.env.MW_SUPPORT_DPAPI_STRICT_JSON_CHECK = (appOpts.supportDpApiStrictJsonCheck ? "true" : "");

process.env.MW_ERROR_RAW_FORMAT = (appOpts.errorRawFormat ? "true" : "");
process.env.MW_ERROR_LOGGING = (appOpts.errorLogging ? "true" : "");

process.env.MW_APP_LICENSES_FILEPATH = MW_APP_LICENSES_FILEPATH;
process.env.MW_APP_LICENSE_US_FILEPATH = MW_APP_LICENSE_US_FILEPATH;
process.env.MW_APP_LICENSE_JP_FILEPATH = MW_APP_LICENSE_JP_FILEPATH;

process.env.MW_APP_WAIT_BEFORE_ACTION = appOpts.waitBeforeAction.toString();

process.env.MW_DEBUGGABLE = (debuggable ? "true" : "");

// AutoMagic 検証環境への接続設定
// process.env.MW_DEBUG_AUTO_MAGIC = "true";


///////////////////////////////////
///    経過措置のコード
///////////////////////////////////

if ( appOpts.experimental ) {
    process.env.MW_DEV_APP_EXPERIMENTAL = 1;
} else {
    delete process.env.MW_DEV_APP_EXPERIMENTAL;
}

// [2016-07-20 16:51:53+09:00] kan.k: [TODO] 古いreg-store-mwを利用し
// ている人に対する経過措置。

// try {
//     var userDataDirStat = fs.statSync(app.getPath('userData'));
// } catch (e) {
//     if ( e.code === 'ENOENT' ) {
//         fs.mkdirSync(app.getPath('userData'));
//     }
// }

///////////////////////////////////
/// Initial Settings for Electron and Chromium
///////////////////////////////////

// All host mapped to local host. This app will not access other than
// local host.
app.commandLine.appendSwitch('host-resolver-rules', 'MAP * 127.0.0.1');

// Cache must be disabled.
app.commandLine.appendSwitch('disable-http-cache');

// Altair will never use HTTP proxy to call Web API
app.commandLine.appendSwitch('no-proxy-server');

// Proxy must be turn off for initial setting.
process.env.NO_PROXY = '*';

if (appOpts.ignoreCertErrors) {
    app.commandLine.appendSwitch('ignore-certificate-errors');
}

/// Electronがデータを保存する先を指定する。
app.setPath('userData', app.getPath('appData') + MW_PATH_PREFIX_ELECTRON);

///////////////////////////////////
/// App global setting for Main and Render process
///////////////////////////////////

/**
 * アプリケーションで利用するディレクトリを定義している場所
 *
 * 情報を書き込む場合には、ディレクトリの存在確認をし、存在しなけれ
 * ばディレクトリを作成すること。
 */
if ( process.platform === 'win32' || process.platform === 'darwin' ) {

    /**
     * Applicationで、各ユーザにバインドする情報を保存するディレクトリの
     * Path
     */
    process.env.MW_USER_DATA_DIR_PATH = app.getPath('appData') + MW_PATH_PREFIX;


    /**
     * Applicationのログファイルの
     * Path
     */
    process.env.MW_LOG_FILE_DIR_PATH = app.getPath('appData') + MW_PATH_PREFIX + '/log';


    /**
     * Applicationで、アプリまたはデバイスのアップデーターをダウンロードする
     * ディレクトリのPath
     */
    process.env.MW_UPDATER_DIR_PATH = app.getPath('appData') + MW_PATH_PREFIX_UPDATER;

    /**
     * ユーザがダウンロードに利用するパス。OSで通常設定されているディレ
     * クトリを使う。
     */
    process.env.MW_DOWNLOADS_DIR_PATH = app.getPath('downloads')

    /**
     * アプリケーションで一時的に使用されるファイルを格納するディレクトリ
     * アプリ終了時に中身はすべて削除される
     */
    process.env.MW_TEMPORARY_FILE_DIR_PATH = app.getPath('appData') + MW_PATH_PREFIX + '/temporary';

    // /**
    //  * Applicationで、システムグローバルに共有する情報を保存するディレク
    //  * トリのPath
    //  */
    // process.env.MW_PROG_DATA_DIR_PATH = process.env.ProgramData.replace('\\', '/') + MW_PATH_PREFIX;

} else {
    throw new Error('The platform "' + process.platform + '" is not supported.');
    app.quit();
}

///////////////////////////////////
/// Before Start check
///////////////////////////////////

// [2016-07-20 14:49:46+09:00] kan.k: [TODO] Needs more brush up

const path = require('path');

try {
    var userDataDirStat = fs.statSync(process.env.MW_USER_DATA_DIR_PATH);
} catch (e) {
    if ( e.code === 'ENOENT' ) {
        try {
            fs.mkdirSync(process.env.MW_USER_DATA_DIR_PATH);
        } catch (e) {
            if ( e.code === 'ENOENT' ) {
                fs.mkdirSync(path.dirname(process.env.MW_USER_DATA_DIR_PATH));
                fs.mkdirSync(process.env.MW_USER_DATA_DIR_PATH);
            }
        }
    }
}

// ログフォルダを作成する
try {
    var logsDirStat = fs.statSync(process.env.MW_LOG_FILE_DIR_PATH);
    appOpts.logToFile = true;
} catch(e) {
    if ( e.code === 'ENOENT' ) {
        if ( appOpts.logToFile ) {
            fs.mkdirSync(process.env.MW_LOG_FILE_DIR_PATH);
        }
    }
}


// ログファイルの数が上限を超えた場合、古いファイルを削除する
// bakファイルが9個　かつ　ログファイルが上限を超えた場合には、ログファイルの置き換えにより、
// 上限+1個になり得る。　次回起動時に上限個数になる。
try {
    var logFileArr = fs.readdirSync( process.env.MW_LOG_FILE_DIR_PATH );
    while(logFileArr.length > LOG_COUNT_LIMIT) {
        logFileArr.sort( (a, b) => {
            if( a > b ) {
                return 1;
            } else {
                return -1;
            }
        });

        let file = logFileArr.shift();
        fs.unlinkSync(`${process.env.MW_LOG_FILE_DIR_PATH}/${file}`);
    }

} catch(e) {
    // ignore this error
    // console.log(e);
}


// log file のサイズが設定値を超えたらリネームする
// 今回のログ書き込みで上限を超えてもファイルを置き換えない
// 次回起動時に置き換える
let logFilePath = process.env.MW_LOG_FILE_DIR_PATH + '/logfile.log';
// console.log(logFilePath);
try {
    var logFileStat = fs.statSync( logFilePath );
    if( logFileStat && logFileStat.size > LOG_SIZE_LIMIT ) {
        let d = new Date();
        let yyyy = d.getFullYear().toString();
        let MM = `0${d.getMonth() + 1}`.slice(-2);
        let dd = `0${d.getDate()}`.slice(-2);
        let hh = `0${d.getHours()}`.slice(-2);
        let mm = `0${d.getMinutes()}`.slice(-2);
        let ss = `0${d.getSeconds()}`.slice(-2);;
        fs.renameSync(logFilePath, `${process.env.MW_LOG_FILE_DIR_PATH }/${yyyy}${MM}${dd}-${hh}${mm}${ss}.bak`);
    }

} catch(e) {
    // ignore this error
    // console.log(e);
}

// loggerを設定

// var logger = null;

// if( appOpts.logToFile === true ) {
//     logger = new (winston.Logger)({
//         transports: [
//             new (winston.transports.File)({
//                 name: 'log-file',
//                 filename: logFilePath,
//                 level: appOpts.logLevel
//             })
//         ]
//     });
// } else if ( appOpts.logToConsole === true ) {
//     logger = new (winston.Logger)({
//         transports: [
//             new (winston.transports.Console)({
//                 level: appOpts.logLevel
//             }),
//         ]
//     });
// }

var loggerTransports = [];

if( appOpts.logToFile ) {
    loggerTransports.push(new (winston.transports.File)({
        name: 'log-file',
        filename: logFilePath,
        level: appOpts.logLevel
    }));
}
if ( appOpts.logToConsole ) {
    loggerTransports.push(new (winston.transports.Console)({
        level: appOpts.logLevel
    }));
}

var logger = new (winston.Logger)({
    transports: loggerTransports
});

app.logger = logger;

// handle error occurred in the main process
if( appOpts.stderrUncaughtException === true ) {
    process.on('uncaughtException', function(e) {
        logger.log('error', 'uncaughtException at main process: ', e);
    });
}

///////////////////////////////////
/// Single App Instance Check
///////////////////////////////////

let explorerReady = false;          // Explorerの初期化処理が完了しているかを表す
let printDocumentPath = null;       // PrintToDP機能で指定されたファイルパス
let closeAppRequired = false;       // アプリの終了を要求されていることを表す
let forceCloseAppRequired = false;  // アプリの強制終了を要求されていることを表す

const shouldQuit = app.makeSingleInstance((commandLine, workingDirectory) => {
    // console.log('second instance commandLine: ' + commandLine);

    let secondAppOpts = processArguments(commandLine, appOpts);

    // --close/--force-close によるアプリの終了
    // ※RC直前の仕様変更による追加対応のため、--close/--force-closeのフラグで両実装を保持
    // ExplorerBaseViewのロード処理およびリスナー登録が完了していないと
    // ExplorerBaseViewで通知を受け取れないため、explorerReadyの値を確認する
    if (secondAppOpts && secondAppOpts.closeApp) {
        // --close が指定された場合
        if (explorerReady) {
            mainWindow.webContents.send('closeApp');
        } else {
            closeAppRequired = true;
        }
        return;
    }
    if (secondAppOpts && secondAppOpts.forceCloseApp) {
        // --force-close が指定された場合
        if (explorerReady) {
            mainWindow.webContents.send('forceCloseApp');
        } else {
            forceCloseAppRequired = true;
        }
        return;
    }

    // printToDevice機能で起動された場合、
    // Explorerが初期化済みであれば、プリント実行
    // 初期化できてないなら、一旦パスを保存する
    if(secondAppOpts && secondAppOpts.printDocumentPath) {
        // console.log('printDocumentPath: ' + secondAppOpts.printDocumentPath);
        if (explorerReady) {
            printToDevice(secondAppOpts.printDocumentPath);
        } else {
            printDocumentPath = secondAppOpts.printDocumentPath;
        }
    }
});

if (shouldQuit) {
    app.quit();
    // console.log('second instance quit');
    return;
}

// --close/--force-close によるアプリの終了
// ※RC直前の仕様変更による追加対応のため、--close/--force-closeのフラグで両実装を保持
// 
// インストーラーがアップデートインストールを開始する際に、アプリが現在起動しているか否かに
// 関わらず、--close/--force-close によるアプリの終了を要求する可能性が高い。そのため、
// アプリが起動していない状態で呼び出された場合には、即座にアプリを終了させる。
// 
if (appOpts && appOpts.closeApp) {
    // --close が指定された場合には、画面を表示せずにアプリを終了する
    // console.log('first instance quit by --close');
    app.quit();
    return;
}
if (appOpts && appOpts.forceCloseApp) {
    // --force-close が指定された場合には、画面を表示せずにアプリを終了する
    // console.log('first instance quit by --force-close');
    app.quit();
    return;
}

printDocumentPath = appOpts.printDocumentPath;

///////////////////////////////////
/// Event Handlers for mainWindow
///////////////////////////////////

// ウィンドウオブジェクトをグローバル宣言する
// JavaScript のオブジェクトが GC されたときにウィンドウが閉じてしまうため
var mainWindow = null;

// すべてのウィンドウが閉じられたら終了
app.on('window-all-closed', function() {
    app.quit();
});

var connSelector = require('mw-conn-selector');
var discoveryCtrl = require('mw-discovery-ctrl');
var finalized = false;

app.on('will-quit', function(ev) {
    if ( finalized ) {
        return;
    }
    // finalizing.
    ev.preventDefault();
    logger.info('will-quit');

    Promise.all([
        new Promise(function(resolve, reject) {
            discoveryCtrl.close( function(err) {
                resolve();
            });
        }), 
        new Promise(function(resolve, reject) {
            autoBtPanConnector.destroy(function (err) {
                resolve();
            });
        }),
        // temporary folder のファイルを削除する
        new Promise(function(resolve, reject) {
            fs.readdir( process.env.MW_TEMPORARY_FILE_DIR_PATH, function(err, files){
                if(err) {
                    if( err.code !== 'ENOENT') {
                        logger.warn('can not read dir. (MW_TEMPORARY_FILE_DIR_PATH)');
                    }
                    resolve();
                    return;
                }

                removeFiles(
                    files, 
                    process.env.MW_TEMPORARY_FILE_DIR_PATH, 
                    () => {
                        resolve();
                    }
                );
            });
        }),
    ]).then(
        function() {
            logger.info('will-quit then closed');
            finalized = true;
            app.quit();
        }
    );

    setTimeout(function() {
        // [2016-11-28 21:38:37+09:00] kan.k: [TODO] for the case
        // usbInitiator does not call callback function.
        logger.info('will-quit then closed by timeout.');
        finalized = true;
        app.quit();
    }, 3000);
});

// 指定されたフォルダ直下の指定されたファイルを削除する。フォルダは削除しない
function removeFiles( files, folder, callback ) {
    if( typeof folder === 'string' && typeof files === 'object' && files.length > 0 ) {
        
        // folderの最後の'/'の有無はnodejsが処理してくれる
        let file = folder + '/' + files.pop(); 
        fs.unlink(file, (err) => {
            //ignore this error
            removeFiles(files, folder, callback);
        });
    } else {
        callback();
    }
}

// Electron の初期化が終わってブラウザウィンドウを作る準備ができたら呼ばれる
app.on('ready', function() {
    // startMainWindow();

    // main process error tester
    // setTimeout( () => {
    //  throw new Error('main process error!!!')
    // }, 3000)

    var deviceList = connSelector.getDeviceList();
    var handled = false;
    // console.log(deviceList);

    if ( appOpts.deviceId === null ) {
        handled = true;
        startMainWindow();
        return;
    }

    for ( var i in deviceList ) {
        let device = deviceList[i];
        if ( device.deviceId === appOpts.deviceId ) {
            handled = true;
            startMainWindow();
            return;
        }
    }

    console.log('Waiting to device found... This is to emulate precondition for "' + appOpts.windowId + '"');

    // console.log('Registering');
    connSelector.on('deviceAppear', function(device) {
        // console.log('Something found', device);
        if ( device.deviceId === appOpts.deviceId ) {
            if ( handled ) {
                return;
            }
            handled = true;
            // console.log('Found one!');
            // connSelector.removeAllListener('deviceAppear');
            console.log('Found designated device. Launching "' + appOpts.windowId + '"...');
            startMainWindow();
            return;
        }
    });

    setTimeout(function() {
        if ( handled ) {
            return;
        }
        handled = true;
        if ( appOpts.waitDevice > 0 ) {
            electron.dialog.showErrorBox(
                'The device with device id not found',
                'The device "' + appOpts.deviceId + '" could not be found before ' +
                    appOpts.windowId + '. The app continues to launch.');
        }
        startMainWindow();
        // throw new Error('deviceId: "' + appOpts.deviceId + '" could not be found before initSetup');
        // close();
    }, appOpts.waitDevice);
});

function startMainWindow() {
    mainWindow = new BrowserWindow(windowOptionMap[appOpts.windowId]);
    if (appOpts.windowId === 'explorer') {
        mainWindow.preventClose = true;
        // mainWindow.setMenuBarVisibility(false);
    }

    mainWindow.setMenuBarVisibility(false);

    // Loading index.html of each window.
    mainWindow.loadURL('file://' + __dirname + '/' + windowMap[appOpts.windowId]);
    // mainWindow.loadURL('file://' + __dirname + '/app/index_init_setup.html');

    mainWindow.on('*', function(event){
        // console.log(event);
    });

    // Prevent any kind of navigation triggered by the user!
    // textファイルなどを素早くメイン画面上にドロップすると、
    // そのファイルが開かれるのを防ぐため
    mainWindow.webContents.on('will-navigate', (ev) => {
        if(ev) {
            ev.preventDefault();
        }
    });

    // アプリ実行ファイル exe と同じディレクトリーに "debug" があれば devtools を開く
    if (appOpts.debug) {
        mainWindow.openDevTools();
    }

    var close = false;
    // ウィンドウが閉じられたら実行
    mainWindow.on('close', function(e) {
        if(appOpts.windowId === 'init_setup'){
            if (!close) {
                e.sender.send('init-setup-close-message', 'close!');
                e.preventDefault();
            }
        }
        if(appOpts.windowId === 'explorer') {
            if ( mainWindow.preventClose ) {
                // Close判断の処理は、ExplorerViewが行う。
                e.preventDefault();
            }
        }
    });
    const ipcMain = require('electron').ipcMain;
    ipcMain.on('cancel-dialog-message', function(e, arg) {
        close = true;
        mainWindow.setClosable(true);
        mainWindow.close();
    });

    ipcMain.on('explorerReady', (e) => {
        explorerReady = true;

        // --close/--force-close によるアプリの終了        
        if (closeAppRequired) {
            // --close によるアプリの終了を要求されていた場合
            mainWindow.webContents.send('closeApp');
            return;
        }
        if (forceCloseAppRequired) {
            // --force-close によるアプリの強制終了を要求されていた場合
            mainWindow.webContents.send('forceCloseApp');
            return;
        }

        if(printDocumentPath) {
            printToDevice(printDocumentPath);
            printDocumentPath = null;
        }

        discoveryCtrl.on('usbSerialConnected', ( device ) => {
            // console.log('usbSerialConnected: ');
            // console.log(device);
            mainWindow.webContents.send('usbSerialConnected', device);
        });
                        
        discoveryCtrl.on('usbSerialDisconnected', ( device ) => {
            // console.log('usbSerialdisconnected: ');
            // console.log(device);
            mainWindow.webContents.send('usbSerialDisconnected', device);
        });

        electron.powerMonitor.on('suspend', function () {
            mainWindow.webContents.send('systemIsSuspending');
            autoBtPanConnector.suspend();
        });

        electron.powerMonitor.on('resume', function () {
            autoBtPanConnector.resume();
            mainWindow.webContents.send('systemIsResuming');
        });
    });

    // ウィンドウが閉じられたら実行
    mainWindow.on('closed', function() {
        mainWindow = null;
    });
}

function printToDevice(filePath) {
    // console.log('printToDevice(filePath): ' + filePath);
    mainWindow.webContents.send('printToDevice', filePath);
}



//----------------------------------------------------------------------------
// ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓  ここから下はmain.js再設計部分　↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
//----------------------------------------------------------------------------

//ipc通信用のメッセージ文字列(DPMW.View.Dialog.IpcMessageのコピー)
const ipcMessage = {
    //parentWin to main
    PARENT_TO_MAIN : {
        OPEN_DIALOG: 'open_dialog',
        CLOSE_DIALOG: 'close_dialog',
        SEND_INIT_INFO: 'send_init_info',
        SUBMIT_SUCCEED: 'submit_succeed',
        SUBMIT_FAILED: 'submit_failed',
        SEND_PROGRESS: 'send_progress',
        OPEN_DIALOG_CONNECTING: 'open_dialog_connecting',
        CLOSE_DIALOG_CONNECTING: 'close_dialog_connecting',
    },

    //main to parentWin
    MAIN_TO_PARENT : {
        FINISH_CONNECT: 'finish_connect',
        DIALOG_SHOWED: 'dialog_showed',
        SUBMIT: 'submit',
        CANCEL: 'cancel',
        DIALOG_CLOSED: 'dialog_closed',
        DIALOG_CLOSE: 'dialog_close',
        GET_PROGRESS: 'get-progress',
        DIALOG_RELAY: 'dialog_relay',
        LOADING_CANCEL: 'loading_cancel',
    },

    //main to childWin
    MAIN_TO_CHILD : {
        INIT_INFO: 'init_info',
        SUBMIT_SUCCEED: 'submit_succeed',
        SUBMIT_FAILED: 'submit_failed',
        DIALOG_ON_CLOSE: 'dialog_on_close',
        PROGRESS: 'progress',
        OPEN_DIALOG_CONNECTING: 'open_dialog_connecting',
        CLOSE_DIALOG_CONNECTING: 'close_dialog_connecting',
    },

    //childWin to main
    CHILD_TO_MAIN : {
        CLOSE_DIALOG: 'close_dialog',
        FINISH_INIT: 'finish-init',
        GET_PROGRESS: 'get-progress',
        SUBMIT: 'submit',
        CANCEL: 'cancel',
        DIALOG_RELAY: 'dialog_relay',
        LOADING_CANCEL: 'loading_cancel',
    },
}

//ipcに反応し、ダイヤログをを作る
ipc.on(ipcMessage.PARENT_TO_MAIN.OPEN_DIALOG, function(e, dialogName, dialogURL, browserWindowOptions, parentWinId, channel4Parent) {
    // console.log('createDialog:' + dialogName + ': ' + dialogURL);
    let dialog = new Dialog(dialogName, dialogURL, browserWindowOptions, parentWinId, channel4Parent);
});

/**
 * Dialog
 *
 * ダイヤログ制御用クラス
 *
 * 用語
 *  - parentWin：親画面
 *  - childWin：子ダイヤログ
 *  - main：main process
 *
 * シーケンス
 *  - ダイヤログの表示
 *      - parentWin: => main [ipc通信]： PARENT_TO_MAIN.OPEN_DIALOG
 *      - main: childWinを作る
 *      - childWin: ipc listenerを登録し、チャンネル名を決める 
 *      - childWin: => main [ipc通信]： dialogChannelEntry
 *      - main: channelを確立し、channelにparentWin,childWinのリスナーの登録する
 *      - main: => parentWin [ipc通信]: MAIN_TO_PARENT.FINISH_CONNECT 
 *      - parentWin: => main [ipc通信]: PARENT_TO_MAIN.SEND_INIT_INFO, initData
 *      - main: => childWin [ipc通信]: MAIN_TO_CHILD.INIT_INFO, initData
 *      - childWin: 画面の初期化をする
 *      - childWin: => main [ipc通信]: CHILD_TO_MAIN.FINISH_INIT
 *      - main: childWinを表示する
 *      - main: => parentWin [ipc通信]: MAIN_TO_PARENT.DIALOG_SHOWED
 *
 *  - submit
 *      - childWin: OKボタン押下など、submit実行
 *      - childWin: submit前処理(BeforeSubmit)を実行(Loading画面を出すとか)
 *      - childWin: => main [ipc通信] CHILD_TO_MAIN.SUBMITi, userInput
 *      - main: => parentWin [ipc通信] MAIN_TO_PARENT.SUBMIT, userInput
 *      - parentWin: submit処理を実行する
 *          - 成功した場合:
 *              - parentWin: => main [ipc通信] PARENT_TO_MAIN.SUBMIT_SUCCEED
 *              - main: => childWin [ipc通信] MAIN_TO_CHILD.SUBMIT_SUCCEE
 *              - childWin: Loading画面が開かれている場合、Loading画面を閉じる。
 *              - childWin: childWinを閉じる。
 *          - 失敗した場合：
 *              - parentWin: => main [ipc通信] PARENT_TO_MAIN.SUBMIT_FAILED, err
 *                  - err: DPMW.View.Dialog.IDialogOptions
 *              - main: => childWin [ipc通信] MAIN_TO_CHILD.SUBMIT_FAILED, err
 *              - childWin: Loading画面が開かれている場合、Loading画面を閉じる。
 *              - childWin: errorダイヤログを表示する
 *
 *  - cancel
 *      - 前提: childWinが開かれている。cancelボタンが表示されている
 *      - childWin: cancelボタンが押された
 *      - childWin: => main [ipc通信] CHILD_TO_MAIN.CANCEL, null
 *      - main: => parentWin [ipc通信] MAIN_TO_PARENT.CANCEL, null
 *      - parentWin: キャンセル処理を実行（handler.canceled）
 *
 *  - ダイヤログ遷移
 *      - 前提: childWinが開かれている
 *      - childWin: => main [ipc通信] CHILD_TO_MAIN.DIALOG_RELAY, dialogRelayInfo
 *      - main => parentWin [ipc通信] MAIN_TO_PARENT.DIALOG_RELAY, dialogRelayInfo
 *      - parentWin: 遷移先子ダイヤログ(childWin_new)を開く（「シーケンス.ダイヤログの表示」を参照）
 *          - childWin_newからのDIALOG_SHOWEDイベントを受けて、childWinを閉じる
 *
 *  - ダイヤログの終了
 *      - 前提: childWinが開かれている
 *      - childWin: 'close'イベントを発火する(バツボタンを押すなど)
 *      - main: childWinの'close'イベントをフックして、一旦止める（preventDefault）
 *          - dialogClosable = trun の場合、childWinを閉じる
 *          - dialogClosable = false の場合：
 *              - main: => childWin [ipc通信] MAIN_TO_CHILD.DIALOG_ON_CLOSE
 *              - childWin: 閉じれるかどうかを判断する
 *                  - 閉じれる場合:
 *                      - childWin: => main [ipc通信] CHILD_TO_MAIN.CLOSE_DIALOG
 *                      - main: dialogClosable = trunに設定し、childWinを閉じる
 *                  - 閉じれない場合: 
 *                      - 閉じれない場合の処理
 *
 *
 * @param e {event} event
 * @param dialogName {string} 子画面の名称
 * @param dialogName {string} 子画面のURL
 * @param browserWindowOptions {any} ElectronのBrowserWindowのoptions
 * @param parentWinId {number} 親画面のid
 * @param channel4Parent {string} 親画面とのipc通信チャンネル
 *
 */
Dialog = function(dialogName, dialogURL, browserWindowOptions, parentWinId, channel4Parent) {
    this.dialogName = dialogName;
    this.dialogURL = dialogURL;
    this.browserWindowOptions = browserWindowOptions;
    this.parentWin = BrowserWindow.fromId(parentWinId);
    this.browserWindowOptions.parent = this.parentWin;
    // this.browserWindowOptions.icon = appIcon;
    this.channel4Parent = channel4Parent;
    this.childWin = new BrowserWindow(this.browserWindowOptions);
    this.childWin.setMenuBarVisibility(false);
    this.channel4Child;
    this.dialogClosable = false;
    this.dialogChannelEntry = this.dialogName + '-channelEntry';

    this.dialogClosed();

    // this.childWin.openDevTools();
    if (appOpts.debug) {
        this.childWin.openDevTools();
    }

    let me = this;

    // MacのMenuをコントロールするために、Explorerの子ダイヤログが開かれたことをExplorerに通知する
    if( process.platform === 'darwin' && me.parentWin.id === mainWindow.id) {
        // console.log(`ExplorerSubWindowCalled: ${me.dialogName}`);
        me.parentWin.webContents.send('ExplorerSubWindowCalled', me.dialogName);
    }

    let promis = new Promise(function(resolve, reject) {
        // console.log('Dialog.prototype.setChildChannel ');
        // console.log(dialogChannelEntry);
        ipc.on(me.dialogChannelEntry, function(e, channel) {
            ipc.removeAllListeners(me.dialogChannelEntry);
            me.dialogChannelEntry = null;
            if (e.sender.getOwnerBrowserWindow().id === me.childWin.id) {
                me.channel4Child = channel;
                // console.log('resolve: ' + channel);
                resolve(channel);
            }
        });
        // console.log('Dialog.prototype.setChildChannel END');
    });

    promis.then(function(channel) {
        // console.log('then');
        me.setParentListener();
        me.setChildListener();

        let detail = {
            'channel4Parent': me.channel4Parent,
            'channel4Child': me.channel4Child,
            'childWinId': me.childWin.id,
        }
        // console.log(ipcMessage.MAIN_TO_PARENT.FINISH_CONNECT);
        me.parentWin.webContents.send(me.channel4Parent, ipcMessage.MAIN_TO_PARENT.FINISH_CONNECT, detail);
    });

    this.childWin.loadURL(dialogURL);
    
    // Prevent any kind of navigation triggered by the user!
    // textファイルなどを素早くメイン画面上にドロップすると、
    // そのファイルが開かれるのを防ぐため
    this.childWin.webContents.on('will-navigate', (ev) => {
        if(ev) {
            ev.preventDefault();
        }
    });
}

//親画面のリスナーを設定する
Dialog.prototype.setParentListener = function() {
    ipc.on(this.channel4Parent, (e, message, detail) => {
        // console.log('parentListener: ');
        // console.log('message: ' + message);
        // console.log('detail: ' + detail);
        // console.log('channel4Child: ' + this.channel4Child);
        if (message === ipcMessage.PARENT_TO_MAIN.SEND_INIT_INFO) {
            // console.log(ipcMessage.PARENT_TO_MAIN.SEND_INIT_INFO);

            this.childWin.webContents.send(this.channel4Child, ipcMessage.MAIN_TO_CHILD.INIT_INFO, detail);
        }

        if (message === ipcMessage.PARENT_TO_MAIN.SUBMIT_SUCCEED) {
            this.childWin.webContents.send(this.channel4Child, ipcMessage.MAIN_TO_CHILD.SUBMIT_SUCCEED, detail);
        }

        if (message === ipcMessage.PARENT_TO_MAIN.SUBMIT_FAILED) {
            this.childWin.webContents.send(this.channel4Child, ipcMessage.MAIN_TO_CHILD.SUBMIT_FAILED, detail);
        }

        if (message === ipcMessage.PARENT_TO_MAIN.CLOSE_DIALOG) {
            this.childWin.setClosable(true);
            this.dialogClosable = true;
            this.childWin.close();
        }

        if (message === ipcMessage.PARENT_TO_MAIN.SEND_PROGRESS) {
            this.childWin.webContents.send(this.channel4Child, ipcMessage.MAIN_TO_CHILD.PROGRESS, detail);
        }

        if (message === ipcMessage.PARENT_TO_MAIN.OPEN_DIALOG_CONNECTING) {
            this.childWin.webContents.send(this.channel4Child, ipcMessage.MAIN_TO_CHILD.OPEN_DIALOG_CONNECTING);
        }
        
        if (message === ipcMessage.PARENT_TO_MAIN.CLOSE_DIALOG_CONNECTING) {
            this.childWin.webContents.send(this.channel4Child, ipcMessage.MAIN_TO_CHILD.CLOSE_DIALOG_CONNECTING);
        }
    });
}

//子画面のリスナーを設定する
Dialog.prototype.setChildListener = function() {
    ipc.on(this.channel4Child, (e, message, detail) => {
        // console.log('childListener.message: ' + message);
        // console.log('childListener.detail: ' + detail);

        this.childWin.on('close', (e) => {
            // [2016-09-20 10:54:55+09:00] kan.k: [TODO] Macの場合だと、
            // ここにこないという事。
            if (this.dialogClosable === false) {
                // console.log('on close  preventDefault');
                e.preventDefault();
                this.childWin.webContents.send(this.channel4Child, ipcMessage.MAIN_TO_CHILD.DIALOG_ON_CLOSE)
            }
        });

        if (message === ipcMessage.CHILD_TO_MAIN.CANCEL) {
            this.parentWin.webContents.send(this.channel4Parent, ipcMessage.MAIN_TO_PARENT.CANCEL, detail);
        }

        if (message === ipcMessage.CHILD_TO_MAIN.FINISH_INIT) {
            // 親画面が最小化された状態で、
            // 小画面が開かれて、閉じられると親画面が操作できなくなる現象対応
            if( process.platform === 'darwin' && this.parentWin.isVisible() === false ) {
                this.parentWin.show();
            }
            this.childWin.show();
            this.parentWin.webContents.send(this.channel4Parent, ipcMessage.MAIN_TO_PARENT.DIALOG_SHOWED, detail);
        }

        if (message === ipcMessage.CHILD_TO_MAIN.GET_PROGRESS) {
            this.parentWin.webContents.send(this.channel4Parent, ipcMessage.MAIN_TO_PARENT.GET_PROGRESS, detail);
        }

        if (message === ipcMessage.CHILD_TO_MAIN.LOADING_CANCEL) {
            this.parentWin.webContents.send(this.channel4Parent, ipcMessage.MAIN_TO_PARENT.LOADING_CANCEL, detail);
        }

        if (message === ipcMessage.CHILD_TO_MAIN.SUBMIT) {
            this.parentWin.webContents.send(this.channel4Parent, ipcMessage.MAIN_TO_PARENT.SUBMIT, detail);
        }

        if (message === ipcMessage.CHILD_TO_MAIN.CLOSE_DIALOG) {
            this.dialogClosable = true;
            this.childWin.close();
        }

        if (message === ipcMessage.CHILD_TO_MAIN.DIALOG_RELAY) {
            // console.log(ipcMessage.CHILD_TO_MAIN.DIALOG_RELAY + ' : ' + detail);
            this.parentWin.webContents.send(this.channel4Parent, ipcMessage.MAIN_TO_PARENT.DIALOG_RELAY, detail);
        }
    });
}

Dialog.prototype.dialogClosed = function() {
    this.childWin.on('closed', () => {
        this.childWin = null;
        this.parentWin.webContents.send(this.channel4Parent, ipcMessage.MAIN_TO_PARENT.DIALOG_CLOSED);
        // MacのMenuをコントロールするために、Explorerの子ダイヤログが開かれたことをExplorerに通知する
        if( process.platform === 'darwin' && this.parentWin.id === mainWindow.id) {
            // console.log(`ExplorerSubWindowClosed: ${this.dialogName}`);
            this.parentWin.webContents.send('ExplorerSubWindowClosed', this.dialogName);
        }
        ipc.removeAllListeners(this.channel4Parent);
        ipc.removeAllListeners(this.channel4Child);
        if(this.dialogChannelEntry) {
            ipc.removeAllListeners(this.dialogChannelEntry);
        }
    });
}


