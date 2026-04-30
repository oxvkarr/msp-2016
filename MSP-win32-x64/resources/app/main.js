const { app, BrowserWindow, session } = require('electron');
const path = require('path');
require('./app');

const flashPath = path.join(__dirname, 'pepflashplayer.dll');
const LOCAL_BASE_URL = 'http://127.0.0.1';
const localHostRules = [
    'MAP 127.0.0.1translations 127.0.0.1',
    'MAP 127.0.0.1localization 127.0.0.1',
    'MAP 127.0.0.1dictionaries 127.0.0.1',
    'MAP cdn.alpha.moviestarplanet.com 127.0.0.1',
    'MAP upload.alpha.moviestarplanet.com 127.0.0.1',
    'MAP alpha.moviestarplanet.com 127.0.0.1',
    'MAP cdn.moviestarplanet.com 127.0.0.1',
    'MAP localcdn.moviestarplanet.com 127.0.0.1',
    'MAP upload.moviestarplanet.com 127.0.0.1',
    'MAP cdnlocaldev.moviestarplanet.com 127.0.0.1',
    'MAP cdndev.moviestarplanet.com 127.0.0.1',
    'MAP cdnlocaltest.moviestarplanet.com 127.0.0.1',
    'MAP cdnlocalrc.moviestarplanet.com 127.0.0.1',
    'MAP cdn.beta.moviestarplanet.com 127.0.0.1',
    'MAP upload.beta.moviestarplanet.com 127.0.0.1',
    'MAP content.mspapis.com 127.0.0.1',
    'MAP mspapis.com 127.0.0.1'
].join(', ');

app.commandLine.appendSwitch('ppapi-flash-path', flashPath);
app.commandLine.appendSwitch('ppapi-flash-version', '32.0.0.465');
app.commandLine.appendSwitch('no-sandbox');
app.commandLine.appendSwitch('disable-web-security');
app.commandLine.appendSwitch('ignore-certificate-errors');
app.commandLine.appendSwitch('allow-running-insecure-content');
app.commandLine.appendSwitch('host-rules', localHostRules);

let mainWindow;

function redirectExternalMspRequests() {
    const filter = {
        urls: [
            '*://*.moviestarplanet.com/*',
            '*://*.moviestarplanet.co.uk/*',
            '*://*.moviestarplanet.de/*',
            '*://*.moviestarplanet.fi/*',
            '*://*.moviestarplanet.fr/*',
            '*://*.moviestarplanet.pl/*',
            '*://*.moviestarplanet.nl/*',
            '*://*.moviestarplanet.no/*',
            '*://*.moviestarplanet.se/*',
            '*://*.moviestarplanet.dk/*',
            '*://*.moviestarplanet.com.tr/*',
            '*://*.moviestarplanet.com.au/*',
            '*://*.moviestarplanet.co.nz/*',
            '*://*.moviestarplanet.ca/*',
            '*://*.moviestarplanet.ie/*',
            '*://*.moviestarplanet.es/*',
            '*://*.moviestarplanet.it/*',
            '*://*.moviestarplanet.br/*',
            '*://*.mspapis.com/*'
        ]
    };

    session.defaultSession.webRequest.onBeforeRequest(filter, (details, callback) => {
        try {
            const url = new URL(details.url);
            if (url.protocol === 'http:' && url.hostname === '127.0.0.1') {
                callback({});
                return;
            }

            const redirectURL = `${LOCAL_BASE_URL}${url.pathname}${url.search}`;
            console.log(`[REDIRECT] ${details.url} -> ${redirectURL}`);
            callback({ redirectURL });
        } catch (err) {
            callback({});
        }
    });
}

function createWindow() {
    redirectExternalMspRequests();

    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        title: 'MSP Private Server',
        webPreferences: {
            plugins: true,
            contextIsolation: false,
            nodeIntegration: true,
            webSecurity: false
        }
    });

    mainWindow.webContents.openDevTools({ mode: 'detach' });
    mainWindow.loadURL('http://127.0.0.1/play.html');
}

app.on('ready', createWindow);
app.on('window-all-closed', () => app.quit());
