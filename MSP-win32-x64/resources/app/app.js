const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { Writable } = require('stream');
const amfjs = require('amfjs');
const { MongoClient } = require('mongodb');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const app = express();

const publicPath = path.join(__dirname, 'public');
const assetCachePath = path.join(__dirname, 'asset-cache');
const dbPath = path.join(__dirname, 'msp-db.json');
const debugLogPath = path.join(__dirname, 'msp-debug.log');
const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URI || '';
const mongoDbName = process.env.MONGODB_DB || 'msp_2016';
const mongoStateCollection = process.env.MONGODB_STATE_COLLECTION || 'state';
const defaultRemoteAssetBaseUrl = 'https://pub-2ec8e3c2f0a24e46ab1defac06482eb3.r2.dev';
const remoteAssetBaseUrl = (process.env.REMOTE_ASSET_BASE_URL || defaultRemoteAssetBaseUrl).replace(/\/+$/, '');
const remoteGatewayUrl = (process.env.REMOTE_GATEWAY_URL || '').replace(/\/+$/, '');
const isDebugMode = process.env.MSP_DEBUG === '1';
const normalizeLocaleCode = (value) => {
    const parts = String(value || 'pl_PL').replace('-', '_').split('_');
    const language = (parts[0] || 'pl').toLowerCase();
    const country = (parts[1] || language).toUpperCase();
    return `${language}_${country}`;
};
const forcedLocale = normalizeLocaleCode(process.env.MSP_LOCALE || 'pl_PL');
const forcedLocalePath = forcedLocale.toLowerCase();
let mongoClient = null;
let mongoDatabase = null;
let dbSource = 'json';
const recentLogs = [];
const log = (message) => {
    const line = `${new Date().toISOString()} ${message}`;
    recentLogs.push(line);
    if (recentLogs.length > 500) {
        recentLogs.shift();
    }
    if (isDebugMode) {
        console.log(message);
        fs.appendFile(debugLogPath, `${line}\n`, () => {});
    }
};

app.use(express.raw({ type: '*/*', limit: '50mb' }));

app.use((req, res, next) => {
    log(`[REQ] ${req.method} ${req.url} host=${req.headers.host || ''}`);
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "*");
    next();
});

// Sztywne serwowanie crossdomain - to musi zatrzymać pętlę
app.all('/crossdomain.xml', (req, res) => {
    log(`[POLICY] ${req.headers.host || ''}${req.url}`);
    res.set('Content-Type', 'text/xml');
    res.send(`<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*" to-ports="*" /></cross-domain-policy>`);
});

const fallbackPlayHtml = () => `<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>MSP</title>
    <style>
        html, body {
            width: 100%;
            height: 100%;
            margin: 0;
            overflow: hidden;
            background: #000;
        }
        object, embed {
            width: 100%;
            height: 100%;
            display: block;
        }
        #debug-console {
            position: fixed;
            right: 14px;
            bottom: 14px;
            z-index: 999999;
            width: 440px;
            max-width: calc(100vw - 28px);
            height: 260px;
            display: none;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,.18);
            border-radius: 8px;
            background: rgba(14, 18, 28, .94);
            box-shadow: 0 16px 60px rgba(0,0,0,.45);
            color: #e8eefc;
            font: 12px Consolas, monospace;
        }
        #debug-console header {
            height: 34px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 10px;
            background: rgba(255,255,255,.08);
            font: 600 12px Arial, sans-serif;
        }
        #debug-console button {
            height: 24px;
            border: 0;
            border-radius: 5px;
            background: #2f80ed;
            color: #fff;
            cursor: pointer;
            font: 600 11px Arial, sans-serif;
        }
        #debug-log {
            height: 226px;
            margin: 0;
            padding: 10px;
            overflow: auto;
            white-space: pre-wrap;
            box-sizing: border-box;
        }
    </style>
</head>
<body>
    <object id="msp" type="application/x-shockwave-flash" data="/Main_20161102_160430.swf">
        <param name="movie" value="/Main_20161102_160430.swf">
        <param name="allowScriptAccess" value="always">
        <param name="allowFullScreen" value="true">
        <param name="wmode" value="direct">
        <param name="flashvars" value="resourceModuleUrl=swf/locales/${forcedLocalePath}_resourcemodule.swf?v=Main_20161102_160430&swfVer=Main_20161102_160430&translationsVersion=2016112_16431">
        <embed src="/Main_20161102_160430.swf" allowScriptAccess="always" allowFullScreen="true" wmode="direct" flashvars="resourceModuleUrl=swf/locales/${forcedLocalePath}_resourcemodule.swf?v=Main_20161102_160430&swfVer=Main_20161102_160430&translationsVersion=2016112_16431">
    </object>
    <div id="debug-console">
        <header>
            <span>MSP Debug Console</span>
            <button id="debug-clear" type="button">Clear</button>
        </header>
        <pre id="debug-log"></pre>
    </div>
    <script>
        (function () {
            var debug = new URLSearchParams(location.search).get('debug') === '1';
            var panel = document.getElementById('debug-console');
            var output = document.getElementById('debug-log');
            var clear = document.getElementById('debug-clear');
            function write(level, args) {
                if (!debug || !output) return;
                var text = Array.prototype.slice.call(args).map(function (item) {
                    if (typeof item === 'string') return item;
                    try { return JSON.stringify(item); } catch (e) { return String(item); }
                }).join(' ');
                output.textContent += '[' + level + '] ' + text + '\\n';
                output.scrollTop = output.scrollHeight;
            }
            if (debug && panel) panel.style.display = 'block';
            ['log', 'warn', 'error'].forEach(function (level) {
                var original = console[level];
                console[level] = function () {
                    write(level.toUpperCase(), arguments);
                    return original.apply(console, arguments);
                };
            });
            window.onerror = function (message, source, line) {
                write('ERROR', [message + ' @ ' + source + ':' + line]);
            };
            if (clear) clear.onclick = function () { output.textContent = ''; };
            console.log('Fallback play.html loaded');
            if (debug) {
                var serverLogCursor = 0;
                var pollServerLogs = function () {
                    fetch('/api/debug/logs?since=' + serverLogCursor)
                        .then(function (response) {
                            if (!response.ok) throw new Error('HTTP ' + response.status);
                            return response.json();
                        })
                        .then(function (data) {
                            serverLogCursor = data.next || serverLogCursor;
                            (data.lines || []).forEach(function (line) {
                                write('SERVER', [line.replace(/^\\d{4}-\\d{2}-\\d{2}T[^ ]+ /, '')]);
                            });
                        })
                        .catch(function (error) {
                            write('SERVER', ['debug logs unavailable: ' + error.message]);
                        });
                };
                pollServerLogs();
                setInterval(pollServerLogs, 1000);
            }
        }());
    </script>
</body>
</html>`;

const sendPlayHtml = (req, res) => {
    const filePath = path.join(publicPath, 'play.html');
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
        return;
    }
    log(`[FALLBACK] ${req.url} -> embedded play.html`);
    res.type('html').send(fallbackPlayHtml());
};


app.get(['/', '/play.html'], sendPlayHtml);
app.get('/cdnpath.txt', (req, res) => {
    res.type('text/plain').send('http://127.0.0.1/');
});

const sanitizeLocalMap = (text) => text
    .replace(/https?:\/\/(?:localcdn|cdn|upload|cdndev|cdnlocaldev|cdnlocaltest|cdnlocalrc|cdn\.alpha|upload\.alpha|cdn\.beta|upload\.beta|cdn\.rc|uploadtest|cdntest|cdnupload)\.moviestarplanet(?:\.[a-z]+)?(?:\.[a-z]+)?\//gi, 'http://127.0.0.1/')
    .replace(/https?:\/\/(?:alpha|beta|dev|test|rc|www|info)\.moviestarplanet(?:\.[a-z]+)?(?:\.[a-z]+)?\//gi, 'http://127.0.0.1/')
    .replace(/https?:\/\/(?:[a-z0-9-]+\.)?mspapis\.com\//gi, 'http://127.0.0.1/')
    .replace(/https?:\/\/(?:[a-z0-9-]+\.)?mspcdns\.com\//gi, 'http://127.0.0.1/');

const remoteAssetExtensions = new Set([
    '.swf', '.png', '.jpg', '.jpeg', '.gif', '.mp3', '.txt', '.xml', '.json', '.css', '.html', '.js'
]);

const contentTypeFor = (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return {
        '.swf': 'application/x-shockwave-flash',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.mp3': 'audio/mpeg',
        '.txt': 'text/plain',
        '.xml': 'text/xml',
        '.json': 'application/json',
        '.css': 'text/css',
        '.html': 'text/html',
        '.js': 'application/javascript'
    }[ext] || 'application/octet-stream';
};

const downloadRemoteAsset = (url, destination) => new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    const request = client.get(url, (response) => {
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
            response.resume();
            downloadRemoteAsset(new URL(response.headers.location, url).toString(), destination).then(resolve, reject);
            return;
        }
        if (response.statusCode !== 200) {
            response.resume();
            reject(new Error(`HTTP ${response.statusCode}`));
            return;
        }
        const tempFile = `${destination}.download`;
        const stream = fs.createWriteStream(tempFile);
        response.pipe(stream);
        stream.on('finish', () => {
            stream.close(() => {
                fs.rename(tempFile, destination, (err) => err ? reject(err) : resolve(destination));
            });
        });
        stream.on('error', reject);
    });
    request.on('error', reject);
    request.setTimeout(15000, () => {
        request.destroy(new Error('Remote asset timeout'));
    });
});

const proxyGatewayRequest = (req, res, method) => {
    if (!remoteGatewayUrl) return false;

    const targetUrl = new URL(`${remoteGatewayUrl}/Gateway.aspx`);
    if (method) {
        targetUrl.searchParams.set('method', method);
    }
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const client = targetUrl.protocol === 'https:' ? https : http;
    const proxyReq = client.request(targetUrl, {
        method: req.method,
        headers: {
            'content-type': req.headers['content-type'] || 'application/x-amf',
            'content-length': body.length
        },
        timeout: 20000
    }, (proxyRes) => {
        res.status(proxyRes.statusCode || 502);
        res.set('Content-Type', proxyRes.headers['content-type'] || 'application/x-amf');
        proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
        log(`[REMOTE GATEWAY FAIL] ${targetUrl.toString()} ${err.message}`);
        res.status(502).type('text/plain').send('Remote gateway unavailable');
    });
    proxyReq.on('timeout', () => {
        proxyReq.destroy(new Error('Remote gateway timeout'));
    });
    proxyReq.end(body);
    log(`[REMOTE GATEWAY] ${method || ''} -> ${targetUrl.toString()}`);
    return true;
};

const serveRemoteAsset = async (req, res, cleanPath) => {
    if (!remoteAssetBaseUrl || !remoteAssetExtensions.has(path.extname(cleanPath).toLowerCase())) {
        return false;
    }
    if (!cleanPath || cleanPath.includes('..')) {
        return false;
    }

    const cachedPath = path.join(assetCachePath, cleanPath);
    if (fs.existsSync(cachedPath) && fs.statSync(cachedPath).isFile()) {
        res.type(contentTypeFor(cachedPath)).sendFile(cachedPath);
        return true;
    }

    const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const candidates = [
        `${remoteAssetBaseUrl}/${cleanPath}${query}`,
        `${remoteAssetBaseUrl}/${cleanPath.toLowerCase()}${query}`
    ];

    for (const remoteUrl of candidates) {
        try {
            await downloadRemoteAsset(remoteUrl, cachedPath);
            log(`[REMOTE ASSET] ${req.url} -> ${remoteUrl}`);
            res.type(contentTypeFor(cachedPath)).sendFile(cachedPath);
            return true;
        } catch (err) {
            log(`[REMOTE ASSET TRY MISS] ${remoteUrl} ${err.message}`);
        }
    }

    return false;
};

app.get(['/languagemaps.txt', '/localization/languagemaps.txt'], async (req, res) => {
    const filePath = path.join(publicPath, req.path.replace(/^\/+/, ''));
    log(`[LANGMAP] ${req.url} -> ${filePath}`);
    fs.readFile(filePath, 'utf8', (err, text) => {
        if (err) {
            serveRemoteAsset(req, res, req.path.replace(/^\/+/, '')).then((served) => {
                if (!served) {
                    res.status(404).type('text/plain').send(`Missing language map: ${req.url}`);
                }
            });
            return;
        }
        res.type('application/json').send(sanitizeLocalMap(text));
    });
});

app.get(/^\/(?:null)?lookdata_[0-9_]+$/i, (req, res) => {
    log(`[LOOKDATA] ${req.url}`);
    res.type('application/octet-stream').send(lookDataPayload());
});

app.get(/^\/Main_20161102_160430\.swf$/i, async (req, res, next) => {
    const filePath = path.join(publicPath, 'main_20161102_160430.swf');
    if (fs.existsSync(filePath)) {
        res.type('application/x-shockwave-flash').sendFile(filePath);
        return;
    }
    if (await serveRemoteAsset(req, res, 'main_20161102_160430.swf')) {
        return;
    }
    next();
});

app.get(/^\/msp\/[^/]+\/(.+)$/i, (req, res, next) => {
    const requestedPath = req.params[0];
    if (!requestedPath || requestedPath.includes('..')) {
        next();
        return;
    }

    const filePath = path.join(publicPath, requestedPath);
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
        next();
        return;
    }

    log(`[VERSIONED ASSET] ${req.url} -> ${filePath}`);
    res.sendFile(filePath);
});

app.all('/translations/crossdomain.xml', (req, res) => {
    log(`[POLICY] ${req.headers.host || ''}${req.url}`);
    res.set('Content-Type', 'text/xml');
    res.send(`<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*" to-ports="*" /></cross-domain-policy>`);
});

app.get('/:client(MSPWeb|MSPMobile)/:locale/myResources.txt', async (req, res) => {
    const client = req.params.client.toLowerCase();
    const filePath = path.join(__dirname, 'public', 'translations', client, forcedLocalePath, 'myresources.txt');
    log(`[TRANSLATION] ${req.url} -> ${filePath}`);
    if (fs.existsSync(filePath)) {
        res.type('text/plain').sendFile(filePath);
        return;
    }
    const remotePaths = [
        `${req.params.client}/${forcedLocale}/myResources.txt`,
        `translations/${client}/${forcedLocalePath}/myresources.txt`
    ];
    for (const remotePath of remotePaths) {
        if (await serveRemoteAsset(req, res, remotePath)) {
            return;
        }
    }
    log(`[TRANSLATION MISS] ${filePath}`);
    res.status(404).type('text/plain').send(`Missing translation: ${req.url}`);
});

app.use(express.static(publicPath));

app.get('*', async (req, res, next) => {
    if (await serveRemoteAsset(req, res, req.path.replace(/^\/+/, ''))) {
        return;
    }
    log(`[REMOTE ASSET MISS] ${req.url}`);
    next();
});

const readUtf = (buffer, offset) => {
    const length = buffer.readUInt16BE(offset);
    const start = offset + 2;
    return {
        value: buffer.slice(start, start + length).toString('utf8'),
        offset: start + length
    };
};

const skipAmfEnvelopeHeaders = (buffer, offset, count) => {
    for (let i = 0; i < count; i++) {
        const name = readUtf(buffer, offset);
        offset = name.offset + 1;
        const length = buffer.readInt32BE(offset);
        offset += 4;
        if (length >= 0) {
            offset += length;
        }
    }
    return offset;
};

const parseAmfEnvelope = (buffer) => {
    if (!Buffer.isBuffer(buffer) || buffer.length < 6) {
        return null;
    }
    let offset = 0;
    const version = buffer.readUInt16BE(offset);
    offset += 2;
    const headerCount = buffer.readUInt16BE(offset);
    offset += 2;
    offset = skipAmfEnvelopeHeaders(buffer, offset, headerCount);
    const messageCount = buffer.readUInt16BE(offset);
    offset += 2;
    const messages = [];
    for (let i = 0; i < messageCount; i++) {
        const target = readUtf(buffer, offset);
        offset = target.offset;
        const response = readUtf(buffer, offset);
        offset = response.offset;
        const length = buffer.readInt32BE(offset);
        offset += 4;
        const bodyStart = offset;
        const bodyEnd = length >= 0 ? offset + length : buffer.length;
        messages.push({
            target: target.value,
            response: response.value,
            length,
            bodyStart,
            body: buffer.slice(bodyStart, bodyEnd)
        });
        offset = bodyEnd;
    }
    return { version, messages };
};

const writeUtf = (value) => {
    const bytes = Buffer.from(value, 'utf8');
    const length = Buffer.alloc(2);
    length.writeUInt16BE(bytes.length);
    return Buffer.concat([length, bytes]);
};

const amf0String = (value) => {
    const bytes = Buffer.from(String(value), 'utf8');
    const header = Buffer.alloc(3);
    header[0] = 0x02;
    header.writeUInt16BE(bytes.length, 1);
    return Buffer.concat([header, bytes]);
};

const amf0Number = (value) => {
    const buffer = Buffer.alloc(9);
    buffer[0] = 0x00;
    buffer.writeDoubleBE(Number(value) || 0, 1);
    return buffer;
};

const amf0Boolean = (value) => Buffer.from([0x01, value ? 1 : 0]);
const amf0Null = () => Buffer.from([0x05]);

const amf0Array = (items) => {
    const length = Buffer.alloc(5);
    length[0] = 0x0a;
    length.writeUInt32BE(items.length, 1);
    return Buffer.concat([length, ...items.map(amf0Value)]);
};

const amf0Object = (object) => {
    const parts = [Buffer.from([0x03])];
    Object.keys(object).forEach((key) => {
        parts.push(writeUtf(key));
        parts.push(amf0Value(object[key]));
    });
    parts.push(Buffer.from([0x00, 0x00, 0x09]));
    return Buffer.concat(parts);
};

const amf0Value = (value) => {
    if (value === null || value === undefined) {
        return amf0Null();
    }
    if (Array.isArray(value)) {
        return amf0Array(value);
    }
    if (typeof value === 'boolean') {
        return amf0Boolean(value);
    }
    if (typeof value === 'number') {
        return amf0Number(value);
    }
    if (typeof value === 'object') {
        return amf0Object(value);
    }
    return amf0String(value);
};

const amf3U29 = (value) => {
    value &= 0x1fffffff;
    if (value < 0x80) return Buffer.from([value]);
    if (value < 0x4000) return Buffer.from([(value >> 7) | 0x80, value & 0x7f]);
    if (value < 0x200000) return Buffer.from([(value >> 14) | 0x80, ((value >> 7) & 0x7f) | 0x80, value & 0x7f]);
    return Buffer.from([(value >> 22) | 0x80, ((value >> 15) & 0x7f) | 0x80, ((value >> 8) & 0x7f) | 0x80, value & 0xff]);
};

const amf3Utf = (value) => {
    const bytes = Buffer.from(String(value || ''), 'utf8');
    return Buffer.concat([amf3U29((bytes.length << 1) | 1), bytes]);
};

const amf3Value = (value) => {
    if (value === undefined || value === null) return Buffer.from([0x01]);
    if (value === false) return Buffer.from([0x02]);
    if (value === true) return Buffer.from([0x03]);
    if (typeof value === 'number') {
        if (Number.isInteger(value) && value >= -268435456 && value <= 268435455) {
            return Buffer.concat([Buffer.from([0x04]), amf3U29(value)]);
        }
        const buffer = Buffer.alloc(9);
        buffer[0] = 0x05;
        buffer.writeDoubleBE(value, 1);
        return buffer;
    }
    if (typeof value === 'string') return Buffer.concat([Buffer.from([0x06]), amf3Utf(value)]);
    if (value instanceof Date) {
        const buffer = Buffer.alloc(8);
        buffer.writeDoubleBE(value.getTime(), 0);
        return Buffer.concat([Buffer.from([0x08]), amf3U29(1), buffer]);
    }
    if (Buffer.isBuffer(value)) {
        return Buffer.concat([Buffer.from([0x0c]), amf3U29((value.length << 1) | 1), value]);
    }
    if (Array.isArray(value)) {
        return Buffer.concat([
            Buffer.from([0x09]),
            amf3U29((value.length << 1) | 1),
            amf3Utf(''),
            ...value.map(amf3Value)
        ]);
    }
    if (typeof value === 'object') {
        const className = value.__class || '';
        const keys = Object.keys(value).filter((key) => key !== '__class');
        return Buffer.concat([
            Buffer.from([0x0a]),
            amf3U29((keys.length << 4) | 3),
            amf3Utf(className),
            ...keys.map(amf3Utf),
            ...keys.map((key) => amf3Value(value[key]))
        ]);
    }
    return Buffer.concat([Buffer.from([0x06]), amf3Utf(String(value))]);
};

const typed = (__class, object) => Object.assign({ __class }, object);

const amf0Amf3Value = (value) => Buffer.concat([Buffer.from([0x11]), amf3Value(value)]);

const toAmfSerializable = (value) => {
    if (value === undefined || value === null) return value;
    if (value instanceof Date || Buffer.isBuffer(value)) return value;
    if (Array.isArray(value)) return value.map(toAmfSerializable);
    if (typeof value !== 'object') return value;

    const output = new amfjs.Serializable(value.__class || '');
    Object.keys(value).forEach((key) => {
        if (key !== '__class') {
            output[key] = toAmfSerializable(value[key]);
        }
    });
    return output;
};

const amfjsBody = (value, useAmf3) => {
    const chunks = [];
    const sink = new Writable({
        write(chunk, encoding, callback) {
            chunks.push(Buffer.from(chunk));
            callback();
        }
    });
    const encoder = new amfjs.AMFEncoder(sink);
    const encodedValue = toAmfSerializable(value);

    if (useAmf3) {
        encoder.encode(encodedValue, amfjs.AMF3);
    } else {
        encoder.writeObject(encodedValue, amfjs.AMF0);
    }

    return Buffer.concat(chunks);
};

const decodeAmfjsBody = (body) => {
    if (!Buffer.isBuffer(body) || body.length === 0) return null;
    let offset = 0;
    const reader = {
        read(length = 1) {
            if (offset >= body.length) return null;
            const end = Math.min(offset + length, body.length);
            const chunk = body.slice(offset, end);
            offset = end;
            return chunk;
        }
    };
    const decoder = new amfjs.AMFDecoder(reader);
    return decoder.decode(amfjs.AMF0);
};

const previewValue = (value, limit = 900) => {
    const seen = new WeakSet();
    const text = JSON.stringify(value, (key, innerValue) => {
        if (typeof innerValue === 'object' && innerValue !== null) {
            if (seen.has(innerValue)) return '[Circular]';
            seen.add(innerValue);
        }
        if (Buffer.isBuffer(innerValue)) return `[Buffer ${innerValue.length}]`;
        return innerValue;
    });
    return text && text.length > limit ? `${text.slice(0, limit)}...` : text;
};

const buildAmfResponse = (version, responseUri, value, options = {}) => {
    let body;
    let usedAmfjs = true;
    try {
        body = amfjsBody(value, options.amf3);
    } catch (err) {
        log(`[AMFJS FALLBACK] ${err.message}`);
        usedAmfjs = false;
        body = options.amf3 ? amf0Amf3Value(value) : amf0Value(value);
    }
    if (options.debugLabel) {
        log(`[AMF RESPONSE] ${options.debugLabel} amf=${options.amf3 ? 'AMF3' : 'AMF0'} encoder=${usedAmfjs ? 'amfjs' : 'legacy'} length=${body.length} hex=${body.slice(0, 32).toString('hex')}`);
    }
    const length = Buffer.alloc(4);
    length.writeInt32BE(body.length);
    const envelope = Buffer.alloc(4);
    envelope.writeUInt16BE(version || 0, 0);
    envelope.writeUInt16BE(0, 2);
    const messageCount = Buffer.alloc(2);
    messageCount.writeUInt16BE(1);
    const target = writeUtf(`${responseUri || '/1'}/onResult`);
    const response = writeUtf('');
    return Buffer.concat([envelope, messageCount, target, response, length, body]);
};

const facePart = (className, idField, id, swf, colors = '') => typed(className, {
    [idField]: id,
    [`_${idField}`]: id,
    Id: id,
    id,
    SWF: swf,
    _SWF: swf,
    DragonBone: swf.replace(/\/texture\.swf$/i, ''),
    _DragonBone: swf.replace(/\/texture\.swf$/i, ''),
    SWFLocation: swf,
    _SWFLocation: swf,
    SkinId: 0,
    _SkinId: 0,
    DefaultColors: colors,
    _DefaultColors: colors,
    RegNewUser: true,
    _RegNewUser: true,
    sortorder: id,
    _sortorder: id,
    hidden: false,
    initialAnimation: ''
});

const cloth = (id, swf, filename, slotTypeId, gender, colors = '') => {
    const slotType = typed('com.moviestarplanet.moviestar.valueObjects.SlotType', {
        SlotTypeId: slotTypeId,
        _SlotTypeId: slotTypeId
    });
    const clothesCategory = typed('com.moviestarplanet.moviestar.valueObjects.ClothesCategory', {
        ClothesCategoryId: slotTypeId,
        _ClothesCategoryId: slotTypeId,
        SlotTypeId: slotTypeId,
        _SlotTypeId: slotTypeId,
        SlotType: slotType,
        _SlotType: slotType
    });
    const item = typed('com.moviestarplanet.moviestar.valueObjects.Cloth', {
        ClothId: id,
        ClothesId: id,
        Id: id,
        SWF: swf,
        _SWF: swf,
        Filename: filename,
        _Filename: filename,
        Price: 0,
        _Price: 0,
        ShopId: 0,
        _ShopId: 0,
        SkinId: 0,
        _SkinId: 0,
        Scale: 1,
        _Scale: 1,
        Vip: false,
        _Vip: false,
        RegNewUser: true,
        _RegNewUser: true,
        sortorder: id,
        _sortorder: id,
        isNew: false,
        _isNew: false,
        Discount: 0,
        _Discount: 0,
        MouseAction: '',
        _MouseAction: '',
        DiamondsPrice: 0,
        _DiamondsPrice: 0,
        ColorScheme: colors,
        _ColorScheme: colors,
        Gender: gender,
        ClothesCategory: clothesCategory,
        _ClothesCategory: clothesCategory,
        ThemeId: 0,
        _ThemeId: 0
    });

    return typed('com.moviestarplanet.moviestar.valueObjects.ActorClothesRel', {
        ActorClothesRelId: id,
        _ActorClothesRelId: id,
        ClothesId: id,
        _ClothesId: id,
        Color: colors,
        _Color: colors,
        IsWearing: true,
        _IsWearing: true,
        x: 0,
        _x: 0,
        y: 0,
        _y: 0,
        Cloth: item,
        _Cloth: item
    });
};

const withCollectionAliases = (data) => {
    Object.keys(data).forEach((key) => {
        data[`_${key}`] = data[key];
        data[key.charAt(0).toUpperCase() + key.slice(1)] = data[key];
    });
    return data;
};

const starterClothes = () => [
    cloth(1001, 'swf/stuff/nickelodeon_spotlight_girlstop_fj.swf', 'nickelodeon_spotlight_girlstop_fj.swf', 3, 'Female', '0xff66aa,0xffffff'),
    cloth(1002, 'swf/stuff/nickelodeon_spotlight_boystop_fj.swf', 'nickelodeon_spotlight_boystop_fj.swf', 3, 'Male', '0x3366cc,0xffffff'),
    cloth(1003, 'swf/stuff/birthdaycampaign_2013_boystop_ms_mf.swf', 'birthdaycampaign_2013_boystop_ms_mf.swf', 3, 'Male', '0x1e63aa,0xffffff'),
    cloth(1004, 'swf/stuff/nickelodeon_2015_maletopred_mf.swf', 'nickelodeon_2015_maletopred_mf.swf', 4, 'Male', '0xcc3333,0xffffff'),
    ...catalogClothes(30)
];

const registerNewUserData = () => withCollectionAliases(typed('com.moviestarplanet.moviestar.valueObjects.RegisterNewUserData', {
    eyes: [
        facePart('com.moviestarplanet.moviestar.valueObjects.Eye', 'EyeId', 1, 'swf/dragonbone_faceparts/eyes/eyes_girlnextdoor_2013/texture.swf', '0x5b351c'),
        facePart('com.moviestarplanet.moviestar.valueObjects.Eye', 'EyeId', 2, 'swf/dragonbone_faceparts/eyes/eyes_boynextdoor_2013/texture.swf', '0x5b351c'),
        facePart('com.moviestarplanet.moviestar.valueObjects.Eye', 'EyeId', 3, 'swf/dragonbone_faceparts/eyes/eyes_moviestar_2013/texture.swf', '0x3a6eb5'),
        facePart('com.moviestarplanet.moviestar.valueObjects.Eye', 'EyeId', 4, 'swf/dragonbone_faceparts/eyes/eyes_theman_2013/texture.swf', '0x2d251c')
    ],
    noses: [
        facePart('com.moviestarplanet.moviestar.valueObjects.Nose', 'NoseId', 1, 'swf/world/shopicons/nose.swf'),
        facePart('com.moviestarplanet.moviestar.valueObjects.Nose', 'NoseId', 2, 'swf/world/shopicons/nose.swf')
    ],
    mouths: [
        facePart('com.moviestarplanet.moviestar.valueObjects.Mouth', 'MouthId', 1, 'swf/world/shopicons/mouth.swf', '0xd45a6a'),
        facePart('com.moviestarplanet.moviestar.valueObjects.Mouth', 'MouthId', 2, 'swf/world/shopicons/mouth.swf', '0xb64254')
    ],
    eyeShadows: [
        facePart('com.moviestarplanet.moviestar.valueObjects.EyeShadow', 'EyeShadowId', 0, 'swf/dragonbone_faceparts/eyeshadow/eyeshadow_femalestar_2013/texture.swf', '0xffffff'),
        facePart('com.moviestarplanet.moviestar.valueObjects.EyeShadow', 'EyeShadowId', 1, 'swf/dragonbone_faceparts/eyeshadow/eyeshadow_party_2013/texture.swf', '0x333333')
    ],
    skins: [
        { SkinId: 1, _SkinId: 1, SWF: 'swf/skins/femaleskin.swf', _SWF: 'swf/skins/femaleskin.swf', SkinColor: '0xffd1b3', _SkinColor: '0xffd1b3', Gender: 'Female' },
        { SkinId: 2, _SkinId: 2, SWF: 'swf/skins/maleskin.swf', _SWF: 'swf/skins/maleskin.swf', SkinColor: '0xffd1b3', _SkinColor: '0xffd1b3', Gender: 'Male' }
    ],
    skinColors: ['0xffd1b3', '0xe8b48f', '0xc58a65', '0x8a5a44'],
    clothes: starterClothes(),
    hairs: starterClothes().filter((item) => item.Cloth && item.Cloth.ClothesCategory && item.Cloth.ClothesCategory.SlotTypeId === 2),
    tops: starterClothes().filter((item) => item.Cloth && item.Cloth.ClothesCategory && item.Cloth.ClothesCategory.SlotTypeId === 3),
    bottoms: starterClothes().filter((item) => item.Cloth && item.Cloth.ClothesCategory && item.Cloth.ClothesCategory.SlotTypeId === 4),
    shoes: starterClothes().filter((item) => item.Cloth && item.Cloth.ClothesCategory && item.Cloth.ClothesCategory.SlotTypeId === 5),
    defaultFemaleSkinSWF: 'swf/skins/femaleskin.swf',
    defaultMaleSkinSWF: 'swf/skins/maleskin.swf'
}));

const DEV_ACTOR_ID = 1;
const DEV_USERNAME = 'admin';
const DEV_PASSWORD = 'admin';

const actorDefaults = (actorRecord = {}) => {
    const actor = actorRecord || {};
    return {
    actorId: actor.actorId || actor.ActorId || DEV_ACTOR_ID,
    name: actor.name || actor.Name || DEV_USERNAME,
    level: actor.level || actor.Level || 101,
    money: actor.money || actor.Money || 999999999,
    diamonds: actor.diamonds || actor.Diamonds || 999999999,
    fame: actor.fame || actor.Fame || 999999999,
    fortune: actor.fortune || actor.Fortune || 999999999,
    skinSWF: actor.skinSWF || actor.SkinSWF || 'swf/skins/maleskin.swf',
    skinColor: actor.skinColor || actor.SkinColor || '0xffd1b3',
    eyeId: actor.eyeId || actor.EyeId || 2,
    noseId: actor.noseId || actor.NoseId || 1,
    mouthId: actor.mouthId || actor.MouthId || 1
};
};

const devActorDetails = (actorRecord = null) => {
    const actor = actorDefaults(actorRecord);
    return typed('com.moviestarplanet.usersession.valueobjects.ActorDetails', {
    ActorId: actor.actorId,
    Name: actor.name,
    Level: actor.level,
    SkinSWF: actor.skinSWF,
    _SkinSWF: actor.skinSWF,
    SkinColor: actor.skinColor,
    NoseId: actor.noseId,
    EyeId: actor.eyeId,
    MouthId: actor.mouthId,
    Money: actor.money,
    EyeColors: '0x5b351c',
    MouthColors: '0xd45a6a',
    Fame: actor.fame,
    Fortune: actor.fortune,
    FriendCount: 0,
    ProfileText: 'Local admin/dev account',
    Moderator: 0,
    ProfileDisplays: 0,
    FavoriteMovie: '',
    FavoriteActor: '',
    FavoriteActress: '',
    FavoriteSinger: '',
    FavoriteSong: '',
    IsExtra: 0,
    HasUnreadMessages: 0,
    InvitedByActorId: 0,
    PollTaken: 1,
    ValueOfGiftsReceived: 0,
    ValueOfGiftsGiven: 0,
    NumberOfGiftsGiven: 0,
    NumberOfGiftsReceived: 0,
    NumberOfAutographsReceived: 0,
    NumberOfAutographsGiven: 0,
    FacebookId: '',
    BoyfriendId: 0,
    BoyfriendStatus: 0,
    BehaviourStatus: 0,
    LockedText: '',
    BadWordCount: 0,
    EmailValidated: 1,
    RetentionStatus: 0,
    GiftStatus: 0,
    MarketingNextStepLogins: 0,
    MarketingStep: 0,
    TotalVipDays: 9999,
    RecyclePoints: 0,
    EmailSettings: 0,
    TimeOfLastAutographGivenStr: '',
    BestFriendId: 0,
    BestFriendStatus: 0,
    FriendCountVIP: 0,
    ForceNameChange: 0,
    CreationRewardStep: 0,
    NameBeforeDeleted: '',
    LastTransactionId: 0,
    AllowCommunication: 1,
    Diamonds: 999999999,
    PopUpStyleId: 0,
    BoyFriend: null,
    ActorClothesRels: starterClothes().slice(0, 6),
    _ActorClothesRels: starterClothes().slice(0, 6),
    ActorClothesRels2: starterClothes().slice(0, 6),
    _ActorClothesRels2: starterClothes().slice(0, 6),
    Animations: [{
        ActorAnimationRelId: 1,
        AnimationId: 1,
        SWF: 'swf/animationtest.swf',
        Name: 'stand',
        InitialAnimation: 'stand'
    }],
    ActorPersonalInfo: typed('com.moviestarplanet.usersession.valueobjects.ActorPersonalInfo', {
        ActorId: actor.actorId,
        ParentEmail: '',
        ChatAllowed: 1,
        ActorEmailAllowed: 1,
        BirthMonth: 1,
        BirthYear: 2000,
        ParentConsentEmailSent: false,
        UserEmailParentOptOut: false,
        ParentEmailConfirmed: true,
        RealBirthdayCollected: true,
        YoutubeAllowed: true
    }),
    ActorRelationships: []
});
};

const makePostLoginSequence = (className) => typed(className, {
    ShowCampaign: false,
    ShowVipRebuy: false
});

const postLoginSequence = () => makePostLoginSequence('com.moviestarplanet.valueObjects.PostLoginSequenceDomain');
const servicePostLoginSequence = () => makePostLoginSequence('com.moviestarplanet.services.userservice.valueObjects.PostLoginSequenceDomain');

const loginActorPersonalInfo = () => typed('MovieStarPlanet.DBML.ActorPersonalInfo', {
    ActorId: DEV_ACTOR_ID,
    BirthDate: null,
    ParentEmail: '',
    ChatAllowed: 1,
    ActorEmailAllowed: 1,
    BirthMonth: 1,
    BirthYear: 2000,
    ParentConsentEmailSent: false,
    UserEmailParentOptOut: false,
    ParentEmailConfirmed: true,
    RealBirthdayCollected: true,
    YoutubeAllowed: true
});

const loginActorDetails = (actorRecord = null) => {
    const actor = actorDefaults(actorRecord);
    return typed('MovieStarPlanet.DBML.ActorDetails', {
    ActorId: actor.actorId,
    Name: actor.name,
    Level: actor.level,
    SkinSWF: actor.skinSWF,
    _SkinSWF: actor.skinSWF,
    SkinColor: actor.skinColor,
    NoseId: actor.noseId,
    EyeId: actor.eyeId,
    MouthId: actor.mouthId,
    Money: actor.money,
    EyeColors: '0x5b351c',
    MouthColors: '0xd45a6a',
    Fame: actor.fame,
    Fortune: actor.fortune,
    FriendCount: 0,
    ProfileText: 'Local admin/dev account',
    Created: new Date(),
    LastLogin: new Date(),
    Moderator: 0,
    ProfileDisplays: 0,
    FavoriteMovie: '',
    FavoriteActor: '',
    FavoriteActress: '',
    FavoriteSinger: '',
    FavoriteSong: '',
    IsExtra: 0,
    HasUnreadMessages: 0,
    InvitedByActorId: 0,
    PollTaken: 1,
    ValueOfGiftsReceived: 0,
    ValueOfGiftsGiven: 0,
    NumberOfGiftsGiven: 0,
    NumberOfGiftsReceived: 0,
    NumberOfAutographsReceived: 0,
    NumberOfAutographsGiven: 0,
    TimeOfLastAutographGiven: null,
    FacebookId: '',
    BoyfriendId: 0,
    BoyfriendStatus: 0,
    MembershipPurchasedDate: new Date(),
    MembershipTimeoutDate: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
    MembershipGiftRecievedDate: null,
    BehaviourStatus: 0,
    LockedUntil: null,
    LockedText: '',
    BadWordCount: 0,
    PurchaseTimeoutDate: null,
    EmailValidated: 1,
    RetentionStatus: 0,
    GiftStatus: 0,
    MarketingNextStepLogins: 0,
    MarketingStep: 0,
    TotalVipDays: 9999,
    RecyclePoints: 0,
    EmailSettings: 0,
    TimeOfLastAutographGivenStr: '',
    BestFriendId: 0,
    BestFriendStatus: 0,
    FriendCountVIP: 0,
    ForceNameChange: 0,
    CreationRewardStep: 0,
    CreationRewardLastAwardDate: null,
    NameBeforeDeleted: '',
    LastTransactionId: 0,
    AllowCommunication: 1,
    Diamonds: 999999999,
    PopUpStyleId: 0,
    BoyFriend: null,
    ActorPersonalInfo: null,
    ActorRelationships: null
});
};

const makeLoginStatus = (className, postLoginSeq = postLoginSequence(), actorRecord = null) => typed(className, {
    status: 'Success',
    actor: loginActorDetails(actorRecord),
    statusDetails: '',
    actorLocale: [],
    lbs: [],
    userType: 'Admin',
    adCountryMap: [],
    postLoginSeq,
    previousLastLogin: '',
    version: '20161102_160430',
    userIp: 2130706433,
    ticket: 'local-admin-ticket',
    piggyBank: null,
    mutedUntil: null,
    helpMessage: '',
    purchaseTypeId: 0,
    amsHash: ''
});

const loginStatus = (actorRecord = null) => makeLoginStatus('com.moviestarplanet.valueObjects.LoginStatus', postLoginSequence(), actorRecord);
const serviceLoginStatus = (actorRecord = null) => makeLoginStatus('com.moviestarplanet.services.userservice.valueObjects.LoginStatus', null, actorRecord);

const webLoginStatus = (actorRecord = null) => {
    return loginStatus2(actorRecord);
};

const loginHash = (status) => {
    const actor = status.actor || {};
    const values = [
        status.status,
        actor.ActorId,
        actor.Moderator,
        actor.Money,
        actor.Diamonds,
        actor.Fame,
        actor.Level
    ].map((value) => value === undefined || value === null ? '' : String(value));
    return crypto.createHash('md5').update(`idu!2*;d${values.join('')}`, 'utf8').digest('hex');
};

const loginStatus2 = (actorRecord = null) => {
    const status = serviceLoginStatus(actorRecord);
    const hash = loginHash(status);
    const hDetails = crypto.createHash('md5').update(`wiurh2i${status.actor.ActorId}`, 'utf8').digest('hex');
    delete status.__class;
    return {
        loginStatus: status,
        hDetails,
        hash
    };
};

const invalidLoginStatus2 = () => {
    const status = serviceLoginStatus();
    status.status = 'InvalidCredentials';
    status.statusDetails = '';
    const hash = loginHash(status);
    const hDetails = crypto.createHash('md5').update(`wiurh2i${status.actor.ActorId}`, 'utf8').digest('hex');
    delete status.__class;
    return {
        loginStatus: status,
        hDetails,
        hash
    };
};

const createNewUserStatus = (actorRecord = null) => {
    const actor = actorDefaults(actorRecord);
    return typed('com.moviestarplanet.services.userservice.valueObjects.CreateNewUserStatus', {
    status: 'Created',
    Status: 'Created',
    success: true,
    Success: true,
    actorId: actor.actorId,
    ActorId: actor.actorId,
    actorName: actor.name,
    ActorName: actor.name,
    actorDetails: devActorDetails(actorRecord),
    ActorDetails: devActorDetails(actorRecord),
    loginStatus: serviceLoginStatus(actorRecord),
    LoginStatus: serviceLoginStatus(actorRecord),
    loginStatus2: loginStatus2(actorRecord),
    LoginStatus2: loginStatus2(actorRecord),
    newActorCreationData: typed('MovieStarPlanet.WebService.User.ValueObjects.NewActorCreationData', {
        ActorId: actor.actorId,
        Name: actor.name,
        SkinSWF: actor.skinSWF,
        SkinColor: actor.skinColor,
        EyeId: actor.eyeId,
        NoseId: actor.noseId,
        MouthId: actor.mouthId,
        Clothes: starterClothes().slice(0, 6),
        ActorClothesRels: starterClothes().slice(0, 6)
    }),
    errorCode: 0,
    ErrorCode: 0,
    message: '',
    Message: ''
});
};

const createNewUserError = (message, errorCode = 1) => typed('com.moviestarplanet.services.userservice.valueObjects.CreateNewUserStatus', {
    status: 'Error',
    Status: 'Error',
    success: false,
    Success: false,
    errorCode,
    ErrorCode: errorCode,
    message,
    Message: message
});

const createAccountFromArgs = async (args = []) => {
    const { username, password } = credentialsFromArgs(args);
    const cleanUsername = String(username || '').trim();

    if (!/^[a-zA-Z0-9_.-]{3,20}$/.test(cleanUsername)) {
        return createNewUserError('Invalid username', 2);
    }
    if (findUserByName(cleanUsername)) {
        return createNewUserError('Username already exists', 3);
    }

    const actorId = nextActorId();
    const actor = {
        actorId,
        name: cleanUsername,
        level: 1,
        money: 5000,
        diamonds: 100,
        fame: 0,
        fortune: 0,
        skinSWF: 'swf/skins/maleskin.swf',
        skinColor: '0xffd1b3',
        eyeId: 2,
        noseId: 1,
        mouthId: 1,
        createdAt: new Date().toISOString()
    };
    const user = {
        id: actorId,
        username: cleanUsername,
        passwordHash: hashPassword(password),
        actorId,
        role: 'player',
        createdAt: actor.createdAt
    };

    db.users.push(user);
    db.actors.push(actor);
    db.inventory[String(actorId)] = starterClothes().slice(0, 6);
    await saveDb();
    log(`[ACCOUNT] created username=${cleanUsername} actorId=${actorId} source=${dbSource}`);
    return createNewUserStatus(actor);
};

const actorForLoginArgs = (args = []) => {
    const { username, password } = credentialsFromArgs(args);
    const user = findUserByName(username);

    if (user && passwordMatches(user, password)) {
        return findActorById(user.actorId) || null;
    }
    if (String(username || '').toLowerCase() === DEV_USERNAME && password === DEV_PASSWORD) {
        return findActorById(DEV_ACTOR_ID) || db.actors[0] || null;
    }
    return null;
};

const relativePublicPath = (filePath) => path.relative(publicPath, filePath).replace(/\\/g, '/');

const walkFiles = (dir, predicate, limit = 1000, result = []) => {
    if (result.length >= limit || !fs.existsSync(dir)) return result;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (result.length >= limit) break;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            walkFiles(fullPath, predicate, limit, result);
        } else if (!predicate || predicate(fullPath)) {
            result.push(fullPath);
        }
    }
    return result;
};

const inferClothSlotType = (filename) => {
    const name = filename.toLowerCase();
    if (name.includes('hair')) return 2;
    if (name.includes('top') || name.includes('shirt') || name.includes('dress')) return 3;
    if (name.includes('bottom') || name.includes('pants') || name.includes('skirt')) return 4;
    if (name.includes('shoe') || name.includes('boot')) return 5;
    if (name.includes('acc') || name.includes('hat') || name.includes('glasses')) return 6;
    return 3;
};

const inferGender = (filename) => {
    const name = filename.toLowerCase();
    if (name.includes('female') || name.includes('girl') || name.includes('_fj') || name.includes('fem')) return 'Female';
    if (name.includes('male') || name.includes('boy') || name.includes('_mj') || name.includes('_mf')) return 'Male';
    return 'Unisex';
};

const buildClothesCatalog = () => {
    const stuffDir = path.join(publicPath, 'swf', 'stuff');
    return walkFiles(stuffDir, (filePath) => filePath.toLowerCase().endsWith('.swf'), 800)
        .map((filePath, index) => {
            const filename = path.basename(filePath);
            return {
                id: 100000 + index + 1,
                swf: relativePublicPath(filePath),
                filename,
                slotTypeId: inferClothSlotType(filename),
                gender: inferGender(filename),
                colors: '0xffffff,0x222222'
            };
        });
};

const defaultDb = () => ({
    version: 1,
    createdAt: new Date().toISOString(),
    users: [{
        id: 1,
        username: DEV_USERNAME,
        password: DEV_PASSWORD,
        actorId: DEV_ACTOR_ID,
        role: 'admin'
    }],
    actors: [{
        actorId: DEV_ACTOR_ID,
        name: DEV_USERNAME,
        level: 101,
        money: 999999999,
        diamonds: 999999999,
        fame: 999999999,
        fortune: 999999999
    }],
    catalog: {
        clothes: buildClothesCatalog()
    },
    inventory: {
        [DEV_ACTOR_ID]: []
    },
    looks: [],
    movies: [],
    friends: [],
    messages: [],
    wallPosts: [],
    transactions: []
});

const ensureDbShape = (state) => {
    const next = state && typeof state === 'object' ? state : defaultDb();
    next.catalog = next.catalog || {};
    if (!Array.isArray(next.catalog.clothes) || next.catalog.clothes.length === 0) {
        next.catalog.clothes = buildClothesCatalog();
    }
    next.users = Array.isArray(next.users) ? next.users : defaultDb().users;
    next.actors = Array.isArray(next.actors) ? next.actors : defaultDb().actors;
    next.inventory = next.inventory || { [DEV_ACTOR_ID]: [] };
    next.looks = Array.isArray(next.looks) ? next.looks : [];
    next.movies = Array.isArray(next.movies) ? next.movies : [];
    next.friends = Array.isArray(next.friends) ? next.friends : [];
    next.messages = Array.isArray(next.messages) ? next.messages : [];
    next.wallPosts = Array.isArray(next.wallPosts) ? next.wallPosts : [];
    next.transactions = Array.isArray(next.transactions) ? next.transactions : [];
    return next;
};

const loadJsonDb = () => {
    try {
        if (fs.existsSync(dbPath)) {
            const existing = ensureDbShape(JSON.parse(fs.readFileSync(dbPath, 'utf8')));
            if (!Array.isArray(existing.catalog.clothes) || existing.catalog.clothes.length === 0) {
                fs.writeFileSync(dbPath, JSON.stringify(existing, null, 2));
            }
            return existing;
        }
    } catch (err) {
        log(`[DB] Nie udalo sie wczytac bazy, tworze nowa: ${err.message}`);
    }
    const created = defaultDb();
    fs.writeFileSync(dbPath, JSON.stringify(created, null, 2));
    log(`[DB] Utworzono lokalna baze: ${dbPath} (${created.catalog.clothes.length} ubran)`);
    return created;
};

const loadMongoDb = async () => {
    if (!mongoUri) {
        log('[DB] MONGODB_URI nie ustawione, uzywam msp-db.json');
        return null;
    }

    try {
        mongoClient = new MongoClient(mongoUri, {
            serverSelectionTimeoutMS: 5000
        });
        await mongoClient.connect();
        mongoDatabase = mongoClient.db(mongoDbName);
        const collection = mongoDatabase.collection(mongoStateCollection);
        let document = await collection.findOne({ _id: 'main' });

        if (!document) {
            document = Object.assign({ _id: 'main' }, defaultDb());
            await collection.insertOne(document);
            log(`[DB] Utworzono baze MongoDB: ${mongoDbName}.${mongoStateCollection}`);
        }

        const { _id, ...storedState } = document;
        const state = ensureDbShape(storedState);
        await collection.updateOne({ _id: 'main' }, { $set: state }, { upsert: true });
        dbSource = 'mongodb';
        log(`[DB] Polaczono z MongoDB: ${mongoDbName}.${mongoStateCollection} (${state.catalog.clothes.length} ubran)`);
        return state;
    } catch (err) {
        dbSource = 'json';
        log(`[DB] MongoDB niedostepne (${err.message}), uzywam msp-db.json`);
        if (mongoClient) {
            await mongoClient.close().catch(() => {});
        }
        mongoClient = null;
        mongoDatabase = null;
        return null;
    }
};

const loadDb = async () => {
    const mongoState = await loadMongoDb();
    if (mongoState) return mongoState;
    return loadJsonDb();
};

let db = defaultDb();

const saveDb = async () => {
    db = ensureDbShape(db);
    if (mongoClient && mongoDatabase) {
        await mongoDatabase.collection(mongoStateCollection).updateOne(
            { _id: 'main' },
            { $set: db },
            { upsert: true }
        );
        return;
    }
    fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));
};

const isDevCredentials = (requestBody) => {
    const text = Buffer.isBuffer(requestBody) ? requestBody.toString('utf8').toLowerCase() : '';
    return text.includes(DEV_USERNAME) || text.includes(DEV_PASSWORD);
};

const methodLeaf = (method) => String(method || '').split('.').pop();

const hashPassword = (password) => crypto.createHash('sha256').update(String(password || ''), 'utf8').digest('hex');

const collectStrings = (value, output = []) => {
    if (typeof value === 'string') {
        output.push(value);
    } else if (Array.isArray(value)) {
        value.forEach((item) => collectStrings(item, output));
    } else if (value && typeof value === 'object') {
        Object.keys(value).forEach((key) => {
            if (key !== '__class' && key !== 'Ticket') {
                collectStrings(value[key], output);
            }
        });
    }
    return output;
};

const usefulCredentialStrings = (args = []) => collectStrings(args)
    .map((value) => String(value || '').trim())
    .filter((value) => value.length >= 3 && value.length <= 32)
    .filter((value) => !/^0x[0-9a-f]+$/i.test(value))
    .filter((value) => !/^(http|swf\/|img\/|lookdata_|mockhash_|en_|pl_|de_|fr_|nl_)/i.test(value))
    .filter((value) => !/[\\/:]/.test(value));

const credentialsFromArgs = (args = []) => {
    if (typeof args[0] === 'string' && typeof args[1] === 'string') {
        return { username: args[0].trim(), password: args[1] };
    }
    const strings = usefulCredentialStrings(args);
    return {
        username: strings[0] || `player${Date.now()}`,
        password: strings[1] || crypto.randomBytes(8).toString('hex')
    };
};

const findUserByName = (username) => {
    const wanted = String(username || '').toLowerCase();
    return (db.users || []).find((user) => String(user.username || '').toLowerCase() === wanted) || null;
};

const findActorById = (actorId) => {
    return (db.actors || []).find((actor) => Number(actor.actorId) === Number(actorId)) || null;
};

const passwordMatches = (user, password) => {
    if (!user) return false;
    if (user.passwordHash) return user.passwordHash === hashPassword(password);
    return user.password === password;
};

const nextActorId = () => Math.max(DEV_ACTOR_ID, ...(db.actors || []).map((actor) => Number(actor.actorId) || 0)) + 1;

const okResult = (data = null) => ({
    Success: true,
    success: true,
    Status: 0,
    status: 0,
    Message: '',
    message: '',
    Data: data,
    data
});

const emptyPagedList = () => ({
    TotalRecords: 0,
    totalRecords: 0,
    PageIndex: 0,
    pageIndex: 0,
    PageSize: 50,
    pageSize: 50,
    Items: [],
    items: [],
    list: [],
    Result: [],
    result: []
});

const catalogClothes = (limit = 200) => db.catalog.clothes.slice(0, limit).map((item) => (
    cloth(item.id, item.swf, item.filename, item.slotTypeId, item.gender, item.colors)
));

const profileSummary = () => typed('com.moviestarplanet.profile.valueObjects.ProfileSummary', {
    ActorId: DEV_ACTOR_ID,
    Name: DEV_USERNAME,
    Level: 101,
    Fame: 999999999,
    Fortune: 999999999,
    Money: 999999999,
    Diamonds: 999999999,
    ProfileText: 'Local admin/dev account',
    FriendCount: 0,
    Clothes: catalogClothes(12),
    Looks: [],
    Movies: [],
    Pets: [],
    WallPosts: []
});

const lookDataPayload = () => Buffer.from(JSON.stringify({
    actorId: DEV_ACTOR_ID,
    actorName: DEV_USERNAME,
    skinSWF: 'swf/skins/maleskin.swf',
    skinColor: '0xffd1b3',
    eyeId: 2,
    noseId: 1,
    mouthId: 1,
    eyeColors: '0x5b351c',
    mouthColors: '0xd45a6a',
    clothes: starterClothes().slice(0, 6).map((item) => item.Cloth ? {
        clothesId: item.ClothesId,
        swf: item.Cloth.SWF,
        color: item.Color
    } : item),
    animation: 'stand'
}), 'utf8');

const randomFrontpageLook = () => {
    const clothes = starterClothes().slice(0, 6);
    const actor = devActorDetails();
    actor.ActorClothesRels = clothes;
    actor._ActorClothesRels = clothes;
    actor.ActorClothesRels2 = clothes;
    actor._ActorClothesRels2 = clothes;
    actor.initialAnimation = 'stand';
    actor.InitialAnimation = 'stand';
    actor.AnimationId = 1;
    actor.AnimationSWF = 'swf/animationtest.swf';
    return typed('com.moviestarplanet.look.valueobjects.LookItem', {
        LookId: 1,
        ActorId: DEV_ACTOR_ID,
        actorName: DEV_USERNAME,
        CreatorId: DEV_ACTOR_ID,
        creatorName: DEV_USERNAME,
        Created: new Date(),
        Headline: 'Local animated admin',
        LookData: lookDataPayload(),
        lookData: 'lookdata_000_000_000_001',
        LookDataUrl: 'lookdata_000_000_000_001',
        lookDataUrl: 'lookdata_000_000_000_001',
        Url: 'lookdata_000_000_000_001',
        url: 'lookdata_000_000_000_001',
        Likes: Math.floor(Math.random() * 9000) + 1000,
        Sells: 0,
        LookActorLikes: [],
        Actor: actor,
        actor,
        ActorDetails: actor,
        actorDetails: actor,
        ActorClothesRels: clothes,
        actorClothesRels: clothes,
        lookActorClothesRels: clothes,
        SkinSWF: actor.SkinSWF,
        SkinColor: actor.SkinColor,
        AnimationId: 1,
        AnimationSWF: 'swf/animationtest.swf',
        initialAnimation: 'stand'
    });
};

const postLoginState = () => typed('com.moviestarplanet.commonvalueobjects.login.PostLoginData', {
    ActorDetails: devActorDetails(),
    actorDetails: devActorDetails(),
    ProfileSummary: profileSummary(),
    profileSummary: profileSummary(),
    Friends: [],
    friends: [],
    Messages: [],
    messages: [],
    Notifications: [],
    notifications: [],
    News: [],
    news: [],
    Quests: [],
    quests: [],
    Gifts: [],
    gifts: [],
    Campaigns: [],
    campaigns: [],
    ServerTime: new Date(),
    serverTime: new Date()
});

const looksList = () => [randomFrontpageLook()];

const shouldReturnPagedList = (leaf) => /Paged|Page|Highscore|Browser|Search|List/i.test(leaf);

const genericReadResult = (method, leaf) => {
    const key = `${method}.${leaf}`;
    if (/ActorDetails|ActorDetail/i.test(leaf)) return devActorDetails();
    if (/ActorPersonalInfo|PersonalInfo/i.test(leaf)) return devActorDetails().ActorPersonalInfo;
    if (/ProfileSummary|Profile/i.test(key)) return profileSummary();
    if (/LoadState|PostLogin|OfflineTodo|Todo/i.test(leaf)) return postLoginState();
    if (/ActorIdFromName/i.test(leaf)) return DEV_ACTOR_ID;
    if (/ActorNameFromId|Username/i.test(leaf)) return DEV_USERNAME;
    if (/Locale/i.test(leaf)) return 'en_US';
    if (/Look/i.test(key)) return looksList();
    if (/Shop|Cloth|Clothes|Spending|Inventory|Wardrobe|BeautyClinic|GiftableItems|ContextClothes/i.test(key)) {
        const clothes = catalogClothes(250);
        return shouldReturnPagedList(leaf) ? Object.assign(emptyPagedList(), { Items: clothes, items: clothes, list: clothes, Result: clothes }) : clothes;
    }
    if (/Payment|Transaction|Price|Vip|Diamond|StarCoin|Money/i.test(key)) return [];
    if (/Friend|Invitation|Block|Blocked|Blocking/i.test(key)) return [];
    if (/Message|Mail|Chat|Conversation/i.test(key)) return [];
    if (/Movie|News|Forum|Club|Quest|Gift|Pet|PetPet|Boonie|Room|Highscore|Autograph|Status|Notification|Campaign|Poll/i.test(key)) {
        return shouldReturnPagedList(leaf) ? emptyPagedList() : [];
    }
    return shouldReturnPagedList(leaf) ? emptyPagedList() : [];
};

const genericWriteResult = (method, leaf) => {
    const key = `${method}.${leaf}`;
    if (/Buy|Purchase|Spend/i.test(key)) return okResult(devActorDetails());
    if (/Award|Give|Claim|Redeem|Reward/i.test(key)) return okResult(devActorDetails());
    if (/SaveLook/i.test(leaf)) return okResult(looksList()[0]);
    return okResult();
};

const shouldUseAmf3 = (method, result) => {
    if (result && typeof result === 'object' && result.__class) return true;
    return /Login|LoadDataForRegisterNewUser|LoadActorDetails|UserSession|UserService|MovieStar|Shopping|Shop|Spending|Profile|Friend|Movie|Look|News|Quest|Gift|Admin|Payment|Messaging|Room|Inventory|Wardrobe|Logging/i.test(method);
};

const getAmfResultForMethod = async (method, args = []) => {
    const leaf = methodLeaf(method);
    if (method.endsWith('GetAppSettings')) {
        return {
            Success: true,
            ServerTime: new Date().toISOString(),
            Language: 'en_US',
            Country: 'us',
            CdnBasePath: 'http://127.0.0.1/',
            CdnLocalBasePath: 'http://127.0.0.1/',
            WebServerPath: 'http://127.0.0.1/'
        };
    }
    if (method.endsWith('GetCurrentPaymentPossibilities')) {
        return [];
    }
    if (method.endsWith('ClientLog') || method.endsWith('LogClient')) {
        log(`[CLIENT LOG] ${method}`);
        return true;
    }
    if (method.endsWith('CreateTestException')) {
        return true;
    }
    if (method.endsWith('GetLatestServerException')) {
        return {
            Version: '20161102_160430',
            Exception: ''
        };
    }
    if (method.endsWith('GetRandomLookByLikes')) {
        return looksList()[0];
    }
    if (method.endsWith('Login2')) {
        const actor = actorForLoginArgs(args);
        return actor ? loginStatus2(actor) : invalidLoginStatus2();
    }
    if (method.endsWith('Login')) {
        const actor = actorForLoginArgs(args);
        return actor ? webLoginStatus(actor) : invalidLoginStatus2();
    }
    if (method.endsWith('CreateNewUser') || method.endsWith('CreateNewUserOld')) {
        return createAccountFromArgs(args);
    }
    if (method.endsWith('LoadActorDetails') || method.endsWith('LoadActorDetails2') || method.endsWith('LoadActorDetailsExtended')) {
        return devActorDetails();
    }
    if (method.endsWith('LoadActorDetailsSecure')) {
        return typed('com.moviestarplanet.usersession.valueobjects.ActorDetailSecure', {
            actorDetails: devActorDetails(),
            password: DEV_PASSWORD
        });
    }
    if (method.endsWith('GetActorIdFromName')) {
        return DEV_ACTOR_ID;
    }
    if (method.endsWith('GetActorNameFromId')) {
        return DEV_USERNAME;
    }
    if (method.endsWith('GetActorLocale')) {
        return 'en_US';
    }
    if (method.endsWith('LoadState')) {
        return postLoginState();
    }
    if (method.endsWith('IsModerator') || method.endsWith('IsAdminSite') || method.endsWith('IsDevSite')) {
        return true;
    }
    if (method.endsWith('awardActorMoneySecure') || method.endsWith('awardActorVIP')) {
        return null;
    }
    if (method.endsWith('LoadDataForRegisterNewUser')) {
        const data = registerNewUserData();
        return data;
    }
    if (/^(Is|Has|Can|Check)/i.test(leaf)) {
        if (/NameUsed|NameTaken|Blocked|Banned|Muted|Locked/i.test(leaf)) return false;
        return true;
    }
    if (/^(Get|Load|Find|Search|Browse|List)/i.test(leaf)) {
        return genericReadResult(method, leaf);
    }
    if (/^(Save|Update|Delete|Remove|Add|Set|Send|Report|Claim|Redeem|Award|Give|Accept|Reject|Invite|Buy|Purchase|Block|Unblock)/i.test(leaf)) {
        return genericWriteResult(method, leaf);
    }
    log(`[AMF FALLBACK] ${method} -> null`);
    return null;
};

app.all('/Gateway.aspx', async (req, res) => {
    const size = Buffer.isBuffer(req.body) ? req.body.length : 0;
    const method = req.query.method || '';
    if (proxyGatewayRequest(req, res, method)) {
        return;
    }
    const envelope = parseAmfEnvelope(req.body);
    const responseUri = envelope && envelope.messages[0] ? envelope.messages[0].response : '/1';
    let decodedArgs = [];
    log(`[AMF] ${req.method} /Gateway.aspx method=${method} body=${size} bytes response=${responseUri}`);
    if (envelope && envelope.messages[0]) {
        try {
            log(`[AMF BODY] target=${envelope.messages[0].target} length=${envelope.messages[0].body.length} hex=${envelope.messages[0].body.slice(0, 32).toString('hex')}`);
            const decodedBody = decodeAmfjsBody(envelope.messages[0].body);
            decodedArgs = Array.isArray(decodedBody) ? decodedBody : [];
            log(`[AMF DECODE] target=${envelope.messages[0].target} args=${previewValue(decodedBody)}`);
        } catch (err) {
            log(`[AMF DECODE MISS] target=${envelope.messages[0].target} error=${err.message}`);
        }
    }
    if ((method.endsWith('Login') || method.endsWith('Login2')) && !isDevCredentials(req.body)) {
        log(`[DEV LOGIN] accepting local dev login as ${DEV_USERNAME}/${DEV_PASSWORD}`);
    }
    try {
        const result = await getAmfResultForMethod(method, decodedArgs);
        res.type('application/x-amf').send(buildAmfResponse(envelope ? envelope.version : 0, responseUri, result, {
            amf3: shouldUseAmf3(method, result),
            debugLabel: method
        }));
    } catch (err) {
        log(`[AMF ERROR] ${method} ${err.stack || err.message}`);
        const result = okResult();
        res.type('application/x-amf').send(buildAmfResponse(envelope ? envelope.version : 0, responseUri, result, {
            amf3: true,
            debugLabel: `${method} ERROR_FALLBACK`
        }));
    }
});

app.get('/getConfig', (req, res) => {
    res.json({
        "version": 5,
        "swfUrl": "http://127.0.0.1/main_20161102_160430.swf",
        "basePath": "http://127.0.0.1/",
        "cdnPath": "http://127.0.0.1/",
        "isLocal": "true",
        "language": "PL"
    });
});

app.get('/api/db/status', (req, res) => {
    res.json({
        source: dbSource,
        mongoConnected: Boolean(mongoClient && mongoDatabase),
        mongoDbName,
        mongoStateCollection,
        clothes: db.catalog && Array.isArray(db.catalog.clothes) ? db.catalog.clothes.length : 0,
        users: Array.isArray(db.users) ? db.users.length : 0
    });
});

app.get('/api/debug/logs', (req, res) => {
    if (!isDebugMode) {
        res.status(404).json({ error: 'debug disabled' });
        return;
    }
    const since = Math.max(0, Number(req.query.since) || 0);
    res.json({
        next: recentLogs.length,
        lines: recentLogs.slice(since)
    });
});


app.use((req, res) => {
    log(`[MISS] ${req.method} ${req.url}`);
    res.status(404).type('text/plain').send(`Missing local file/route: ${req.url}`);
});
const startServer = (port) => {
    app.listen(port, '0.0.0.0', () => {
        log(`Serwer czeka na porcie ${port}...`);
    }).on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            log(`Port ${port} jest juz zajety, pomijam.`);
        } else {
            console.error(`Nie mozna uruchomic portu ${port}:`, err);
        }
    });
};

const start = async () => {
    db = await loadDb();
    startServer(80);
    startServer(1600);
};

start().catch((err) => {
    log(`[START] Nie udalo sie uruchomic serwera: ${err.stack || err.message}`);
    process.exitCode = 1;
});
