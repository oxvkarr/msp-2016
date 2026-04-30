const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
const app = express();

const publicPath = path.join(__dirname, 'public');
const dbPath = path.join(__dirname, 'msp-db.json');
const debugLogPath = path.join(__dirname, 'msp-debug.log');
const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URI || '';
const mongoDbName = process.env.MONGODB_DB || 'msp_2016';
const mongoStateCollection = process.env.MONGODB_STATE_COLLECTION || 'state';
let mongoClient = null;
let mongoDatabase = null;
let dbSource = 'json';
const log = (message) => {
    const line = `${new Date().toISOString()} ${message}`;
    console.log(message);
    fs.appendFile(debugLogPath, `${line}\n`, () => {});
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



app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'play.html'));
});
app.get('/cdnpath.txt', (req, res) => {
    res.type('text/plain').send('http://127.0.0.1/');
});

const sanitizeLocalMap = (text) => text
    .replace(/https?:\/\/(?:localcdn|cdn|upload|cdndev|cdnlocaldev|cdnlocaltest|cdnlocalrc|cdn\.alpha|upload\.alpha|cdn\.beta|upload\.beta|cdn\.rc|uploadtest|cdntest|cdnupload)\.moviestarplanet(?:\.[a-z]+)?(?:\.[a-z]+)?\//gi, 'http://127.0.0.1/')
    .replace(/https?:\/\/(?:alpha|beta|dev|test|rc|www|info)\.moviestarplanet(?:\.[a-z]+)?(?:\.[a-z]+)?\//gi, 'http://127.0.0.1/')
    .replace(/https?:\/\/(?:content\.)?mspapis\.com\//gi, 'http://127.0.0.1/');

app.get(['/languagemaps.txt', '/localization/languagemaps.txt'], (req, res) => {
    const filePath = path.join(publicPath, req.path.replace(/^\/+/, ''));
    log(`[LANGMAP] ${req.url} -> ${filePath}`);
    fs.readFile(filePath, 'utf8', (err, text) => {
        if (err) {
            res.status(404).type('text/plain').send(`Missing language map: ${req.url}`);
            return;
        }
        res.type('application/json').send(sanitizeLocalMap(text));
    });
});

app.get(/^\/(?:null)?lookdata_[0-9_]+$/i, (req, res) => {
    log(`[LOOKDATA] ${req.url}`);
    res.type('application/octet-stream').send(lookDataPayload());
});

app.get(/^\/Main_20161102_160430\.swf$/i, (req, res) => {
    res.type('application/x-shockwave-flash').sendFile(path.join(publicPath, 'main_20161102_160430.swf'));
});

app.all('/translations/crossdomain.xml', (req, res) => {
    log(`[POLICY] ${req.headers.host || ''}${req.url}`);
    res.set('Content-Type', 'text/xml');
    res.send(`<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*" to-ports="*" /></cross-domain-policy>`);
});

app.get('/:client(MSPWeb|MSPMobile)/:locale/myResources.txt', (req, res) => {
    const client = req.params.client.toLowerCase();
    const locale = req.params.locale.toLowerCase();
    const filePath = path.join(__dirname, 'public', 'translations', client, locale, 'myresources.txt');
    log(`[TRANSLATION] ${req.url} -> ${filePath}`);
    res.type('text/plain').sendFile(filePath, (err) => {
        if (err) {
            log(`[TRANSLATION MISS] ${filePath}`);
            res.status(err.statusCode || 404).type('text/plain').send(`Missing translation: ${req.url}`);
        }
    });
});

app.use(express.static(publicPath));

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

const buildAmfResponse = (version, responseUri, value, options = {}) => {
    const body = options.amf3 ? amf0Amf3Value(value) : amf0Value(value);
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

const devActorDetails = () => typed('com.moviestarplanet.usersession.valueobjects.ActorDetails', {
    ActorId: DEV_ACTOR_ID,
    Name: DEV_USERNAME,
    Level: 101,
    SkinSWF: 'swf/skins/maleskin.swf',
    SkinColor: '0xffd1b3',
    NoseId: 1,
    EyeId: 2,
    MouthId: 1,
    Money: 999999999,
    EyeColors: '0x5b351c',
    MouthColors: '0xd45a6a',
    Fame: 999999999,
    Fortune: 999999999,
    FriendCount: 0,
    ProfileText: 'Local admin/dev account',
    Moderator: 1,
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
        ActorId: DEV_ACTOR_ID,
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

const postLoginSequence = () => typed('com.moviestarplanet.valueObjects.PostLoginSequenceDomain', {
    ShowCampaign: false,
    ShowVipRebuy: false
});

const loginActorPersonalInfo = () => typed('com.moviestarplanet.usersession.valueobjects.ActorPersonalInfo', {
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

const loginActorDetails = () => typed('com.moviestarplanet.usersession.valueobjects.ActorDetails', {
    ActorId: DEV_ACTOR_ID,
    Name: DEV_USERNAME,
    Level: 101,
    SkinSWF: 'swf/skins/maleskin.swf',
    SkinColor: '0xffd1b3',
    NoseId: 1,
    EyeId: 2,
    MouthId: 1,
    Money: 999999999,
    EyeColors: '0x5b351c',
    MouthColors: '0xd45a6a',
    Fame: 999999999,
    Fortune: 999999999,
    FriendCount: 0,
    ProfileText: 'Local admin/dev account',
    Created: new Date(),
    LastLogin: new Date(),
    Moderator: 1,
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
    ActorPersonalInfo: loginActorPersonalInfo(),
    ActorRelationships: []
});

const makeLoginStatus = (className) => typed(className, {
    status: 'LoggedIn',
    actor: loginActorDetails(),
    statusDetails: '',
    actorLocale: ['en_US'],
    lbs: [],
    userType: 'Admin',
    adCountryMap: [],
    postLoginSeq: postLoginSequence(),
    previousLastLogin: '',
    version: '20161102_160430',
    userIp: 2130706433,
    ticket: 'local-admin-ticket'
});

const loginStatus = () => makeLoginStatus('com.moviestarplanet.valueObjects.LoginStatus');
const serviceLoginStatus = () => makeLoginStatus('com.moviestarplanet.services.userservice.valueObjects.LoginStatus');

const webLoginStatus = () => {
    return loginStatus2();
};

const loginHash = (status) => {
    const actor = status.actor || {};
    const values = [
        actor.ActorId,
        actor.Name,
        actor.Level,
        actor.Money,
        actor.Fame,
        actor.Fortune,
        actor.Diamonds,
        actor.Moderator,
        status.status,
        status.ticket
    ].map((value) => value === undefined || value === null ? '' : String(value));
    return crypto.createHash('md5').update(values.join('....'), 'utf8').digest('hex');
};

const loginStatus2 = () => {
    const status = serviceLoginStatus();
    const hash = loginHash(status);
    return typed('com.moviestarplanet.services.userservice.valueObjects.LoginStatus2', {
        loginStatus: status,
        hDetails: hash
    });
};

const createNewUserStatus = () => typed('com.moviestarplanet.services.userservice.valueObjects.CreateNewUserStatus', {
    status: 'Created',
    Status: 'Created',
    success: true,
    Success: true,
    actorId: DEV_ACTOR_ID,
    ActorId: DEV_ACTOR_ID,
    actorName: DEV_USERNAME,
    ActorName: DEV_USERNAME,
    actorDetails: devActorDetails(),
    ActorDetails: devActorDetails(),
    loginStatus: serviceLoginStatus(),
    LoginStatus: serviceLoginStatus(),
    loginStatus2: loginStatus2(),
    LoginStatus2: loginStatus2(),
    newActorCreationData: typed('MovieStarPlanet.WebService.User.ValueObjects.NewActorCreationData', {
        ActorId: DEV_ACTOR_ID,
        Name: DEV_USERNAME,
        SkinSWF: 'swf/skins/maleskin.swf',
        SkinColor: '0xffd1b3',
        EyeId: 2,
        NoseId: 1,
        MouthId: 1,
        Clothes: starterClothes().slice(0, 6),
        ActorClothesRels: starterClothes().slice(0, 6)
    }),
    errorCode: 0,
    ErrorCode: 0,
    message: '',
    Message: ''
});

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

const isDevCredentials = (requestBody) => {
    const text = Buffer.isBuffer(requestBody) ? requestBody.toString('utf8').toLowerCase() : '';
    return text.includes(DEV_USERNAME) || text.includes(DEV_PASSWORD);
};

const methodLeaf = (method) => String(method || '').split('.').pop();

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
    return /Login|LoadDataForRegisterNewUser|LoadActorDetails|UserSession|UserService|MovieStar|Shopping|Shop|Spending|Profile|Friend|Movie|Look|News|Quest|Gift|Admin|Payment|Messaging|Room|Inventory|Wardrobe/i.test(method);
};

const getAmfResultForMethod = (method) => {
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
    if (method.endsWith('GetRandomLookByLikes')) {
        return looksList()[0];
    }
    if (method.endsWith('Login2')) {
        return loginStatus2();
    }
    if (method.endsWith('Login')) {
        return webLoginStatus();
    }
    if (method.endsWith('CreateNewUser') || method.endsWith('CreateNewUserOld')) {
        return createNewUserStatus();
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

app.all('/Gateway.aspx', (req, res) => {
    const size = Buffer.isBuffer(req.body) ? req.body.length : 0;
    const method = req.query.method || '';
    const envelope = parseAmfEnvelope(req.body);
    const responseUri = envelope && envelope.messages[0] ? envelope.messages[0].response : '/1';
    log(`[AMF] ${req.method} /Gateway.aspx method=${method} body=${size} bytes response=${responseUri}`);
    if ((method.endsWith('Login') || method.endsWith('Login2')) && !isDevCredentials(req.body)) {
        log(`[DEV LOGIN] accepting local dev login as ${DEV_USERNAME}/${DEV_PASSWORD}`);
    }
    const result = getAmfResultForMethod(method);
    res.type('application/x-amf').send(buildAmfResponse(envelope ? envelope.version : 0, responseUri, result, {
        amf3: shouldUseAmf3(method, result)
    }));
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
