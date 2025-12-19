const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const CryptoJS = require('crypto-js');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", process.env.MONITORING_URL || 'http://localhost:3001']
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP, please try again later.'
});

app.use('/api/', limiter);
app.use(cors({
    origin: function(origin, callback) {
        const allowedOrigins = [process.env.FRONTEND_URL, 'http://localhost:3000'];
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || CryptoJS.lib.WordArray.random(32).toString(),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 2 * 60 * 60 * 1000
    }
}));
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const MONITORING_URL = process.env.MONITORING_URL || 'http://localhost:3001';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'default-encryption-key-256-bit';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const BACKUP_PASSWORD = process.env.BACKUP_PASSWORD;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    ssl: true,
    tlsAllowInvalidCertificates: false
}).then(() => console.log('✅ Primary MongoDB Connected'))
  .catch(err => {
      console.error('❌ MongoDB Connection Error:', err);
      process.exit(1);
  });

const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true, index: true },
    passwordHash: { type: String, required: true },
    backupPasswordHash: { type: String, required: true },
    mainPasswordLockedUntil: { type: Date, default: null },
    backupPasswordLockedUntil: { type: Date, default: null },
    websiteLockedUntil: { type: Date, default: null },
    telegramChatId: { type: String },
    securityKey: { type: String, default: () => CryptoJS.lib.WordArray.random(32).toString() },
    failedAttempts: { type: Number, default: 0 },
    lastFailedAttempt: { type: Date },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const DiaryEntrySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    encryptedContent: { type: String },
    isDraft: { type: Boolean, default: false },
    draftId: { type: String, unique: true, sparse: true },
    tags: [{ type: String }],
    location: {
        lat: Number,
        lon: Number,
        accuracy: Number,
        city: String,
        country: String
    },
    deviceInfo: {
        deviceId: String,
        deviceName: String,
        ip: String,
        userAgent: String,
        browser: String,
        os: String,
        isMobile: Boolean
    },
    wordCount: { type: Number, default: 0 },
    charCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now, index: true },
    updatedAt: { type: Date, default: Date.now }
});

const LoginAttemptSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    username: { type: String, index: true },
    deviceId: { type: String, index: true },
    deviceName: String,
    ip: { type: String, index: true },
    userAgent: String,
    location: {
        lat: Number,
        lon: Number,
        accuracy: Number,
        city: String,
        country: String
    },
    passwordType: { type: String, enum: ['main', 'backup'] },
    success: { type: Boolean, default: false },
    locationAllowed: { type: Boolean, default: false },
    suspicious: { type: Boolean, default: false },
    lockTriggered: { type: Boolean, default: false },
    timestamp: { type: Date, default: Date.now, index: true }
});

const ActiveSessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    sessionId: { type: String, unique: true, index: true },
    deviceId: { type: String, index: true },
    deviceName: String,
    ip: String,
    userAgent: String,
    location: {
        lat: Number,
        lon: Number,
        accuracy: Number
    },
    lastActivity: { type: Date, default: Date.now, index: true },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, index: true }
});

const BlockedIPSchema = new mongoose.Schema({
    ip: { type: String, unique: true, index: true },
    reason: String,
    blockedBy: String,
    blockedAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, index: true }
});

const User = mongoose.model('User', UserSchema);
const DiaryEntry = mongoose.model('DiaryEntry', DiaryEntrySchema);
const LoginAttempt = mongoose.model('LoginAttempt', LoginAttemptSchema);
const ActiveSession = mongoose.model('ActiveSession', ActiveSessionSchema);
const BlockedIP = mongoose.model('BlockedIP', BlockedIPSchema);

let isWebsiteLocked = false;
let websiteLockTimeout = null;

function encryptText(text) {
    return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
}

function decryptText(encryptedText) {
    const bytes = CryptoJS.AES.decrypt(encryptedText, ENCRYPTION_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
}

async function getLocationInfo(ip) {
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}`);
        const data = await response.json();
        if (data.status === 'success') {
            return {
                city: data.city,
                country: data.country,
                lat: data.lat,
                lon: data.lon
            };
        }
    } catch (error) {
        console.error('Location API error:', error);
    }
    return null;
}

async function sendTelegramAlert(chatId, message) {
    if (!TELEGRAM_BOT_TOKEN || !chatId) return;
    try {
        await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: chatId,
                text: message,
                parse_mode: 'HTML'
            })
        });
    } catch (error) {
        console.error('Telegram alert failed:', error);
    }
}

async function sendTelegramLocation(chatId, lat, lon, deviceInfo, ip) {
    if (!TELEGRAM_BOT_TOKEN || !chatId) return;
    try {
        await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendLocation`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: chatId,
                latitude: lat,
                longitude: lon
            })
        });
        await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: chatId,
                text: `📍 <b>Location Detected!</b>\n\n📱 Device: ${deviceInfo.deviceName}\n🌐 IP: ${ip}\n📍 Coordinates: ${lat.toFixed(4)}, ${lon.toFixed(4)}\n🕐 Time: ${new Date().toLocaleString()}`,
                parse_mode: 'HTML'
            })
        });
    } catch (error) {
        console.error('Telegram location failed:', error);
    }
}

async function lockWebsite(minutes = 15) {
    isWebsiteLocked = true;
    const lockUntil = new Date(Date.now() + minutes * 60 * 1000);
    await User.updateOne({}, { websiteLockedUntil: lockUntil });
    if (websiteLockTimeout) clearTimeout(websiteLockTimeout);
    websiteLockTimeout = setTimeout(() => {
        isWebsiteLocked = false;
        console.log('🔓 Website unlocked automatically');
    }, minutes * 60 * 1000);
    console.log(`🔒 Website locked for ${minutes} minutes`);
    const adminUser = await User.findOne({});
    if (adminUser && adminUser.telegramChatId) {
        await sendTelegramAlert(adminUser.telegramChatId,
            `🚨 <b>WEBSITE LOCKDOWN ACTIVATED</b>\n\n🕐 Locked until: ${lockUntil.toLocaleString()}\n⏰ Duration: ${minutes} minutes\n⚠️ All access blocked until unlock`
        );
    }
}

async function checkWebsiteLock() {
    const adminUser = await User.findOne({});
    if (!adminUser) return false;
    if (adminUser.websiteLockedUntil && new Date() < adminUser.websiteLockedUntil) {
        isWebsiteLocked = true;
        const remainingMs = adminUser.websiteLockedUntil - new Date();
        if (websiteLockTimeout) clearTimeout(websiteLockTimeout);
        websiteLockTimeout = setTimeout(() => {
            isWebsiteLocked = false;
        }, remainingMs);
        return true;
    }
    isWebsiteLocked = false;
    return false;
}

async function lockPassword(username, passwordType, minutes = 15) {
    const user = await User.findOne({ username });
    if (!user) return;
    const lockUntil = new Date(Date.now() + minutes * 60 * 1000);
    if (passwordType === 'main') {
        user.mainPasswordLockedUntil = lockUntil;
        user.failedAttempts += 1;
        user.lastFailedAttempt = new Date();
    } else if (passwordType === 'backup') {
        user.backupPasswordLockedUntil = lockUntil;
        user.failedAttempts += 1;
        user.lastFailedAttempt = new Date();
    }
    await user.save();
    if (user.telegramChatId) {
        await sendTelegramAlert(user.telegramChatId,
            `🔐 <b>Password Locked!</b>\n\n👤 User: ${username}\n🔒 Type: ${passwordType.toUpperCase()} password\n🕐 Locked until: ${lockUntil.toLocaleString()}\n⚠️ Remaining attempts: ${3 - user.failedAttempts}`
        );
    }
}

async function checkPasswordLock(username, passwordType) {
    const user = await User.findOne({ username });
    if (!user) return false;
    if (passwordType === 'main' && user.mainPasswordLockedUntil) {
        return new Date() < user.mainPasswordLockedUntil;
    }
    if (passwordType === 'backup' && user.backupPasswordLockedUntil) {
        return new Date() < user.backupPasswordLockedUntil;
    }
    return false;
}

async function initializeAdminUser() {
    const existingUser = await User.findOne({ username: ADMIN_USERNAME });
    if (existingUser) {
        console.log('Admin user already exists');
        return;
    }
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    const backupPasswordHash = await bcrypt.hash(BACKUP_PASSWORD, 12);
    const user = new User({
        username: ADMIN_USERNAME,
        passwordHash: passwordHash,
        backupPasswordHash: backupPasswordHash,
        telegramChatId: TELEGRAM_CHAT_ID,
        securityKey: CryptoJS.lib.WordArray.random(32).toString()
    });
    await user.save();
    console.log('Admin user created');
    if (TELEGRAM_CHAT_ID) {
        await sendTelegramAlert(TELEGRAM_CHAT_ID,
            `🎉 <b>Private Diary System Activated!</b>\n\n👤 Admin: ${ADMIN_USERNAME}\n🛡️ Security: Military-grade enabled\n📍 Location tracking: ACTIVE\n🔔 Notifications: ACTIVE\n\nUse /start to see bot commands`
        );
    }
}

app.use(async (req, res, next) => {
    if (isWebsiteLocked && !req.path.startsWith('/api/health')) {
        return res.status(503).json({
            error: 'Website is temporarily locked for security reasons. Please try again in 15 minutes.',
            locked: true,
            retryAfter: 900
        });
    }
    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const blocked = await BlockedIP.findOne({
        ip: ip,
        expiresAt: { $gt: new Date() }
    });
    if (blocked) {
        return res.status(403).json({
            error: 'Your IP address has been blocked for security reasons.',
            reason: blocked.reason,
            expiresAt: blocked.expiresAt
        });
    }
    next();
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'home.html'));
});
app.get('/account-activity', (req, res) => {
    res.sendFile(path.join(__dirname, 'account-activity.html'));
});

app.get('/api/health', async (req, res) => {
    const mongoStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    res.json({
        status: 'healthy',
        service: 'primary',
        timestamp: new Date().toISOString(),
        mongodb: mongoStatus,
        websiteLocked: isWebsiteLocked,
        uptime: process.uptime()
    });
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password, isBackup, deviceInfo, location, userAgent, ip } = req.body;
        await checkWebsiteLock();
        if (isWebsiteLocked) {
            return res.status(503).json({
                error: 'Website is locked for security. Try again in 15 minutes.',
                locked: true
            });
        }
        const passwordType = isBackup ? 'backup' : 'main';
        const isPasswordLocked = await checkPasswordLock(username, passwordType);
        if (isPasswordLocked) {
            return res.status(423).json({
                error: `${passwordType} password is locked. Try again later.`,
                passwordLocked: true
            });
        }
        const user = await User.findOne({ username });
        if (!user) {
            await LoginAttempt.create({
                username,
                deviceId: deviceInfo?.deviceId,
                deviceName: deviceInfo?.deviceName,
                ip,
                userAgent,
                passwordType,
                success: false,
                suspicious: true
            });
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const passwordHash = isBackup ? user.backupPasswordHash : user.passwordHash;
        const isValid = await bcrypt.compare(password, passwordHash);
        if (!isValid) {
            await LoginAttempt.create({
                userId: user._id,
                username,
                deviceId: deviceInfo?.deviceId,
                deviceName: deviceInfo?.deviceName,
                ip,
                userAgent,
                passwordType,
                success: false,
                locationAllowed: !!location
            });
            user.failedAttempts += 1;
            user.lastFailedAttempt = new Date();
            await user.save();
            if (user.failedAttempts >= 3) {
                await lockPassword(username, passwordType, 15);
                if (user.telegramChatId) {
                    await sendTelegramAlert(user.telegramChatId,
                        `🚨 <b>Multiple Failed Login Attempts!</b>\n\n👤 User: ${username}\n🔒 Password type: ${passwordType}\n📱 Device: ${deviceInfo?.deviceName || 'Unknown'}\n🌐 IP: ${ip}\n🔐 Status: Password LOCKED for 15 minutes`
                    );
                }
                return res.status(423).json({
                    error: 'Too many failed attempts. Password locked for 15 minutes.',
                    passwordLocked: true
                });
            }
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        if (!location) {
            await LoginAttempt.create({
                userId: user._id,
                username,
                deviceId: deviceInfo?.deviceId,
                deviceName: deviceInfo?.deviceName,
                ip,
                userAgent,
                passwordType,
                success: false,
                locationAllowed: false,
                suspicious: true,
                lockTriggered: true
            });
            const geoInfo = await getLocationInfo(ip);
            const deviceName = deviceInfo?.deviceName ||
                userAgent?.split('(')[1]?.split(')')[0] ||
                'Unknown Device';
            if (user.telegramChatId) {
                await sendTelegramAlert(user.telegramChatId,
                    `🚨🚨🚨 <b>SECURITY BREACH DETECTED!</b> 🚨🚨🚨\n\n👤 User: ${username}\n🔐 Password type: ${passwordType}\n📱 Device: ${deviceName}\n🌐 IP: ${ip}\n📍 Location: ${geoInfo ? `${geoInfo.city}, ${geoInfo.country}` : 'Unknown'}\n❌ Location permission: DENIED\n\n⚠️ <b>Action Taken:</b>\n• Password ${passwordType} LOCKED\n• All diary entries LOCKED\n• Device logged out immediately\n• 15-minute cooldown activated`
                );
            }
            await lockPassword(username, passwordType, 15);
            const tempLockKey = CryptoJS.lib.WordArray.random(32).toString();
            await DiaryEntry.updateMany(
                { userId: user._id },
                {
                    $set: {
                        encryptedContent: encryptText('ENTRY_LOCKED_BY_SECURITY_SYSTEM'),
                        content: '🔒 ENTRY LOCKED - Security breach detected. Contact admin.'
                    }
                }
            );
            await ActiveSession.deleteMany({ userId: user._id });
            await BlockedIP.create({
                ip: ip,
                reason: 'Location permission denied on login',
                blockedBy: 'Security System',
                expiresAt: new Date(Date.now() + 15 * 60 * 1000)
            });
            const updatedUser = await User.findOne({ username });
            const mainLocked = updatedUser.mainPasswordLockedUntil &&
                new Date() < updatedUser.mainPasswordLockedUntil;
            const backupLocked = updatedUser.backupPasswordLockedUntil &&
                new Date() < updatedUser.backupPasswordLockedUntil;
            if (mainLocked && backupLocked) {
                await lockWebsite(15);
                if (user.telegramChatId) {
                    await sendTelegramAlert(user.telegramChatId,
                        `☢️☢️☢️ <b>WEBSITE LOCKDOWN ACTIVATED!</b> ☢️☢️☢️\n\nBoth passwords are locked due to security breaches.\n🌐 Website is now OFFLINE for 15 minutes.\n🚫 No access allowed to any page.\n🛡️ Ghost mode activated.`
                    );
                }
            }
            return res.status(403).json({
                error: 'Location permission required for security. Access denied and security measures activated.',
                passwordLocked: true,
                entriesLocked: true,
                action: 'security_breach_detected'
            });
        }
        await LoginAttempt.create({
            userId: user._id,
            username,
            deviceId: deviceInfo?.deviceId,
            deviceName: deviceInfo?.deviceName,
            ip,
            userAgent,
            location: location,
            passwordType,
            success: true,
            locationAllowed: true
        });
        user.failedAttempts = 0;
        user.lastFailedAttempt = null;
        await user.save();
        if (user.telegramChatId && location.lat && location.lon) {
            await sendTelegramLocation(
                user.telegramChatId,
                location.lat,
                location.lon,
                {
                    deviceName: deviceInfo?.deviceName || 'Unknown',
                    browser: deviceInfo?.browser || 'Unknown'
                },
                ip
            );
        }
        const sessionId = CryptoJS.lib.WordArray.random(32).toString();
        const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
        await ActiveSession.create({
            userId: user._id,
            sessionId,
            deviceId: deviceInfo?.deviceId,
            deviceName: deviceInfo?.deviceName,
            ip,
            userAgent,
            location: location,
            lastActivity: new Date(),
            expiresAt
        });
        const authToken = CryptoJS.AES.encrypt(
            JSON.stringify({
                userId: user._id.toString(),
                sessionId,
                expiresAt: expiresAt.toISOString()
            }),
            ENCRYPTION_KEY
        ).toString();
        res.json({
            success: true,
            token: authToken,
            user: {
                username: user.username,
                requiresNotificationPermission: !user.telegramChatId
            },
            session: {
                id: sessionId,
                expiresAt
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/logout', async (req, res) => {
    try {
        const { sessionId } = req.body;
        await ActiveSession.deleteOne({ sessionId });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Logout failed' });
    }
});

app.post('/api/diary/save-draft', async (req, res) => {
    try {
        const { token, title, content, tags, deviceInfo } = req.body;
        const decryptedToken = JSON.parse(decryptText(token));
        const session = await ActiveSession.findOne({
            sessionId: decryptedToken.sessionId,
            expiresAt: { $gt: new Date() }
        });
        if (!session) {
            return res.status(401).json({ error: 'Session expired' });
        }
        const draftId = `draft_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const draft = new DiaryEntry({
            userId: session.userId,
            title: title || 'Untitled Draft',
            content,
            encryptedContent: encryptText(content),
            isDraft: true,
            draftId,
            tags: tags || [],
            deviceInfo,
            wordCount: content.split(/\s+/).length,
            charCount: content.length
        });
        await draft.save();
        const localStorageBackup = {
            draftId,
            title: draft.title,
            content,
            tags: draft.tags,
            savedAt: new Date().toISOString(),
            deviceId: deviceInfo?.deviceId
        };
        res.json({
            success: true,
            draftId,
            savedAt: new Date().toISOString(),
            localStorageBackup
        });
    } catch (error) {
        console.error('Save draft error:', error);
        res.status(500).json({ error: 'Failed to save draft' });
    }
});

app.get('/api/diary/drafts', async (req, res) => {
    try {
        const { token } = req.query;
        const decryptedToken = JSON.parse(decryptText(token));
        const session = await ActiveSession.findOne({
            sessionId: decryptedToken.sessionId,
            expiresAt: { $gt: new Date() }
        });
        if (!session) {
            return res.status(401).json({ error: 'Session expired' });
        }
        const drafts = await DiaryEntry.find({
            userId: session.userId,
            isDraft: true
        }).sort({ updatedAt: -1 });
        const decryptedDrafts = drafts.map(draft => ({
            ...draft.toObject(),
            content: decryptText(draft.encryptedContent)
        }));
        res.json({ drafts: decryptedDrafts });
    } catch (error) {
        console.error('Get drafts error:', error);
        res.status(500).json({ error: 'Failed to fetch drafts' });
    }
});

app.post('/api/diary/publish', async (req, res) => {
    try {
        const { token, draftId, title, content, tags, location, deviceInfo } = req.body;
        const decryptedToken = JSON.parse(decryptText(token));
        const session = await ActiveSession.findOne({
            sessionId: decryptedToken.sessionId,
            expiresAt: { $gt: new Date() }
        });
        if (!session) {
            return res.status(401).json({ error: 'Session expired' });
        }
        let diaryEntry;
        if (draftId) {
            diaryEntry = await DiaryEntry.findOneAndUpdate(
                { draftId, userId: session.userId },
                {
                    title,
                    content,
                    encryptedContent: encryptText(content),
                    isDraft: false,
                    draftId: null,
                    tags,
                    location,
                    deviceInfo,
                    wordCount: content.split(/\s+/).length,
                    charCount: content.length,
                    updatedAt: new Date()
                },
                { new: true }
            );
        } else {
            diaryEntry = new DiaryEntry({
                userId: session.userId,
                title,
                content,
                encryptedContent: encryptText(content),
                isDraft: false,
                tags,
                location,
                deviceInfo,
                wordCount: content.split(/\s+/).length,
                charCount: content.length
            });
            await diaryEntry.save();
        }
        const user = await User.findById(session.userId);
        if (user && user.telegramChatId) {
            const wordCount = content.split(/\s+/).length;
            await sendTelegramAlert(user.telegramChatId,
                `📝 <b>New Diary Entry Published!</b>\n\n📌 Title: ${title}\n📊 Words: ${wordCount}\n📍 Location: ${location?.city || 'Unknown'}\n📱 Device: ${deviceInfo?.deviceName || 'Unknown'}\n🕐 Time: ${new Date().toLocaleString()}`
            );
        }
        res.json({
            success: true,
            entryId: diaryEntry._id,
            publishedAt: diaryEntry.createdAt
        });
    } catch (error) {
        console.error('Publish error:', error);
        res.status(500).json({ error: 'Failed to publish entry' });
    }
});

app.get('/api/diary/entries', async (req, res) => {
    try {
        const { token } = req.query;
        const decryptedToken = JSON.parse(decryptText(token));
        const session = await ActiveSession.findOne({
            sessionId: decryptedToken.sessionId,
            expiresAt: { $gt: new Date() }
        });
        if (!session) {
            return res.status(401).json({ error: 'Session expired' });
        }
        const entries = await DiaryEntry.find({
            userId: session.userId,
            isDraft: false
        }).sort({ createdAt: -1 }).limit(50);
        const decryptedEntries = entries.map(entry => ({
            ...entry.toObject(),
            content: decryptText(entry.encryptedContent)
        }));
        res.json({ entries: decryptedEntries });
    } catch (error) {
        console.error('Get entries error:', error);
        res.status(500).json({ error: 'Failed to fetch entries' });
    }
});

app.get('/api/activity', async (req, res) => {
    try {
        const { token } = req.query;
        const decryptedToken = JSON.parse(decryptText(token));
        const session = await ActiveSession.findOne({
            sessionId: decryptedToken.sessionId,
            expiresAt: { $gt: new Date() }
        });
        if (!session) {
            return res.status(401).json({ error: 'Session expired' });
        }
        const loginHistory = await LoginAttempt.find({
            userId: session.userId
        }).sort({ timestamp: -1 }).limit(50);
        const activeSessions = await ActiveSession.find({
            userId: session.userId,
            expiresAt: { $gt: new Date() }
        });
        const blockedIPs = await BlockedIP.find({
            expiresAt: { $gt: new Date() }
        });
        res.json({
            loginHistory,
            activeSessions,
            blockedIPs,
            stats: {
                totalLogins: await LoginAttempt.countDocuments({ userId: session.userId }),
                successfulLogins: await LoginAttempt.countDocuments({
                    userId: session.userId,
                    success: true
                }),
                suspiciousAttempts: await LoginAttempt.countDocuments({
                    userId: session.userId,
                    suspicious: true
                }),
                activeDevices: activeSessions.length
            }
        });
    } catch (error) {
        console.error('Get activity error:', error);
        res.status(500).json({ error: 'Failed to fetch activity' });
    }
});

app.post('/api/telegram/command', async (req, res) => {
    try {
        const { command, parameters, chatId } = req.body;
        const user = await User.findOne({ telegramChatId: chatId });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        let response;
        switch(command) {
            case '/start':
                response = `🤖 <b>Private Diary Bot</b>\n\nAvailable Commands:\n/entries - View recent diary entries\n/drafts - View unpublished drafts\n/activity - Check login activity\n/devices - View active devices\n/blockip [IP] - Block an IP address\n/unblockip [IP] - Unblock IP\n/logoutall - Logout all devices\n/lockwebsite - Lock website (admin)\n/unlockwebsite - Unlock website (admin)\n/status - System status\n/help - Show this message`;
                break;
            case '/entries':
                const entries = await DiaryEntry.find({
                    userId: user._id,
                    isDraft: false
                }).sort({ createdAt: -1 }).limit(5);
                if (entries.length === 0) response = 'No diary entries found.';
                else {
                    response = '📝 <b>Recent Diary Entries:</b>\n\n';
                    entries.forEach(entry => {
                        const date = new Date(entry.createdAt).toLocaleDateString();
                        response += `• <b>${entry.title}</b>\n  ${date}\n\n`;
                    });
                }
                break;
            case '/drafts':
                const drafts = await DiaryEntry.find({
                    userId: user._id,
                    isDraft: true
                }).sort({ updatedAt: -1 });
                if (drafts.length === 0) response = 'No drafts found.';
                else {
                    response = '📄 <b>Unpublished Drafts:</b>\n\n';
                    drafts.forEach(draft => {
                        const words = draft.content.split(/\s+/).length;
                        response += `• <b>${draft.title || 'Untitled'}</b>\n  ${words} words\n\n`;
                    });
                }
                break;
            case '/activity':
                const recentActivity = await LoginAttempt.find({
                    userId: user._id
                }).sort({ timestamp: -1 }).limit(5);
                response = '🔐 <b>Recent Login Activity:</b>\n\n';
                recentActivity.forEach(activity => {
                    const time = new Date(activity.timestamp).toLocaleString();
                    const status = activity.success ? '✅' : '❌';
                    const location = activity.locationAllowed ? '📍' : '🚫';
                    response += `${status}${location} ${activity.deviceName || 'Unknown'}\n   ${time}\n   IP: ${activity.ip}\n\n`;
                });
                break;
            case '/devices':
                const devices = await ActiveSession.find({
                    userId: user._id,
                    expiresAt: { $gt: new Date() }
                });
                response = '📱 <b>Active Devices:</b>\n\n';
                devices.forEach(device => {
                    const timeAgo = Math.floor((new Date() - device.lastActivity) / (1000 * 60));
                    response += `• ${device.deviceName}\n  IP: ${device.ip}\n  Active: ${timeAgo} minutes ago\n\n`;
                });
                break;
            case '/blockip':
                if (!parameters || !parameters[0]) response = 'Usage: /blockip [IP_ADDRESS]';
                else {
                    const ip = parameters[0];
                    await BlockedIP.create({
                        ip,
                        reason: 'Blocked via Telegram bot',
                        blockedBy: chatId,
                        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
                    });
                    response = `✅ IP ${ip} blocked for 24 hours.`;
                }
                break;
            case '/unblockip':
                if (!parameters || !parameters[0]) response = 'Usage: /unblockip [IP_ADDRESS]';
                else {
                    const ip = parameters[0];
                    await BlockedIP.deleteOne({ ip });
                    response = `✅ IP ${ip} unblocked.`;
                }
                break;
            case '/logoutall':
                await ActiveSession.deleteMany({ userId: user._id });
                response = '✅ All devices logged out.';
                break;
            case '/lockwebsite':
                await lockWebsite(15);
                response = '🔒 Website locked for 15 minutes.';
                break;
            case '/unlockwebsite':
                isWebsiteLocked = false;
                if (websiteLockTimeout) clearTimeout(websiteLockTimeout);
                await User.updateOne({}, { websiteLockedUntil: null });
                response = '🔓 Website unlocked.';
                break;
            case '/status':
                const totalEntries = await DiaryEntry.countDocuments({ userId: user._id });
                const totalDrafts = await DiaryEntry.countDocuments({
                    userId: user._id,
                    isDraft: true
                });
                const activeDevices = await ActiveSession.countDocuments({
                    userId: user._id,
                    expiresAt: { $gt: new Date() }
                });
                response = `📊 <b>System Status:</b>\n\n👤 User: ${user.username}\n📝 Entries: ${totalEntries}\n📄 Drafts: ${totalDrafts}\n📱 Active Devices: ${activeDevices}\n🔒 Website Locked: ${isWebsiteLocked ? 'YES' : 'NO'}\n🛡️ Security: ACTIVE`;
                break;
            case '/help':
                response = `🤖 <b>Private Diary Bot Help</b>\n\nCommands:\n/start - Show all commands\n/entries - View diary entries\n/drafts - View drafts\n/activity - Login history\n/devices - Active devices\n/blockip - Block IP\n/unblockip - Unblock IP\n/logoutall - Logout all\n/lockwebsite - Lock site\n/unlockwebsite - Unlock site\n/status - System status`;
                break;
            case '/backup':
                const backupData = await DiaryEntry.find({ userId: user._id });
                response = `📦 <b>Backup Data</b>\n\nTotal entries: ${backupData.length}\nLast backup: ${new Date().toLocaleString()}\n\nUse /restore to restore from backup.`;
                break;
            case '/emergency':
                response = `🚨 <b>Emergency Procedures</b>\n\n1. If hacked: /lockwebsite\n2. Then: /logoutall\n3. Block IP: /blockip [IP]\n4. Change passwords\n5. Contact admin`;
                break;
            default:
                response = 'Unknown command. Use /help for available commands.';
        }
        await sendTelegramAlert(chatId, response);
        res.json({ success: true, response });
    } catch (error) {
        console.error('Telegram command error:', error);
        res.status(500).json({ error: 'Command processing failed' });
    }
});

async function sendDailyReminder() {
    try {
        const now = new Date();
        const assamTime = new Date(now.getTime() + (5.5 * 60 * 60 * 1000));
        if (assamTime.getHours() === 22 && assamTime.getMinutes() === 0) {
            const users = await User.find();
            for (const user of users) {
                if (user.telegramChatId) {
                    await sendTelegramAlert(user.telegramChatId,
                        `⏰ <b>Daily Diary Reminder</b>\n\nIt's 10:00 PM in Assam!\nTime to write your daily journal entry.\n\n📝 Remember: Consistency is key to reflection.`
                    );
                    console.log(`Daily reminder sent to ${user.username}`);
                }
            }
        }
    } catch (error) {
        console.error('Daily reminder error:', error);
    }
}

setInterval(sendDailyReminder, 60000);

async function pingMonitoringService() {
    try {
        await fetch(`${MONITORING_URL}/api/ping`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                service: 'primary',
                timestamp: new Date().toISOString(),
                status: 'alive'
            })
        });
        console.log('✅ Ping sent to monitoring service');
    } catch (error) {
        console.warn('⚠️ Monitoring service unreachable');
    }
}

setInterval(pingMonitoringService, 30000);

app.listen(PORT, () => {
    console.log(`✅ Primary server running on port ${PORT}`);
    console.log(`🔗 Monitoring service: ${MONITORING_URL}`);
    checkWebsiteLock().then(locked => {
        if (locked) {
            console.log('🔒 Website is currently locked');
        }
    });
    initializeAdminUser();
    pingMonitoringService();
});
