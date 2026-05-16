const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3469;

// ============================================================
// SECURITY HELPER: Persistent session secret
// Dibuat sekali, disimpan ke file, tidak berubah tiap restart
// ============================================================
function getOrCreateSessionSecret() {
  const secretFile = './data/.session_secret';
  if (fs.existsSync(secretFile)) {
    return fs.readFileSync(secretFile, 'utf8').trim();
  }
  const secret = crypto.randomBytes(64).toString('hex');
  if (!fs.existsSync('./data')) fs.mkdirSync('./data', { recursive: true });
  fs.writeFileSync(secretFile, secret, { mode: 0o600 });
  return secret;
}

// ============================================================
// IN-MEMORY RATE LIMITER (tidak perlu library tambahan)
// ============================================================
const rateLimitStore = new Map(); // key → { count, resetAt }

function rateLimit({ windowMs = 60000, max = 10, keyFn = (req) => req.ip } = {}) {
  return (req, res, next) => {
    const key = keyFn(req);
    const now = Date.now();
    const entry = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };

    if (now > entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + windowMs;
    }

    entry.count++;
    rateLimitStore.set(key, entry);

    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - entry.count));
    res.setHeader('X-RateLimit-Reset', Math.ceil(entry.resetAt / 1000));

    if (entry.count > max) {
      return res.status(429).json({
        error: 'Terlalu banyak permintaan. Coba lagi nanti.',
        retryAfter: Math.ceil((entry.resetAt - now) / 1000)
      });
    }
    next();
  };
}

// Bersihkan store tiap 10 menit supaya tidak memory leak
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitStore.entries()) {
    if (now > val.resetAt) rateLimitStore.delete(key);
  }
}, 10 * 60 * 1000);

// ============================================================
// BRUTE FORCE TRACKER untuk login
// ============================================================
const loginAttempts = new Map(); // key=ip → { count, blockedUntil }

function checkBruteForce(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, blockedUntil: 0 };

  if (entry.blockedUntil > now) {
    const wait = Math.ceil((entry.blockedUntil - now) / 1000);
    return res.status(429).json({
      error: `Terlalu banyak percobaan login. Coba lagi dalam ${wait} detik.`
    });
  }
  req._loginEntry = entry;
  req._loginIp = ip;
  next();
}

function recordLoginFailure(ip) {
  const entry = loginAttempts.get(ip) || { count: 0, blockedUntil: 0 };
  entry.count++;
  // Block escalation: 5x→1min, 10x→5min, 15x→30min
  if (entry.count >= 15) entry.blockedUntil = Date.now() + 30 * 60 * 1000;
  else if (entry.count >= 10) entry.blockedUntil = Date.now() + 5 * 60 * 1000;
  else if (entry.count >= 5) entry.blockedUntil = Date.now() + 60 * 1000;
  loginAttempts.set(ip, entry);
}

function clearLoginAttempts(ip) {
  loginAttempts.delete(ip);
}

// ============================================================
// INPUT VALIDATION HELPERS
// ============================================================
const ALLOWED_USERNAME = /^[a-zA-Z0-9_]{3,30}$/;
const ALLOWED_EMAIL    = /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{1,63}$/;

function sanitizeText(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '').trim().substring(0, maxLen);
}

function validateUsername(username) {
  if (!username || typeof username !== 'string') return 'Username wajib diisi';
  if (!ALLOWED_USERNAME.test(username)) return 'Username hanya boleh huruf, angka, underscore (3-30 karakter)';
  return null;
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') return 'Password wajib diisi';
  if (password.length < 8) return 'Password minimal 8 karakter';
  if (password.length > 128) return 'Password terlalu panjang';
  return null;
}

// ============================================================
// SAFE FILENAME: hapus path traversal
// ============================================================
function safePath(filename) {
  return path.basename(filename).replace(/[^a-zA-Z0-9._-]/g, '_');
}

// Ekstensi file yang diizinkan
const ALLOWED_IMAGE_EXT = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
const ALLOWED_VIDEO_EXT = ['.mp4', '.webm', '.mov', '.avi', '.mkv'];
const ALLOWED_AUDIO_EXT = ['.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac'];

function isAllowedExt(filename, allowed) {
  return allowed.includes(path.extname(filename).toLowerCase());
}

// ============================================================
// SECURITY HEADERS MIDDLEWARE
// ============================================================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  // Hapus header yang bocorkan info server
  res.removeHeader('X-Powered-By');
  next();
});

// ============================================================
// BODY SIZE LIMIT — cegah DoS via payload besar
// ============================================================
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// Static files
app.use('/uploads', express.static('uploads'));
app.use(express.static('public'));

// ============================================================
// SESSION CONFIG — gunakan secret persisten
// ============================================================
app.use(session({
  secret: getOrCreateSessionSecret(),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,      // cegah akses JS ke cookie
    sameSite: 'lax',     // CSRF protection dasar
    // secure: true,     // aktifkan jika pakai HTTPS
  },
  name: 'mio.sid'        // jangan pakai nama default 'connect.sid'
}));

// ============================================================
// GLOBAL RATE LIMIT — semua request (anti-DoS umum)
// ============================================================
app.use(rateLimit({ windowMs: 60000, max: 300 })); // 300 req/menit per IP

// ============================================================
// LEVEL CONFIGURATION (tidak berubah dari asli)
// ============================================================
function generateLevelConfig() {
  const config = {};
  for (let level = 1; level <= 999; level++) {
    const minXP = Math.floor(50 * (level - 1) * level);
    let name = '', icon = '';
    if (level <= 10) {
      const names = ['Newbie','Rookie','Explorer','Creator','Influencer','Elite','Legend','Mythic','Godlike','Immortal'];
      const icons = ['🌱','⭐','🚀','🎨','🌟','💎','🏆','⚡','👑','🔥'];
      name = names[level - 1]; icon = icons[level - 1];
    } else if (level <= 50)  { name = 'Master';      icon = '✨'; }
    else if (level <= 100)   { name = 'Grandmaster'; icon = '💫'; }
    else if (level <= 200)   { name = 'Legendary';   icon = '🏅'; }
    else if (level <= 500)   { name = 'Mythic';      icon = '🌌'; }
    else                     { name = 'Ascendant';   icon = '👁️'; }
    config[level] = { name, minXp: minXP, icon };
  }
  return config;
}

function calculateLevel(xp) {
  const levelsData = readJSON('data/levels.json');
  const levelConfig = levelsData.levelConfig;
  for (let i = 999; i >= 1; i--) {
    if (levelConfig[i] && xp >= levelConfig[i].minXp) return i;
  }
  return 1;
}

// ============================================================
// INITIALIZE DATA FILES
// ============================================================
function initializeDataFiles() {
  const dirs = [
    './data','./uploads','./uploads/images','./uploads/videos',
    './uploads/profiles','./uploads/comments','./uploads/music',
    './uploads/wallpapers','./uploads/chat'
  ];
  dirs.forEach(dir => { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); });

  const fullLevelConfig = generateLevelConfig();
  const files = {
    'data/login.json':         { users: [], adminUsers: [] },
    'data/user.json':          {},
    'data/database.json':      { posts: [], comments: [], likes: [] },
    'data/setting.user.json':  {},
    'data/verified.users.json':{ verified: [] },
    'data/saved.login.json':   { savedLogins: [], rememberTokens: {} },
    'data/follow.data.json':   { followers: {}, following: {}, followRequests: {} },
    'data/levels.json':        { userLevels: {}, levelConfig: fullLevelConfig },
    'data/badges.json':        { customBadges: {}, badgeColors: { gold:'#FFD700',silver:'#C0C0C0',bronze:'#CD7F32',platinum:'#E5E4E2',diamond:'#B9F2FF' } },
    'data/chats.json':         { conversations: {}, messages: {} }
  };

  Object.entries(files).forEach(([filePath, defaultData]) => {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2));
    } else {
      try {
        const existing = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (filePath === 'data/levels.json' && (!existing.levelConfig || Object.keys(existing.levelConfig).length < 100)) {
          existing.levelConfig = fullLevelConfig;
        }
        Object.keys(defaultData).forEach(key => { if (existing[key] === undefined) existing[key] = defaultData[key]; });
        fs.writeFileSync(filePath, JSON.stringify(existing, null, 2));
      } catch { fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2)); }
    }
  });

  try {
    const loginData = JSON.parse(fs.readFileSync('data/login.json', 'utf8'));
    if (!loginData.adminUsers) loginData.adminUsers = [];
    if (loginData.users.length > 0 && loginData.adminUsers.length === 0) {
      const firstUser = loginData.users[0];
      loginData.adminUsers.push(firstUser.id);
      const verifiedData = JSON.parse(fs.readFileSync('data/verified.users.json', 'utf8'));
      if (!verifiedData.verified) verifiedData.verified = [];
      if (!verifiedData.verified.includes(firstUser.id)) {
        verifiedData.verified.push(firstUser.id);
        fs.writeFileSync('data/verified.users.json', JSON.stringify(verifiedData, null, 2));
      }
      fs.writeFileSync('data/login.json', JSON.stringify(loginData, null, 2));
    }
  } catch {}
}

initializeDataFiles();

// ============================================================
// HELPER FUNCTIONS
// ============================================================
function readJSON(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch { return null; }
}
function writeJSON(filePath, data) {
  try { fs.writeFileSync(filePath, JSON.stringify(data, null, 2)); return true; } catch { return false; }
}
function getUserById(userId) {
  if (!userId || typeof userId !== 'string') return null;
  const userData = readJSON('data/user.json');
  return userData?.[userId] || null;
}
function isAdmin(userId) {
  const loginData = readJSON('data/login.json');
  return !!(loginData?.adminUsers?.includes(userId));
}
function isVerified(userId) {
  const verifiedData = readJSON('data/verified.users.json');
  return !!(verifiedData?.verified?.includes(userId));
}
function getUserLevel(userId) {
  const levelsData = readJSON('data/levels.json');
  if (!levelsData.userLevels[userId]) {
    levelsData.userLevels[userId] = { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };
    writeJSON('data/levels.json', levelsData);
  }
  return levelsData.userLevels[userId];
}
function addXP(userId, amount) {
  const levelsData = readJSON('data/levels.json');
  if (!levelsData.userLevels[userId]) levelsData.userLevels[userId] = { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };
  const userLevel = levelsData.userLevels[userId];
  userLevel.xp += amount;
  const newLevel = calculateLevel(userLevel.xp);
  const leveledUp = newLevel > userLevel.level;
  userLevel.level = newLevel;
  writeJSON('data/levels.json', levelsData);
  return { leveledUp, newLevel };
}
function getLevelInfo(userId) {
  const levelsData = readJSON('data/levels.json');
  const levelConfig = levelsData.levelConfig;
  const userLevel = getUserLevel(userId);
  const cur = levelConfig[userLevel.level] || levelConfig[999];
  const next = levelConfig[userLevel.level + 1] || null;
  return {
    level: userLevel.level, xp: userLevel.xp,
    levelName: cur.name, levelIcon: cur.icon,
    xpNeeded: next ? next.minXp - userLevel.xp : 0,
    xpForNext: next ? next.minXp : userLevel.xp,
    totalPosts: userLevel.totalPosts, totalLikes: userLevel.totalLikes,
    progress: next ? (userLevel.xp - cur.minXp) / (next.minXp - cur.minXp) * 100 : 100
  };
}
function getUserBadges(userId) {
  const badgesData = readJSON('data/badges.json');
  const userBadges = badgesData?.customBadges?.[userId] || [];
  const badges = [];
  if (isVerified(userId)) badges.push({ name:'Verified', icon:'✓', color:'#1da1f2', isCustom:false });
  if (isAdmin(userId)) badges.push({ name:'Developer', icon:'👑', color:'#FF4444', isCustom:false });
  userBadges.forEach(b => badges.push({ ...b, isCustom:true }));
  return badges;
}
function assignBadge(userId, badgeName, badgeIcon, badgeColor) {
  const badgesData = readJSON('data/badges.json');
  if (!badgesData.customBadges[userId]) badgesData.customBadges[userId] = [];
  const existing = badgesData.customBadges[userId].find(b => b.name === badgeName);
  if (existing) { existing.icon = badgeIcon; existing.color = badgeColor; }
  else badgesData.customBadges[userId].push({ name: badgeName, icon: badgeIcon, color: badgeColor });
  writeJSON('data/badges.json', badgesData);
  return true;
}
function removeBadge(userId, badgeName) {
  const badgesData = readJSON('data/badges.json');
  if (badgesData.customBadges[userId]) {
    badgesData.customBadges[userId] = badgesData.customBadges[userId].filter(b => b.name !== badgeName);
    writeJSON('data/badges.json', badgesData);
    return true;
  }
  return false;
}
function getAllCustomBadges() {
  const badgesData = readJSON('data/badges.json');
  const allBadges = [];
  for (const [userId, badges] of Object.entries(badgesData?.customBadges || {})) {
    const user = getUserById(userId);
    if (user) badges.forEach(b => allBadges.push({ ...b, userId, username: user.username }));
  }
  return allBadges;
}
function generateRememberToken() { return crypto.randomBytes(32).toString('hex'); }
function saveRememberToken(userId, username) {
  const savedData = readJSON('data/saved.login.json');
  const token = generateRememberToken();
  const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
  if (!savedData.rememberTokens) savedData.rememberTokens = {};
  savedData.rememberTokens[token] = { userId, username, expires };
  writeJSON('data/saved.login.json', savedData);
  return token;
}
function validateRememberToken(token) {
  // Validasi format token dulu
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const savedData = readJSON('data/saved.login.json');
  if (!savedData?.rememberTokens?.[token]) return null;
  const tokenData = savedData.rememberTokens[token];
  if (tokenData.expires < Date.now()) {
    delete savedData.rememberTokens[token];
    writeJSON('data/saved.login.json', savedData);
    return null;
  }
  tokenData.expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
  savedData.rememberTokens[token] = tokenData;
  writeJSON('data/saved.login.json', savedData);
  return tokenData;
}
function removeRememberToken(token) {
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return;
  const savedData = readJSON('data/saved.login.json');
  if (savedData?.rememberTokens?.[token]) {
    delete savedData.rememberTokens[token];
    writeJSON('data/saved.login.json', savedData);
  }
}
function getFollowStatus(userId, targetUserId) {
  const followData = readJSON('data/follow.data.json');
  return {
    isFollowing: !!(followData?.following?.[userId]?.includes(targetUserId)),
    isFollowedBack: !!(followData?.followers?.[userId]?.includes(targetUserId)),
    followersCount: followData?.followers?.[targetUserId]?.length || 0,
    followingCount: followData?.following?.[targetUserId]?.length || 0
  };
}
function toggleFollow(userId, targetUserId) {
  const followData = readJSON('data/follow.data.json');
  if (!followData.following[userId]) followData.following[userId] = [];
  if (!followData.followers[targetUserId]) followData.followers[targetUserId] = [];
  const idx = followData.following[userId].indexOf(targetUserId);
  let action;
  if (idx === -1) {
    followData.following[userId].push(targetUserId);
    followData.followers[targetUserId].push(userId);
    action = 'follow';
  } else {
    followData.following[userId].splice(idx, 1);
    const fi = followData.followers[targetUserId].indexOf(userId);
    if (fi !== -1) followData.followers[targetUserId].splice(fi, 1);
    action = 'unfollow';
  }
  const userData = readJSON('data/user.json');
  if (userData[userId]) userData[userId].following = followData.following[userId].length;
  if (userData[targetUserId]) userData[targetUserId].followers = followData.followers[targetUserId].length;
  writeJSON('data/user.json', userData);
  writeJSON('data/follow.data.json', followData);
  return { success:true, action, followersCount: followData.followers[targetUserId]?.length||0 };
}

// CHAT HELPERS
function getConversationId(a, b) { return [a, b].sort().join('_'); }
function getChatData() { return readJSON('data/chats.json') || { conversations:{}, messages:{} }; }
function saveChatData(data) { return writeJSON('data/chats.json', data); }
function getUnreadCount(userId) {
  const chatData = getChatData();
  let total = 0;
  for (const convId in chatData.conversations) {
    const conv = chatData.conversations[convId];
    if (conv.participants.includes(userId)) total += conv.unreadCount?.[userId] || 0;
  }
  return total;
}

// DELETE USER DATA
function deleteUserData(userId) {
  const loginData = readJSON('data/login.json');
  loginData.users = loginData.users.filter(u => u.id !== userId);
  loginData.adminUsers = (loginData.adminUsers || []).filter(id => id !== userId);
  writeJSON('data/login.json', loginData);

  const userData = readJSON('data/user.json');
  delete userData[userId];
  writeJSON('data/user.json', userData);

  const verifiedData = readJSON('data/verified.users.json');
  verifiedData.verified = (verifiedData.verified || []).filter(id => id !== userId);
  writeJSON('data/verified.users.json', verifiedData);

  const database = readJSON('data/database.json');
  database.posts = (database.posts || []).filter(p => p.userId !== userId);
  database.comments = (database.comments || []).filter(c => c.userId !== userId);
  writeJSON('data/database.json', database);

  const followData = readJSON('data/follow.data.json');
  delete followData.followers[userId];
  delete followData.following[userId];
  Object.keys(followData.followers || {}).forEach(k => {
    followData.followers[k] = followData.followers[k].filter(id => id !== userId);
  });
  Object.keys(followData.following || {}).forEach(k => {
    followData.following[k] = followData.following[k].filter(id => id !== userId);
  });
  writeJSON('data/follow.data.json', followData);

  const savedData = readJSON('data/saved.login.json');
  if (savedData.rememberTokens) {
    Object.keys(savedData.rememberTokens).forEach(token => {
      if (savedData.rememberTokens[token].userId === userId) delete savedData.rememberTokens[token];
    });
    writeJSON('data/saved.login.json', savedData);
  }

  const levelsData = readJSON('data/levels.json');
  delete levelsData.userLevels[userId];
  writeJSON('data/levels.json', levelsData);

  const badgesData = readJSON('data/badges.json');
  delete badgesData.customBadges[userId];
  writeJSON('data/badges.json', badgesData);

  const chatData = getChatData();
  for (const convId in chatData.conversations) {
    if (chatData.conversations[convId].participants.includes(userId)) {
      delete chatData.conversations[convId];
      delete chatData.messages[convId];
    }
  }
  saveChatData(chatData);
}

// ============================================================
// MULTER — dengan validasi ekstensi dan ukuran ketat
// ============================================================
const storage = multer.diskStorage({
  destination(req, file, cb) {
    let folder = 'uploads/';
    if (file.mimetype.startsWith('image/')) folder += 'images/';
    else if (file.mimetype.startsWith('video/')) folder += 'videos/';
    else if (file.mimetype.startsWith('audio/')) folder += 'music/';
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename(req, file, cb) {
    const unique = Date.now() + '-' + crypto.randomBytes(8).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, 'media-' + unique + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024, files: 6 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (file.fieldname.startsWith('media')) {
      if ((file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) ||
          (file.mimetype.startsWith('video/') && ALLOWED_VIDEO_EXT.includes(ext))) return cb(null, true);
      return cb(new Error('Format media tidak didukung'));
    }
    if (file.fieldname === 'music') {
      if (file.mimetype.startsWith('audio/') && ALLOWED_AUDIO_EXT.includes(ext)) return cb(null, true);
      return cb(new Error('Format audio tidak didukung'));
    }
    cb(new Error('Field tidak dikenal'));
  }
});

const profileStorage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/profiles/'); },
  filename(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${req.session.userId}-${file.fieldname}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ext}`);
  }
});
const profileUpload = multer({
  storage: profileStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) return cb(null, true);
    cb(new Error('Hanya gambar yang diizinkan'));
  }
});

const wallpaperStorage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/wallpapers/'); },
  filename(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `wallpaper-${req.session.userId}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ext}`);
  }
});
const wallpaperUpload = multer({
  storage: wallpaperStorage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if ((file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) ||
        (file.mimetype.startsWith('video/') && ALLOWED_VIDEO_EXT.includes(ext))) return cb(null, true);
    cb(new Error('Format tidak didukung'));
  }
});

const commentStorage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/comments/'); },
  filename(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, 'comment-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
  }
});
const commentUpload = multer({
  storage: commentStorage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if ((file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) ||
        (file.mimetype.startsWith('video/') && ALLOWED_VIDEO_EXT.includes(ext))) return cb(null, true);
    cb(new Error('Format tidak didukung'));
  }
});

const chatMediaStorage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/chat/'); },
  filename(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, 'chat-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
  }
});
const chatMediaUpload = multer({
  storage: chatMediaStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if ((file.mimetype.startsWith('image/') && ALLOWED_IMAGE_EXT.includes(ext)) ||
        (file.mimetype.startsWith('video/') && ALLOWED_VIDEO_EXT.includes(ext)) ||
        (file.mimetype.startsWith('audio/') && ALLOWED_AUDIO_EXT.includes(ext))) return cb(null, true);
    cb(new Error('Format tidak didukung'));
  }
});

// ============================================================
// MIDDLEWARE AUTH
// ============================================================
function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  const token = req.cookies?.rememberToken;
  if (token) {
    const tokenData = validateRememberToken(token);
    if (tokenData) {
      req.session.userId = tokenData.userId;
      req.session.username = tokenData.username;
      return next();
    }
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

function requireAdmin(req, res, next) {
  // Double-check: cek session DAN baca ulang dari file
  if (req.session.userId && isAdmin(req.session.userId)) return next();
  return res.status(403).json({ error: 'Forbidden' });
}

// ============================================================
// ROUTES
// ============================================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ----------------------------------------------------------
// AUTH: Register — rate limit sangat ketat (anti-bot)
// 5 registrasi per IP per jam
// ----------------------------------------------------------
app.post('/api/register',
  rateLimit({ windowMs: 60 * 60 * 1000, max: 5, keyFn: (req) => 'reg:' + req.ip }),
  async (req, res) => {
    const { username, password, email } = req.body;

    // Validasi username
    const unameErr = validateUsername(username);
    if (unameErr) return res.status(400).json({ error: unameErr });

    // Validasi password
    const passErr = validatePassword(password);
    if (passErr) return res.status(400).json({ error: passErr });

    // Validasi email (opsional tapi jika diisi harus valid)
    if (email && email.length > 0 && !ALLOWED_EMAIL.test(email)) {
      return res.status(400).json({ error: 'Format email tidak valid' });
    }

    const loginData = readJSON('data/login.json');
    if (loginData.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(400).json({ error: 'Username sudah digunakan' });
    }

    // Batasi total user (opsional, aktifkan jika perlu)
    // if (loginData.users.length >= 10000) return res.status(503).json({ error: 'Registrasi ditutup sementara' });

    const hashedPassword = await bcrypt.hash(password, 12); // cost 12 lebih aman
    const userId = 'user_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const cleanEmail = email ? sanitizeText(email, 254) : '';

    loginData.users.push({
      id: userId,
      username: sanitizeText(username, 30),
      password: hashedPassword,
      email: cleanEmail,
      createdAt: new Date().toISOString(),
      registeredIp: req.ip // catat IP registrasi untuk investigasi
    });
    writeJSON('data/login.json', loginData);

    const userData = readJSON('data/user.json');
    userData[userId] = {
      id: userId,
      username: sanitizeText(username, 30),
      email: cleanEmail,
      profilePic: '', wallpaper: '', bio: '',
      followers: 0, following: 0, posts: 0,
      createdAt: new Date().toISOString()
    };
    writeJSON('data/user.json', userData);

    const levelsData = readJSON('data/levels.json');
    levelsData.userLevels[userId] = { xp: 0, level: 1, totalPosts: 0, totalLikes: 0 };
    writeJSON('data/levels.json', levelsData);

    res.json({ success: true, userId });
  }
);

// ----------------------------------------------------------
// AUTH: Login — brute force protection + rate limit
// 10 percobaan per 15 menit per IP
// ----------------------------------------------------------
app.post('/api/login',
  rateLimit({ windowMs: 15 * 60 * 1000, max: 10, keyFn: (req) => 'login:' + req.ip }),
  checkBruteForce,
  async (req, res) => {
    const { username, password, rememberMe } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username dan password wajib diisi' });

    // Sanitasi input sebelum query
    if (typeof username !== 'string' || username.length > 30) {
      return res.status(400).json({ error: 'Username tidak valid' });
    }

    const loginData = readJSON('data/login.json');
    const user = loginData.users.find(u => u.username.toLowerCase() === username.toLowerCase());

    // Tetap jalankan bcrypt meskipun user tidak ada (timing attack prevention)
    const dummyHash = '$2a$12$invalidhashtopreventtimingattacksXXXXXXXXXXXXXXXXXXXXXX';
    const valid = user ? await bcrypt.compare(password, user.password) : await bcrypt.compare(password, dummyHash);

    if (!user || !valid) {
      recordLoginFailure(req.ip);
      // Pesan generik, tidak bocorkan mana yang salah
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    clearLoginAttempts(req.ip);

    // Regenerate session ID setelah login (session fixation prevention)
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Session error' });

      req.session.userId = user.id;
      req.session.username = user.username;

      let token = null;
      if (rememberMe === true || rememberMe === 'true') {
        token = saveRememberToken(user.id, user.username);
        res.cookie('rememberToken', token, {
          maxAge: 30 * 24 * 60 * 60 * 1000,
          httpOnly: true,
          sameSite: 'lax'
        });
      }

      res.json({ success: true, userId: user.id, username: user.username });
    });
  }
);

app.post('/api/logout', (req, res) => {
  const token = req.cookies?.rememberToken;
  if (token) removeRememberToken(token);
  req.session.destroy();
  res.clearCookie('mio.sid');
  res.clearCookie('rememberToken');
  res.json({ success: true });
});

app.get('/api/me', requireLogin, (req, res) => {
  const user = getUserById(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const levelInfo = getLevelInfo(req.session.userId);
  const badges = getUserBadges(req.session.userId);
  const unreadChats = getUnreadCount(req.session.userId);
  res.json({
    id: user.id, username: user.username, profilePic: user.profilePic,
    wallpaper: user.wallpaper, wallpaperSettings: user.wallpaperSettings,
    bio: user.bio, followers: user.followers, following: user.following,
    posts: user.posts, isVerified: isVerified(user.id), isAdmin: isAdmin(user.id),
    level: levelInfo.level, levelName: levelInfo.levelName, levelIcon: levelInfo.levelIcon,
    xp: levelInfo.xp, xpProgress: levelInfo.progress, badges, unreadChats
  });
});

// PROFILE
app.get('/api/profile/:userId', requireLogin, (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  const user = getUserById(targetId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const database = readJSON('data/database.json');
  const userPosts = (database.posts || []).filter(p => p.userId === targetId);
  const totalLikes = userPosts.reduce((sum, p) => sum + (p.likes?.length || 0), 0);
  const followStatus = getFollowStatus(req.session.userId, targetId);
  const levelInfo = getLevelInfo(targetId);
  const badges = getUserBadges(targetId);
  res.json({
    id: user.id, username: user.username, profilePic: user.profilePic,
    wallpaper: user.wallpaper, wallpaperSettings: user.wallpaperSettings,
    bio: user.bio, followers: followStatus.followersCount, following: followStatus.followingCount,
    posts: user.posts, totalLikes, isVerified: isVerified(targetId), isAdmin: isAdmin(targetId),
    isFollowing: followStatus.isFollowing, isFollowedBack: followStatus.isFollowedBack,
    level: levelInfo.level, levelName: levelInfo.levelName, levelIcon: levelInfo.levelIcon,
    xp: levelInfo.xp, xpProgress: levelInfo.progress, badges
  });
});

app.post('/api/profile/update', requireLogin, (req, res) => {
  const bio = sanitizeText(req.body.bio || '', 150);
  const userData = readJSON('data/user.json');
  if (!userData[req.session.userId]) return res.status(404).json({ error: 'User not found' });
  userData[req.session.userId].bio = bio;
  writeJSON('data/user.json', userData);
  res.json({ success: true });
});

app.post('/api/profile/upload-pic', requireLogin,
  profileUpload.fields([{ name:'profilePic', maxCount:1 }, { name:'wallpaper', maxCount:1 }]),
  (req, res) => {
    const userData = readJSON('data/user.json');
    if (req.files['profilePic']) userData[req.session.userId].profilePic = '/uploads/profiles/' + req.files['profilePic'][0].filename;
    if (req.files['wallpaper']) {
      const url = '/uploads/profiles/' + req.files['wallpaper'][0].filename;
      userData[req.session.userId].wallpaper = url;
      if (!userData[req.session.userId].wallpaperSettings) userData[req.session.userId].wallpaperSettings = {};
      userData[req.session.userId].wallpaperSettings.type = 'image';
      userData[req.session.userId].wallpaperSettings.image = url;
    }
    writeJSON('data/user.json', userData);
    res.json({ success:true, profilePic: userData[req.session.userId].profilePic, wallpaper: userData[req.session.userId].wallpaper });
  }
);

app.post('/api/profile/upload-wallpaper', requireLogin, wallpaperUpload.single('wallpaper'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file' });
  const fileUrl = '/uploads/wallpapers/' + req.file.filename;
  const fileType = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
  const userData = readJSON('data/user.json');
  if (!userData[req.session.userId]) return res.status(404).json({ error: 'User not found' });
  userData[req.session.userId].wallpaper = fileUrl;
  if (!userData[req.session.userId].wallpaperSettings) userData[req.session.userId].wallpaperSettings = {};
  userData[req.session.userId].wallpaperSettings.type = 'media';
  userData[req.session.userId].wallpaperSettings.mediaUrl = fileUrl;
  userData[req.session.userId].wallpaperSettings.mediaType = fileType;
  writeJSON('data/user.json', userData);
  res.json({ success:true, wallpaperUrl: fileUrl, mediaType: fileType });
});

app.post('/api/profile/wallpaper', requireLogin, (req, res) => {
  const { wallpaperType, wallpaperValue, blur } = req.body;
  const allowedTypes = ['image', 'color', 'gradient', 'media'];
  if (wallpaperType && !allowedTypes.includes(wallpaperType)) {
    return res.status(400).json({ error: 'wallpaperType tidak valid' });
  }
  const userData = readJSON('data/user.json');
  if (!userData[req.session.userId]) return res.status(404).json({ error: 'User not found' });
  userData[req.session.userId].wallpaperSettings = {
    type: wallpaperType || 'image',
    value: sanitizeText(wallpaperValue || '', 500),
    blur: blur === true || blur === 'true'
  };
  writeJSON('data/user.json', userData);
  res.json({ success:true, settings: userData[req.session.userId].wallpaperSettings });
});

app.get('/api/profile/wallpaper', requireLogin, (req, res) => {
  const userData = readJSON('data/user.json');
  const user = userData[req.session.userId];
  if (!user) return res.status(404).json({ error: 'User not found' });
  const settings = user.wallpaperSettings || { type:'image', value: user.wallpaper||'', blur:false };
  res.json({ success:true, settings });
});

// POST UPLOAD — rate limit 20 upload per jam
app.post('/api/upload',
  requireLogin,
  rateLimit({ windowMs: 60 * 60 * 1000, max: 20, keyFn: (req) => 'upload:' + req.session.userId }),
  (req, res) => {
    const uploadMiddleware = upload.fields([
      { name:'media0', maxCount:1 }, { name:'media1', maxCount:1 }, { name:'media2', maxCount:1 },
      { name:'media3', maxCount:1 }, { name:'media4', maxCount:1 }, { name:'music', maxCount:1 }
    ]);
    uploadMiddleware(req, res, async (err) => {
      if (err) return res.status(400).json({ error: err.message });
      try {
        const caption = sanitizeText(req.body.caption || '', 2200);
        const files = req.files;
        if (!files || Object.keys(files).length === 0) return res.status(400).json({ error: 'Tidak ada file' });
        const mediaFiles = [];
        const count = Math.min(parseInt(req.body.fileCount) || 0, 5);
        for (let i = 0; i < count; i++) {
          if (files[`media${i}`]?.[0]) mediaFiles.push(files[`media${i}`][0]);
        }
        if (!mediaFiles.length) return res.status(400).json({ error: 'Tidak ada media valid' });
        const musicFile = files.music?.[0] || null;
        const mediaArray = mediaFiles.map(f => ({
          mediaUrl: '/uploads/' + (f.mimetype.startsWith('image/') ? 'images/' : 'videos/') + f.filename,
          mediaType: f.mimetype.startsWith('image/') ? 'image' : 'video'
        }));
        const database = readJSON('data/database.json');
        const postId = 'post_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
        const newPost = {
          id: postId, userId: req.session.userId, username: req.session.username,
          mediaArray, mediaUrl: mediaArray[0].mediaUrl, mediaType: mediaArray[0].mediaType,
          caption, likes: [], comments: [],
          musicUrl: musicFile ? '/uploads/music/' + musicFile.filename : null,
          musicName: musicFile ? sanitizeText(musicFile.originalname, 100) : null,
          createdAt: new Date().toISOString()
        };
        if (!database.posts) database.posts = [];
        database.posts.push(newPost);
        writeJSON('data/database.json', database);
        const userData = readJSON('data/user.json');
        userData[req.session.userId].posts = (userData[req.session.userId].posts || 0) + 1;
        writeJSON('data/user.json', userData);
        const levelResult = addXP(req.session.userId, 50);
        res.json({ success:true, post: newPost, leveledUp: levelResult.leveledUp, newLevel: levelResult.newLevel });
      } catch (e) { res.status(500).json({ error: 'Upload gagal' }); }
    });
  }
);

// COMMENTS — rate limit 30 komentar per 10 menit
app.post('/api/comment/upload-media', requireLogin, commentUpload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file' });
  res.json({ success:true, mediaUrl: '/uploads/comments/' + req.file.filename, mediaType: req.file.mimetype.startsWith('image/') ? 'image' : 'video' });
});

app.post('/api/post/:postId/comment',
  requireLogin,
  rateLimit({ windowMs: 10 * 60 * 1000, max: 30, keyFn: (req) => 'comment:' + req.session.userId }),
  (req, res) => {
    const postId = sanitizeText(req.params.postId, 60);
    const text = sanitizeText(req.body.text || '', 1000);
    const mediaUrl = req.body.mediaUrl ? sanitizeText(req.body.mediaUrl, 300) : null;
    const mediaType = ['image','video'].includes(req.body.mediaType) ? req.body.mediaType : null;
    if (!text && !mediaUrl) return res.status(400).json({ error: 'Komentar tidak boleh kosong' });
    const database = readJSON('data/database.json');
    const postIndex = database.posts.findIndex(p => p.id === postId);
    if (postIndex === -1) return res.status(404).json({ error: 'Post not found' });
    const commentId = 'comment_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const newComment = {
      id: commentId, postId, userId: req.session.userId, username: req.session.username,
      text, mediaUrl, mediaType,
      profilePic: getUserById(req.session.userId)?.profilePic || '',
      isVerified: isVerified(req.session.userId), createdAt: new Date().toISOString()
    };
    if (!database.comments) database.comments = [];
    database.comments.push(newComment);
    if (!database.posts[postIndex].comments) database.posts[postIndex].comments = [];
    database.posts[postIndex].comments.push(commentId);
    writeJSON('data/database.json', database);
    addXP(req.session.userId, 10);
    res.json({ success:true, comment: newComment });
  }
);

app.get('/api/post/:postId/comments', requireLogin, (req, res) => {
  const postId = sanitizeText(req.params.postId, 60);
  const database = readJSON('data/database.json');
  const comments = (database.comments || [])
    .filter(c => c.postId === postId)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  res.json({ comments });
});

// FEED & EXPLORE
app.get('/api/feed', requireLogin, (req, res) => {
  const database = readJSON('data/database.json');
  const followData = readJSON('data/follow.data.json');
  const following = followData.following?.[req.session.userId] || [];
  const posts = (database.posts || [])
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .map(post => ({
      ...post,
      likesCount: post.likes?.length || 0,
      commentsCount: post.comments?.length || 0,
      isLiked: post.likes?.includes(req.session.userId) || false,
      isFromFollowing: following.includes(post.userId) || post.userId === req.session.userId,
      userProfilePic: getUserById(post.userId)?.profilePic || '',
      isVerified: isVerified(post.userId)
    }));
  res.json({ posts });
});

app.get('/api/user/:userId/posts', requireLogin, (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  const database = readJSON('data/database.json');
  const posts = (database.posts || [])
    .filter(p => p.userId === targetId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .map(p => ({ ...p, likesCount: p.likes?.length || 0, commentsCount: p.comments?.length || 0, isLiked: p.likes?.includes(req.session.userId) || false }));
  res.json({ posts });
});

app.post('/api/post/:postId/like', requireLogin,
  rateLimit({ windowMs: 60000, max: 60, keyFn: (req) => 'like:' + req.session.userId }),
  (req, res) => {
    const postId = sanitizeText(req.params.postId, 60);
    const database = readJSON('data/database.json');
    const idx = database.posts.findIndex(p => p.id === postId);
    if (idx === -1) return res.status(404).json({ error: 'Post not found' });
    const post = database.posts[idx];
    if (!post.likes) post.likes = [];
    const likeIdx = post.likes.indexOf(req.session.userId);
    let liked = false;
    if (likeIdx === -1) { post.likes.push(req.session.userId); liked = true; addXP(req.session.userId, 5); addXP(post.userId, 10); }
    else { post.likes.splice(likeIdx, 1); liked = false; }
    database.posts[idx] = post;
    writeJSON('data/database.json', database);
    res.json({ success:true, liked, likesCount: post.likes.length });
  }
);

app.get('/api/search', requireLogin,
  rateLimit({ windowMs: 60000, max: 30, keyFn: (req) => 'search:' + req.session.userId }),
  (req, res) => {
    const query = sanitizeText(req.query.q || '', 50).toLowerCase();
    if (!query || query.length < 2) return res.json({ users: [] });
    const userData = readJSON('data/user.json');
    const users = Object.values(userData)
      .filter(u => u.username.toLowerCase().includes(query))
      .map(u => ({ id: u.id, username: u.username, profilePic: u.profilePic, bio: u.bio, isVerified: isVerified(u.id) }))
      .slice(0, 20);
    res.json({ users });
  }
);

app.post('/api/user/:userId/follow', requireLogin,
  rateLimit({ windowMs: 60000, max: 20, keyFn: (req) => 'follow:' + req.session.userId }),
  (req, res) => {
    const targetId = sanitizeText(req.params.userId, 50);
    if (targetId === req.session.userId) return res.status(400).json({ error: 'Tidak bisa follow diri sendiri' });
    if (!getUserById(targetId)) return res.status(404).json({ error: 'User not found' });
    const result = toggleFollow(req.session.userId, targetId);
    res.json(result);
  }
);

app.get('/api/explore', requireLogin, (req, res) => {
  const database = readJSON('data/database.json');
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
  const startIndex = (page - 1) * limit;
  const posts = (database.posts || [])
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(startIndex, startIndex + limit)
    .map(p => ({ ...p, likesCount: p.likes?.length || 0, commentsCount: p.comments?.length || 0, isLiked: p.likes?.includes(req.session.userId) || false, isVerified: isVerified(p.userId) }));
  res.json({ posts, hasMore: startIndex + limit < (database.posts || []).length });
});

// LEADERBOARD
app.get('/api/leaderboard', requireLogin, (req, res) => {
  const userData = readJSON('data/user.json');
  const levelsData = readJSON('data/levels.json');
  const verifiedData = readJSON('data/verified.users.json');
  const loginData = readJSON('data/login.json');
  const leaderboardData = [];
  for (const [userId, user] of Object.entries(userData)) {
    const levelInfo = levelsData.userLevels[userId] || { xp:0, level:1, totalPosts:0, totalLikes:0 };
    leaderboardData.push({
      userId, username: user.username, profilePic: user.profilePic || '',
      level: levelInfo.level, xp: levelInfo.xp, totalPosts: levelInfo.totalPosts || 0,
      totalLikes: levelInfo.totalLikes || 0, followers: user.followers || 0,
      isVerified: verifiedData.verified?.includes(userId) || false,
      isAdmin: loginData.adminUsers?.includes(userId) || false
    });
  }
  const sortedByLevel = [...leaderboardData].sort((a, b) => b.level !== a.level ? b.level - a.level : b.xp - a.xp);
  const topUsers = sortedByLevel.slice(0, 50);
  const topDevelopers = leaderboardData.filter(u => u.isAdmin).sort((a, b) => b.level !== a.level ? b.level - a.level : b.xp - a.xp);
  const currentUserRank = sortedByLevel.findIndex(u => u.userId === req.session.userId) + 1;
  res.json({ success:true, topUsers, topDevelopers, currentUserRank, totalUsers: leaderboardData.length });
});

// CHAT ROUTES
app.get('/api/chat/conversations', requireLogin, (req, res) => {
  const chatData = getChatData();
  const userId = req.session.userId;
  const userData = readJSON('data/user.json');
  const conversations = [];
  for (const [convId, conv] of Object.entries(chatData.conversations)) {
    if (!conv.participants.includes(userId)) continue;
    const otherUserId = conv.participants.find(id => id !== userId);
    const otherUser = userData[otherUserId];
    if (!otherUser) continue;
    const messages = chatData.messages[convId] || [];
    const lastMessage = messages[messages.length - 1] || null;
    const unreadCount = (conv.unreadCount || {})[userId] || 0;
    conversations.push({
      id: convId,
      otherUser: { id: otherUserId, username: otherUser.username, profilePic: otherUser.profilePic || '', isVerified: isVerified(otherUserId), isAdmin: isAdmin(otherUserId) },
      lastMessage: lastMessage ? { text: lastMessage.text, mediaType: lastMessage.mediaType || null, senderId: lastMessage.senderId, createdAt: lastMessage.createdAt, isRead: lastMessage.isRead || false } : null,
      unreadCount, updatedAt: conv.updatedAt || conv.createdAt
    });
  }
  conversations.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  res.json({ success:true, conversations });
});

app.get('/api/chat/with/:userId', requireLogin, (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  const myId = req.session.userId;
  if (targetId === myId) return res.status(400).json({ error: 'Tidak bisa chat dengan diri sendiri' });
  const targetUser = getUserById(targetId);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  const convId = getConversationId(myId, targetId);
  const chatData = getChatData();
  if (!chatData.conversations[convId]) {
    chatData.conversations[convId] = { id: convId, participants: [myId, targetId], createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), unreadCount: { [myId]:0, [targetId]:0 } };
    chatData.messages[convId] = [];
    saveChatData(chatData);
  }
  res.json({ success:true, conversationId: convId, otherUser: { id: targetId, username: targetUser.username, profilePic: targetUser.profilePic || '', bio: targetUser.bio || '', isVerified: isVerified(targetId), isAdmin: isAdmin(targetId) } });
});

app.get('/api/chat/:conversationId/messages', requireLogin, (req, res) => {
  const { conversationId } = req.params;
  const userId = req.session.userId;
  const chatData = getChatData();
  const conv = chatData.conversations[conversationId];
  if (!conv || !conv.participants.includes(userId)) return res.status(403).json({ error: 'Akses ditolak' });
  if (conv.unreadCount) conv.unreadCount[userId] = 0;
  const messages = chatData.messages[conversationId] || [];
  messages.forEach(msg => { if (msg.senderId !== userId) msg.isRead = true; });
  saveChatData(chatData);
  const userData = readJSON('data/user.json');
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = 30;
  const total = messages.length;
  const startIndex = Math.max(0, total - page * limit);
  const endIndex = total - (page - 1) * limit;
  const enriched = messages.slice(startIndex, endIndex).map(msg => {
    const sender = userData[msg.senderId];
    return { ...msg, senderUsername: sender?.username || 'Unknown', senderProfilePic: sender?.profilePic || '', isVerified: isVerified(msg.senderId) };
  });
  res.json({ success:true, messages: enriched, hasMore: startIndex > 0, total });
});

app.post('/api/chat/:conversationId/send', requireLogin,
  rateLimit({ windowMs: 60000, max: 60, keyFn: (req) => 'chat:' + req.session.userId }),
  (req, res) => {
    const { conversationId } = req.params;
    const text = sanitizeText(req.body.text || '', 2000);
    const mediaUrl = req.body.mediaUrl ? sanitizeText(req.body.mediaUrl, 300) : null;
    const mediaType = ['image','video','audio'].includes(req.body.mediaType) ? req.body.mediaType : null;
    const userId = req.session.userId;
    if (!text && !mediaUrl) return res.status(400).json({ error: 'Pesan tidak boleh kosong' });
    const chatData = getChatData();
    const conv = chatData.conversations[conversationId];
    if (!conv || !conv.participants.includes(userId)) return res.status(403).json({ error: 'Akses ditolak' });
    const messageId = 'msg_' + Date.now() + '_' + crypto.randomBytes(6).toString('hex');
    const newMsg = { id: messageId, conversationId, senderId: userId, text, mediaUrl, mediaType, isRead:false, createdAt: new Date().toISOString() };
    if (!chatData.messages[conversationId]) chatData.messages[conversationId] = [];
    chatData.messages[conversationId].push(newMsg);
    const otherUserId = conv.participants.find(id => id !== userId);
    if (!conv.unreadCount) conv.unreadCount = {};
    conv.unreadCount[otherUserId] = (conv.unreadCount[otherUserId] || 0) + 1;
    conv.updatedAt = new Date().toISOString();
    saveChatData(chatData);
    const sender = getUserById(userId);
    res.json({ success:true, message: { ...newMsg, senderUsername: sender?.username || 'Unknown', senderProfilePic: sender?.profilePic || '', isVerified: isVerified(userId) } });
  }
);

app.post('/api/chat/upload-media', requireLogin, chatMediaUpload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Tidak ada file' });
  let mediaType = 'image';
  if (req.file.mimetype.startsWith('video/')) mediaType = 'video';
  else if (req.file.mimetype.startsWith('audio/')) mediaType = 'audio';
  res.json({ success:true, mediaUrl: '/uploads/chat/' + req.file.filename, mediaType });
});

app.delete('/api/chat/message/:messageId', requireLogin, (req, res) => {
  const messageId = sanitizeText(req.params.messageId, 80);
  const userId = req.session.userId;
  const chatData = getChatData();
  let found = false;
  for (const convId in chatData.messages) {
    const idx = chatData.messages[convId].findIndex(m => m.id === messageId);
    if (idx !== -1) {
      if (chatData.messages[convId][idx].senderId !== userId) return res.status(403).json({ error: 'Tidak bisa menghapus pesan orang lain' });
      chatData.messages[convId][idx].deleted = true;
      chatData.messages[convId][idx].text = '';
      chatData.messages[convId][idx].mediaUrl = null;
      found = true; break;
    }
  }
  if (!found) return res.status(404).json({ error: 'Pesan tidak ditemukan' });
  saveChatData(chatData);
  res.json({ success:true });
});

app.get('/api/chat/unread', requireLogin, (req, res) => {
  res.json({ success:true, count: getUnreadCount(req.session.userId) });
});

// ADMIN ROUTES — semua ada requireAdmin
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const userData = readJSON('data/user.json');
  const verifiedData = readJSON('data/verified.users.json');
  const levelsData = readJSON('data/levels.json');
  const loginData = readJSON('data/login.json');
  const users = Object.values(userData).map(u => ({
    id: u.id, username: u.username, profilePic: u.profilePic, bio: u.bio,
    posts: u.posts || 0, followers: u.followers || 0, following: u.following || 0,
    isVerified: verifiedData.verified?.includes(u.id) || false,
    isAdmin: loginData.adminUsers?.includes(u.id) || false,
    level: levelsData.userLevels[u.id]?.level || 1,
    xp: levelsData.userLevels[u.id]?.xp || 0,
    badges: getUserBadges(u.id), createdAt: u.createdAt,
    registeredIp: u.registeredIp || '-' // tampilkan IP registrasi untuk deteksi bot
  }));
  res.json({ users });
});

app.get('/api/admin/posts', requireAdmin, (req, res) => {
  const database = readJSON('data/database.json');
  const userData = readJSON('data/user.json');
  const posts = (database.posts || [])
    .map(p => ({ ...p, username: userData[p.userId]?.username || 'Unknown', userProfilePic: userData[p.userId]?.profilePic || '', likesCount: p.likes?.length || 0, commentsCount: p.comments?.length || 0 }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ posts });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const userData = readJSON('data/user.json');
  const database = readJSON('data/database.json');
  const loginData = readJSON('data/login.json');
  const verifiedData = readJSON('data/verified.users.json');
  const levelsData = readJSON('data/levels.json');
  const chatData = getChatData();
  let totalXP = 0;
  for (const userId in levelsData.userLevels) totalXP += levelsData.userLevels[userId].xp || 0;
  const totalMessages = Object.values(chatData.messages || {}).reduce((sum, msgs) => sum + msgs.length, 0);
  res.json({
    stats: {
      totalUsers: Object.keys(userData).length,
      totalPosts: (database.posts || []).length,
      totalComments: database.comments?.length || 0,
      totalAdmins: loginData.adminUsers?.length || 0,
      totalVerified: verifiedData.verified?.length || 0,
      totalImages: (database.posts || []).filter(p => p.mediaType === 'image').length,
      totalVideos: (database.posts || []).filter(p => p.mediaType === 'video').length,
      totalXP, totalMessages,
      blockedIPs: rateLimitStore.size // info berguna untuk admin
    }
  });
});

app.post('/api/admin/verify/:userId', requireAdmin, (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  const verifiedData = readJSON('data/verified.users.json');
  if (!verifiedData.verified) verifiedData.verified = [];
  if (!verifiedData.verified.includes(targetId)) { verifiedData.verified.push(targetId); writeJSON('data/verified.users.json', verifiedData); addXP(targetId, 100); }
  res.json({ success:true, verified:true });
});

app.post('/api/admin/unverify/:userId', requireAdmin, (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  const verifiedData = readJSON('data/verified.users.json');
  if (verifiedData.verified) { verifiedData.verified = verifiedData.verified.filter(id => id !== targetId); writeJSON('data/verified.users.json', verifiedData); }
  res.json({ success:true, verified:false });
});

app.post('/api/admin/make-admin/:userId', requireAdmin, (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  const loginData = readJSON('data/login.json');
  if (!loginData.adminUsers) loginData.adminUsers = [];
  if (!loginData.adminUsers.includes(targetId)) { loginData.adminUsers.push(targetId); writeJSON('data/login.json', loginData); addXP(targetId, 200); }
  res.json({ success:true, isAdmin:true });
});

app.post('/api/admin/remove-admin/:userId', requireAdmin, (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  // Cegah admin hapus diri sendiri dari admin
  if (targetId === req.session.userId) return res.status(400).json({ error: 'Tidak bisa menghapus status admin diri sendiri' });
  const loginData = readJSON('data/login.json');
  if (loginData.adminUsers) { loginData.adminUsers = loginData.adminUsers.filter(id => id !== targetId); writeJSON('data/login.json', loginData); }
  res.json({ success:true, isAdmin:false });
});

app.delete('/api/admin/post/:postId', requireAdmin, (req, res) => {
  const postId = sanitizeText(req.params.postId, 60);
  const database = readJSON('data/database.json');
  const idx = database.posts.findIndex(p => p.id === postId);
  if (idx === -1) return res.status(404).json({ error: 'Post not found' });
  const post = database.posts[idx];
  database.posts.splice(idx, 1);
  if (database.comments) database.comments = database.comments.filter(c => c.postId !== postId);
  writeJSON('data/database.json', database);
  const userData = readJSON('data/user.json');
  if (userData[post.userId]) { userData[post.userId].posts = Math.max(0, (userData[post.userId].posts || 0) - 1); writeJSON('data/user.json', userData); }
  res.json({ success:true });
});

app.delete('/api/admin/user/:userId', requireAdmin, (req, res) => {
  const targetId = sanitizeText(req.params.userId, 50);
  if (targetId === req.session.userId) return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri' });
  const user = getUserById(targetId);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  try {
    deleteUserData(targetId);
    res.json({ success:true, message: `Akun @${user.username} berhasil dihapus` });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Gagal menghapus akun' });
  }
});

// ============================================================
// FITUR BARU: Admin bisa block/unblock IP (anti-bot manual)
// ============================================================
const blockedIPs = new Set();

app.post('/api/admin/block-ip', requireAdmin, (req, res) => {
  const { ip } = req.body;
  if (!ip || typeof ip !== 'string') return res.status(400).json({ error: 'IP tidak valid' });
  blockedIPs.add(ip.trim());
  res.json({ success:true, message: `IP ${ip} diblokir` });
});

app.post('/api/admin/unblock-ip', requireAdmin, (req, res) => {
  const { ip } = req.body;
  blockedIPs.delete(ip?.trim());
  res.json({ success:true });
});

app.get('/api/admin/blocked-ips', requireAdmin, (req, res) => {
  res.json({ ips: [...blockedIPs] });
});

// Middleware IP block (taruh setelah route admin supaya admin tetap bisa akses)
app.use((req, res, next) => {
  if (blockedIPs.has(req.ip)) return res.status(403).json({ error: 'Akses diblokir' });
  next();
});

app.get('/api/admin/badges', requireAdmin, (req, res) => { res.json({ badges: getAllCustomBadges() }); });

app.post('/api/admin/assign-badge', requireAdmin, (req, res) => {
  const userId = sanitizeText(req.body.userId || '', 50);
  const badgeName = sanitizeText(req.body.badgeName || '', 30);
  if (!userId || !badgeName) return res.status(400).json({ error: 'User ID dan nama badge diperlukan' });
  if (!getUserById(userId)) return res.status(404).json({ error: 'User tidak ditemukan' });
  const result = assignBadge(userId, badgeName, sanitizeText(req.body.badgeIcon || '🏷️', 10), sanitizeText(req.body.badgeColor || '#667eea', 20));
  res.json(result ? { success:true } : { error:'Gagal' });
});

app.post('/api/admin/remove-badge', requireAdmin, (req, res) => {
  const userId = sanitizeText(req.body.userId || '', 50);
  const badgeName = sanitizeText(req.body.badgeName || '', 30);
  if (!userId || !badgeName) return res.status(400).json({ error: 'Parameter kurang' });
  const result = removeBadge(userId, badgeName);
  res.json(result ? { success:true } : { error:'Gagal' });
});

// NOTIFICATIONS
app.get('/api/notifications', requireLogin, (req, res) => {
  const database = readJSON('data/database.json');
  const userData = readJSON('data/user.json');
  const notifications = [];
  (database.posts || []).forEach(post => {
    if (post.userId !== req.session.userId) return;
    (post.likes || []).forEach(likeUserId => {
      if (likeUserId !== req.session.userId) {
        notifications.push({ id:`like_${post.id}_${likeUserId}`, type:'like', userId: likeUserId, username: userData[likeUserId]?.username || 'Unknown', profilePic: userData[likeUserId]?.profilePic || '', isVerified: isVerified(likeUserId), postId: post.id, postMedia: post.mediaUrl, createdAt: post.createdAt, read:false });
      }
    });
    (database.comments || []).forEach(c => {
      if (c.postId === post.id && c.userId !== req.session.userId) {
        notifications.push({ id:`comment_${c.id}`, type:'comment', userId: c.userId, username: c.username, profilePic: c.profilePic || '', isVerified: isVerified(c.userId), postId: post.id, postMedia: post.mediaUrl, comment: c.text, createdAt: c.createdAt, read:false });
      }
    });
  });
  notifications.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ notifications: notifications.slice(0, 50) });
});

// SETTINGS
app.post('/api/settings/change-password', requireLogin,
  rateLimit({ windowMs: 60 * 60 * 1000, max: 5, keyFn: (req) => 'chgpw:' + req.session.userId }),
  async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Semua field wajib diisi' });
    const passErr = validatePassword(newPassword);
    if (passErr) return res.status(400).json({ error: passErr });
    const loginData = readJSON('data/login.json');
    const idx = loginData.users.findIndex(u => u.id === req.session.userId);
    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(currentPassword, loginData.users[idx].password);
    if (!valid) return res.status(401).json({ error: 'Password lama salah' });
    loginData.users[idx].password = await bcrypt.hash(newPassword, 12);
    writeJSON('data/login.json', loginData);
    res.json({ success:true });
  }
);

app.delete('/api/settings/delete-account', requireLogin, async (req, res) => {
  const userId = req.session.userId;
  deleteUserData(userId);
  req.session.destroy();
  res.clearCookie('mio.sid');
  res.clearCookie('rememberToken');
  res.json({ success:true });
});

// ============================================================
// ERROR HANDLING — tidak bocorkan stack trace ke client
// ============================================================
app.use((err, req, res, next) => {
  // Log error di server untuk debug
  console.error('[ERROR]', err.message);
  // Kirim pesan generik ke client
  res.status(500).json({ error: 'Terjadi kesalahan server' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint tidak ditemukan' });
});

// ============================================================
// START SERVER
// ============================================================
app.listen(PORT, () => {
  console.log(`✅ Mio Media (SECURE) berjalan di http://localhost:${PORT}`);
  console.log(`🛡️  Rate limiting, brute force protection, input validation: AKTIF`);
});

module.exports = app;
