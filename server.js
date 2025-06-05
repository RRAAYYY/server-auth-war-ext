const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 8080;

const KEYS_PATH = path.join(__dirname, 'apikeys.json');
const ADMINS_PATH = path.join(__dirname, 'admins.json');

function loadAdmins() {
  if (fs.existsSync(ADMINS_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(ADMINS_PATH, 'utf-8'));
    } catch (e) { return []; }
  }
  return [];
}
function saveAdmins(admins) {
  fs.writeFileSync(ADMINS_PATH, JSON.stringify(admins, null, 2));
}

app.use(session({
  secret: 'ganti_ini_dengan_secret_random_lagi',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));

let apiKeys = [];
if (fs.existsSync(KEYS_PATH)) {
  try {
    apiKeys = JSON.parse(fs.readFileSync(KEYS_PATH, 'utf-8'));
  } catch (e) {
    apiKeys = [];
  }
}
function saveKeys() {
  fs.writeFileSync(KEYS_PATH, JSON.stringify(apiKeys, null, 2));
}
function revokeExpiredKeys() {
  const now = Date.now();
  let needSave = false;
  apiKeys.forEach(k => {
    if (!k.revoked && now >= k.expireAt) {
      k.revoked = true;
      needSave = true;
    }
  });
  if (needSave) saveKeys();
}

app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin && req.session.adminUser) return next();
  return res.status(401).json({ message: 'Unauthorized' });
}

function requireSuperadmin(req, res, next) {
  const admins = loadAdmins();
  const user = admins.find(
    u => u.username === req.session.adminUser && u.role === "superadmin" && u.approved
  );
  if (user) return next();
  return res.status(403).json({ message: "Only superadmin allowed" });
}

// Register calon admin
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Username dan password wajib diisi" });
  let admins = loadAdmins();
  if (admins.find(u => u.username === username))
    return res.status(400).json({ message: "Username sudah dipakai" });
  const hash = await bcrypt.hash(password, 10);
  admins.push({ username, password: hash, role: "admin", approved: false });
  saveAdmins(admins);
  res.json({ success: true, message: "Berhasil daftar, menunggu persetujuan admin utama" });
});

// Login (hanya user approved)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const admins = loadAdmins();
  const user = admins.find(u => u.username === username);
  if (!user) return res.status(401).json({ message: 'Username/password salah!' });
  if (!user.approved) return res.status(403).json({ message: 'Akun Anda belum disetujui admin utama.' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: 'Username/password salah!' });
  req.session.isAdmin = true;
  req.session.adminUser = username;
  req.session.adminRole = user.role;
  res.json({ success: true, username, role: user.role });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/status', (req, res) => {
  res.json({
    loggedIn: !!req.session.isAdmin,
    username: req.session.adminUser || null,
    role: req.session.adminRole || null
  });
});

// List admin users (superadmin: semua, admin: diri sendiri)
app.get('/api/admins', requireAdmin, (req, res) => {
  const admins = loadAdmins();
  if (req.session.adminRole === "superadmin") {
    res.json({ admins: admins.map(u => ({ username: u.username, role: u.role, approved: u.approved })) });
  } else {
    const user = admins.find(u => u.username === req.session.adminUser);
    res.json({ admins: [ { username: user.username, role: user.role, approved: user.approved } ] });
  }
});

// List pending users (hanya superadmin)
app.get('/api/pending-users', requireAdmin, requireSuperadmin, (req, res) => {
  const admins = loadAdmins();
  const pending = admins.filter(u => u.role === "admin" && !u.approved)
    .map(u => ({ username: u.username }));
  res.json({ pending });
});

// Approve user (superadmin only)
app.post('/api/approve-user', requireAdmin, requireSuperadmin, (req, res) => {
  const { username } = req.body;
  let admins = loadAdmins();
  const idx = admins.findIndex(u => u.username === username && !u.approved);
  if (idx === -1) return res.status(404).json({ message: "User tidak ditemukan atau sudah diapprove" });
  admins[idx].approved = true;
  saveAdmins(admins);
  res.json({ success: true, username });
});

// Reject (hapus) calon user (superadmin only)
app.post('/api/reject-user', requireAdmin, requireSuperadmin, (req, res) => {
  const { username } = req.body;
  let admins = loadAdmins();
  const idx = admins.findIndex(u => u.username === username && !u.approved);
  if (idx === -1) return res.status(404).json({ message: "User tidak ditemukan atau sudah diapprove" });
  admins.splice(idx, 1);
  saveAdmins(admins);
  res.json({ success: true, username });
});

// Hapus admin (superadmin only, tidak bisa hapus diri sendiri)
app.post('/api/delete-admin', requireAdmin, requireSuperadmin, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ message: "Username wajib diisi" });
  if (username === req.session.adminUser) return res.status(400).json({ message: "Tidak bisa hapus superadmin yang sedang login" });
  let admins = loadAdmins();
  const idx = admins.findIndex(u => u.username === username);
  if (idx === -1) return res.status(404).json({ message: "User tidak ditemukan" });
  admins.splice(idx, 1);
  saveAdmins(admins);
  res.json({ success: true, username });
});

// Reset password admin (superadmin only, tidak bisa reset password dirinya sendiri)
app.post('/api/reset-password', requireAdmin, requireSuperadmin, async (req, res) => {
  const { username, newPassword } = req.body;
  if (!username || !newPassword)
    return res.status(400).json({ message: "Username dan password baru wajib diisi" });
  if (username === req.session.adminUser)
    return res.status(400).json({ message: "Tidak bisa reset password superadmin yang sedang login" });
  let admins = loadAdmins();
  const idx = admins.findIndex(u => u.username === username);
  if (idx === -1) return res.status(404).json({ message: "User tidak ditemukan" });
  admins[idx].password = await bcrypt.hash(newPassword, 10);
  saveAdmins(admins);
  res.json({ success: true });
});

// Ganti password (untuk user login saja)
app.post('/api/change-password', requireAdmin, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const username = req.session.adminUser;
  if (!oldPassword || !newPassword) return res.status(400).json({ message: "Semua kolom wajib diisi" });
  let admins = loadAdmins();
  const userIdx = admins.findIndex(u => u.username === username);
  if (userIdx === -1) return res.status(401).json({ message: "User tidak ditemukan" });
  const valid = await bcrypt.compare(oldPassword, admins[userIdx].password);
  if (!valid) return res.status(401).json({ message: "Password lama salah" });
  admins[userIdx].password = await bcrypt.hash(newPassword, 10);
  saveAdmins(admins);
  res.json({ success: true });
});

app.post('/api/generate-key', requireAdmin, (req, res) => {
  const { expireDays, name } = req.body;
  if (![1, 2, 3].includes(Number(expireDays))) {
    return res.status(400).json({ message: 'expireDays harus 1, 2, atau 3' });
  }
  const newKey = crypto.randomBytes(24).toString('hex');
  const expireAt = Date.now() + Number(expireDays) * 24 * 60 * 60 * 1000;
  const keyObj = { apiKey: newKey, expireAt, revoked: false, name: name || "" };
  apiKeys.push(keyObj);
  saveKeys();
  res.json({ apiKey: newKey, expiry: Math.floor(expireAt / 1000), name: keyObj.name });
});
app.post('/api/rename-key', requireAdmin, (req, res) => {
  const { apiKey, name } = req.body;
  const idx = apiKeys.findIndex(k => k.apiKey === apiKey && !k.revoked && Date.now() < k.expireAt);
  if (idx === -1) return res.status(404).json({ message: 'Key tidak ditemukan, sudah revoked, atau expired' });
  apiKeys[idx].name = name || "";
  saveKeys();
  res.json({ message: 'Nama key berhasil diupdate', name: apiKeys[idx].name });
});
app.get('/api/list-keys', requireAdmin, (req, res) => {
  revokeExpiredKeys();
  const now = Date.now();
  const activeKeys = apiKeys.filter(k => !k.revoked && now < k.expireAt)
    .map(({ apiKey, expireAt, name }) => ({ apiKey, expiry: Math.floor(expireAt / 1000), name: name || "" }));
  res.json({ activeKeys });
});
app.post('/api/revoke-key', requireAdmin, requireSuperadmin, (req, res) => {
  const { apiKey } = req.body;
  const idx = apiKeys.findIndex(k => k.apiKey === apiKey && !k.revoked && Date.now() < k.expireAt);
  if (idx === -1) return res.status(404).json({ message: 'Key tidak ditemukan, sudah revoked, atau expired' });
  apiKeys[idx].revoked = true;
  saveKeys();
  res.json({ message: 'Key berhasil di-revoke' });
});
app.post('/api/validate-key', (req, res) => {
  revokeExpiredKeys();
  const { apiKey } = req.body;
  const idx = apiKeys.findIndex(k =>
    k.apiKey === apiKey &&
    !k.revoked &&
    Date.now() < k.expireAt
  );
  if (idx !== -1) {
    return res.json({ valid: true, expiry: Math.floor(apiKeys[idx].expireAt / 1000) });
  }
  res.status(401).json({ valid: false, message: 'API Key tidak valid, expired, atau di-revoke' });
});
app.post('/api/extend-key', requireAdmin, (req, res) => {
  const { apiKey, days } = req.body;
  if (!apiKey || ![1,2,3].includes(Number(days))) return res.status(400).json({ message: "Parameter tidak valid" });
  const idx = apiKeys.findIndex(k => k.apiKey === apiKey && !k.revoked && Date.now() < k.expireAt);
  if (idx === -1) return res.status(404).json({ message: 'Key tidak ditemukan, sudah revoked, atau expired' });
  apiKeys[idx].expireAt += Number(days) * 24 * 60 * 60 * 1000;
  saveKeys();
  res.json({ message: 'Waktu key berhasil diperpanjang', expiry: Math.floor(apiKeys[idx].expireAt / 1000) });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.listen(PORT, () => {
  console.log('Auth server running at http://localhost:' + PORT);
});