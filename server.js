const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 8080;

const KEYS_PATH = path.join(__dirname, 'apikeys.json');
const ADMIN_SECRET = 'SUPERSECRET123';

// Load API keys
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

// Revoke expired keys (run before every list or validation)
function revokeExpiredKeys() {
  const now = Date.now();
  let needSave = false;
  apiKeys.forEach(k => {
    if (!k.revoked && !k.used && now >= k.expireAt) {
      k.revoked = true;
      needSave = true;
    }
  });
  if (needSave) saveKeys();
}

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// API: Generate Key (POST)
app.post('/api/generate-key', (req, res) => {
  if (req.headers['x-admin-secret'] !== ADMIN_SECRET) {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  const { expireDays } = req.body;
  if (![1, 2, 3].includes(Number(expireDays))) {
    return res.status(400).json({ message: 'expireDays harus 1, 2, atau 3' });
  }
  const newKey = crypto.randomBytes(24).toString('hex');
  const expireAt = Date.now() + Number(expireDays) * 24 * 60 * 60 * 1000;
  const keyObj = { apiKey: newKey, expireAt, revoked: false, used: false };
  apiKeys.push(keyObj);
  saveKeys();
  res.json({ apiKey: newKey, expireAt });
});

// API: Validate Key (POST)
app.post('/api/validate-key', (req, res) => {
  revokeExpiredKeys();
  const { apiKey } = req.body;
  const idx = apiKeys.findIndex(k =>
    k.apiKey === apiKey &&
    !k.revoked &&
    !k.used &&
    Date.now() < k.expireAt
  );
  if (idx !== -1) {
    // Key valid, mark as used
    apiKeys[idx].used = true;
    saveKeys();
    return res.json({ valid: true, expireAt: apiKeys[idx].expireAt });
  }
  res.status(401).json({ valid: false, message: 'API Key tidak valid, expired, sudah digunakan, atau di-revoke' });
});

// API: List Keys (GET)
app.get('/api/list-keys', (req, res) => {
  if (req.headers['x-admin-secret'] !== ADMIN_SECRET) {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  revokeExpiredKeys();
  const now = Date.now();
  // Only active & unused keys
  const activeKeys = apiKeys.filter(k => !k.revoked && !k.used && now < k.expireAt)
    .map(({ apiKey, expireAt }) => ({ apiKey, expireAt }));
  res.json({ activeKeys });
});

// API: Revoke Key (POST)
app.post('/api/revoke-key', (req, res) => {
  if (req.headers['x-admin-secret'] !== ADMIN_SECRET) {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  const { apiKey } = req.body;
  const idx = apiKeys.findIndex(k => k.apiKey === apiKey && !k.revoked && !k.used && Date.now() < k.expireAt);
  if (idx === -1) {
    return res.status(404).json({ message: 'Key tidak ditemukan, sudah revoked, digunakan, atau expired' });
  }
  apiKeys[idx].revoked = true;
  saveKeys();
  res.json({ message: 'Key berhasil di-revoke' });
});

// Serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.listen(PORT, () => {
  console.log('Auth server running at http://localhost:' + PORT);
});