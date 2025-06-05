# WAR JKT48 Auth Server

Server otentikasi dengan API Key yang hanya bisa digunakan 1 device, bisa expire, revoke, dan listing.

## Fitur

- Generate key (input device id & waktu expire)
- List key aktif
- Revoke key
- Semua fitur hanya bisa diakses admin (secret)

## Cara Pakai

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Jalankan server**
   ```bash
   npm start
   ```

3. **Akses halaman admin**
   Buka browser ke [http://localhost:8080/](http://localhost:8080/) dan masukkan admin secret: `SUPERSECRET123`

**Catatan:**
- Key hanya berlaku untuk 1 device id & expired sesuai waktu yang dipilih.
- Ganti `SUPERSECRET123` sebelum deploy!