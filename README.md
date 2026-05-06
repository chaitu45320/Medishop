# 💊 Medishop Pharmacy Billing — License Server v1.0

A complete online license management server for Medishop Pharmacy Billing software.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your secrets
```

### 3. Start Server
```bash
npm start
```

### 4. Open Admin Dashboard
```
http://localhost:8080/?token=ms_admin_2024_secure
```

---

## 📁 Project Structure

```
medishop-license/
├── index.js              ← Main server entry point
├── package.json
├── .env.example          ← Copy to .env and fill in
├── generate-keys.js      ← CLI key generator
├── models/
│   └── db.js             ← SQLite database (sql.js)
├── routes/
│   ├── license.js        ← Client-facing API
│   └── admin.js          ← Admin API
├── utils/
│   └── license.js        ← Key generation & JWT
├── public/
│   ├── dashboard.html    ← Admin dashboard UI
│   └── test.html         ← Server connectivity test
└── data/
    └── medishop_licenses.db  ← Auto-created SQLite DB
```

---

## 🔑 License Key Format

```
MEDSHP-FULL-XXXXXX-XXXXXX-XXXXXX
MEDSHP-TRAL-XXXXXX-XXXXXX-XXXXXX
```

- **Prefix**: `MEDSHP` (Medishop identifier)
- **Type**: `FULL` (permanent) or `TRAL` (trial)
- **Segments**: HMAC-verified — cannot be forged
- **Trial duration**: 10 days (configurable via `TRIAL_DAYS` env var)

---

## 🌐 API Endpoints

### Client (Billing Software) Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/activate` | Activate license on a device |
| POST | `/api/validate` | Periodic license check |
| POST | `/api/deactivate` | Release device slot |

#### Activate Request Body
```json
{
  "licenseKey": "MEDSHP-FULL-FXXXXX-XXXXXX-XXXXXX",
  "email": "pharmacy@example.com",
  "deviceId": "unique-device-id",
  "deviceName": "PC-Main-Counter",
  "appVersion": "1.0.0"
}
```

#### Validate Request Body
```json
{
  "token": "eyJ...",
  "deviceId": "unique-device-id"
}
```

### Admin Endpoints (require Bearer token)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/dashboard` | Stats + recent activity |
| POST | `/admin/keys/generate` | Create new license key |
| GET | `/admin/keys` | List all keys |
| GET | `/admin/keys/:hash` | Key detail + devices + logs |
| POST | `/admin/keys/:hash/revoke` | Revoke license |
| POST | `/admin/keys/:hash/restore` | Restore license |
| POST | `/admin/devices/:hash/:did/revoke` | Revoke device |
| POST | `/admin/devices/:hash/:did/transfer` | Free device slot |
| POST | `/admin/devices/:hash/transfer-all` | Free all slots |
| GET | `/admin/suspicious` | Failed activation report |
| GET | `/admin/logs` | Activity logs |
| GET | `/admin/export` | Download full DB as JSON |
| POST | `/admin/verify` | Manually verify a key |

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `API_SECRET` | `ms_admin_2024_secure` | Admin dashboard token |
| `LICENSE_SECRET` | *(see .env.example)* | HMAC signing secret |
| `JWT_SECRET` | *(see .env.example)* | JWT signing secret |
| `MAX_DEVICES` | `1` | Default max devices per license |
| `TRIAL_DAYS` | `10` | Trial license duration |

> ⚠️ **Always change the default secrets in production!**

---

## 🚂 Deploying to Railway / Render

1. Push to GitHub
2. Connect repo to Railway/Render
3. Set environment variables in dashboard
4. Deploy — the server will start automatically

The SQLite database is stored in the `data/` folder. For persistent storage on Railway, attach a volume mounted at `/app/data`.

---

## 🔒 Security Features

- HMAC-signed license keys (cannot be forged without the secret)
- Keys stored as hashes only (never plaintext in DB)
- JWT tokens for device sessions (365-day expiry)
- Rate limiting on all endpoints
- Device fingerprinting support
- Admin authentication on all management endpoints
- Helmet.js security headers

---

## 📞 Support

**Medishop Pharmacy Billing**  
Email: support@medishop.in  
Website: medishop.in
