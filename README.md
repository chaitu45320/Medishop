# Medishop License Server v3.1

Single-file Node.js license server for MediShop Pro desktop app.  
Deployed on Railway. No native deps — only `express` + `jsonwebtoken`.

## Files

```
server.js       ← entire server (API + admin dashboard)
package.json    ← express + jsonwebtoken only
Procfile        ← web: node server.js
public/
  dashboard.html  ← rich admin UI (auto-loaded by server.js)
data/           ← auto-created by Railway, stores licenses.db.json
```

## Railway Environment Variables

| Variable         | Value                                      | Required |
|------------------|--------------------------------------------|----------|
| `API_SECRET`     | `MediShop@Chaitanya2024`                   | ✅ Yes   |
| `JWT_SECRET`     | `MS_JWT_Medishop_2024_Ultra_Secure_Key_99` | ✅ Yes   |
| `LICENSE_SECRET` | `MS@Medishop#2024!PharmacyBilling$Key@Secure99` | ✅ Yes |
| `TRIAL_DAYS`     | `30`                                       | ✅ Yes   |
| `MAX_DEVICES`    | `1`                                        | ✅ Yes   |
| `PORT`           | set automatically by Railway               | Auto     |

## Admin Dashboard

`https://your-app.railway.app/?token=MediShop@Chaitanya2024`

## API Endpoints

| Method | Path                | Description                  |
|--------|---------------------|------------------------------|
| POST   | /api/activate       | Activate license on device   |
| POST   | /api/validate       | Validate saved token         |
| GET    | /api/validate       | Legacy ?token=&machine_id=   |
| POST   | /api/deactivate     | Remove device activation     |
| GET    | /health             | Server health check          |

## Support

📞 9985223448 | medishoppro.in
