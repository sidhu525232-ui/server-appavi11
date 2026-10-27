# APPAVI KEY SERVER

Your own website for giving out licence keys. No `npm install` needed - only Node 18+.

## Run it
```
cd server
ADMIN_PASSWORD="choose-a-strong-password" node server.js
```
Open http://localhost:8787 -> log in -> pick **7 / 15 / 30 days / LIFETIME** -> **GENERATE KEY**.
(If you don't set ADMIN_PASSWORD, a random one is generated and saved in `data/admin-password.txt`.)

## What the admin site can do
- Generate 1-200 keys at once, per plan, with a customer note
- See which device each key is bound to, activation date, expiry, last seen
- **EXPIRE NOW** on any key -> that device locks itself within ~2 minutes
- **RESTORE**, **RESET DEVICE** (customer changed phone/PC; expiry date is kept), **+DAYS**, **DELETE**

## Rules the server enforces
- One key = one device. First activation binds the key to that device; any other device is refused.
- Days (7/15/30) start counting at the first activation, not when you generate the key.
- Lifetime keys never expire (but you can still EXPIRE NOW them).
- The old key `APPAVI1MODZ` no longer exists anywhere.

## Put it online (so customers can reach it)
1. Host this folder on any Node host (VPS, Render, Railway, Fly...) and keep the `data/` folder on a persistent disk - it holds `keys.json`.
2. Put HTTPS in front (Caddy / nginx / the host's built-in HTTPS).
3. In the extension open `defaults.js` and set `DEFAULT_SERVER_URL` to your address, e.g. `https://keys.yoursite.com`
   (or let yourself test via the extension Options page -> KEY SERVER URL).
4. Zip the extension and give it to customers + a key each.

## Files
- `server.js` - API + static hosting
- `public/admin.html` - the admin website
- `data/keys.json` - all keys (back this up!)  - `data/secret.key` - token secret
