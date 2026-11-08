# Key Vault

Key Vault all-in-one berbasis website: enkripsi, hashing, tanda tangan digital, dan kombinasi kripto. Tanpa email, tanpa nomor telepon. Alamat pengguna dihasilkan dari SHA-256 + Ed448 (Goldilocks).

## Key Vault V3 — encrypted vault sync

- The Vercel site is the public frontend. The Cloudflare Worker (`worker.js` / `core.js`) is the API backend and requires the existing persistent KV namespace binding.
- V3 stores only the password-encrypted vault envelope in Worker KV under `vault:<address>`. The browser encrypts the vault before upload; the server receives neither the password nor plaintext private-key material.
- A user can restore the encrypted envelope on another device by entering the Key Vault address, then unlock it locally with the original password.
- Magic Link is an address locator (`/?magic=<address>`), not a bearer credential. Opening it retrieves ciphertext; the user's Key Vault password is still required.
- The API rejects a backend older than version 3 so the UI does not falsely show an old Worker as V3-ready.

### Deploying the V3 backend

After pulling this branch, deploy the Worker separately from Vercel. First obtain the ID of the **existing** KV namespace already used by production and put that exact ID in the `[[kv_namespaces]]` entry in `wrangler.toml`; do not create or bind a new empty namespace because that would make old accounts and ledger history appear missing. Then deploy:

    npx wrangler deploy

Check:

    curl https://keyvault-web.aste53347.workers.dev/api/health

The response must include `"versi":3` and `"kv":true` before cross-device sync is considered active.

Set the Creator address after creating/unlocking the intended Creator Key Vault:

    npx wrangler secret put CREATOR_ADDRESS

Paste the exact 26-character Key Vault address when prompted. Creator access is checked by the signed backend endpoint; the old hard-coded address in frontend JavaScript has been removed.

**Not yet active:** native app protection (Encrypt Your Ssstt), real-time device instrumentation (I Am In Your Phone), and Bitcoin TXID verification. The interface now reports these as unavailable instead of pretending the operation succeeded.

## Algoritma

- Enkripsi: X448, RSA-2048 (hybrid), Serpent-256, ARIA-256-GCM, CAST-256 (mode GCM per chunk 4MB)
- Hashing: SHA-256, RIPEMD-320 (juga untuk hash blok ledger)
- Tanda tangan digital: Ed448 (Goldilocks/Curve448), ECDSA, Schnorr
- Kombinasi: satu dari tiap kategori

Serpent-256, ARIA-256, CAST-256, RIPEMD-320, dan GCM ditulis sendiri di `public/ciphers.js` (JavaScript murni) dan diuji dengan `npm test`.

## Menjalankan

Syarat: Node.js 18 atau lebih baru. Tanpa dependensi npm.

    git clone https://github.com/USERNAME/keyvault-web.git
    cd keyvault-web
    npm test
    npm start

Buka http://localhost:28836

## Link publik HTTPS (gratis)

Pasang cloudflared (Termux: `pkg install cloudflared`), lalu:

    npm run public

Link https://xxxx.trycloudflare.com muncul di terminal. Link berubah setiap dijalankan ulang; link tetap butuh domain sendiri.

## DNS-over-HTTPS (mode ON)

Server mendengarkan di 0.0.0.0:28836 dan meneruskan DNS ke 10 resolver upstream yang berganti tiap 10 detik. DoH wajib HTTPS (pakai link publik di atas). URL DoH pengguna: https://DOMAIN-KAMU/dns/ALAMAT

## Catatan keamanan

- Kunci dan dokumen diproses di browser, tidak diunggah.
- Server tidak mencatat IP pengguna. Situs tujuan tetap melihat IP pengguna.
- Ledger dan daftar mode ON tersimpan per server (ledger.json, modes.json).
- Modul Serpent, ARIA, CAST, dan RIPEMD-320 belum diaudit pihak ketiga.

## Lisensi

MIT
