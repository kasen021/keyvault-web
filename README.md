# Key Vault

Key Vault all-in-one berbasis website: enkripsi, hashing, tanda tangan digital, dan kombinasi kripto. Tanpa email, tanpa nomor telepon. Alamat pengguna dihasilkan dari SHA-256 + Ed448 (Goldilocks).

## Key Vault V3 — encrypted vault sync

- The Vercel site is the public frontend. The Cloudflare Worker (`worker.js` / `core.js`) is the API backend and requires the existing persistent KV namespace binding.
- V3 stores only the password-encrypted vault envelope in Worker KV under `vault:<address>`. The browser encrypts the vault before upload; the server receives neither the password nor plaintext private-key material.
- A user can restore the encrypted envelope on another device by entering the Key Vault address, then unlock it locally with the original password.
- Magic Link is an address locator (`/?magic=<address>`), not a bearer credential. Opening it retrieves ciphertext; the user's Key Vault password is still required.
- The API rejects a backend older than version 3 so the UI does not falsely show an old Worker as V3-ready.

### Deploying the V3 backend safely

The Worker must be deployed separately from Vercel. **Never create a replacement KV namespace to get past a missing ID**: that would make existing accounts and ledger history appear missing.

1. List existing namespaces:

       npx wrangler kv namespace list

2. Identify the exact production namespace previously used by Key Vault. Put its existing 32-character ID in the `id` field of the `[[kv_namespaces]]` block in `wrangler.toml`. Do not paste credentials or tokens into GitHub.
3. Check the R2 bucket exists:

       npx wrangler r2 bucket list

   The configured bucket name is `keyvault-personal-vault`. Create it only if it is confirmed not to exist in the intended Cloudflare account:

       npx wrangler r2 bucket create keyvault-personal-vault

4. Run the guarded deployment command:

       npm run deploy:worker

   This first runs `npm run check:worker`. The preflight refuses to deploy if the existing KV namespace ID is missing/invalid or the Personal Vault R2 binding is absent. It does not create a namespace and does not print the namespace ID.

Check the deployed Worker:

    curl https://keyvault-web.aste53347.workers.dev/api/health

The response must include `"versi":3` and `"kv":true` before cross-device sync is considered active.

Set the Creator address after creating/unlocking the intended Creator Key Vault:

    npx wrangler secret put CREATOR_ADDRESS

Paste the exact 26-character Key Vault address when prompted. Creator access is checked by the signed backend endpoint; the old hard-coded address in frontend JavaScript has been removed.

**Not yet active:** native app protection (Encrypt Your Ssstt), real-time device instrumentation (I Am In Your Phone), and Bitcoin TXID verification. The interface must report these as unavailable instead of pretending the operation succeeded.

## Personal Vault — encrypted file storage

- Files of any format are encrypted in the browser with an X448-wrapped AES-256-GCM file key before upload.
- The upload session opens for 25 seconds. It controls when file selection can begin; an upload already started continues until it finishes. Open a new session for another upload batch.
- Each file is streamed in 4 MiB encrypted chunks. The Worker streams ciphertext into Cloudflare R2; the browser limits plaintext files to 90 MB and the Worker caps the encrypted stream at 95 MB.
- R2 object keys contain only the account address and random file ID. Filenames and the file list are kept inside the user's password-encrypted vault envelope in KV.
- The file contents are never sent to the Worker in plaintext. Decryption happens in the browser after the ciphertext is fetched.
- R2 storage and operation charges are governed by the Cloudflare account.

## Algoritma

- Enkripsi: X448, RSA-2048 (hybrid), Serpent-256, ARIA-256-GCM, CAST-256 (mode GCM per chunk 4MB)
- Hashing: SHA-256, RIPEMD-320 (juga untuk hash blok ledger)
- Tanda tangan digital: Ed448 (Goldilocks/Curve448), ECDSA, Schnorr
- Kombinasi: satu dari tiap kategori

Serpent-256, ARIA-256, CAST-256, RIPEMD-320, dan GCM ditulis sendiri di `public/ciphers.js` (JavaScript murni) dan diuji dengan `npm test`.

## Menjalankan

Syarat: Node.js 18 atau lebih baru. Tanpa dependensi npm.

    git clone https://github.com/kasen021/keyvault-web.git
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
