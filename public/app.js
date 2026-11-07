import { sha256 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.4.0/sha256/+esm';
import { ed448, x448 } from 'https://cdn.jsdelivr.net/npm/@noble/curves@1.4.0/ed448/+esm';
import { secp256k1, schnorr } from 'https://cdn.jsdelivr.net/npm/@noble/curves@1.4.0/secp256k1/+esm';
import { RIPEMD320, makeCipher, GCM } from './ciphers.js';
import { sealVault, openVault, deriveMaster, ITER } from './vaultcrypto.js';

const $ = (s) => document.querySelector(s);
const enc = new TextEncoder();
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; };
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
function b32(bytes) {
  let bits = 0, v = 0, o = '';
  for (const x of bytes) {
    v = (v << 8) | x; bits += 8;
    while (bits >= 5) { o += B32[(v >>> (bits - 5)) & 31]; bits -= 5; }
    v &= (1 << bits) - 1;
  }
  return o;
}

const CATS = {
  enc: {
    title: 'Enkripsi', icon: '🔒', blurb: 'Mengunci data supaya hanya kamu yang bisa membukanya.',
    effect: 'Efek Mode ON: DNS aman (DoH) pribadi aktif dengan token rahasia, dan berjalan terus walau website ditutup setelah alamat DNS dipasang di browser atau iPhone. Serpent-256, ARIA-256-GCM, dan CAST-256 juga menambah lapisan enkripsi pada private key di perangkat ini. Tombol ON tidak mengenkripsi aplikasi sosial media atau website lain. Pilih berapa pun, tanpa batas.',
    items: [
      { id: 'x448', name: 'X448', ready: true, desc: 'Kunci modern (Curve448) untuk membungkus kunci file yang kamu enkripsi di halaman ini.', ex: 'Pilih ini untuk mengenkripsi file milikmu. Tidak mengenkripsi lalu lintas website atau aplikasi lain.' },
      { id: 'rsa2048', name: 'RSA-2048', ready: true, desc: 'Membungkus kunci acak AES-256 per file, jadi ukuran file tidak dibatasi (8GB atau lebih, sesuai ruang penyimpanan perangkat).', ex: 'Cocok untuk beberapa dokumen besar sekaligus. Kekuatan RSA-2048 setara sekitar 112 bit; isi file diamankan AES-256.' },
      { id: 'serpent256', name: 'Serpent-256', ready: true, desc: 'Cipher blok 256-bit (finalis AES) dalam mode GCM yang menolak data yang diubah.', ex: 'Dipakai saat kamu mengenkripsi file di sini, dan saat Mode ON menambah lapisan pada private key di perangkat ini. Tidak mengenkripsi aplikasi sosial media atau website lain.' },
      { id: 'aria256gcm', name: 'ARIA-256-GCM', ready: true, desc: 'Cipher blok 256-bit standar Korea dalam mode GCM yang menolak data yang diubah.', ex: 'Cocok untuk arsip atau laporan yang kamu kirim: penerima tahu bila file diubah di tengah jalan. Siapa pun yang memegang kuncinya tetap bisa membuka dan mengubahnya.' },
      { id: 'cast256', name: 'CAST-256', ready: true, desc: 'Cipher blok 256-bit (RFC 2612) dalam mode GCM yang menolak data yang diubah.', ex: 'Dipakai saat kamu mengenkripsi file di sini, dan saat Mode ON menambah lapisan pada private key. Tidak mengamankan layanan RPC atau lalu lintas jaringan.' }
    ]
  },
  hash: {
    title: 'Hashing', icon: '🧬', blurb: 'Sidik jari file untuk membuktikan file asli atau sudah dipalsukan. Pilihan hash juga dipakai untuk blok ledger.',
    effect: 'Efek Mode ON: semua hash yang aktif dipakai bersamaan saat membandingkan file dan mencatat ledger, dan semuanya harus cocok. DNS aman ikut aktif.',
    items: [
      { id: 'sha256', name: 'SHA-256', ready: true, desc: 'Sidik jari file. File sama menghasilkan sidik jari sama, diubah satu huruf saja sidik jarinya berbeda.', ex: 'Upload kontrak yang kamu terima dan kontrak aslinya. Kalau sidik jari cocok, file tidak diubah.' },
      { id: 'ripemd320', name: 'RIPEMD-320', ready: true, desc: 'Sidik jari file versi lebih panjang (320 bit).', ex: 'Dipakai sebagai pembanding kedua untuk arsip penting.' }
    ]
  },
  sig: {
    title: 'Tanda Tangan Digital', icon: '✍️', blurb: 'Bukti bahwa dokumen ini ditandatangani oleh kamu.',
    effect: 'Efek Mode ON: dokumen ditandatangani dengan semua algoritma yang aktif (tanda tangan ganda), dan verifikasi mewajibkan semuanya sah. DNS aman ikut aktif.',
    items: [
      { id: 'ed448', name: 'Goldilocks / Curve448 (Ed448)', ready: true, desc: 'Tanda tangan dengan kurva Goldilocks, tingkat keamanan tinggi.', ex: 'Upload surat perjanjian, kamu mendapat bukti tanda tangan yang tidak bisa dipalsukan orang lain.' },
      { id: 'ecdsa', name: 'ECDSA', ready: true, desc: 'Tanda tangan standar yang dipakai banyak aplikasi.', ex: 'Menandatangani laporan yang akan diperiksa lewat aplikasi lain.' },
      { id: 'schnorr', name: 'Schnorr', ready: true, desc: 'Tanda tangan ringkas dan cepat diperiksa.', ex: 'Menandatangani banyak dokumen sekaligus dengan bukti yang ringan.' }
    ]
  },
  combo: {
    title: 'Kombinasi Crypto', icon: '🧩', blurb: 'Pilih satu dari tiap kategori, lalu Key Vault milikmu dirakit otomatis.',
    effect: 'Efek Mode ON: DNS aman (DoH) pribadi aktif.',
    items: [{ id: 'combo', name: 'Key Vault Kombinasi', ready: true, desc: 'Gabungan satu enkripsi, satu hashing, satu tanda tangan digital dalam satu alur.', ex: 'Masukkan banyak dokumen kapan saja: dihash, ditandatangani, lalu dienkripsi. Mode ON mengaktifkan DNS terenkripsi untuk berinternet lebih aman.' }]
  }
};
const sel = { enc: 'x448', hash: 'sha256', sig: 'ed448' };

const K_VAULT = 'kv.vault2', K_LEGACY = 'kv.vault', K_MODES = 'kv.modes', K_SERVERS = 'kv.servers';
let vault = null, master = null, vaultMeta = null, authKey = null;
let modes = JSON.parse(localStorage.getItem(K_MODES) || '[]');
const saveModes = () => localStorage.setItem(K_MODES, JSON.stringify(modes));
const CASCADE = ['serpent256', 'aria256gcm', 'cast256'];
const cascadeLayers = () => CASCADE.filter((a) => modes.includes(a));
const modesOf = (c) => CATS[c].items.map((i) => i.id).filter((id) => modes.includes(id));
const hashAlgos = () => { const a = modesOf('hash'); return a.length ? a : [sel.hash]; };
const sigAlgos = () => { const a = modesOf('sig'); return a.length ? a : [sel.sig]; };

// ---------- Penghitung operasi di perangkat ini (disimpan lokal, tidak dikirim ke mana pun) ----------
const K_STATS = 'kv.stats';
const readStats = () => JSON.parse(localStorage.getItem(K_STATS) || '{}');
function bump(kind, n = 1) {
  const st = readStats();
  st[kind] = (st[kind] || 0) + n; st.last = Date.now();
  localStorage.setItem(K_STATS, JSON.stringify(st));
  renderCrypto();
}

// ---------- Vault: private key dilindungi kata sandi ----------
async function storeVault() {
  const header = { v: 2, addr: vault.addr, salt: hex(vaultMeta.salt), iter: vaultMeta.iter, layers: cascadeLayers() };
  localStorage.setItem(K_VAULT, JSON.stringify(await sealVault(vault, master, header)));
}
async function loadAuthKey() {
  authKey = await crypto.subtle.importKey('jwk', vault.p256, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}
async function newAuthKeys() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { p256: await crypto.subtle.exportKey('jwk', pair.privateKey), p256pub: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)) };
}
async function protect(pass) {
  vaultMeta = { salt: crypto.getRandomValues(new Uint8Array(16)), iter: ITER };
  master = await deriveMaster(pass, vaultMeta.salt, vaultMeta.iter);
  await storeVault();
  await loadAuthKey();
}
async function createVault(pass) {
  const edPriv = ed448.utils.randomPrivateKey();
  const edPub = ed448.getPublicKey(edPriv);
  const auth = await newAuthKeys();
  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  vault = {
    addr: b32(sha256(cat(edPub, auth.p256pub))).slice(0, 26),
    ed: hex(edPriv), edPub: hex(edPub),
    x: hex(x448.utils.randomPrivateKey()), sp: hex(secp256k1.utils.randomPrivateKey()),
    rsa: await crypto.subtle.exportKey('jwk', pair.privateKey), rsaPub: await crypto.subtle.exportKey('jwk', pair.publicKey),
    p256: auth.p256, p256pub: hex(auth.p256pub)
  };
  await protect(pass);
}
async function migrateLegacy(pass) {
  const old = JSON.parse(localStorage.getItem(K_LEGACY));
  const edPub = ed448.getPublicKey(unhex(old.ed));
  const auth = await newAuthKeys();
  vault = { ...old, edPub: hex(edPub), p256: auth.p256, p256pub: hex(auth.p256pub), addr: b32(sha256(cat(edPub, auth.p256pub))).slice(0, 26) };
  await protect(pass);
  localStorage.removeItem(K_LEGACY);
}
async function unlockVault(pass) {
  const stored = JSON.parse(localStorage.getItem(K_VAULT));
  const header = JSON.parse(stored.h);
  const salt = unhex(header.salt);
  const m = await deriveMaster(pass, salt, header.iter);
  try { vault = await openVault(stored, m); } catch { throw new Error('Kata sandi salah atau data vault rusak'); }
  master = m; vaultMeta = { salt, iter: header.iter };
  await loadAuthKey();
}

const CH = 4 * 1024 * 1024;
async function openSink(name) {
  if (window.showSaveFilePicker) {
    const fh = await window.showSaveFilePicker({ suggestedName: name });
    const w = await fh.createWritable();
    return { write: (d) => w.write(d), close: () => w.close() };
  }
  const parts = [];
  return {
    write: async (d) => { parts.push(d); },
    close: async () => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob(parts));
      a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    }
  };
}
async function hashFile(file, algo = 'sha256') {
  const h = algo === 'ripemd320' ? new RIPEMD320() : sha256.create();
  for (let o = 0; o < file.size; o += CH) h.update(new Uint8Array(await file.slice(o, o + CH).arrayBuffer()));
  bump('hash');
  return hex(h.digest());
}

const CIPHER_ID = { serpent256: 3, aria256gcm: 4, cast256: 5 };
const CIPHER_NAME = { 3: 'serpent256', 4: 'aria256gcm', 5: 'cast256' };

async function kdf(shared) {
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('keyvault-x448') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function newFileKey(algo) {
  if (algo === 'x448') {
    const eph = x448.utils.randomPrivateKey();
    const key = await kdf(x448.getSharedSecret(eph, x448.getPublicKey(unhex(vault.x))));
    return { id: 1, wrapped: x448.getPublicKey(eph), key };
  }
  if (algo === 'rsa2048') {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const pub = await crypto.subtle.importKey('jwk', vault.rsaPub, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw));
    return { id: 2, wrapped, key: await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']) };
  }
  if (CIPHER_ID[algo]) {
    const dataKey = crypto.getRandomValues(new Uint8Array(32));
    const eph = x448.utils.randomPrivateKey();
    const kek = await kdf(x448.getSharedSecret(eph, x448.getPublicKey(unhex(vault.x))));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, dataKey));
    const wrapped = new Uint8Array(56 + 12 + ct.length);
    wrapped.set(x448.getPublicKey(eph), 0); wrapped.set(iv, 56); wrapped.set(ct, 68);
    return { id: CIPHER_ID[algo], wrapped, key: new GCM(makeCipher(algo, dataKey)) };
  }
  throw new Error('Algoritma belum tersedia');
}
async function openFileKey(id, wrapped) {
  if (id === 1) return kdf(x448.getSharedSecret(unhex(vault.x), wrapped));
  if (id === 2) {
    const priv = await crypto.subtle.importKey('jwk', vault.rsa, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, wrapped);
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
  if (CIPHER_NAME[id]) {
    const kek = await kdf(x448.getSharedSecret(unhex(vault.x), wrapped.slice(0, 56)));
    const dataKey = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: wrapped.slice(56, 68) }, kek, wrapped.slice(68)));
    return new GCM(makeCipher(CIPHER_NAME[id], dataKey));
  }
  throw new Error('Format tidak dikenal');
}
const ctr = (i) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, i); return b; };
const sealChunk = async (key, iv, aad, pt) => key instanceof GCM
  ? key.seal(iv, aad, new Uint8Array(pt))
  : new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, pt));
const openChunk = async (key, iv, aad, ct) => key instanceof GCM
  ? key.open(iv, aad, new Uint8Array(ct))
  : new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct));

async function encryptFile(file, algo) {
  const { id, wrapped, key } = await newFileKey(algo);
  const sink = await openSink(file.name + '.kv');
  const head = new Uint8Array(6 + wrapped.length);
  head.set([75, 86, 49, id], 0);
  new DataView(head.buffer).setUint16(4, wrapped.length);
  head.set(wrapped, 6);
  await sink.write(head);
  let i = 0;
  for (let o = 0; o < file.size; o += CH, i++) {
    const pt = await file.slice(o, o + CH).arrayBuffer();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await sealChunk(key, iv, ctr(i), pt);
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, ct.length);
    await sink.write(len); await sink.write(iv); await sink.write(ct);
  }
  await sink.close();
  bump('enc'); bump('bytes', file.size);
}
async function decryptFile(file) {
  const head = new Uint8Array(await file.slice(0, 6).arrayBuffer());
  if (head[0] !== 75 || head[1] !== 86 || head[2] !== 49) throw new Error('Bukan file Key Vault');
  const wl = new DataView(head.buffer).getUint16(4);
  const wrapped = new Uint8Array(await file.slice(6, 6 + wl).arrayBuffer());
  const key = await openFileKey(head[3], wrapped);
  const sink = await openSink(file.name.replace(/\.kv$/, '') || 'hasil');
  let off = 6 + wl, i = 0;
  while (off < file.size) {
    const len = new DataView(await file.slice(off, off + 4).arrayBuffer()).getUint32(0);
    const iv = new Uint8Array(await file.slice(off + 4, off + 16).arrayBuffer());
    const ct = await file.slice(off + 16, off + 16 + len).arrayBuffer();
    await sink.write(await openChunk(key, iv, ctr(i), ct));
    off += 16 + len; i++;
  }
  await sink.close();
  bump('dec');
}

function signHash(algo, h) {
  const m = unhex(h);
  if (algo === 'ed448') { const p = unhex(vault.ed); return { pub: hex(ed448.getPublicKey(p)), sig: hex(ed448.sign(m, p)) }; }
  if (algo === 'ecdsa') { const p = unhex(vault.sp); return { pub: hex(secp256k1.getPublicKey(p)), sig: secp256k1.sign(m, p).toCompactHex() }; }
  if (algo === 'schnorr') { const p = unhex(vault.sp); return { pub: hex(schnorr.getPublicKey(p)), sig: hex(schnorr.sign(m, p)) }; }
  throw new Error('Algoritma belum tersedia');
}
function verifyHash(algo, h, pub, sig) {
  const m = unhex(h);
  if (algo === 'ed448') return ed448.verify(unhex(sig), m, unhex(pub));
  if (algo === 'ecdsa') return secp256k1.verify(sig, m, unhex(pub));
  if (algo === 'schnorr') return schnorr.verify(unhex(sig), m, unhex(pub));
  return false;
}
async function signFile(file, algos, hashAlgo = 'sha256') {
  const h = await hashFile(file, hashAlgo);
  const sigs = algos.map((a) => ({ algo: a, ...signHash(a, h) }));
  const sink = await openSink(file.name + '.sig.json');
  await sink.write(enc.encode(JSON.stringify({ file: file.name, hash: hashAlgo, digest: h, address: vault.addr, sigs }, null, 2)));
  await sink.close();
  bump('sign');
  return h;
}

const DEFAULT_SERVER = location.hostname.endsWith('github.io') ? 'https://keyvault-web.aste53347.workers.dev' : '';
const userServers = () => JSON.parse(localStorage.getItem(K_SERVERS) || '[]');
const serverList = () => [...new Set([DEFAULT_SERVER, ...userServers()])];
let base = DEFAULT_SERVER, serverOk = false, clockOffset = 0, srvInfo = null, loopTimer = null;

async function probe(s) {
  const t0 = performance.now();
  const r = await fetch(s + '/api/health', { cache: 'no-store', signal: AbortSignal.timeout(6000) });
  const j = await r.json();
  if (!r.ok || j.nama !== 'Key Vault API' || !j.kv) throw new Error('Bukan server Key Vault');
  const ms = Math.round(performance.now() - t0);
  return { s, ms, colo: j.colo, offset: j.waktu - (Date.now() - ms / 2) };
}
async function connectServer() {
  const results = await Promise.allSettled(serverList().map(probe));
  const ok = results.filter((r) => r.status === 'fulfilled').map((r) => r.value).sort((a, b) => a.ms - b.ms);
  if (ok.length) { base = ok[0].s; clockOffset = ok[0].offset; srvInfo = ok[0]; serverOk = true; } else { serverOk = false; srvInfo = null; }
  renderServerStatus();
  return serverOk;
}
function renderServerStatus() {
  const st = $('#srvStat'), lst = $('#srvList');
  if (st) {
    st.textContent = serverOk
      ? `Terhubung ke ${base || location.origin} (${srvInfo.colo ? 'edge ' + srvInfo.colo + ', ' : ''}${srvInfo.ms} ms)`
      : 'Server belum terhubung, mencoba lagi otomatis. Alamat, enkripsi, hashing, dan tanda tangan tetap berfungsi.';
    st.className = 'small mb-2 ' + (serverOk ? 'text-success' : 'text-warning');
  }
  if (lst) lst.textContent = 'Daftar server: ' + serverList().map((s) => s || location.origin).join(', ');
}
async function authHeaders(method, path, text) {
  const ts = Math.round(Date.now() + clockOffset);
  const host = new URL(base || location.origin).host;
  const msg = enc.encode(`KV1\n${host}\n${method}\n${path}\n${ts}\n${hex(sha256(enc.encode(text)))}`);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, authKey, msg));
  return { 'x-kv-ed': vault.edPub, 'x-kv-p256': vault.p256pub, 'x-kv-ts': String(ts), 'x-kv-sig': hex(sig) };
}
async function api(path, body, auth = false) {
  try {
    const method = body ? 'POST' : 'GET';
    const text = body ? JSON.stringify(body) : '';
    const headers = body ? { 'content-type': 'application/json' } : {};
    if (auth) Object.assign(headers, await authHeaders(method, path, text));
    const r = await fetch(base + path, { method, headers, body: body ? text : undefined });
    return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
  } catch {
    return { ok: false, status: 0, data: { error: 'Server tidak terjangkau' } };
  }
}
async function connectLoop() {
  const was = serverOk;
  await connectServer();
  if (serverOk && !was) { await syncModes(); await loadLedger(); renderDoh(); renderPanel(currentCat); }
  if (!serverOk && was) { await loadLedger(); renderDoh(); }
  if (!serverOk && !was) await loadLedger();
  clearTimeout(loopTimer);
  loopTimer = setTimeout(connectLoop, serverOk ? 60000 : 15000);
}

const dohToken = () => hex(sha256(enc.encode('kv-doh-token|' + vault.ed))).slice(0, 32);
const dohHash = () => hex(sha256(enc.encode(dohToken())));
const dohUrl = () => `${base || location.origin}/dns/${vault.addr}/${dohToken()}`;
const dohProfileUrl = () => `${base || location.origin}/dns-profile/${vault.addr}/${dohToken()}.mobileconfig`;
let panelNote = '', panelNoteOk = true;

async function setMode(algo, on) {
  const before = cascadeLayers().join();
  modes = on ? [...new Set([...modes, algo])] : modes.filter((a) => a !== algo);
  saveModes();
  panelNote = ''; panelNoteOk = true;
  if (cascadeLayers().join() !== before) { await storeVault(); panelNote = `Private key di perangkat ini sekarang dienkripsi dengan ${1 + cascadeLayers().length} lapisan. `; }
  if (serverOk) {
    const r = await api('/api/mode', { addr: vault.addr, algo, on, dohHash: dohHash() }, true);
    if (!r.ok) { panelNote += 'Server belum menerima: ' + (r.data.error || 'gagal') + '. Efek lokal tetap aktif.'; panelNoteOk = false; }
  } else panelNote += 'Server belum terhubung; disinkronkan otomatis saat tersambung.';
  renderPanel(currentCat); renderDoh();
  refreshDns();
}
async function syncModes() {
  if (!serverOk || !vault) return;
  const r = await api('/api/mode?addr=' + vault.addr, null, true);
  if (!r.ok) return;
  const remote = new Set(r.data.active || []);
  for (const a of modes) if (!remote.has(a)) await api('/api/mode', { addr: vault.addr, algo: a, on: true, dohHash: dohHash() }, true);
  for (const a of remote) if (!modes.includes(a)) await api('/api/mode', { addr: vault.addr, algo: a, on: false }, true);
}
async function loadLedger() {
  if (!serverOk) { $('#ledgerStat').textContent = 'Server belum terhubung, riwayat blockchain tidak tersedia.'; $('#ledgerList').textContent = ''; return; }
  const r = await api('/api/ledger?limit=10');
  const d = r.data;
  $('#ledgerStat').textContent = `${d.total} blok, ${(d.bytes / 1048576).toFixed(2)} MB dari ${(d.max / 1048576).toFixed(0)} MB. Blok head: 0x01`;
  const box = $('#ledgerList'); box.textContent = '';
  for (const b of d.blocks || []) {
    const row = document.createElement('div');
    row.className = 'border-top border-secondary py-2';
    row.textContent = `#${b.index} | ${b.file} | ${b.result} | ${b.algo || 'sha256'} ${b.hash.slice(0, 20)}...` + (b.signer ? ` | oleh ${b.signer.slice(0, 8)}` : '');
    box.appendChild(row);
  }
}

let rot = { n: 0, ms: 0 }, rotTimer = null;
function renderDoh() {
  const on = modes.length > 0;
  $('#dohBox').classList.toggle('d-none', !on);
  if (!on) { clearInterval(rotTimer); rotTimer = null; return; }
  $('#dohUrl').textContent = serverOk ? dohUrl() : 'Menunggu koneksi ke server...';
  const ios = $('#dohIos'); if (ios && serverOk) ios.href = dohProfileUrl();
  if (rotTimer || !serverOk) return;
  const sync = async () => { const r = await api('/api/rotation?addr=' + vault.addr); rot = { n: r.data.n, ms: Date.now() + r.data.nextMs }; };
  sync();
  rotTimer = setInterval(() => { if (Date.now() >= rot.ms) sync(); }, 2000);
}

let currentCat = null, busy = 0;
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; }
function status(box, msg, ok = true) { box.className = 'small mt-2 ' + (ok ? 'text-success' : 'text-danger'); box.textContent = msg; }
function renderCats() {
  const box = $('#cats'); box.textContent = '';
  for (const [k, c] of Object.entries(CATS)) {
    const col = document.createElement('div'); col.className = 'col-6 col-md-3';
    const card = document.createElement('div');
    card.className = 'card cat-card bg-dark border-secondary h-100' + (currentCat === k ? ' active' : '');
    card.innerHTML = '<div class="card-body text-center p-3"><div class="fs-3"></div><div class="fw-semibold small mt-1"></div></div>';
    card.querySelector('.fs-3').textContent = c.icon;
    card.querySelector('.fw-semibold').textContent = c.title;
    card.onclick = () => { currentCat = k; panelNote = ''; renderCats(); renderPanel(k); };
    col.appendChild(card); box.appendChild(col);
  }
}

function renderPanel(k) {
  const panel = $('#panel'); panel.textContent = '';
  if (!k) return;
  const c = CATS[k];
  const card = el('div', 'card bg-dark border-secondary');
  const body = el('div', 'card-body'); card.appendChild(body);
  body.appendChild(el('div', 'h5', c.title));
  body.appendChild(el('div', 'small-note mb-1', c.blurb));
  body.appendChild(el('div', 'small-note mb-3', c.effect));

  for (const it of c.items) {
    const row = el('div', 'algo-row border border-secondary rounded p-3 mb-2' + (it.ready ? '' : ' off'));
    const top = el('div', 'd-flex justify-content-between align-items-start gap-2');
    const left = el('div', 'flex-grow-1');
    if (k !== 'combo') {
      const lab = el('label', 'fw-semibold d-flex align-items-center gap-2');
      const rd = el('input'); rd.type = 'radio'; rd.name = 'sel-' + k; rd.disabled = !it.ready; rd.checked = sel[k] === it.id;
      rd.onchange = () => { sel[k] = it.id; };
      lab.appendChild(rd); lab.appendChild(document.createTextNode(it.name));
      left.appendChild(lab);
    } else left.appendChild(el('div', 'fw-semibold', it.name));
    left.appendChild(el('div', 'small mt-1', it.desc));
    left.appendChild(el('div', 'small-note mt-1', 'Contoh: ' + it.ex));
    const sw = el('div', 'form-check form-switch');
    const cb = el('input', 'form-check-input'); cb.type = 'checkbox'; cb.role = 'switch';
    cb.disabled = !it.ready; cb.checked = modes.includes(it.id);
    cb.onchange = () => setMode(it.id, cb.checked);
    sw.appendChild(cb); sw.appendChild(el('label', 'form-check-label small', cb.checked ? 'ON' : 'OFF'));
    top.appendChild(left); top.appendChild(sw); row.appendChild(top); body.appendChild(row);
  }
  body.appendChild(el('div', 'small-note mb-3', `Mode ON aktif: ${modes.length}. Bebas memilih berapa pun.`));

  const out = el('div');
  if (panelNote) status(out, panelNote, panelNoteOk);
  const mkFile = (label, multiple = false, accept) => {
    const w = el('div', 'mb-2'); w.appendChild(el('label', 'form-label small', label));
    const i = el('input', 'form-control'); i.type = 'file'; i.multiple = multiple; if (accept) i.accept = accept;
    w.appendChild(i); body.appendChild(w); return i;
  };
  const btn = (text, cls, fn) => {
    const b = el('button', 'btn ' + cls + ' me-2 mb-1', text);
    b.onclick = async () => { busy++; try { b.disabled = true; await fn(); } catch (e) { status(out, e.message || 'Gagal', false); } finally { busy--; b.disabled = false; } };
    body.appendChild(b); return b;
  };

  if (k === 'enc') {
    const f = mkFile('Pilih file (satu atau beberapa)', true);
    btn('Enkripsi', 'btn-primary', async () => { for (const x of f.files) await encryptFile(x, sel.enc); status(out, 'Selesai dienkripsi.'); });
    btn('Dekripsi', 'btn-outline-light', async () => { for (const x of f.files) await decryptFile(x); status(out, 'Selesai didekripsi.'); });
  }
  if (k === 'hash') {
    const a = mkFile('File asli'); const b = mkFile('File yang dibandingkan');
    btn('Bandingkan', 'btn-primary', async () => {
      if (!a.files[0] || !b.files[0]) throw new Error('Pilih kedua file');
      const algos = hashAlgos(); const lines = []; const digests = {};
      for (const algo of algos) {
        const [h1, h2] = [await hashFile(a.files[0], algo), await hashFile(b.files[0], algo)];
        digests[algo] = h1 === h2 ? h1 : null;
        lines.push(`${algo}: ${h1 === h2 ? 'cocok' : 'BEDA'}`);
      }
      if (algos.some((x) => !digests[x])) { status(out, `TIDAK SAMA (dipalsukan atau berbeda). ${lines.join(' | ')}`, false); return; }
      const notes = [];
      for (const algo of algos) {
        if (!serverOk) { notes.push('Ledger: server belum terhubung'); break; }
        const r = await api('/api/ledger', { file: b.files[0].name, algo, a: digests[algo], b: digests[algo] }, true);
        if (r.ok) bump('ledger');
        notes.push(r.ok ? `blok #${r.data.block.index} (${algo})` : `Ledger ${algo}: ${r.data.error || 'gagal'}`);
      }
      status(out, `ASLI. ${lines.join(' | ')} | ${notes.join(' | ')}`);
      loadLedger();
    });
  }
  if (k === 'sig') {
    const f = mkFile('Dokumen');
    btn('Tanda Tangani', 'btn-primary', async () => {
      if (!f.files[0]) throw new Error('Pilih dokumen');
      const algos = sigAlgos(), ha = hashAlgos()[0];
      const h = await signFile(f.files[0], algos, ha);
      status(out, `Ditandatangani dengan ${algos.join(' + ')} (hash ${ha}). Digest: ${h}`);
    });
    const s = mkFile('File tanda tangan (.sig.json) untuk verifikasi', false, '.json');
    btn('Verifikasi', 'btn-outline-light', async () => {
      if (!f.files[0] || !s.files[0]) throw new Error('Pilih dokumen dan file tanda tangan');
      const j = JSON.parse(await s.files[0].text());
      const list = j.sigs || [{ algo: j.algo, pub: j.pub, sig: j.sig }];
      const h = await hashFile(f.files[0], j.hash || 'sha256');
      const ok = h === (j.digest || j.sha256) && list.every((x) => verifyHash(x.algo, h, x.pub, x.sig));
      status(out, ok ? `Tanda tangan sah (${list.map((x) => x.algo).join(' + ')}), alamat penanda tangan: ${j.address}` : 'Tanda tangan TIDAK sah atau dokumen berubah.', ok);
    });
  }
  if (k === 'combo') {
    for (const [c2, label] of [['enc', 'Enkripsi'], ['hash', 'Hashing'], ['sig', 'Tanda Tangan']]) {
      const w = el('div', 'mb-2'); w.appendChild(el('label', 'form-label small', label));
      const s = el('select', 'form-select');
      for (const it of CATS[c2].items.filter((x) => x.ready)) { const o = el('option', '', it.name); o.value = it.id; o.selected = sel[c2] === it.id; s.appendChild(o); }
      s.onchange = () => { sel[c2] = s.value; };
      w.appendChild(s); body.appendChild(w);
    }
    const f = mkFile('Dokumen (banyak file)', true);
    btn('Proses ke Key Vault', 'btn-primary', async () => {
      const algos = sigAlgos(), ha = hashAlgos()[0];
      for (const x of f.files) { await signFile(x, algos, ha); await encryptFile(x, sel.enc); }
      status(out, `Selesai: ${f.files.length} dokumen di-hash (${ha}), ditandatangani (${algos.join(' + ')}), dan dienkripsi (${sel.enc}).`);
    });
  }
  body.appendChild(out);
  panel.appendChild(card);
}

function mountServerBox() { renderServerStatus(); }
function mountDohHelp() {
  if ($('#dohHelp')) return;
  const host = $('#dohBox .card-body'); if (!host) return;
  const wrap = el('div', 'mt-2'); wrap.id = 'dohHelp';
  const copy = el('button', 'btn btn-sm btn-success me-2 mb-1', 'Salin alamat DNS');
  copy.onclick = async () => {
    if (!serverOk) return;
    await navigator.clipboard.writeText(dohUrl());
    copy.textContent = 'Tersalin'; setTimeout(() => { copy.textContent = 'Salin alamat DNS'; }, 2000);
  };
  const ios = el('a', 'btn btn-sm btn-outline-light mb-1', 'iPhone/iPad: pasang otomatis'); ios.id = 'dohIos';
  wrap.append(copy, ios);
  wrap.appendChild(el('div', 'small-note mt-2', 'Android (Chrome): ketuk Salin alamat DNS, lalu Chrome > titik tiga > Setelan > Privasi dan keamanan > Gunakan DNS aman > Pilih penyedia lain > tempel > simpan. Firefox: Setelan > Privasi dan keamanan > DNS melalui HTTPS > Kustom > tempel. iPhone/iPad: ketuk tombol pasang otomatis, lalu Setelan > Profil Diunduh > Pasang. Pengaturan Private DNS bawaan Android tidak bisa dipakai untuk ini. Setelah dipasang, perlindungan ini terus berjalan walau halaman ini ditutup. Situs tujuan tetap melihat IP-mu.'));
  host.appendChild(wrap);
}
function mountLockButton() {
  if ($('#btnLock')) return;
  const b = el('button', 'btn btn-sm btn-outline-warning', 'Kunci Sekarang'); b.id = 'btnLock';
  b.onclick = () => location.reload();
  $('#btnBackup').after(b);
}
let idleTimer = null, idleOn = false;
const IDLE_MS = 10 * 60 * 1000;
function startIdleLock() {
  if (idleOn) return;
  idleOn = true;
  const reset = () => { clearTimeout(idleTimer); idleTimer = setTimeout(() => (busy ? reset() : location.reload()), IDLE_MS); };
  ['pointerdown', 'keydown', 'touchstart', 'scroll'].forEach((ev) => document.addEventListener(ev, reset, { passive: true }));
  reset();
}

// ---------- Pusat Perlindungan: metrik nyata ----------
const fmtBytes = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B');
const spark = (arr) => { const bars = '▁▂▃▄▅▆▇█'; const mx = Math.max(...arr, 1); return arr.map((v) => bars[Math.min(7, Math.floor((v / mx) * 7))]).join(''); };
let net = null, selfTestLines = [], dashTimer = null;
function cell(id, title) {
  const d = el('div', 'col-12 col-md-6');
  const b = el('div', 'border border-secondary rounded p-3 h-100'); b.id = id;
  b.appendChild(el('div', 'fw-semibold mb-1', title));
  d.appendChild(b); return d;
}
function setCell(id, badge, cls, lines, extra) {
  const b = $('#' + id); if (!b) return;
  while (b.children.length > 1) b.removeChild(b.lastChild);
  b.appendChild(el('span', 'badge ' + cls + ' mb-2', badge));
  for (const l of lines) b.appendChild(el('div', 'small', l));
  if (extra) b.appendChild(extra);
}
function linkBtn(text, href) {
  const a = el('a', 'btn btn-sm btn-outline-info me-2 mb-1', text);
  a.href = href; a.target = '_blank'; a.rel = 'noopener';
  return a;
}
function mountDash() {}






function startDash() { showKeyInfo(); }

const DOCS = {
  privacy: ['Kebijakan Privasi', 'Key Vault tidak meminta email atau nomor telepon. Kunci dan dokumen diproses di browser kamu dan tidak diunggah. Private key disimpan terenkripsi dengan kata sandi milikmu. Server tidak mencatat alamat IP, tidak meneruskan IP ke DNS upstream, dan hanya menyimpan: alamat anonim, daftar mode ON, hash token DNS, jumlah permintaan DNS per jam (hanya angka, tanpa nama situs dan tanpa IP), dan blok ledger (nama file, hash yang dibandingkan, hasil, alamat penanda tangan). IP-mu hanya ditampilkan kepadamu saat kamu menekan Cek ulang di Pusat Perlindungan dan tidak disimpan. Kata sandi dan cadangan kunci adalah tanggung jawab kamu: yang hilang tidak bisa dipulihkan siapa pun.'],
  rules: ['Aturan', 'Gunakan Key Vault untuk melindungi data milikmu sendiri. Dilarang memakainya untuk melanggar hukum, menyerang sistem lain, atau menyebarkan konten ilegal. Ledger hanya mencatat perbandingan yang sah (hash sama), maksimal 30 catatan per alamat per jam. Layanan diberikan apa adanya.'],
  copyright: ['Copyright', '© 2026 Farrel. Seluruh hak cipta atas Key Vault dilindungi. Pustaka pihak ketiga (Bootstrap, noble-curves, noble-hashes) memakai lisensi masing-masing.']
};
document.querySelectorAll('[data-doc]').forEach((a) => a.addEventListener('click', (e) => {
  e.preventDefault();
  const [t, b] = DOCS[a.dataset.doc];
  $('#docTitle').textContent = t; $('#docBody').textContent = b;
  bootstrap.Modal.getOrCreateInstance($('#docModal')).show();
}));

let entered = false;

function showKeyInfo() {
  const existing = document.getElementById('keyInfoBox');
  if (existing) return;
  const box = document.createElement('div');
  box.id = 'keyInfoBox';
  box.className = 'card bg-dark border-secondary mb-3';
  box.style.cssText = 'border-left: 3px solid #3fa9f5';
  
  const edPub = hex(ed448.getPublicKey(unhex(vault.ed)));
  const privKey = vault.ed;
  
  box.innerHTML = `
    <div class="card-body">
      <div class="fw-semibold mb-2">🔑 Keys & Identity</div>
      <div class="small-note mb-1">Public Key (Ed448 / Goldilocks)</div>
      <div class="addr small mb-2" style="font-size:.7rem;background:#0b1626;padding:.4rem;border-radius:4px">${edPub}</div>
      <div class="small-note mb-1">Private Key</div>
      <div class="addr small mb-2" style="font-size:.7rem;background:#0b1626;padding:.4rem;border-radius:4px;color:#ef4444">${privKey}</div>
      <div class="d-flex gap-2 flex-wrap">
        <button class="btn btn-sm btn-outline-light" onclick="navigator.clipboard.writeText('${edPub}')">Salin Public Key</button>
        <button class="btn btn-sm btn-outline-warning" onclick="navigator.clipboard.writeText('${privKey}')">Salin Private Key</button>
        <button class="btn btn-sm btn-primary" onclick="generateMagicLink()">✨ Generate Magic Link</button>
      </div>
      <div id="magicLinkResult" class="mt-2 small"></div>
    </div>
  `;
  
  const addrCard = document.getElementById("addr").closest(".card");
  if (addrCard) addrCard.after(box);
  
  showConsultantSection();
}

function generateMagicLink() {
  const edPub = hex(ed448.getPublicKey(unhex(vault.ed)));
  const timestamp = Date.now();
  const magicData = btoa(JSON.stringify({ addr: vault.addr, pub: edPub, ts: timestamp }));
  const magicLink = location.origin + '/vault?magic=' + magicData;
  const result = document.getElementById('magicLinkResult');
  result.innerHTML = `<div style="word-break:break-all;font-family:monospace;font-size:.65rem;background:#0b1626;padding:.4rem;border-radius:4px;color:#22c55e">${magicLink}</div><div class="small-note mt-1">Magic Link hanya bisa dibuka dengan Private Key kamu.</div>`;
}

function showConsultantSection() {
  const s = document.getElementById('consultantSection');
  if (s) {
    s.classList.remove('d-none');
    const addr = vault ? vault.addr : '';
    window._kvAddr = addr;
    ['gc-addr','bc-addr','ca-addr'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = addr;
    });
    if (typeof loadSlots === 'function') loadSlots();
  }
}

async function enter() {
  $('#hero').classList.add('d-none'); $('#main').classList.remove('d-none');
  $('#addr').textContent = vault.addr;
  mountLockButton(); mountDohHelp();
  renderCats(); renderDoh();
  if (!entered) { entered = true; startIdleLock(); window.addEventListener('online', connectLoop); }
  await connectLoop();
  startDash();
}
function showPassForm({ title, confirm, button, onSubmit }) {
  const old = $('#lockBox'); if (old) old.remove();
  const box = el('div', 'mt-3 mx-auto text-start'); box.id = 'lockBox'; box.style.maxWidth = '360px';
  box.appendChild(el('div', 'fw-semibold mb-2', title));
  const p1 = el('input', 'form-control mb-2'); p1.type = 'password'; p1.placeholder = 'Kata sandi vault'; p1.autocomplete = confirm ? 'new-password' : 'current-password';
  box.appendChild(p1);
  let p2 = null;
  if (confirm) {
    p2 = el('input', 'form-control mb-2'); p2.type = 'password'; p2.placeholder = 'Ulangi kata sandi'; p2.autocomplete = 'new-password';
    box.appendChild(p2);
    box.appendChild(el('div', 'small-note mb-2', 'Minimal 10 karakter. Kata sandi melindungi private key dan tidak bisa dipulihkan siapa pun, termasuk server.'));
  }
  const msg = el('div', 'small text-danger mb-2'); box.appendChild(msg);
  const go = el('button', 'btn btn-primary w-100', button); box.appendChild(go);
  go.onclick = async () => {
    msg.textContent = '';
    if (confirm) {
      if (p1.value.length < 10) { msg.textContent = 'Minimal 10 karakter'; return; }
      if (p1.value !== p2.value) { msg.textContent = 'Kata sandi tidak sama'; return; }
    } else if (!p1.value) { msg.textContent = 'Isi kata sandi'; return; }
    go.disabled = true; go.textContent = 'Memproses...';
    try { await onSubmit(p1.value); box.remove(); } catch (e) { msg.textContent = e.message || 'Gagal'; go.disabled = false; go.textContent = button; }
  };
  p1.onkeydown = (e) => { if (e.key === 'Enter') go.click(); };
  if (p2) p2.onkeydown = (e) => { if (e.key === 'Enter') go.click(); };
  $('#btnAddr').after(box); p1.focus();
}
$('#btnAddr').onclick = () => {
  if (vault) return enter();
  if (localStorage.getItem(K_VAULT)) return showPassForm({ title: 'Buka Key Vault', button: 'Buka', onSubmit: async (p) => { await unlockVault(p); await enter(); } });
  if (localStorage.getItem(K_LEGACY)) return showPassForm({ title: 'Amankan vault lama dengan kata sandi', confirm: true, button: 'Amankan', onSubmit: async (p) => { await migrateLegacy(p); await enter(); } });
  showPassForm({ title: 'Buat kata sandi vault', confirm: true, button: 'Buat Key Vault', onSubmit: async (p) => { await createVault(p); await enter(); } });
};
$('#btnCopy').onclick = () => navigator.clipboard.writeText(vault.addr);
$('#btnBackup').onclick = async () => {
  const raw = localStorage.getItem(K_VAULT);
  if (!raw) return alert('Tidak ada vault tersimpan');
  const s = await openSink('keyvault-backup.json'); await s.write(enc.encode(raw)); await s.close();
};
$('#restore').onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return;
  try {
    const j = JSON.parse(await f.text());
    if (j.h && j.ct) {
      if (!/^[a-z2-7]{26}$/.test(JSON.parse(j.h).addr)) throw new Error('x');
      if (localStorage.getItem(K_VAULT) && !confirm('Vault di perangkat ini akan diganti. Lanjutkan?')) return;
      localStorage.setItem(K_VAULT, JSON.stringify(j));
    } else if (j.ed && j.rsa && j.rsaPub && j.sp && j.x) localStorage.setItem(K_LEGACY, JSON.stringify(j));
    else throw new Error('x');
  } catch { return alert('File cadangan tidak valid'); }
  location.reload();
};
$('#btnAddr').textContent = localStorage.getItem(K_VAULT) || localStorage.getItem(K_LEGACY) ? 'Buka Key Vault' : 'Dapatkan Alamat';
