import { readFileSync } from 'node:fs';

const configPath = new URL('../wrangler.toml', import.meta.url);
let config;
try {
  config = readFileSync(configPath, 'utf8');
} catch {
  console.error('GAGAL: wrangler.toml tidak ditemukan.');
  process.exit(1);
}

const blocks = config.split(/^\s*\[\[kv_namespaces\]\]\s*$/m);
const kvBlock = blocks[1]?.split(/^\s*\[\[/m)[0] || '';
const binding = kvBlock.match(/^\s*binding\s*=\s*["']([^"']+)["']\s*$/m)?.[1];
const namespaceId = kvBlock.match(/^\s*id\s*=\s*["']([^"']+)["']\s*$/m)?.[1];
const r2Block = config.split(/^\s*\[\[r2_buckets\]\]\s*$/m)[1]?.split(/^\s*\[\[/m)[0] || '';
const r2Binding = r2Block.match(/^\s*binding\s*=\s*["']([^"']+)["']\s*$/m)?.[1];
const r2Name = r2Block.match(/^\s*bucket_name\s*=\s*["']([^"']+)["']\s*$/m)?.[1];

const replayBinding = /\[\[durable_objects\.bindings\]\][\s\S]*?name\s*=\s*[\"']REPLAY_GUARD[\"'][\s\S]*?class_name\s*=\s*[\"']ReplayGuard[\"']/.test(config);
const replayMigration = /\[\[migrations\]\][\s\S]*?tag\s*=\s*[\"']v2[\"'][\s\S]*?new_sqlite_classes\s*=\s*\[[^\]]*[\"']ReplayGuard[\"'][^\]]*\]/.test(config);

const errors = [];
if (binding !== 'KV') errors.push('Binding [[kv_namespaces]] dengan binding = "KV" tidak ditemukan.');
if (!namespaceId || !/^[a-f0-9]{32}$/i.test(namespaceId)) {
  errors.push('ID KV namespace produksi belum diisi atau formatnya salah. Gunakan ID namespace LAMA; jangan membuat namespace baru.');
}
if (!replayBinding || !replayMigration) errors.push('Durable Object REPLAY_GUARD atau migrasi v2 belum dikonfigurasi.');
if (r2Binding !== 'PERSONAL_VAULT' || !r2Name) {
  errors.push('Binding R2 PERSONAL_VAULT atau bucket_name belum dikonfigurasi.');
}

if (errors.length) {
  console.error('PRE-FLIGHT WORKER GAGAL:');
  for (const error of errors) console.error(' - ' + error);
  console.error('\nLihat namespace yang tersedia dengan: npx wrangler kv namespace list');
  console.error('Pastikan ID yang dipasang adalah namespace produksi lama agar data dan riwayat tidak terputus.');
  process.exit(1);
}

console.log('PRE-FLIGHT WORKER LULUS');
console.log(' - KV binding: ' + binding + ' (ID terpasang; nilai tidak dicetak)');
console.log(' - R2 binding: ' + r2Binding + ' → ' + r2Name);
console.log(' - Durable replay guard: REPLAY_GUARD (migrasi v2)');
console.log(' - Konfigurasi tidak membuat namespace baru.');
