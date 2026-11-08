// worker.js - titik masuk Cloudflare Workers. Logika di core.js.
// Binding: KV (penyimpanan) dan METRICS (Durable Object penghitung DNS), diatur di wrangler.toml.
import { handle } from './core.js';
import { emptyState, metricsRequest } from './metrics.js';

export class Metrics {
  constructor(ctx) {
    this.ctx = ctx;
    this.state = null;
    this.dirty = false;
    ctx.blockConcurrencyWhile(async () => { this.state = (await ctx.storage.get('s')) || emptyState(); });
  }
  async fetch(req) {
    const path = new URL(req.url).pathname;
    const body = req.method === 'POST' ? await req.json().catch(() => ({})) : {};
    const { out, changed } = metricsRequest(this.state, req.method, path, body);
    if (changed && !this.dirty) { this.dirty = true; await this.ctx.storage.setAlarm(Date.now() + 15000); }
    return new Response(JSON.stringify(out), { headers: { 'content-type': 'application/json' } });
  }
  async alarm() {
    await this.ctx.storage.put('s', this.state);
    this.dirty = false;
  }
}

export default {
  fetch: (req, env, ctx) => handle(req, env, ctx)
};


// Durable, per-address replay protection shared by all Worker instances.
export class ReplayGuard {
  constructor(ctx) {
    this.ctx = ctx;
  }

  async fetch(req) {
    if (req.method !== 'POST') return new Response(null, { status: 405 });
    const body = await req.json().catch(() => null);
    if (!body || typeof body.sig !== 'string' || !/^[0-9a-f]{128}$/.test(body.sig) || !Number.isSafeInteger(body.ts)) {
      return new Response(null, { status: 400 });
    }

    const now = Date.now();
    const key = 'sig:' + body.sig;
    const accepted = await this.ctx.storage.transaction(async (txn) => {
      const previous = await txn.get(key);
      if (Number.isFinite(previous) && now - previous <= 240000) return false;
      await txn.put(key, now);
      return true;
    });
    if (!accepted) return new Response(null, { status: 409 });

    const alarm = await this.ctx.storage.getAlarm();
    if (alarm === null || alarm > now + 60000) await this.ctx.storage.setAlarm(now + 60000);
    return new Response(null, { status: 204 });
  }

  async alarm() {
    const now = Date.now();
    const entries = await this.ctx.storage.list({ prefix: 'sig:' });
    for (const [key, timestamp] of entries) {
      if (!Number.isFinite(timestamp) || now - timestamp > 240000) await this.ctx.storage.delete(key);
    }
    const remaining = await this.ctx.storage.list({ prefix: 'sig:', limit: 1 });
    if (remaining.size) await this.ctx.storage.setAlarm(now + 60000);
  }
}
