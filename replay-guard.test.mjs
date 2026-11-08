import test from 'node:test';
import assert from 'node:assert/strict';
import { ReplayGuard } from './worker.js';

function makeGuard() {
  const values = new Map();
  let alarmAt = null;
  const storage = {
    transaction: async (fn) => fn({
      get: async (key) => values.get(key),
      put: async (key, value) => values.set(key, value)
    }),
    getAlarm: async () => alarmAt,
    setAlarm: async (value) => { alarmAt = value; },
    list: async ({ prefix = '', limit } = {}) => {
      const found = [...values.entries()].filter(([key]) => key.startsWith(prefix));
      return new Map(limit ? found.slice(0, limit) : found);
    },
    delete: async (key) => values.delete(key)
  };
  return { guard: new ReplayGuard({ storage }), values };
}

const signature = 'a'.repeat(128);
const request = (sig = signature, ts = Date.now()) => new Request('https://replay/claim', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ sig, ts })
});

test('signature is accepted once and duplicate is rejected', async () => {
  const { guard, values } = makeGuard();
  assert.equal((await guard.fetch(request())).status, 204);
  assert.equal(values.size, 1);
  assert.equal((await guard.fetch(request())).status, 409);
});

test('invalid replay claims are rejected', async () => {
  const { guard } = makeGuard();
  assert.equal((await guard.fetch(request('bad'))).status, 400);
  assert.equal((await guard.fetch(new Request('https://replay/claim'))).status, 405);
});

test('expired signatures can be claimed again after retention window', async () => {
  const { guard, values } = makeGuard();
  values.set('sig:' + signature, Date.now() - 300000);
  assert.equal((await guard.fetch(request(signature))).status, 204);
});
