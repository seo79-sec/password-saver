import test from 'node:test';
import assert from 'node:assert/strict';
import { clearClipboardIfUnchanged, validChoice, isSecretVisible, toggleSecretVisibility, createGenerationGuard, resolveForGeneration, checkHIBPPasswords } from './security.js';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('clipboard cleanup only clears the password it originally copied', async () => {
  const writes = [];
  const clipboard = { readText: async () => 'user copied something else', writeText: async value => writes.push(value) };
  assert.equal(await clearClipboardIfUnchanged(clipboard, 'secret'), false);
  assert.deepEqual(writes, []);
});

test('clipboard cleanup clears unchanged password', async () => {
  const writes = [];
  const clipboard = { readText: async () => 'secret', writeText: async value => writes.push(value) };
  assert.equal(await clearClipboardIfUnchanged(clipboard, 'secret'), true);
  assert.deepEqual(writes, ['']);
});

test('denied clipboard read rejects without writing', async () => {
  let wrote = false;
  const clipboard = { readText: async () => { throw new Error('denied'); }, writeText: async () => { wrote = true; } };
  await assert.rejects(clearClipboardIfUnchanged(clipboard, 'secret'));
  assert.equal(wrote, false);
});

test('preferences accept supported choices and fall back safely', () => {
  assert.equal(validChoice('10', [1, 5, 10, 15], 1), 10);
  assert.equal(validChoice('999', [1, 5, 10, 15], 1), 1);
});

test('password visibility is hidden initially and toggles per record', () => {
  const initial = new Set();
  assert.equal(isSecretVisible(initial, 'a'), false);
  const shown = toggleSecretVisibility(initial, 'a');
  assert.equal(isSecretVisible(shown, 'a'), true);
  assert.equal(isSecretVisible(shown, 'b'), false);
  assert.equal(isSecretVisible(toggleSecretVisibility(shown, 'a'), 'a'), false);
});

test('late account response is ignored after session invalidation', async () => {
  const guard = createGenerationGuard();
  const token = guard.capture();
  const response = deferred();
  const visibleAccounts = [];
  const loading = resolveForGeneration(response.promise, guard, token, value => visibleAccounts.push(...value));

  guard.invalidate(); // lock/logout happened while GetAccounts was pending
  response.resolve([{ id: 'secret-account', password: 'must-not-return' }]);
  assert.equal(await loading, false);
  assert.deepEqual(visibleAccounts, []);
});

test('late HIBP response after abort is rejected and cannot commit UI state', async () => {
  const controller = new AbortController();
  const generation = createGenerationGuard();
  const token = generation.capture();
  const response = deferred();
  let fetchSignal;
  const account = { id: 'a', password: 'sample' };
  const pending = checkHIBPPasswords([account], {
    signal: controller.signal,
    digest: async () => new Uint8Array(20).fill(1).buffer,
    fetchImpl: (_url, options) => { fetchSignal = options.signal; return response.promise; },
  });

  await new Promise(resolve => setImmediate(resolve));
  assert.equal(fetchSignal, controller.signal);
  controller.abort();
  generation.invalidate(); // lock/logout also makes any result stale
  response.resolve({ ok: true, text: async () => 'ignored' }); // fake fetch settles despite abort
  await assert.rejects(pending, { name: 'AbortError' });

  let applied = false;
  assert.equal(await resolveForGeneration(Promise.resolve([{ id: 'a', breached: true }]), generation, token, () => { applied = true; }), false);
  assert.equal(applied, false);
});
