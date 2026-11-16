import test from 'node:test';
import assert from 'node:assert/strict';
import { clearClipboardIfUnchanged, validChoice, isSecretVisible, toggleSecretVisibility, createGenerationGuard, resolveForGeneration, resolveCapabilityForGeneration, checkHIBPPasswords, loginModeForVaultStatus, canOfferV2BackupRecovery, storageLocationMode, hasStorageBackup, friendlyBackendError } from './security.js';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('late native directory and migration tokens are cancelled after logout or modal close', async () => {
  for (const result of [{ token: 'native-selection', path: 'synthetic-path' }, 'copy-token']) {
    const guard = createGenerationGuard();
    const response = deferred();
    const cancelled = [];
    let opened = false;
    const pending = resolveCapabilityForGeneration(response.promise, guard, guard.capture(),
      async value => cancelled.push(value), () => { opened = true; });
    guard.invalidate(); // same invalidation used on logout, close and destroy
    response.resolve(result);
    assert.equal(await pending, false);
    assert.equal(opened, false);
    assert.deepEqual(cancelled, [result]);
  }
});

test('current native selection opens verification; stale selection cannot replace a newer choice', async () => {
  const guard = createGenerationGuard();
  const oldResult = deferred();
  const applied = [];
  const cancelled = [];
  const oldRequest = resolveCapabilityForGeneration(oldResult.promise, guard, guard.capture(),
    async result => cancelled.push(result), result => applied.push(result));
  guard.advance();
  const current = { token: 'current-selection', path: 'synthetic-folder' };
  assert.equal(await resolveCapabilityForGeneration(Promise.resolve(current), guard, guard.capture(),
    async result => cancelled.push(result), result => applied.push(result)), true);
  oldResult.resolve({ token: 'expired-selection' });
  assert.equal(await oldRequest, false);
  assert.deepEqual(applied, [current]);
  assert.deepEqual(cancelled, [{ token: 'expired-selection' }]);
});

test('expired backend capability cancellation cannot revive a closed migration', async () => {
  const guard = createGenerationGuard();
  const generation = guard.capture();
  guard.invalidate();
  assert.equal(await resolveCapabilityForGeneration(Promise.resolve('expired'), guard, generation,
    async () => { throw new Error('already expired'); }, () => assert.fail('stale result applied')), false);
});

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

test('vault status chooses only the selected login path and blocks ambiguous state', () => {
  assert.equal(loginModeForVaultStatus({ state: 'v1-active' }), 'v1');
  assert.equal(loginModeForVaultStatus({ state: 'v1-prepared', v2ContainerPresent: true }), 'v1');
  assert.equal(loginModeForVaultStatus({ state: 'v1-prepared', v2ContainerPresent: false }), 'blocked');
  assert.equal(loginModeForVaultStatus({ state: 'v2-active' }), 'v2');
  assert.equal(loginModeForVaultStatus({ state: 'uninitialized' }), 'setup');
  assert.equal(loginModeForVaultStatus({ state: 'ambiguous' }), 'blocked');
  assert.equal(loginModeForVaultStatus(null), 'blocked');
});

test('v2 backup recovery is offered only when v2 is active and backup exists', () => {
  assert.equal(canOfferV2BackupRecovery({ state: 'v2-active', v2BackupPresent: true }), true);
  assert.equal(canOfferV2BackupRecovery({ state: 'v2-active', v2BackupPresent: false }), false);
  assert.equal(canOfferV2BackupRecovery({ state: 'v1-active', v2BackupPresent: true }), false);
  assert.equal(canOfferV2BackupRecovery({ state: 'ambiguous', v2BackupPresent: true }), false);
});

test('storage location states distinguish migration, conflict, ready and blocked', () => {
  assert.equal(storageLocationMode({ state: 'ready' }), 'ready');
  assert.equal(storageLocationMode({ state: 'migration-required' }), 'migration');
  assert.equal(storageLocationMode({ state: 'conflict' }), 'conflict');
  assert.equal(storageLocationMode({ state: 'error' }), 'blocked');
  assert.equal(hasStorageBackup({ backupPresent: true }), true);
  assert.equal(hasStorageBackup({ backupPresent: false }), false);
});

test('backend errors are rendered as safe actionable messages', () => {
  assert.match(friendlyBackendError(new Error('v2 vault authentication failed')), /Мастер-пароль/);
  assert.match(friendlyBackendError('v2 activation challenge expired'), /истёк/);
  assert.match(friendlyBackendError('active v2 vault is missing'), /автоматически не открываются/);
  assert.match(friendlyBackendError('master password must be at least 12 characters'), /12 символов/);
  assert.match(friendlyBackendError('different vault files exist in both locations'), /ничего не перезаписало/);
  assert.doesNotMatch(friendlyBackendError('unexpected secret-bearing error'), /unexpected secret-bearing error/);
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
