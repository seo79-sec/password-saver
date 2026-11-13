import test from 'node:test';
import assert from 'node:assert/strict';
import { clearClipboardIfUnchanged, validChoice, isSecretVisible, toggleSecretVisibility } from './security.js';

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
