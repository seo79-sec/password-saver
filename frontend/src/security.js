export const IDLE_MINUTES = [1, 5, 10, 15];
export const CLIPBOARD_SECONDS = [15, 30, 60];

export function createGenerationGuard() {
  let generation = 0;
  return {
    capture: () => generation,
    advance: () => ++generation,
    invalidate: () => ++generation,
    isCurrent: token => token === generation,
  };
}

export async function resolveForGeneration(promise, guard, token, apply) {
  const value = await promise;
  if (!guard.isCurrent(token)) return false;
  apply(value);
  return true;
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    const error = new Error('The operation was aborted');
    error.name = 'AbortError';
    throw error;
  }
}

export async function checkHIBPPasswords(accounts, { signal, fetchImpl, digest }) {
  const results = [];
  let failed = false;
  for (const account of accounts) {
    throwIfAborted(signal);
    try {
      const bytes = new TextEncoder().encode(account.password);
      const hash = new Uint8Array(await digest(bytes));
      throwIfAborted(signal);
      const hashHex = Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
      const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${hashHex.slice(0, 5)}`, { signal });
      throwIfAborted(signal);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const text = await response.text();
      throwIfAborted(signal);
      const suffix = hashHex.slice(5);
      const breached = text.split('\n').some(line => line.split(':')[0] === suffix);
      results.push({ id: account.id, breached });
    } catch (error) {
      if (signal?.aborted) throwIfAborted(signal);
      if (error?.name === 'AbortError') throw error;
      failed = true;
    }
  }
  return { results, failed };
}

export function validChoice(value, choices, fallback) {
  const parsed = Number(value);
  return choices.includes(parsed) ? parsed : fallback;
}

export function isSecretVisible(visibleIDs, id) { return visibleIDs.has(id); }

export function toggleSecretVisibility(visibleIDs, id) {
  const next = new Set(visibleIDs);
  if (next.has(id)) next.delete(id); else next.add(id);
  return next;
}

// Clipboard reads can be denied by the OS/browser. In that case, leave its
// current contents untouched rather than risking erasing a newer copy.
export async function clearClipboardIfUnchanged(clipboard, expected) {
  const current = await clipboard.readText();
  if (current !== expected) return false;
  await clipboard.writeText('');
  return true;
}

export function createClipboardController(clipboard, seconds, onError = () => {}) {
  let timer;
  let generation = 0;
  return {
    async copy(value) {
      const current = ++generation;
      clearTimeout(timer);
      try {
        await clipboard.writeText(value);
        timer = setTimeout(async () => {
          if (current !== generation) return;
          try {
            if (await clearClipboardIfUnchanged(clipboard, value)) generation++;
          } catch (error) { onError(error); }
        }, seconds * 1000);
        return true;
      } catch (error) { onError(error); return false; }
    },
    cancel() { generation++; clearTimeout(timer); },
  };
}
