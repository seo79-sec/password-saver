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

export function loginModeForVaultStatus(status) {
  if (status?.state === 'v2-active') return 'v2';
  if (status?.state === 'v1-active') return 'v1';
  if (status?.state === 'v1-prepared' && status.v2ContainerPresent) return 'v1';
  return 'blocked';
}

export function friendlyBackendError(error) {
  const message = String(error?.message ?? error ?? '').toLowerCase();
  if (/authentication failed|incorrect .*master password|wrong.*password|неверный мастер-пароль/.test(message)) {
    return 'Мастер-пароль неверен или данные хранилища повреждены.';
  }
  if (/password.*(12 characters|12 symbols|at least 12)|парол.*(12 символ|12 знак)/.test(message)) {
    return 'Для контейнера v2 нужен мастер-пароль не короче 12 символов. Исходное хранилище v1 осталось без изменений.';
  }
  if (/неверный код 2fa|2fa verification failed|invalid.*totp/.test(message)) {
    return 'Неверный код двухфакторной аутентификации.';
  }
  if (/activation challenge.*expired|confirmation.*expired|activation.*denied/.test(message)) {
    return 'Срок подтверждения истёк. Повторно проверьте хранилище и начните подтверждение заново.';
  }
  if (/stale|source changed|changed outside this session/.test(message)) {
    return 'Данные изменились после подготовки. Обновите проверку и повторите операцию.';
  }
  if (/commit is uncertain|synchronization.*uncertain|directory sync/.test(message)) {
    return 'Результат записи не удалось подтвердить. Проверьте состояние хранилища перед повтором.';
  }
  if (/no space left|disk full|not enough space|ошибка 112/.test(message)) {
    return 'Недостаточно места для безопасной записи хранилища.';
  }
  if (/ambiguous|selector state is damaged|unknown.*format/.test(message)) {
    return 'Состояние формата хранилища повреждено или неоднозначно. Автоматического перехода между форматами не будет.';
  }
  if (/v2.*(missing|damaged|invalid)|active v2.*file/.test(message)) {
    return 'Активный контейнер v2 отсутствует или повреждён. Данные v1 автоматически не открываются.';
  }
  return 'Операция не выполнена. Проверьте ввод и состояние хранилища.';
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
