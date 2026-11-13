export const IDLE_MINUTES = [1, 5, 10, 15];
export const CLIPBOARD_SECONDS = [15, 30, 60];

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
