// This self-contained function is also emitted as a parser-blocking, same-origin
// head script by Vite. Keep one implementation for bootstrap, settings and tests;
// it reads only the nonsecret theme preference and never uses eval/inline scripts.
export function installThemeRuntime(environment) {
  if (environment.passwordSaverTheme) return environment.passwordSaverTheme;
  const normalizeTheme = value => ['light', 'dark', 'system'].includes(value) ? value : 'light';
  const resolvedTheme = (value, prefersDark) => normalizeTheme(value) === 'system'
    ? (prefersDark ? 'dark' : 'light') : normalizeTheme(value);
  function createThemeController({ storage, media, root, onDestroy = () => {} }) {
    let preference;
    let destroyed = false;
    try { preference = normalizeTheme(storage?.getItem('theme')); } catch { preference = 'light'; }
    const apply = () => { root.dataset.theme = resolvedTheme(preference, media.matches); };
    const change = () => apply();
    media.addEventListener('change', change);
    apply();
    return {
      get preference() { return preference; },
      set(value) {
        preference = normalizeTheme(value);
        try { storage?.setItem('theme', preference); } catch { /* Session preference still works. */ }
        apply();
        return preference;
      },
      destroy() {
        if (destroyed) return;
        destroyed = true;
        media.removeEventListener('change', change);
        onDestroy();
      },
    };
  }
  let controller;
  function getThemeController() {
    if (controller) return controller;
    // Accessing window.localStorage itself may throw before getItem is called.
    let storage;
    try { storage = environment.localStorage; } catch { /* Light fallback. */ }
    const media = environment.matchMedia('(prefers-color-scheme: dark)');
    controller = createThemeController({
      storage, media, root: environment.document.documentElement,
      onDestroy: () => { controller = undefined; },
    });
    return controller;
  }
  const api = { normalizeTheme, resolvedTheme, createThemeController, getThemeController };
  environment.passwordSaverTheme = api;
  if (environment.document) getThemeController();
  return api;
}
