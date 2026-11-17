export const NAVIGATION = [
  { id: 'passwords', label: 'Мои пароли', icon: 'home' },
  { id: 'vaults', label: 'Хранилища', icon: 'layers' },
  { id: 'security', label: 'Безопасность', icon: 'shield' },
  { id: 'devices', label: 'Устройства', icon: 'devices' },
  { id: 'settings', label: 'Настройки', icon: 'settings' },
];
export const CATEGORIES = ['Общие', 'Работа', 'Соцсети', 'Игры', 'Финансы'];
export const validView = value => NAVIGATION.some(item => item.id === value) ? value : 'passwords';
export const normalizeTheme = value => ['light', 'dark', 'system'].includes(value) ? value : 'light';
export const resolvedTheme = (value, prefersDark) => normalizeTheme(value) === 'system' ? (prefersDark ? 'dark' : 'light') : normalizeTheme(value);

export function createThemeController({ storage, media, root }) {
  let preference;
  try { preference = normalizeTheme(storage.getItem('theme')); } catch { preference = 'light'; }
  const apply = () => { root.dataset.theme = resolvedTheme(preference, media.matches); };
  const change = () => apply();
  media.addEventListener('change', change);
  apply();
  return {
    get preference() { return preference; },
    set(value) {
      preference = normalizeTheme(value);
      try { storage.setItem('theme', preference); } catch { /* Session preference still works. */ }
      apply();
      return preference;
    },
    destroy() { media.removeEventListener('change', change); },
  };
}

export function accountLabel(account) {
  const [title, category] = String(account.title || '').split('|||');
  return { title, category: category || 'Общие' };
}
export function isWeak(password) {
  return password.length < 8 || !/[0-9]/.test(password) || !/[^a-zA-Z0-9]/.test(password);
}
export function isOld(updatedAt, now = Date.now()) {
  return Number(updatedAt) > 0 && now / 1000 - Number(updatedAt) > 180 * 24 * 60 * 60;
}
export function auditPasswords(accounts, now = Date.now()) {
  const counts = new Map();
  for (const account of accounts) counts.set(account.password, (counts.get(account.password) || 0) + 1);
  return {
    weak: accounts.filter(a => isWeak(a.password)).length,
    reused: accounts.filter(a => counts.get(a.password) > 1).length,
    old: accounts.filter(a => isOld(a.updatedAt, now)).length,
  };
}
export function filterAccounts(accounts, query, category, risk = 'all') {
  const counts = new Map();
  if (risk === 'reused') for (const a of accounts) counts.set(a.password, (counts.get(a.password) || 0) + 1);
  const needle = query.toLocaleLowerCase();
  return accounts.filter(a => {
    const label = accountLabel(a);
    return (label.title.toLocaleLowerCase().includes(needle) || a.login.toLocaleLowerCase().includes(needle)) &&
      (category === 'Все' || label.category === category) &&
      (risk === 'all' || risk === 'weak' && isWeak(a.password) || risk === 'reused' && counts.get(a.password) > 1 ||
       risk === 'old' && isOld(a.updatedAt) || risk === 'breached' && a.isBreached === true);
  });
}
