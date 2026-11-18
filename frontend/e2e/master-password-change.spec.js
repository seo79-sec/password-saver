import { test, expect } from '@playwright/test';
import { installBridge, unlock } from './bridge.js';

const currentPassword = 'Synthetic-master!42';
const nextPassword = 'Synthetic-new-master!43';

async function openSettings(page, options = {}) {
  await installBridge(page, options);
  await page.goto('/');
  await unlock(page, { totp: options.totp ?? true });
  await page.getByRole('navigation').getByRole('button', { name: 'Настройки', exact: true }).click();
}

async function openDialog(page) {
  await page.getByRole('button', { name: 'Изменить мастер-пароль', exact: true }).click();
  return page.getByRole('dialog', { name: 'Изменить мастер-пароль', exact: true });
}

async function fillForm(dialog, totp = false) {
  await dialog.getByLabel('Текущий мастер-пароль', { exact: true }).fill(currentPassword);
  await dialog.getByLabel('Новый мастер-пароль', { exact: true }).fill(nextPassword);
  await dialog.getByLabel('Повтор нового мастер-пароля', { exact: true }).fill(nextPassword);
  if (totp) await dialog.getByLabel('Код TOTP', { exact: true }).fill('123456');
}

function sendButton(dialog) {
  return dialog.getByRole('button', { name: 'Сменить пароль', exact: true });
}

function submissionCount(page) {
  return page.evaluate(() => window.mock.calls.filter(call => call.name === 'ChangeMasterPassword').length);
}

test('validates all fields, masks passwords by default and clears a dismissed form', async ({ page }) => {
  await openSettings(page);
  const dialog = await openDialog(page);
  const current = dialog.getByLabel('Текущий мастер-пароль', { exact: true });
  const next = dialog.getByLabel('Новый мастер-пароль', { exact: true });
  const confirm = dialog.getByLabel('Повтор нового мастер-пароля', { exact: true });
  const code = dialog.getByLabel('Код TOTP', { exact: true });
  const error = dialog.getByRole('alert');
  for (const field of [current, next, confirm]) await expect(field).toHaveAttribute('type', 'password');
  await sendButton(dialog).click();
  await expect(error).toContainText('Введите текущий');
  await current.fill(currentPassword);
  await next.fill('short');
  await sendButton(dialog).click();
  await expect(error).toContainText('не менее 12 символов');
  await next.fill(currentPassword);
  await sendButton(dialog).click();
  await expect(error).toContainText('должен отличаться');
  await next.fill(nextPassword);
  await confirm.fill('Synthetic-mismatch!42');
  await sendButton(dialog).click();
  await expect(error).toContainText('не совпадают');
  await confirm.fill(nextPassword);
  await code.fill('12a456');
  await sendButton(dialog).click();
  await expect(error).toContainText('шестизначный код TOTP');

  await dialog.getByRole('button', { name: 'Показать: Новый мастер-пароль' }).click();
  await expect(next).toHaveAttribute('type', 'text');
  await expect(current).toHaveAttribute('type', 'password');
  await dialog.getByRole('button', { name: 'Скрыть: Новый мастер-пароль' }).click();
  await expect(next).toHaveAttribute('type', 'password');
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  expect(await submissionCount(page)).toBe(0);
  await openDialog(page);
  for (const field of [current, next, confirm, code]) await expect(field).toHaveValue('');
});

test('reports backend TOTP failure and clears the submitted secrets while staying unlocked', async ({ page }) => {
  await openSettings(page);
  const dialog = await openDialog(page);
  await page.evaluate(() => window.mock.errors = { ChangeMasterPassword: 'неверный код 2FA' });
  await fillForm(dialog, true);
  await sendButton(dialog).click();
  await expect(dialog.getByRole('alert')).toHaveText('Неверный код двухфакторной аутентификации.');
  expect(await page.evaluate(() => window.mock.calls.find(call => call.name === 'ChangeMasterPassword').args))
    .toEqual([currentPassword, nextPassword, nextPassword, '123456']);
  for (const field of await dialog.locator('input').all()) await expect(field).toHaveValue('');
  await expect(sendButton(dialog)).toBeEnabled();
  await expect(page.getByRole('heading', { name: 'Настройки', exact: true })).toBeVisible();
});

test('prevents closing or submitting twice while pending, and locks on success', async ({ page }) => {
  await openSettings(page, { totp: false, delayPasswordChange: true });
  const dialog = await openDialog(page);
  await expect(dialog.getByLabel('Код TOTP')).toHaveCount(0);
  await fillForm(dialog);
  await sendButton(dialog).click();
  await expect.poll(() => submissionCount(page)).toBe(1);
  await expect(dialog.getByRole('button', { name: 'Смена пароля…' })).toBeDisabled();
  await expect(dialog.getByRole('button', { name: 'Закрыть окно' })).toBeDisabled();
  await page.keyboard.press('Escape');
  await page.keyboard.press('Enter');
  await expect(dialog).toBeVisible();
  for (const field of await dialog.locator('input').all()) await expect(field).toHaveValue('');
  expect(await submissionCount(page)).toBe(1);
  await page.evaluate(() => window.mock.resolvePasswordChange());
  await expect(page.getByText('Мастер-пароль изменён. Войдите с новым паролем', { exact: true })).toBeVisible();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByLabel('Мастер-пароль', { exact: true })).toHaveValue('');
  await expect(page.locator('.app-shell')).toHaveCount(0);
});

test('unconfirmed writes lead to the login screen with recovery guidance', async ({ page }) => {
  await openSettings(page, { totp: false, delayPasswordChange: true });
  const dialog = await openDialog(page);
  await fillForm(dialog);
  await sendButton(dialog).click();
  await expect.poll(() => page.evaluate(() => typeof window.mock.rejectPasswordChange)).toBe('function');
  await page.evaluate(() => {
    window.mock.locked = true;
    window.mock.rejectPasswordChange(new Error('Результат смены мастер-пароля не подтверждён. Основной файл — состояние до операции.\nsynthetic disk error'));
  });
  await expect(page.getByText(/Результат смены мастер-пароля не подтверждён.*подтвердите восстановление/)).toBeVisible();
  await expect(page.getByText('synthetic disk error')).toHaveCount(0);
  await expect(dialog).toHaveCount(0);
});

for (const outcome of ['success', 'error']) {
  test('autolock discards a pending password change response: ' + outcome, async ({ page }) => {
    await openSettings(page, { totp: false, delayPasswordChange: true });
    const dialog = await openDialog(page);
    await fillForm(dialog);
    await sendButton(dialog).click();
    await expect.poll(() => page.evaluate(() => typeof window.mock.resolvePasswordChange)).toBe('function');
    await page.evaluate(() => window.mock.locked = true);
    await expect(page.locator('.app-shell')).toHaveCount(0);
    await expect(dialog).toHaveCount(0);
    await expect(page.getByLabel('Мастер-пароль', { exact: true })).toHaveValue('');
    if (outcome === 'error') await unlock(page, { totp: false });
    await page.evaluate(result => {
      if (result === 'success') window.mock.resolvePasswordChange();
      else window.mock.rejectPasswordChange(new Error('synthetic stale error'));
    }, outcome);
    await expect(dialog).toHaveCount(0);
    await expect(page.getByText('Мастер-пароль изменён. Войдите с новым паролем', { exact: true })).toHaveCount(0);
    if (outcome === 'error') {
      await expect(page.getByRole('heading', { name: 'Мои пароли', exact: true })).toBeVisible();
      await expect(page.getByText('synthetic stale error')).toHaveCount(0);
    } else {
      await expect(page.locator('.app-shell')).toHaveCount(0);
    }
  });
}

test('unmount clears the dialog even when the password change reply is outstanding', async ({ page }) => {
  await openSettings(page, { totp: false, delayPasswordChange: true });
  const dialog = await openDialog(page);
  await fillForm(dialog);
  await sendButton(dialog).click();
  await expect.poll(() => page.evaluate(() => typeof window.mock.resolvePasswordChange)).toBe('function');
  await page.evaluate(async () => {
    const { default: app } = await import('/src/main.js');
    app.$destroy();
    window.mock.resolvePasswordChange();
  });
  await expect(page.locator('#app')).toBeEmpty();
  await expect(dialog).toHaveCount(0);
  expect(await page.evaluate(() => window.mock.calls.some(call => call.name === 'Logout'))).toBe(true);
});

test('the v1 settings explain that changing the password requires v2', async ({ page }) => {
  await openSettings(page, { totp: false, vault: { state: 'v1-active' }, storage: { format: 'v1 (legacy)' } });
  await expect(page.getByRole('button', { name: 'Изменить мастер-пароль', exact: true })).toBeDisabled();
  await expect(page.getByText('Для смены мастер-пароля сначала перейдите на формат v2', { exact: false })).toBeVisible();
});

for (const [preference, expected] of [['light', 'light'], ['dark', 'dark'], ['system', 'dark']]) {
  test('password dialog follows the ' + preference + ' theme', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.addInitScript(theme => localStorage.setItem('theme', theme), preference);
    await openSettings(page, { totp: false });
    const dialog = await openDialog(page);
    await expect(page.locator('html')).toHaveAttribute('data-theme', expected);
    const getBackground = () => dialog.evaluate(element => getComputedStyle(element).backgroundColor);
    const initial = await getBackground();
    expect(initial).toBe(expected === 'dark' ? 'rgb(25, 37, 54)' : 'rgb(255, 255, 255)');
    if (preference === 'system') {
      await page.emulateMedia({ colorScheme: 'light' });
      await expect.poll(getBackground).toBe('rgb(255, 255, 255)');
    }
    await expect(dialog).toBeVisible();
  });
}
