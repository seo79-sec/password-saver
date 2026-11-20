import { test, expect } from '@playwright/test';
import { installBridge, unlock } from './bridge.js';

const testKey = 'PSRK1-synthetic-key-not-a-real-secret';
const newPassword = 'Synthetic-new-password-only';

async function openManagement(page, options = {}) {
  await installBridge(page, options);
  await page.goto('/');
  await unlock(page);
  await page.getByRole('navigation').getByRole('button', { name: 'Настройки', exact: true }).click();
  await page.getByRole('button', { name: 'Ключ восстановления', exact: true }).click();
  return page.getByRole('dialog', { name: 'Ключ восстановления', exact: true });
}

async function openReset(page, options = {}) {
  await installBridge(page, options);
  await page.goto('/');
  await page.getByRole('button', { name: 'Забыли мастер-пароль? Восстановить по ключу', exact: true }).click();
  return page.getByRole('dialog', { name: 'Восстановление по ключу', exact: true });
}

async function fillManagement(dialog) {
  await dialog.getByLabel('Текущий мастер-пароль').fill('Synthetic-current-password');
  await dialog.getByLabel('Код TOTP', { exact: true }).fill('123456');
}

async function prepareReset(dialog) {
  await dialog.getByLabel('Сохранённый ключ восстановления').fill(testKey);
  await dialog.getByLabel('Новый мастер-пароль', { exact: true }).fill(newPassword);
  await dialog.getByLabel('Повторите новый мастер-пароль', { exact: true }).fill(newPassword);
  await dialog.getByLabel('Код TOTP выбранной версии, если он включён').fill('123456');
  await dialog.getByRole('button', { name: 'Проверить и подготовить' }).click();
}

function calls(page, name) {
  return page.evaluate(name => window.mock.calls.filter(call => call.name === name), name);
}

test('key is shown once after password and TOTP, while verification and revocation require reauthentication', async ({ page }) => {
  const dialog = await openManagement(page);
  await fillManagement(dialog);
  await dialog.getByRole('button', { name: 'Создать ключ' }).click();
  await expect(dialog.getByLabel('Новый ключ восстановления')).toHaveValue(testKey);
  await expect(dialog.getByLabel('Текущий мастер-пароль')).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Готово' }).click();
  await expect(dialog).toHaveCount(0);
  await page.getByRole('button', { name: 'Ключ восстановления', exact: true }).click();
  await expect(dialog.getByLabel('Новый ключ восстановления')).toHaveCount(0);
  await dialog.getByLabel('Действие').selectOption('verify');
  await dialog.getByLabel('Сохранённый ключ восстановления').fill(testKey);
  await fillManagement(dialog);
  await dialog.getByRole('button', { name: 'Проверить ключ', exact: true }).click();
  await expect(dialog.getByRole('status')).toHaveText('Ключ подходит к текущему хранилищу.');
  await expect(dialog.getByLabel('Сохранённый ключ восстановления')).toHaveValue('');
  await dialog.getByLabel('Действие').selectOption('disable');
  await fillManagement(dialog);
  await dialog.getByRole('button', { name: 'Отключить ключ' }).click();
  await expect(dialog.getByRole('status')).toHaveText('Восстановление по ключу отключено.');
  expect(await calls(page, 'CreateRecoveryKey')).toHaveLength(1);
  expect(await calls(page, 'VerifyRecoveryKey')).toHaveLength(1);
  expect(await calls(page, 'DisableRecoveryKey')).toHaveLength(1);
});

test('reset waits for separate confirmation and exposes no previous or replacement password', async ({ page }) => {
  const dialog = await openReset(page);
  await expect(dialog).toContainText('восстановить доступ невозможно');
  await dialog.getByRole('checkbox', { name: /Использовать .bak/ }).check();
  await prepareReset(dialog);
  await expect(dialog.getByLabel('Новый мастер-пароль', { exact: true })).toHaveCount(0);
  await expect(dialog.getByLabel('Сохранённый ключ восстановления')).toHaveCount(0);
  await expect(dialog).toContainText('настройки TOTP будут восстановлены из .bak');
  expect((await calls(page, 'PrepareRecoveryKeyReset'))[0].args.at(-1)).toBe(true);
  expect(await calls(page, 'ConfirmRecoveryKeyReset')).toHaveLength(0);
  await dialog.getByRole('button', { name: 'Подтвердить смену пароля' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('Мастер-пароль изменён. Войдите с новым паролем.', { exact: false })).toBeVisible();
});

test('invalid key leaves no confirmation, and cancel discards a valid token', async ({ page }) => {
  const dialog = await openReset(page);
  await page.evaluate(() => window.mock.errors = { PrepareRecoveryKeyReset: 'не удалось аутентифицировать ключ восстановления и контейнер' });
  await prepareReset(dialog);
  await expect(dialog.getByRole('alert')).toContainText('Не удалось проверить ключ и контейнер');
  await expect(dialog.getByRole('button', { name: 'Подтвердить смену пароля' })).toHaveCount(0);
  await expect(dialog.getByLabel('Сохранённый ключ восстановления')).toHaveValue('');
  await page.evaluate(() => window.mock.errors = {});
  await prepareReset(dialog);
  await expect(dialog.getByRole('button', { name: 'Подтвердить смену пароля' })).toBeVisible();
  await dialog.getByRole('button', { name: 'Отмена', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(await calls(page, 'CancelRecoveryKeyReset')).toEqual([
    { name: 'CancelRecoveryKeyReset', args: ['synthetic-key-confirmation'] },
  ]);
  expect(await calls(page, 'ConfirmRecoveryKeyReset')).toHaveLength(0);
});

test('a late recovery key is never displayed after autoblock', async ({ page }) => {
  const dialog = await openManagement(page, { delayRecoveryKeyCreate: true });
  await fillManagement(dialog);
  await dialog.getByRole('button', { name: 'Создать ключ' }).click();
  await expect.poll(() => page.evaluate(() => typeof window.mock.resolveRecoveryKeyCreate)).toBe('function');
  await page.evaluate(() => window.mock.locked = true);
  await expect(dialog).toHaveCount(0);
  await page.evaluate(key => window.mock.resolveRecoveryKeyCreate(key), testKey);
  await expect(page.getByLabel('Мастер-пароль', { exact: true })).toBeVisible();
  await expect(page.locator('.key-display')).toHaveCount(0);
});
