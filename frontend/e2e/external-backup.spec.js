import { test, expect } from '@playwright/test';
import { installBridge, unlock } from './bridge.js';

test('exports only from an unlocked v2 vault and reports the completed copy', async ({ page }) => {
  await installBridge(page, { totp: false });
  await page.goto('/');
  await unlock(page, { totp: false });
  await page.getByRole('navigation').getByRole('button', { name: 'Хранилища' }).click();
  await page.getByRole('button', { name: 'Экспортировать зашифрованную копию' }).click();
  await expect(page.getByRole('status')).toHaveText('Зашифрованная копия сохранена и проверена.');
  expect(await page.evaluate(() => window.mock.calls.some(call => call.name === 'ExportEncryptedV2Backup'))).toBe(true);
  await page.getByRole('button', { name: 'Заблокировать', exact: false }).first().click();
  await expect(page.getByRole('button', { name: 'Экспортировать зашифрованную копию' })).toHaveCount(0);
});

test('previews an authenticated external copy before confirmation and remains locked', async ({ page }) => {
  await installBridge(page, { totp: false });
  await page.goto('/');
  await page.getByRole('button', { name: 'Восстановить из внешней зашифрованной копии v2' }).click();
  const dialog = page.getByRole('dialog', { name: 'Восстановить из внешней копии v2' });
  await dialog.getByRole('button', { name: 'Выбрать файл' }).click();
  await dialog.getByLabel('Мастер-пароль копии').fill('Synthetic-master!42');
  await dialog.getByLabel('Код TOTP копии, если он был включён').fill('123456');
  await dialog.getByRole('button', { name: 'Проверить копию' }).click();
  await expect(dialog).toContainText('backup.v2.enc');
  await expect(dialog).toContainText('Записей: 2');
  expect(await page.evaluate(() => window.mock.calls.some(call => call.name === 'ConfirmExternalV2Restore'))).toBe(false);
  await dialog.getByRole('button', { name: 'Подтвердить восстановление' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('Зашифрованная копия восстановлена. Войдите с её мастер-паролем.')).toBeVisible();
  await expect(page.getByLabel('Мастер-пароль', { exact: true })).toBeVisible();
});

test('cancels a preview without replacing any files', async ({ page }) => {
  await installBridge(page, { totp: false });
  await page.goto('/');
  await page.getByRole('button', { name: 'Восстановить из внешней зашифрованной копии v2' }).click();
  const dialog = page.getByRole('dialog', { name: 'Восстановить из внешней копии v2' });
  await dialog.getByRole('button', { name: 'Выбрать файл' }).click();
  await dialog.getByLabel('Мастер-пароль копии').fill('Synthetic-master!42');
  await dialog.getByRole('button', { name: 'Проверить копию' }).click();
  await expect(dialog).toContainText('backup.v2.enc');
  await dialog.getByRole('button', { name: 'Не восстанавливать' }).click();
  await expect(dialog).toHaveCount(0);
  const names = await page.evaluate(() => window.mock.calls.map(call => call.name));
  expect(names).toContain('CancelExternalV2Restore');
  expect(names).not.toContain('ConfirmExternalV2Restore');
});
