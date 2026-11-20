import { test, expect } from '@playwright/test';
import { installBridge, unlock } from './bridge.js';

async function openCopy(page, options = {}) {
  const { verify = false, ...bridgeOptions } = options;
  await installBridge(page, { totp: false, ...bridgeOptions });
  await page.goto('/');
  await unlock(page, { totp: false });
  await page.getByRole('navigation').getByRole('button', { name: 'Хранилища', exact: true }).click();
  await page.getByRole('button', {
    name: verify ? 'Проверить целостность копии' : 'Импортировать записи из копии', exact: true,
  }).click();
  return page.getByRole('dialog', {
    name: verify ? 'Проверка целостности копии v2' : 'Импорт записей из копии v2', exact: true,
  });
}

async function checkCopy(dialog) {
  await dialog.getByRole('button', { name: 'Выбрать файл' }).click();
  await dialog.getByLabel('Мастер-пароль копии').fill('Synthetic-copy-master!42');
  await dialog.getByLabel('Код TOTP копии, если он был включён').fill('123456');
  await dialog.getByRole('button', { name: 'Проверить копию' }).click();
}

function calls(page, name) {
  return page.evaluate(name => window.mock.calls.filter(call => call.name === name), name);
}

test('integrity mode asks for credentials after file selection and offers no write', async ({ page }) => {
  const dialog = await openCopy(page, { verify: true });
  await expect(dialog.getByLabel('Мастер-пароль копии')).toHaveCount(0);
  await checkCopy(dialog);
  await expect(dialog.getByRole('status')).toHaveText('Целостность копии подтверждена. Файлы не менялись.');
  await expect(dialog).toContainText('Записей: 2');
  await expect(dialog.getByLabel('Мастер-пароль копии')).toHaveCount(0);
  await expect(dialog.getByRole('checkbox')).toHaveCount(0);
  await expect(dialog.getByRole('button', { name: 'Подтвердить импорт' })).toHaveCount(0);
  expect((await calls(page, 'SelectExternalV2Import'))[0].args).toEqual([false]);
  expect(await calls(page, 'ConfirmExternalV2Import')).toHaveLength(0);
});

test('cancelled native selection never asks for a master password', async ({ page }) => {
  const dialog = await openCopy(page, { cancelImportPicker: true });
  await dialog.getByRole('button', { name: 'Выбрать файл' }).click();
  await expect(dialog.getByRole('button', { name: 'Выбрать файл' })).toBeEnabled();
  await expect(dialog.getByLabel('Мастер-пароль копии')).toHaveCount(0);
  expect(await calls(page, 'CheckSelectedExternalV2Backup')).toHaveLength(0);
});

test('preview shows conflict, defaults to skip and submits only checked entries', async ({ page }) => {
  const dialog = await openCopy(page);
  await checkCopy(dialog);
  const confirm = dialog.getByRole('button', { name: 'Подтвердить импорт' });
  await expect(confirm).toBeDisabled();
  await expect(dialog.getByText('Записей: 2.', { exact: false })).toBeVisible();
  await expect(dialog.getByText('Совпадение', { exact: false })).toBeVisible();
  expect(await calls(page, 'ConfirmExternalV2Import')).toHaveLength(0);
  await dialog.getByRole('checkbox', { name: /Synthetic other service/ }).check();
  await confirm.click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole('status')).toHaveText('Импортировано записей: 1.');
  expect((await calls(page, 'ConfirmExternalV2Import'))[0].args).toEqual([
    'synthetic-import-review', [{ index: 1, separate: false }],
  ]);
});

test('a duplicate can be requested as a separate record', async ({ page }) => {
  const dialog = await openCopy(page);
  await checkCopy(dialog);
  await dialog.getByRole('checkbox', { name: /GitHub/ }).check();
  const policy = dialog.getByRole('combobox');
  await expect(policy.locator('option:checked')).toHaveText('Пропустить при совпадении');
  await policy.selectOption({ label: 'Создать отдельную запись' });
  await dialog.getByRole('button', { name: 'Подтвердить импорт' }).click();
  await expect(page.getByRole('status')).toHaveText('Импортировано записей: 1.');
  expect((await calls(page, 'ConfirmExternalV2Import'))[0].args[1]).toEqual([{ index: 0, separate: true }]);
});

test('cancelling preview discards the capability without saving', async ({ page }) => {
  const dialog = await openCopy(page);
  await checkCopy(dialog);
  await expect(dialog.getByRole('checkbox')).toHaveCount(2);
  await dialog.getByRole('button', { name: 'Отмена', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect((await calls(page, 'CancelExternalV2Import')).at(-1).args).toEqual(['synthetic-import-review']);
  expect(await calls(page, 'ConfirmExternalV2Import')).toHaveLength(0);
});

test('authentication failure offers no preview and does not classify the file as corrupt', async ({ page }) => {
  const dialog = await openCopy(page);
  await page.evaluate(() => window.mock.errors = { CheckSelectedExternalV2Backup: 'v2 vault authentication failed' });
  await checkCopy(dialog);
  await expect(dialog.getByRole('alert')).toHaveText('Не удалось аутентифицировать копию. Проверьте пароль и исходный файл.');
  await expect(dialog.getByRole('checkbox')).toHaveCount(0);
  await expect(dialog.getByLabel('Мастер-пароль копии')).toHaveCount(0);
});

test('source substitution on confirmation clears the preview and reports the error', async ({ page }) => {
  const dialog = await openCopy(page);
  await checkCopy(dialog);
  await dialog.getByRole('checkbox', { name: /Synthetic other service/ }).check();
  await page.evaluate(() => window.mock.errors = { ConfirmExternalV2Import: 'выбранная копия изменилась; повторите проверку' });
  await dialog.getByRole('button', { name: 'Подтвердить импорт' }).click();
  await expect(dialog.getByRole('alert')).toContainText('Файлы изменились');
  await expect(dialog.getByRole('checkbox')).toHaveCount(0);
  await expect(page.getByText('Импортировано записей: 1.')).toHaveCount(0);
});

test('autoblock during a pending write asks the user to check the result after login', async ({ page }) => {
  const dialog = await openCopy(page, { delayImportConfirm: true });
  await checkCopy(dialog);
  await dialog.getByRole('checkbox', { name: /Synthetic other service/ }).check();
  await dialog.getByRole('button', { name: 'Подтвердить импорт' }).click();
  await expect.poll(() => page.evaluate(() => typeof window.mock.resolveImportConfirm)).toBe('function');
  await page.evaluate(() => window.mock.locked = true);
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('Сессия закрыта. Проверьте записи после входа перед повтором импорта.')).toBeVisible();
  await page.evaluate(() => window.mock.resolveImportConfirm(1));
  await expect(page.getByText('Импортировано записей: 1.')).toHaveCount(0);
});

for (const stage of ['selection', 'review']) {
  test('a late ' + stage + ' after autoblock is discarded and cancelled', async ({ page }) => {
    const dialog = await openCopy(page, stage === 'selection' ? { delayImportSelection: true } : { delayImportReview: true });
    if (stage === 'selection') await dialog.getByRole('button', { name: 'Выбрать файл' }).click();
    else await checkCopy(dialog);
    const key = stage === 'selection' ? 'resolveImportSelection' : 'resolveImportReview';
    await expect.poll(() => page.evaluate(key => typeof window.mock[key], key)).toBe('function');
    await page.evaluate(() => window.mock.locked = true);
    await expect(dialog).toHaveCount(0);
    await expect(page.getByLabel('Мастер-пароль', { exact: true })).toBeVisible();
    await page.evaluate(key => window.mock[key]({
      token: 'synthetic-late-import', fileName: 'late-source.v2.enc', accountCount: 1,
      records: [{ index: 0, title: 'Synthetic late preview', login: 'late@example.test', conflict: false }],
    }), key);
    await expect.poll(async () => (await calls(page, 'CancelExternalV2Import')).some(call =>
      call.args[0] === 'synthetic-late-import')).toBe(true);
    await expect(dialog).toHaveCount(0);
    await expect(page.getByText('Synthetic late preview')).toHaveCount(0);
  });
}
