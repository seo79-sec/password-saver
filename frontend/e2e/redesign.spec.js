import { test, expect } from '@playwright/test';
import { installBridge, unlock, demoAccounts } from './bridge.js';
import fs from 'node:fs/promises';
const shot = async (page,name) => {
  if(!process.env.CAPTURE_UI) return;
  await fs.mkdir('../docs/screenshots/ui-2.5',{recursive:true});
  await page.screenshot({path:'../docs/screenshots/ui-2.5/'+name+'.png',fullPage:true});
};

test('light/dark/system, navigation, honest security cards and screenshots', async({page})=>{
  await installBridge(page);
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('data-theme','light');
  await shot(page,'login-light');
  await page.getByRole('button',{name:'Dark',exact:true}).click();
  await shot(page,'login-dark');
  await page.reload(); await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
  await page.getByRole('button',{name:'Light',exact:true}).click();
  await unlock(page);
  await expect(page.locator('tbody tr')).toHaveCount(4);
  await expect(page.getByText('Двухфакторная защита включена',{exact:true})).toBeVisible();
  await expect(page.getByText('Копия имеется на устройстве',{exact:true})).toBeVisible();
  await expect(page.getByText('Обновлена: сегодня')).toHaveCount(0);
  await shot(page,'passwords-light');
  const nav=page.getByRole('navigation',{name:'Основная навигация'});
  await nav.getByRole('button',{name:'Безопасность',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Безопасность',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:/Слабые пароли/})).toContainText('2');
  await expect(page.getByRole('button',{name:/Повторяющиеся/})).toContainText('2');
  await expect(page.getByText('Пароли ещё не проверены.',{exact:false})).toBeVisible();
  await shot(page,'security');
  await nav.getByRole('button',{name:'Настройки',exact:true}).click();
  await shot(page,'settings');
  await page.getByRole('button',{name:'System',exact:true}).click();
  await page.emulateMedia({colorScheme:'dark'});
  await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
  await page.emulateMedia({colorScheme:'light'});
  await expect(page.locator('html')).toHaveAttribute('data-theme','light');
  await page.getByRole('button',{name:'Dark',exact:true}).click();
  await nav.getByRole('button',{name:'Мои пароли',exact:true}).click();
  await shot(page,'passwords-dark');
  await nav.getByRole('button',{name:'Устройства',exact:true}).click();
  await expect(page.getByText('В этой версии нет синхронизации', {exact:false})).toBeVisible();
  await nav.getByRole('button',{name:'Хранилища',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Основное',exact:true})).toBeVisible();
});

test('CRUD, hidden passwords, copy, focus trap, confirmation and lock cleanup',async({page})=>{
  await page.context().grantPermissions(['clipboard-read','clipboard-write']);
  await installBridge(page); await page.goto('/'); await unlock(page);
  const first=page.locator('tbody tr').first();
  await expect(first).not.toContainText(demoAccounts[0].password);
  await first.getByRole('button',{name:'Скопировать пароль',exact:true}).click();
  await expect.poll(()=>page.evaluate(()=>navigator.clipboard.readText())).toBe(demoAccounts[0].password);
  await first.getByRole('button',{name:'Показать пароль',exact:true}).click();
  await expect(first).toContainText(demoAccounts[0].password);
  await page.getByRole('button',{name:'Добавить',exact:true}).click();
  let dialog=page.getByRole('dialog',{name:'Добавить пароль',exact:true});
  await expect(dialog.getByLabel('Название',{exact:true})).toBeFocused();
  await dialog.getByLabel('Название',{exact:true}).fill('Synthetic Added');
  await dialog.getByLabel('Логин',{exact:true}).fill('synthetic@example.test');
  await dialog.locator('input[autocomplete="new-password"]').fill('Synthetic-added!12');
  await expect(dialog.locator('input[autocomplete="new-password"]')).toHaveAttribute('type','password');
  await dialog.getByRole('button',{name:'Сохранить запись',exact:true}).focus();
  await page.keyboard.press('Tab'); await expect(dialog.getByRole('button',{name:'Закрыть окно'})).toBeFocused();
  await dialog.getByRole('button',{name:'Сохранить запись',exact:true}).click();
  await expect(page.locator('tbody tr')).toHaveCount(5);
  const added=page.locator('tbody tr').filter({hasText:'Synthetic Added'});
  await added.getByLabel('Действия с записью').click();
  await added.getByRole('button',{name:'Редактировать',exact:true}).click();
  dialog=page.getByRole('dialog',{name:'Редактировать запись',exact:true});
  await expect(dialog.locator('input[autocomplete="new-password"]')).toHaveAttribute('type','password');
  await dialog.getByLabel('Название',{exact:true}).fill('Synthetic Updated');
  await dialog.getByRole('button',{name:'Сохранить запись',exact:true}).click();
  const updated=page.locator('tbody tr').filter({hasText:'Synthetic Updated'});
  await updated.getByLabel('Действия с записью').click();
  await updated.getByRole('button',{name:'Удалить',exact:true}).click();
  await page.getByRole('dialog').getByRole('button',{name:'Отмена',exact:true}).click();
  await expect(updated).toBeVisible();
  await updated.getByLabel('Действия с записью').click();
  await updated.getByRole('button',{name:'Удалить',exact:true}).click();
  await page.getByRole('dialog').getByRole('button',{name:'Подтвердить',exact:true}).click();
  await expect(page.locator('tbody tr')).toHaveCount(4);
  await page.getByRole('button',{name:'Добавить',exact:true}).click();
  await page.evaluate(()=>window.mock.locked=true);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.locator('.app-shell')).toHaveCount(0);
  await unlock(page);
  await expect(page.locator('tbody tr').first()).not.toContainText(demoAccounts[0].password);
  await expect.poll(()=>page.evaluate(()=>Object.keys(localStorage))).toEqual([]);
});

test('late accounts and TOTP setup never return after lock',async({page})=>{
  await installBridge(page,{delayAccounts:true,delayTOTP:true,totp:false});
  await page.goto('/'); await unlock(page,{totp:false});
  await page.getByRole('navigation').getByRole('button',{name:'Безопасность',exact:true}).click();
  await page.getByRole('button',{name:'Настроить TOTP',exact:true}).click();
  await page.getByRole('button',{name:'Заблокировать',exact:true}).click();
  await page.evaluate(accounts=>{
    window.mock.resolveAccounts(accounts);
    window.mock.resolveTOTP({secret:'MUST_NOT_RETURN',qrCode:''});
  },demoAccounts);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByText('MUST_NOT_RETURN')).toHaveCount(0);
  await expect(page.locator('tbody tr')).toHaveCount(0);
});

test('AppData migration confirmation, diagnostics and stale token cancellation',async({page})=>{
  await installBridge(page,{storage:{state:'migration-required',legacyPaths:['D:\\SyntheticVault']},delayMigration:true});
  await page.goto('/');
  await page.getByRole('button',{name:'Проверить и перенести зашифрованное хранилище',exact:true}).click();
  await shot(page,'appdata-migration');
  let dialog=page.getByRole('dialog',{name:'Перенос в AppData',exact:true});
  await dialog.getByLabel('Мастер-пароль',{exact:true}).fill('Synthetic-master!42');
  await dialog.getByRole('button',{name:'Проверить хранилище',exact:true}).click();
  await dialog.getByRole('button',{name:'Закрыть окно',exact:true}).click();
  await page.evaluate(()=>window.mock.resolveMigration('stale-copy-token'));
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect.poll(()=>page.evaluate(()=>window.mock.calls.some(c=>c.name==='CancelStorageLocationMigration' && c.args[0]==='stale-copy-token'))).toBe(true);
  await page.getByRole('button',{name:'Проверить и перенести зашифрованное хранилище',exact:true}).click();
  dialog=page.getByRole('dialog',{name:'Перенос в AppData',exact:true});
  await dialog.getByLabel('Мастер-пароль',{exact:true}).fill('Synthetic-master!42');
  await dialog.getByRole('button',{name:'Проверить хранилище',exact:true}).click();
  await page.evaluate(()=>window.mock.resolveMigration('confirmed-copy-token'));
  await expect(dialog.getByRole('heading',{name:'Подтвердите копирование',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>window.mock.calls.some(c=>c.name==='ConfirmStorageLocationMigration'))).toBe(false);
  await dialog.getByRole('button',{name:'Подтвердить копирование',exact:true}).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Разблокировать',exact:true})).toBeVisible();
});

test('incomplete/unsafe state blocks setup and diagnostics never claim integrity',async({page})=>{
  await installBridge(page,{storage:{state:'incomplete-write',temporaryFiles:1,diagnostic:'incomplete-write'},vault:{state:'uninitialized'}});
  await page.goto('/');
  await expect(page.getByRole('button',{name:'Создать хранилище v2',exact:true})).toHaveCount(0);
  await expect(page.getByText('Создание нового хранилища заблокировано.',{exact:false})).toBeVisible();
});

test('residue warning, backup honesty and responsive sizes',async({page})=>{
  await installBridge(page,{storage:{temporaryFiles:1,diagnostic:'write-residue',backupPresent:false},totp:false});
  await page.goto('/');
  await expect(page.getByText('Наличие этих файлов само по себе не подтверждает целостность хранилища.',{exact:false})).toBeVisible();
  await expect(page.getByText('Основное хранилище не изменено.',{exact:false})).toHaveCount(0);
  await unlock(page,{totp:false});
  await expect(page.getByText('Двухфакторная защита не включена',{exact:true})).toBeVisible();
  await expect(page.getByText('Наличие копии не подтверждено',{exact:true})).toBeVisible();
  for(const [width,height] of [[1920,1080],[1440,900],[1366,768],[1024,768],[800,600]]) {
    await page.setViewportSize({width,height});
    await expect(page.getByRole('button',{name:'Добавить',exact:true})).toBeVisible();
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
    if(width===800)await shot(page,'narrow-800');
  }
});

test('HIBP asks consent, reports errors, and cancels late results on lock',async({page})=>{
  await installBridge(page,{totp:false});
  let requests=0; let complete;
  await page.route('https://api.pwnedpasswords.com/**', async route=>{requests++;await new Promise(resolve=>complete=resolve);await route.fulfill({status:503,body:'unavailable'}).catch(()=>{});});
  await page.goto('/'); await unlock(page,{totp:false});
  await page.getByRole('navigation').getByRole('button',{name:'Безопасность',exact:true}).click();
  await page.getByRole('button',{name:'Проверить через интернет',exact:true}).click();
  expect(requests).toBe(0);
  await page.getByRole('dialog').getByRole('button',{name:'Подтвердить',exact:true}).click();
  await expect.poll(()=>requests).toBe(1);
  await page.getByRole('button',{name:'Заблокировать',exact:true}).click();
  complete();
  await expect(page.locator('.app-shell')).toHaveCount(0);
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('search, categories, local security filters and keyboard dialog cancellation',async({page})=>{
  await installBridge(page,{totp:false}); await page.goto('/'); await unlock(page,{totp:false});
  await page.getByRole('textbox',{name:'Поиск по записям',exact:true}).fill('GitHub');
  await expect(page.locator('tbody tr')).toHaveCount(1);
  await page.getByRole('textbox',{name:'Поиск по записям',exact:true}).fill('');
  await page.getByRole('group',{name:'Категории записей'}).getByRole('button',{name:/Финансы/}).click();
  await expect(page.locator('tbody tr')).toHaveCount(1);
  await page.getByRole('navigation').getByRole('button',{name:'Безопасность',exact:true}).click();
  await page.getByRole('button',{name:/Слабые пароли/}).click();
  await expect(page.locator('tbody tr')).toHaveCount(2);
  await page.getByRole('button',{name:'Добавить',exact:true}).click();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Добавить',exact:true})).toBeFocused();
});

test('TOTP setup secrets disappear on close; recovery still requires confirmation and second factor',async({page})=>{
  await installBridge(page,{totp:false}); await page.goto('/'); await unlock(page,{totp:false});
  await page.getByRole('navigation').getByRole('button',{name:'Безопасность',exact:true}).click();
  await page.getByRole('button',{name:'Настроить TOTP',exact:true}).click();
  await expect(page.getByText('SYNTHETICSETUPSECRET',{exact:true})).toBeVisible();
  await page.getByRole('dialog').getByRole('button',{name:'Закрыть окно',exact:true}).click();
  await expect(page.getByText('SYNTHETICSETUPSECRET',{exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Заблокировать',exact:true}).click();
  await page.evaluate(()=>{window.mock.totp=true;window.mock.vault.v2ContainerPresent=false;});
  await page.getByRole('textbox',{name:'Мастер-пароль',exact:true}).fill('Synthetic-master!42');
  await page.getByRole('button',{name:'Восстановить из резервной копии v2',exact:true}).click();
  expect(await page.evaluate(()=>window.mock.calls.some(c=>c.name==='ConfirmV2VaultRecovery'))).toBe(false);
  await page.getByRole('dialog').getByRole('button',{name:'Подтвердить',exact:true}).click();
  await expect(page.getByRole('textbox',{name:'Код TOTP',exact:true})).toBeVisible();
  await expect(page.locator('tbody tr')).toHaveCount(0);
  await page.getByRole('textbox',{name:'Код TOTP',exact:true}).fill('123456');
  await page.getByRole('button',{name:'Подтвердить код',exact:true}).click();
  await expect(page.locator('tbody tr')).toHaveCount(4);
});

test('HIBP errors remain explicit instead of reporting zero leaked passwords',async({page})=>{
  await installBridge(page,{totp:false});
  await page.route('https://api.pwnedpasswords.com/**',route=>route.fulfill({status:503,body:'unavailable'}));
  await page.goto('/'); await unlock(page,{totp:false});
  await page.getByRole('navigation').getByRole('button',{name:'Безопасность',exact:true}).click();
  await page.getByRole('button',{name:'Проверить через интернет',exact:true}).click();
  await page.getByRole('dialog').getByRole('button',{name:'Подтвердить',exact:true}).click();
  await expect(page.getByText('Не удалось завершить проверку.',{exact:false})).toBeVisible();
});

test('nested setup errors keep focus in the top dialog and release inert state on lock',async({page})=>{
  await installBridge(page,{totp:false}); await page.goto('/'); await unlock(page,{totp:false});
  await page.getByRole('navigation').getByRole('button',{name:'Безопасность',exact:true}).click();
  await page.getByRole('button',{name:'Настроить TOTP',exact:true}).click();
  await page.evaluate(()=>window.mock.errors={ConfirmAndEnable2FA:'неверный код 2FA'});
  await page.getByRole('button',{name:'Включить TOTP',exact:true}).click();
  await expect(page.locator('.modal-overlay')).toHaveCount(2);
  await page.keyboard.press('Escape');
  await expect(page.locator('.modal-overlay')).toHaveCount(1);
  await expect(page.getByText('SYNTHETICSETUPSECRET',{exact:true})).toBeVisible();
  await page.evaluate(()=>window.mock.locked=true);
  await expect(page.locator('.modal-overlay')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Разблокировать',exact:true})).toBeEnabled();
  await expect(page.locator('.login-layout')).not.toHaveAttribute('inert','');
});

test('first-run setup requires explicit choice and uses the v2 bindings',async({page})=>{
  await installBridge(page,{totp:false,vault:{state:'uninitialized'},storage:{format:'',algorithm:'',backupPresent:false}});
  await page.goto('/');
  await page.getByRole('textbox',{name:'Новый мастер-пароль',exact:true}).fill('Synthetic-new-master!42');
  await page.getByRole('textbox',{name:'Повторите мастер-пароль',exact:true}).fill('Synthetic-new-master!42');
  const create=page.getByRole('button',{name:'Создать хранилище v2',exact:true});
  await expect(create).toBeDisabled();
  await page.getByRole('checkbox',{name:/Создать отдельное пустое хранилище/}).check();
  await create.click();
  await expect(page.getByRole('heading',{name:'Мои пароли',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>window.mock.calls.filter(c=>c.name==='CreateV2Vault').length)).toBe(1);
  expect(await page.evaluate(()=>window.mock.calls.filter(c=>c.name==='Login').length)).toBe(0);
});

test('v1 to v2 requires preparation and separate activation confirmation',async({page})=>{
  await installBridge(page,{vault:{state:'v1-active'},storage:{format:'v1 (legacy)',algorithm:''}});
  await page.goto('/'); await unlock(page);
  await page.getByRole('navigation').getByRole('button',{name:'Хранилища',exact:true}).click();
  await page.getByRole('button',{name:'Подготовить переход на v2',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'Миграция формата хранилища',exact:true});
  await dialog.getByLabel('Повторно введите мастер-пароль',{exact:true}).fill('Synthetic-master!42');
  await dialog.getByLabel('Код TOTP, если включена 2FA',{exact:true}).fill('123456');
  await dialog.getByRole('button',{name:'Создать и проверить контейнер',exact:true}).click();
  await expect(dialog.getByRole('heading',{name:'Контейнер v2 проверен',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>window.mock.calls.some(c=>c.name==='ConfirmV2Migration'))).toBe(false);
  await dialog.getByLabel('Мастер-пароль для подтверждения',{exact:true}).fill('Synthetic-master!42');
  await dialog.getByLabel('Код TOTP, если включена 2FA',{exact:true}).fill('123456');
  await dialog.getByRole('button',{name:'Явно активировать v2',exact:true}).click();
  await expect(page.locator('.app-shell')).toHaveCount(0);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByText('Хранилище обновлено до v2. Войдите повторно.',{exact:true})).toBeVisible();
});

test('a late v1 migration result cannot reopen its modal after autoblock',async({page})=>{
  await installBridge(page,{totp:false,delayMigration:true,vault:{state:'v1-active'},storage:{format:'v1 (legacy)',algorithm:''}});
  await page.goto('/'); await unlock(page,{totp:false});
  await page.getByRole('navigation').getByRole('button',{name:'Хранилища',exact:true}).click();
  await page.getByRole('button',{name:'Подготовить переход на v2',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'Миграция формата хранилища',exact:true});
  await dialog.getByLabel('Повторно введите мастер-пароль',{exact:true}).fill('Synthetic-master!42');
  await dialog.getByRole('button',{name:'Создать и проверить контейнер',exact:true}).click();
  await page.evaluate(()=>window.mock.locked=true);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.evaluate(()=>window.mock.resolveMigration('must-not-return'));
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Явно активировать v2',exact:true})).toHaveCount(0);
});
