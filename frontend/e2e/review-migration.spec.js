import { test, expect } from '@playwright/test';
import { installBridge, unlock } from './bridge.js';

async function startPreparation(page) {
  await installBridge(page,{totp:false,delayMigration:true,vault:{state:'v1-active'},storage:{format:'v1 (legacy)',algorithm:''}});
  await page.goto('/'); await unlock(page,{totp:false});
  await page.getByRole('navigation').getByRole('button',{name:'Хранилища',exact:true}).click();
  await page.getByRole('button',{name:'Подготовить переход на v2',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'Миграция формата хранилища',exact:true});
  await dialog.getByLabel('Повторно введите мастер-пароль',{exact:true}).fill('Synthetic-master!42');
  await dialog.getByRole('button',{name:'Создать и проверить контейнер',exact:true}).click();
  await expect.poll(()=>page.evaluate(()=>typeof window.mock.resolveMigration)).toBe('function');
  return dialog;
}

for(const outcome of ['success','error-after-commit','expired-after-commit','error-before-commit']) {
  test('closing preparation reconciles metadata without reviving token: '+outcome,async({page})=>{
    const dialog=await startPreparation(page);
    await dialog.getByRole('button',{name:'Закрыть окно',exact:true}).click();
    const reads=await page.evaluate(()=>window.mock.calls.filter(c=>c.name==='GetVaultStatus').length);
    await page.evaluate(outcome=>{
      if(outcome==='success') window.mock.resolveMigration('discarded-activation-token');
      else {
        if(outcome!=='error-before-commit')window.mock.vault={...window.mock.vault,state:'v1-prepared',preparationFresh:true};
        window.mock.rejectMigration(new Error(outcome.startsWith('expired')?'activation challenge expired':'synthetic preparation error'));
      }
    },outcome);
    await expect.poll(()=>page.evaluate(()=>window.mock.calls.filter(c=>c.name==='GetVaultStatus').length)).toBeGreaterThan(reads);
    await expect(page.getByRole('dialog')).toHaveCount(0);
    if(outcome==='error-before-commit') {
      await expect(page.getByText('Активен совместимый формат v1.',{exact:true})).toBeVisible();
      await expect(page.getByRole('button',{name:'Отменить подготовку v2',exact:true})).toHaveCount(0);
    } else {
      await expect(page.getByText('Переход к v2 подготовлен и ожидает вашего решения.',{exact:true})).toBeVisible();
      await expect(page.getByRole('button',{name:'Отменить подготовку v2',exact:true})).toBeVisible();
      await page.getByRole('button',{name:'Подготовить переход на v2',exact:true}).click();
      await expect(dialog.getByLabel('Повторно введите мастер-пароль',{exact:true})).toHaveValue('');
      await expect(dialog.getByRole('button',{name:'Явно активировать v2',exact:true})).toHaveCount(0);
      await dialog.getByRole('button',{name:'Закрыть окно',exact:true}).click();
      // The durable cancellation action gets its own fresh challenge.
      await page.getByRole('button',{name:'Отменить подготовку v2',exact:true}).click();
      await dialog.getByRole('button',{name:'Подтвердить отмену',exact:true}).click();
      await expect(page.getByText('Активен совместимый формат v1.',{exact:true})).toBeVisible();
    }
    expect(await page.evaluate(()=>window.mock.calls.filter(c=>c.name==='ConfirmV2Migration').length)).toBe(0);
  });
}

test('completion after autoblock updates only public status and never restores the session',async({page})=>{
  await startPreparation(page);
  await page.evaluate(()=>window.mock.locked=true);
  await expect(page.locator('.app-shell')).toHaveCount(0);
  await page.evaluate(()=>window.mock.resolveMigration('old-secret-token'));
  await expect(page.getByText('Активное хранилище: v1 (v2 подготовлен)',{exact:true})).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.locator('tbody tr')).toHaveCount(0);
  await expect(page.getByRole('textbox',{name:'Мастер-пароль',exact:true})).toHaveValue('');
  await unlock(page,{totp:false});
  await page.getByRole('navigation').getByRole('button',{name:'Хранилища',exact:true}).click();
  await expect(page.getByRole('button',{name:'Отменить подготовку v2',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>window.mock.calls.some(c=>c.name==='ConfirmV2Migration'))).toBe(false);
});

test('old status snapshot cannot overwrite reconciliation after logout and a new login',async({page})=>{
  const dialog=await startPreparation(page);
  await dialog.getByRole('button',{name:'Закрыть окно',exact:true}).click();
  await page.evaluate(()=>window.mock.deferNextStatus=true);
  await page.getByRole('button',{name:'Заблокировать',exact:true}).click();
  await expect.poll(()=>page.evaluate(()=>typeof window.mock.releaseStatus)).toBe('function');
  await unlock(page,{totp:false});
  await page.getByRole('navigation').getByRole('button',{name:'Хранилища',exact:true}).click();
  await page.evaluate(()=>window.mock.resolveMigration('prior-session-token'));
  await expect(page.getByText('Переход к v2 подготовлен и ожидает вашего решения.',{exact:true})).toBeVisible();
  await page.evaluate(()=>window.mock.releaseStatus()); // older v1-active snapshot
  await expect(page.getByRole('button',{name:'Отменить подготовку v2',exact:true})).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await page.evaluate(()=>window.mock.calls.filter(c=>c.name==='Login').length)).toBe(2);
  expect(await page.evaluate(()=>window.mock.calls.some(c=>c.name==='ConfirmV2Migration'))).toBe(false);
});

test('unmounted App cannot commit or request metadata from a completed preparation',async({page})=>{
  await startPreparation(page);
  await page.evaluate(async()=>{const {default:app}=await import('/src/main.js');app.$destroy();});
  const reads=await page.evaluate(()=>window.mock.calls.filter(c=>c.name==='GetVaultStatus').length);
  await page.evaluate(()=>window.mock.resolveMigration('unmounted-token'));
  await expect.poll(()=>page.evaluate(()=>window.mock.vault.state)).toBe('v1-prepared');
  expect(await page.evaluate(()=>window.mock.calls.filter(c=>c.name==='GetVaultStatus').length)).toBe(reads);
  await expect(page.locator('#app')).toBeEmpty();
  await page.evaluate(async()=>{
    window.mock.locked=true;
    const {default:App}=await import('/src/App.svelte');
    new App({target:document.getElementById('app')});
  });
  await expect(page.getByText('Активное хранилище: v1 (v2 подготовлен)',{exact:true})).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.locator('tbody tr')).toHaveCount(0);
});
