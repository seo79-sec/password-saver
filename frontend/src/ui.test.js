import { installThemeRuntime } from './theme-runtime.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createThemeController, normalizeTheme, resolvedTheme, validView, accountLabel, filterAccounts, auditPasswords } from './ui.js';

test('new installations use light while existing theme values remain compatible', () => {
  assert.equal(normalizeTheme(null), 'light');
  assert.equal(normalizeTheme('light'), 'light');
  assert.equal(normalizeTheme('dark'), 'dark');
  assert.equal(normalizeTheme('unexpected'), 'light');
  assert.equal(resolvedTheme('system', true), 'dark');
  assert.equal(resolvedTheme('system', false), 'light');
});
test('theme persists only its preference and follows live system changes with cleanup', () => {
  const saved = new Map([['theme','dark']]);
  const root = { dataset:{} };
  let listener;
  const media = { matches:false, addEventListener:(_, fn) => listener=fn, removeEventListener:(_, fn) => { assert.equal(fn, listener); listener=null; } };
  const controller = createThemeController({ storage:{ getItem:k=>saved.get(k), setItem:(k,v)=>saved.set(k,v) }, root, media });
  assert.equal(root.dataset.theme, 'dark');
  controller.set('system');
  assert.equal(saved.get('theme'), 'system');
  assert.equal(root.dataset.theme, 'light');
  media.matches=true; listener();
  assert.equal(root.dataset.theme, 'dark');
  controller.set('light'); listener();
  assert.equal(root.dataset.theme, 'light');
  assert.deepEqual([...saved.keys()], ['theme']);
  controller.destroy(); assert.equal(listener, null);
});
test('unavailable preference storage does not break the UI', () => {
  const root = { dataset:{} };
  const controller = createThemeController({ storage:{ getItem(){throw Error();}, setItem(){throw Error();} }, root, media:{ matches:true, addEventListener(){}, removeEventListener(){} } });
  assert.equal(root.dataset.theme, 'light');
  controller.set('dark'); assert.equal(root.dataset.theme, 'dark');
  controller.destroy();
});
test('navigation accepts implemented screens and refuses unknown routes', () => {
  for (const view of ['passwords','vaults','security','devices','settings']) assert.equal(validView(view), view);
  assert.equal(validView('remote-sync'), 'passwords');
});
test('category display preserves legacy and unknown category values without changing records', () => {
  const account = { id:'1', title:'Example|||Особая', login:'synthetic', password:'Synthetic!123' };
  assert.deepEqual(accountLabel(account), { title:'Example', category:'Особая' });
  assert.equal(accountLabel({ title:'Legacy' }).category, 'Общие');
  assert.deepEqual(filterAccounts([account], 'example', 'Особая'), [account]);
  assert.equal(account.title, 'Example|||Особая');
});
test('security counts include weak, reused and old passwords including special object keys', () => {
  const accounts = [{ title:'a', login:'x', password:'__proto__', updatedAt:1 }, { title:'b', login:'y', password:'__proto__', updatedAt:0 }, { title:'c', login:'z', password:'Synthetic-Strong!123', updatedAt:Date.now()/1000 }];
  assert.deepEqual(auditPasswords(accounts), { weak:2, reused:2, old:1 });
  assert.equal(filterAccounts(accounts, '', 'Все', 'weak').length, 2);
  assert.equal(filterAccounts(accounts, '', 'Все', 'reused').length, 2);
  assert.equal(filterAccounts(accounts, '', 'Все', 'breached').length, 0);
});


test('head bootstrap and App share one controller with idempotent cleanup', () => {
  let listeners=0;
  const root={dataset:{}};
  const env={document:{documentElement:root},localStorage:{getItem:()=> 'system'},
    matchMedia:()=>({matches:true,addEventListener(){listeners++;},removeEventListener(){listeners--;}})};
  const runtime=installThemeRuntime(env);
  assert.equal(root.dataset.theme,'dark');
  assert.equal(listeners,1);
  const controller=runtime.getThemeController();
  assert.equal(installThemeRuntime(env),runtime);
  assert.equal(runtime.getThemeController(),controller);
  assert.equal(listeners,1);
  controller.destroy();controller.destroy();
  assert.equal(listeners,0);
  runtime.getThemeController().destroy();
  assert.equal(listeners,0);
});

test('bootstrap handles a throwing storage getter before first render', () => {
  const root={dataset:{}};
  const env={document:{documentElement:root},get localStorage(){throw Error('denied');},
    matchMedia:()=>({matches:true,addEventListener(){},removeEventListener(){}})};
  const runtime=installThemeRuntime(env);
  assert.equal(root.dataset.theme,'light');
  runtime.getThemeController().set('dark');
  assert.equal(root.dataset.theme,'dark');
  runtime.getThemeController().destroy();
});
