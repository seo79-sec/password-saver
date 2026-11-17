import { test, expect } from '@playwright/test';
import { installBridge } from './bridge.js';

test.use({baseURL:'http://127.0.0.1:5174'}); // Actual production build and emitted head asset.
const cases=[
  {preference:null,system:'dark',expected:'light'},
  {preference:'light',system:'dark',expected:'light'},
  {preference:'dark',system:'light',expected:'dark'},
  {preference:'system',system:'light',expected:'light'},
  {preference:'system',system:'dark',expected:'dark'},
  {preference:'invalid',system:'dark',expected:'light'},
  {preference:'blocked',system:'dark',expected:'light'},
];
for(const scenario of cases) {
  test('correct first frame before App loads: '+JSON.stringify(scenario),async({page})=>{
    const errors=[];page.on('pageerror',error=>errors.push(error.message));
    await page.emulateMedia({colorScheme:scenario.system});
    await installBridge(page);
    await page.addInitScript(preference=>{
      window.themeFrames=[]; window.themeListeners=0; window.preferenceReads=[];
      const matchMedia=window.matchMedia.bind(window);
      window.matchMedia=query=>{
        const media=matchMedia(query);
        const add=media.addEventListener.bind(media),remove=media.removeEventListener.bind(media);
        media.addEventListener=(type,listener,...args)=>{if(type==='change')window.themeListeners++;return add(type,listener,...args);};
        media.removeEventListener=(type,listener,...args)=>{if(type==='change')window.themeListeners--;return remove(type,listener,...args);};
        return media;
      };
      if(preference==='blocked')Object.defineProperty(window,'localStorage',{get(){throw new DOMException('denied','SecurityError');}});
      else {
        if(preference)localStorage.setItem('theme',preference);
        const getItem=Storage.prototype.getItem;
        Storage.prototype.getItem=function(key){window.preferenceReads.push(key);return getItem.call(this,key);};
      }
    },scenario.preference);
    // Strict script CSP proves the bootstrap requires no inline-script/eval exception.
    await page.route('http://127.0.0.1:5174/',async route=>{
      const response=await route.fetch();
      await route.fulfill({response,headers:{...response.headers(),'content-security-policy':"script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'"}});
    });
    let release;
    const gate=new Promise(resolve=>release=resolve);
    let requested;
    const arrived=new Promise(resolve=>requested=resolve);
    await page.route(/\/assets\/index\.[^/]+\.js$/,async route=>{requested();await gate;await route.continue();});
    await page.goto('/',{waitUntil:'commit'}); await arrived;
    try {
      await expect(page.locator('#app')).toBeEmpty();
      await expect(page.locator('html')).toHaveAttribute('data-theme',scenario.expected);
      const color=scenario.expected==='dark'?'rgb(16, 24, 38)':'rgb(245, 248, 254)';
      await expect.poll(()=>page.evaluate(()=>getComputedStyle(document.documentElement).backgroundColor)).toBe(color);
      const frames=await page.evaluate(async()=>{
        const samples=[];
        for(let i=0;i<3;i++)samples.push(await new Promise(resolve=>requestAnimationFrame(()=>resolve({theme:document.documentElement.dataset.theme,color:getComputedStyle(document.documentElement).backgroundColor}))));
        return samples;
      });
      expect(frames).toEqual(Array(3).fill({theme:scenario.expected,color}));
      // Force a compositor frame while the Svelte bundle is still withheld.
      await page.screenshot();
      expect(await page.evaluate(()=>window.themeListeners)).toBe(1);
      if(scenario.preference!=='blocked')expect(await page.evaluate(()=>window.preferenceReads)).toEqual(['theme']);
    } finally { release(); }
    await expect(page.getByRole('heading',{name:'Ваши пароли. Только у вас.',exact:true})).toBeVisible();
    expect(await page.evaluate(()=>window.themeListeners)).toBe(1); // Head/App reuse, no duplicate owner.
    await expect(page.locator('html')).toHaveAttribute('data-theme',scenario.expected);
    let persistedTheme=scenario.expected;
    if(scenario.preference==='system') {
      await page.emulateMedia({colorScheme:scenario.system==='dark'?'light':'dark'});
      persistedTheme=scenario.expected==='dark'?'light':'dark';
      await expect(page.locator('html')).toHaveAttribute('data-theme',persistedTheme);
    }
    await page.reload();
    await expect(page.getByRole('button',{name:'Разблокировать',exact:true})).toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('data-theme',persistedTheme);
    expect(errors).toEqual([]);
  });
}

test('system listener is removed on actual App destroy and re-created once on remount',async({page})=>{
  await page.addInitScript(()=>{
    localStorage.setItem('theme','system');window.listeners=0;
    const original=window.matchMedia.bind(window);
    window.matchMedia=q=>{
      const media=original(q),add=media.addEventListener.bind(media),remove=media.removeEventListener.bind(media);
      media.addEventListener=(...args)=>{window.listeners++;return add(...args);};
      media.removeEventListener=(...args)=>{window.listeners--;return remove(...args);};
      return media;
    };
  });
  await installBridge(page);
  await page.goto('http://127.0.0.1:5173/');
  await expect.poll(()=>page.evaluate(()=>window.listeners)).toBe(1);
  await page.evaluate(async()=>{const {default:app}=await import('/src/main.js');app.$destroy();});
  expect(await page.evaluate(()=>window.listeners)).toBe(0);
  await page.evaluate(async()=>{const {default:App}=await import('/src/App.svelte');window.remount=new App({target:document.getElementById('app')});});
  await expect.poll(()=>page.evaluate(()=>window.listeners)).toBe(1);
  await page.evaluate(()=>window.remount.$destroy());
  expect(await page.evaluate(()=>window.listeners)).toBe(0);
});
