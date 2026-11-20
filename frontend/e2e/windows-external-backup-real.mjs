import { spawn, execFile, execFileSync } from 'node:child_process';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { appendFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium, expect as playwrightExpect } from '@playwright/test';

const expect = playwrightExpect.configure({ timeout: 20_000 });
const run = promisify(execFile);
const secrets = new Set();
let phase = 'initializing';
const saveTitle = 'Экспорт зашифрованной копии PasswordSaver';
const openTitle = 'Выберите зашифрованную копию PasswordSaver v2';
const primaryName = 'vault_data.v2.enc';
const backupName = primaryName + '.bak';
const selectorName = 'vault_format.state';
const archivedTitle = 'Synthetic original record';
const laterTitle = 'Synthetic later record';

function powershell(command) {
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], {
    encoding: 'utf8', timeout: 10_000, windowsHide: true,
  }).trim();
}

async function report(message) {
  console.log('::notice title=Native external backup verification::' + message);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, message + '\n\n');
  }
}

// The test binds Chromium DevTools on loopback for the disposable child only.
async function availablePort() {
  const server = createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  await new Promise((done, fail) => server.close(error => error ? fail(error) : done()));
  return port;
}

async function waitForWebView(child, url) {
  const deadline = Date.now() + 25_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error('PasswordSaver exited before its WebView2 window opened');
    }
    try {
      const response = await fetch(url + '/json/version', { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch {
      // WebView2 starts asynchronously with the Windows process.
    }
    await delay(250);
  }
  throw new Error('WebView2 did not expose its loopback test endpoint');
}

async function withApp(exe, profile, test) {
  const port = await availablePort();
  const url = 'http://127.0.0.1:' + port;
  const localAppData = join(profile, 'Local');
  const child = spawn(exe, [], {
    cwd: profile,
    stdio: 'ignore',
    env: {
      ...process.env,
      LOCALAPPDATA: localAppData,
      APPDATA: join(profile, 'Roaming'),
      WEBVIEW2_USER_DATA_FOLDER: join(profile, 'WebView2'),
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: '--remote-debugging-address=127.0.0.1 --remote-debugging-port=' + port,
    },
  });
  const exit = new Promise(done => child.once('exit', done));
  let browser;
  try {
    await once(child, 'spawn');
    await waitForWebView(child, url);
    browser = await chromium.connectOverCDP(url, { timeout: 10_000 });
    await expect.poll(() => browser.contexts().flatMap(context => context.pages()).length).toBeGreaterThan(0);
    const page = browser.contexts().flatMap(context => context.pages())[0];
    page.setDefaultTimeout(20_000);
    await expect.poll(() => Number(powershell(
      '(Get-Process -Id ' + child.pid + ' -ErrorAction SilentlyContinue).MainWindowHandle'
    ))).toBeGreaterThan(0);
    await page.getByRole('heading', { name: 'Ваши пароли. Только у вас.', exact: true }).waitFor();
    const storage = await page.evaluate(() => window.go.main.App.GetStorageLocationStatus());
    const expectedStorage = join(localAppData, 'PasswordSaver', 'vaults', 'default');
    expect(resolve(storage.path).toLowerCase()).toBe(expectedStorage.toLowerCase());
    await report('Opened native PasswordSaver HWND and real WebView2 with isolated LOCALAPPDATA.');
    await test(page, expectedStorage, child.pid);

    await page.evaluate(() => window.runtime.Quit()).catch(() => {});
    const exited = await Promise.race([exit.then(() => true), delay(7500, false)]);
    if (!exited || child.exitCode !== 0) throw new Error('PasswordSaver did not exit cleanly');
  } finally {
    if (child.pid && child.exitCode === null && child.signalCode === null) {
      child.kill();
      await Promise.race([exit, delay(5000)]);
    }
    await browser?.close().catch(() => {});
  }
}

async function fileDialog(appProcessId, title, action, path = '') {
  const args = [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', resolve('.github', 'verification', 'native-file-dialog.ps1'),
    '-AppProcessId', String(appProcessId), '-Title', title, '-Action', action,
    '-ButtonName', title === saveTitle ? 'Save' : 'Open',
  ];
  if (path) args.push('-FilePath', path);
  const result = await run('powershell.exe', args, { timeout: 28_000, encoding: 'utf8', windowsHide: true });
  if (result.stdout.includes('Native overwrite prompt acknowledged')) {
    await report('Windows UI Automation acknowledged the actual overwrite prompt.');
  }
  if (!result.stdout.includes('Native file dialog')) throw new Error('No native file-dialog observation');
}

function secret(value) {
  secrets.add(value);
  return value;
}

function otpValue(base32, secondsOffset = 0) {
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const symbol of base32.toUpperCase().replace(/=+$/, '')) {
    const n = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(symbol);
    if (n < 0) throw new Error('Invalid generated TOTP data');
    value = (value << 5) | n;
    bits += 5;
    if (bits >= 8) bytes.push((value >>> (bits -= 8)) & 255);
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor((Date.now() / 1000 + secondsOffset) / 30)));
  const key = Buffer.from(bytes);
  const digest = createHmac('sha1', key).update(counter).digest();
  key.fill(0);
  bytes.fill(0);
  const binary = digest.readUInt32BE(digest[digest.length - 1] & 15) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, '0');
}

async function enableTOTP(page) {
  await page.getByRole('navigation').getByRole('button', { name: 'Безопасность', exact: true }).click();
  await page.getByRole('button', { name: 'Настроить TOTP', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Настройка TOTP', exact: true });
  const authenticator = secret((await dialog.locator('.secret-code').textContent()).trim());
  await dialog.getByLabel('Код подтверждения').fill(secret(otpValue(authenticator)));
  await dialog.getByRole('button', { name: 'Включить TOTP', exact: true }).click();
  const success = page.getByRole('dialog', { name: 'Успешно', exact: true });
  await success.getByRole('button', { name: 'Понятно', exact: true }).click();
  return authenticator;
}

async function addRecord(page, title) {
  await page.getByRole('navigation').getByRole('button', { name: 'Мои пароли', exact: true }).click();
  await page.getByRole('button', { name: 'Добавить', exact: true }).click();
  const editor = page.getByRole('dialog', { name: 'Добавить пароль', exact: true });
  await editor.getByLabel('Название', { exact: true }).fill(title);
  await editor.getByLabel('Логин', { exact: true }).fill('synthetic@example.invalid');
  await editor.locator('input[autocomplete="new-password"]').fill(secret(randomBytes(16).toString('hex')));
  await editor.getByRole('button', { name: 'Сохранить запись', exact: true }).click();
  await expect(page.getByText(title, { exact: true })).toBeVisible();
}

const hash = buffer => createHash('sha256').update(buffer).digest('hex');

async function snapshot(storage) {
  const result = {};
  for (const name of (await readdir(storage)).sort()) {
    result[name] = hash(await readFile(join(storage, name)));
  }
  return result;
}

async function login(page, password, authenticator) {
  await page.getByLabel('Мастер-пароль', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Разблокировать', exact: true }).click();
  const code = page.getByLabel('Код TOTP', { exact: true });
  if (authenticator) {
    await expect(code).toBeVisible();
    await expect(page.locator('.app-shell')).toHaveCount(0);
    await code.fill(secret(otpValue(authenticator)));
    await page.getByRole('button', { name: 'Подтвердить код', exact: true }).click();
  }
  await page.getByRole('heading', { name: 'Мои пароли', exact: true }).waitFor();
  await expect(code).toHaveCount(0);
  await expect(page.getByText(archivedTitle, { exact: true })).toBeVisible();
  await expect(page.getByText(laterTitle, { exact: true })).toHaveCount(0);
}

async function exerciseBackup(page, storage, appProcessId, options) {
  const { password, externalFolder, withTOTP } = options;
  const tag = withTOTP ? 'TOTP enabled' : 'TOTP disabled';
  const stage = name => phase = tag + ' / ' + name;
  stage('create vault');
  await page.getByLabel('Создать отдельное пустое хранилище; перенос сейчас не требуется').check();
  await page.getByLabel('Новый мастер-пароль', { exact: true }).fill(password);
  await page.getByLabel('Повторите мастер-пароль', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Создать хранилище v2', exact: true }).click();
  await page.getByRole('heading', { name: 'Мои пароли', exact: true }).waitFor();
  await addRecord(page, archivedTitle);
  if (withTOTP) options.authenticator = await enableTOTP(page);
  await page.getByRole('navigation').getByRole('button', { name: 'Хранилища', exact: true }).click();

  const exportButton = page.getByRole('button', { name: 'Экспортировать зашифрованную копию', exact: true });
  const externalPath = join(externalFolder, 'external.v2.enc');
  const existingPath = join(externalFolder, 'do-not-replace.v2.enc');
  const beforeExport = await snapshot(storage);
  stage('cancel native save');
  await exportButton.click();
  await fileDialog(appProcessId, saveTitle, 'cancel');
  await expect(exportButton).toBeEnabled();
  expect(await readdir(externalFolder)).toEqual([]);
  expect(await snapshot(storage)).toEqual(beforeExport);

  stage('export through native save');
  await exportButton.click();
  await fileDialog(appProcessId, saveTitle, 'select', externalPath);
  await expect(page.getByRole('status')).toHaveText('Зашифрованная копия сохранена и проверена.');
  expect(hash(await readFile(externalPath))).toBe(beforeExport[primaryName]);

  stage('refuse native overwrite');
  const sentinel = Buffer.from('Original synthetic file to keep.');
  await writeFile(existingPath, sentinel, { flag: 'wx' });
  await exportButton.click();
  await fileDialog(appProcessId, saveTitle, 'overwrite', existingPath);
  await expect(page.getByRole('status')).toContainText('существующая копия не перезаписывается');
  expect((await readFile(existingPath)).equals(sentinel)).toBe(true);
  expect(await snapshot(storage)).toEqual(beforeExport);
  await report(tag + ': native Save dialog cancellation, export outside the vault, and refusal to overwrite verified.');

  stage('add later record and lock');
  await addRecord(page, laterTitle);
  const beforeRestore = await snapshot(storage);
  const beforeSource = hash(await readFile(externalPath));
  expect(beforeRestore[primaryName]).not.toBe(beforeSource);
  await page.getByRole('button', { name: 'Заблокировать', exact: true }).click();

  const openRestore = page.getByRole('button', { name: 'Восстановить из внешней зашифрованной копии v2', exact: true });
  const dialog = page.getByRole('dialog', { name: 'Восстановить из внешней копии v2', exact: true });
  const choose = dialog.getByRole('button', { name: 'Выбрать файл', exact: true });
  const passwordField = dialog.getByLabel('Мастер-пароль копии', { exact: true });
  const codeField = dialog.getByLabel('Код TOTP копии, если он был включён');
  const prepare = dialog.getByRole('button', { name: 'Проверить копию', exact: true });
  const confirm = dialog.getByRole('button', { name: 'Подтвердить восстановление', exact: true });

  async function selectAndCheck(value, code = '') {
    await choose.click();
    await fileDialog(appProcessId, openTitle, 'select', externalPath);
    await expect(dialog).toContainText('external.v2.enc');
    await passwordField.fill(value);
    await codeField.fill(code);
    await prepare.click();
  }

  stage('cancel native open');
  await openRestore.click();
  await choose.click();
  await fileDialog(appProcessId, openTitle, 'cancel');
  await expect(choose).toBeEnabled();
  await expect(passwordField).toHaveCount(0);
  expect(await snapshot(storage)).toEqual(beforeRestore);

  stage('reject wrong restore password');
  await selectAndCheck(secret(randomBytes(16).toString('hex')));
  await expect(dialog.getByRole('alert')).toContainText('Мастер-пароль неверен');
  await expect(confirm).toHaveCount(0);
  expect(await snapshot(storage)).toEqual(beforeRestore);

  if (withTOTP) {
    stage('reject wrong restore TOTP');
    const valid = [-60, -30, 0, 30, 60].map(offset => otpValue(options.authenticator, offset));
    const wrong = ['100000', '200000', '300000', '400000', '500000', '600000'].find(candidate => !valid.includes(candidate));
    await selectAndCheck(password, secret(wrong));
    await expect(dialog.getByRole('alert')).toContainText('Неверный код двухфакторной аутентификации');
    await expect(confirm).toHaveCount(0);
    expect(await snapshot(storage)).toEqual(beforeRestore);
  }
  await report(tag + ': native Open dialog cancellation and credential rejection left all vault files unchanged.');

  async function preview() {
    const code = options.authenticator ? secret(otpValue(options.authenticator)) : '';
    await selectAndCheck(password, code);
    await expect(confirm).toBeEnabled();
    await expect(dialog).toContainText('Записей: 1');
    await expect(dialog).toContainText(withTOTP ? 'TOTP: включён' : 'TOTP: выключен');
    await expect(passwordField).toHaveCount(0);
    expect(await snapshot(storage)).toEqual(beforeRestore);
  }

  stage('preview and cancel restore');
  await preview();
  await dialog.getByRole('button', { name: 'Не восстанавливать', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(await snapshot(storage)).toEqual(beforeRestore);

  stage('confirm restore and verify archive bytes');
  await openRestore.click();
  await preview();
  await confirm.click();
  await expect(page.getByText('Зашифрованная копия восстановлена. Войдите с её мастер-паролем.')).toBeVisible();
  await expect(page.locator('.app-shell')).toHaveCount(0);
  const restored = await snapshot(storage);
  expect(restored[primaryName]).toBe(beforeSource);
  expect(restored[backupName]).toBe(beforeSource);
  expect(restored[selectorName]).toBe(beforeRestore[selectorName]);
  for (const file of [primaryName, backupName]) {
    const archives = Object.keys(restored).filter(name => name.startsWith(file + '.pre-restore-'));
    expect(archives).toHaveLength(1);
    expect(restored[archives[0]]).toBe(beforeRestore[file]);
  }
  expect(hash(await readFile(externalPath))).toBe(beforeSource);
  await report(tag + ': preview and cancellation preserved files; confirmation restored both encrypted containers and preserved both prior archives byte-for-byte.');
  stage('new login after restore');
  await login(page, password, options.authenticator);
  await report(tag + ': GUI reopened the original record after new login, and the later record was absent.');
}

async function main() {
  if (process.platform !== 'win32') throw new Error('The native verification requires Windows');
  if (powershell('((Get-Process -Id $PID).SessionId -gt 0) -and [Environment]::UserInteractive') !== 'True') {
    throw new Error('The hosted runner has no interactive Windows session');
  }
  const exe = process.env.PASSWORDSAVER_TEST_EXE;
  if (!exe) throw new Error('The CI-verified EXE path was not provided');
  for (const withTOTP of [false, true]) {
    const profile = await mkdtemp(join(process.env.RUNNER_TEMP || tmpdir(), 'passwordsaver-native-backup-'));
    try {
      for (const name of ['Local', 'Roaming', 'WebView2', 'external']) await mkdir(join(profile, name));
      const options = {
        withTOTP, password: secret(randomBytes(20).toString('hex')),
        externalFolder: join(profile, 'external'),
      };
      await withApp(exe, profile, (page, storage, pid) => exerciseBackup(page, storage, pid, options));
      phase = (withTOTP ? 'TOTP enabled' : 'TOTP disabled') + ' / restart and login';
      await withApp(exe, profile, page => login(page, options.password, options.authenticator));
      await report((withTOTP ? 'TOTP enabled' : 'TOTP disabled') + ': after a clean EXE restart, GUI login reopened only the restored record.');
    } finally {
      await rm(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    }
  }
  await report('Both Windows GUI scenarios passed with independent synthetic profiles.');
}

try {
  await main();
} catch (error) {
  let firstLine = String(error?.message ?? error).trim().split('\n')[0];
  for (const value of secrets) firstLine = firstLine.split(value).join('[redacted]');
  console.error('::error title=Native external backup verification failed::' + phase + ': ' + firstLine);
  process.exitCode = 1;
}
