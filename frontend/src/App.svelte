<script>
  import { onMount } from 'svelte';
  import AppShell from './components/AppShell.svelte';
  import Icon from './components/Icon.svelte';
  import LoginView from './components/LoginView.svelte';
  import Modal from './components/Modal.svelte';
  import PasswordList from './components/PasswordList.svelte';
  import PasswordEditor from './components/PasswordEditor.svelte';
  import SearchAndFilters from './components/SearchAndFilters.svelte';
  import SecurityCenter from './components/SecurityCenter.svelte';
  import SecurityView from './components/SecurityView.svelte';
  import StorageView from './components/StorageView.svelte';
  import StorageStatusBar from './components/StorageStatusBar.svelte';
  import StorageDiagnostics from './components/StorageDiagnostics.svelte';
  import SettingsView from './components/SettingsView.svelte';
  import { validView, getThemeController, auditPasswords, filterAccounts } from './ui.js';
  import {
    Login, LoginV2, CreateV2Vault, GetVaultStatus, GetStorageLocationStatus, OpenStorageFolder, OpenLegacyStorageFolder,
    PrepareStorageLocationMigration, ConfirmStorageLocationMigration, CancelStorageLocationMigration,
    SelectLegacyStorageDirectory, PrepareSelectedStorageLocationMigration, CancelLegacyStorageSelection,
    PrepareV2Migration, ConfirmV2Migration, BeginCancelV2Preparation, ConfirmCancelV2Preparation,
    Logout, GetAccounts, AddAccount, DeleteAccount, ResetVault, UpdateAccount,
    BeginVaultReset, CancelVaultReset, PrepareVaultRecovery, ConfirmVaultRecovery, CancelVaultRecovery,
    PrepareV2VaultRecovery, ConfirmV2VaultRecovery, CancelV2VaultRecovery,
    Generate2FA, ConfirmAndEnable2FA, Verify2FA, SetIdleTimeout, TouchActivity, IsLocked, CheckInactivity
  } from '../wailsjs/go/main/App.js';
  import { createClipboardController, createGenerationGuard, resolveForGeneration, resolveCapabilityForGeneration, checkHIBPPasswords, IDLE_MINUTES, CLIPBOARD_SECONDS, validChoice, toggleSecretVisibility, loginModeForVaultStatus, canOfferV2BackupRecovery, friendlyBackendError } from './security.js';



  let isLoggedIn = false;
  let activeView = 'passwords';
  let editorOpen = false;
  let editorBusy = false;
  let authBusy = false;
  let totpEnabled = false;
  let riskFilter = 'all';
  let breachState = 'idle';
  let themeController = getThemeController();
  let theme = themeController.preference;
  let vaultStatus = { state: 'loading', v2ContainerPresent: false, v2BackupPresent: false, preparationFresh: false };
  let storageStatus = { state: 'loading', path: '', legacyPaths: [], format: '', algorithm: '', backupPresent: false, migrationPending: false };
  let loginFormat = 'v1';
  let setupMasterPassword = '';
  let setupConfirmPassword = '';
  let setupBusy = false;
  let confirmNewVault = false;
  let masterPassword = '';
  let errorMessage = '';
  let lockReason = '';
  let recoveryBusy = false;

  let accounts = [];

  let newTitle = '';
  let newLogin = '';
  let newPass = '';
  let visiblePasswordIDs = new Set();
  let selectedCategory = 'Общие';
  let editingId = null;

  let showAbout = false;

  let showMigrationModal = false;
  let migrationStage = 'reauth';
  let migrationPassword = '';
  let migrationTotp = '';
  let activationPassword = '';
  let activationTotp = '';
  let activationToken = '';
  let migrationBusy = false;
  let migrationError = '';

  let showStorageMigrationModal = false;
  let storageMigrationStage = 'verify';
  let storageMigrationPassword = '';
  let storageMigrationTotp = '';
  let storageMigrationToken = '';
  let storageSelectionToken = '';
  let storageMigrationSource = '';
  let storageMigrationTarget = '';
  let storageMigrationBusy = false;
  let storageMigrationError = '';

  // --- ЛОГИКА 2FA ---
  let show2FAInput = false;
  let twoFACode = '';

  let show2FASetupModal = false;
  let totpSecret = '';
  let totpQRCode = '';
  let setupCode = '';
  let idleMinutes = 1;
  let clipboardSeconds = 15;
  let clipboardController;
  let lockPoll;
  let lastActivitySent = 0;
  let componentAlive = true;
  const statusGeneration = createGenerationGuard();
  const sessionGeneration = createGenerationGuard();
  const breachGeneration = createGenerationGuard();
  const migrationGeneration = createGenerationGuard();
  const storageMigrationGeneration = createGenerationGuard();
  let breachController;

  // --- ЛОГИКА ТЕМЫ ---


  onMount(() => {
    refreshVaultStatus();
    // Storage can be unavailable even when merely accessing its getter.
    try {
      idleMinutes = validChoice(localStorage.getItem('idleLockMinutes'), IDLE_MINUTES, 1);
      clipboardSeconds = validChoice(localStorage.getItem('clipboardClearSeconds'), CLIPBOARD_SECONDS, 15);
    } catch { /* Keep safe in-memory defaults. */ }
    SetIdleTimeout(idleMinutes).catch(() => {});
    clipboardController = createClipboardController(navigator.clipboard, clipboardSeconds, () => {
      toastMessage = 'Не удалось получить доступ к буферу обмена';
    });
    themeController = getThemeController();
    theme = themeController.preference;
    return () => { componentAlive = false; statusGeneration.invalidate(); themeController.destroy(); };
  });

  function setTheme(value) { theme = themeController.set(value); }
  function navigate(view) { activeView = validView(view); }
  function showRisk(risk) { riskFilter = risk; activeFilter = 'Все'; searchQuery = ''; navigate('passwords'); }

  // Кастомные диалоговые окна
  let dialog = { show: false, type: 'alert', title: '', message: '', onConfirm: null, onCancel: null };

  function showAlert(title, message) { dialog = { show: true, type: 'alert', title, message, onConfirm: null, onCancel: null }; }
  function showConfirm(title, message, onConfirmCallback, onCancelCallback = null) { dialog = { show: true, type: 'confirm', title, message, onConfirm: onConfirmCallback, onCancel: onCancelCallback }; }
  function closeDialog() { const cancel = dialog.onCancel; dialog = { show:false }; if (cancel) cancel(); }
  function confirmDialog() { const confirm = dialog.onConfirm; dialog = { show:false }; if (confirm) confirm(); }

  let toastMessage = '';
  let searchQuery = '';
  let activeFilter = 'Все';
  $: audit = auditPasswords(accounts);
  $: weakCount = audit.weak;
  $: reusedCount = audit.reused;
  $: filteredAccounts = filterAccounts(accounts, searchQuery, activeFilter, riskFilter);

  let breachedCount = 0;

  function cancelBreachCheck() {
    breachGeneration.invalidate();
    breachController?.abort();
    breachController = null;
  }

  async function checkBreaches() {
    if (!isLoggedIn) return;
    cancelBreachCheck();
    const checkToken = breachGeneration.capture();
    const sessionToken = sessionGeneration.capture();
    const controller = new AbortController();
    breachController = controller;
    breachedCount = 0; breachState = 'checking';
    accounts = accounts.map(account => ({ ...account, isBreached: undefined }));
    try {
      const result = await checkHIBPPasswords(accounts, {
        signal: controller.signal,
        fetchImpl: fetch,
        digest: bytes => window.crypto.subtle.digest('SHA-1', bytes),
      });
      if (!breachGeneration.isCurrent(checkToken) || !sessionGeneration.isCurrent(sessionToken) || !isLoggedIn) return;
      const byID = new Map(result.results.map(item => [item.id, item.breached]));
      accounts = accounts.map(account => {
        if (byID.has(account.id)) account.isBreached = byID.get(account.id);
        return account;
      });
      breachedCount = result.results.filter(item => item.breached).length;
      breachState = result.failed ? (result.results.length ? 'partial' : 'error') : 'complete';
      toastMessage = result.failed ? 'Сетевая проверка утечек не завершена. SHA-1 префиксы отправляются в HIBP; открытые пароли не отправляются.' : 'Проверка выполнена через сеть HIBP (отправляется только SHA-1 префикс)';
      setTimeout(() => toastMessage = '', 4500);
    } catch (error) {
      if (error?.name !== 'AbortError' && breachGeneration.isCurrent(checkToken) && sessionGeneration.isCurrent(sessionToken) && isLoggedIn) {
        console.error(error);
        breachState = 'error';
        toastMessage = 'Не удалось проверить утечки через сеть HIBP';
        setTimeout(() => toastMessage = '', 4500);
      }
    } finally {
      if (breachGeneration.isCurrent(checkToken)) {
            breachController = null;
      }
    }
  }

  function handleActivity() {
    if (!isLoggedIn) return;
    const now = Date.now();
    if (now - lastActivitySent > 1000) { lastActivitySent = now; TouchActivity().catch(() => {}); }
  }

  function clearSensitiveState(reason = '') {
    sessionGeneration.invalidate();
    cancelBreachCheck();
    totpEnabled = false; editorOpen = false; editorBusy = false; authBusy = false; breachState = 'idle'; activeView = 'passwords'; riskFilter = 'all';
    isLoggedIn = false; accounts = []; masterPassword = ''; newPass = ''; twoFACode = '';
    setupCode = ''; totpSecret = ''; totpQRCode = ''; show2FASetupModal = false;
    show2FAInput = false; visiblePasswordIDs = new Set();
    showAbout = false; dialog = { show: false, type: 'alert', title: '', message: '', onConfirm: null, onCancel: null };
    closeMigrationModal(); migrationStage = 'reauth'; migrationPassword = ''; migrationTotp = '';
    activationPassword = ''; activationTotp = ''; activationToken = ''; migrationBusy = false; migrationError = '';
    closeStorageMigrationModal();
    recoveryBusy = false; confirmNewVault = false; setupMasterPassword = ''; setupConfirmPassword = '';
    cancelEdit(); searchQuery = ''; breachedCount = 0; activeFilter = 'Все';
    if (reason) lockReason = reason;
  }

  function setIdlePreference(value) {
    idleMinutes = validChoice(value, IDLE_MINUTES, 1);
    try { localStorage.setItem('idleLockMinutes', String(idleMinutes)); } catch { /* In-memory preference still applies. */ }
    SetIdleTimeout(idleMinutes).catch(() => { toastMessage = 'Не удалось применить тайм-аут блокировки'; });
  }
  function setClipboardPreference(value) {
    clipboardSeconds = validChoice(value, CLIPBOARD_SECONDS, 15);
    try { localStorage.setItem('clipboardClearSeconds', String(clipboardSeconds)); } catch { /* In-memory preference still applies. */ }
    clipboardController?.cancel();
    clipboardController = createClipboardController(navigator.clipboard, clipboardSeconds, () => { toastMessage = 'Не удалось получить доступ к буферу обмена'; });
  }

  onMount(() => {
    lockPoll = setInterval(async () => {
      if (!isLoggedIn) return;
      try { if (await IsLocked()) clearSensitiveState('Хранилище заблокировано по тайм-ауту'); }
      catch (error) { console.error(error); }
    }, 1000);
    const checkOnReturn = async () => {
      if (document.visibilityState !== 'visible' || !isLoggedIn) return;
      try { if (await CheckInactivity()) { clearSensitiveState('Хранилище заблокировано по тайм-ауту'); return; } }
      catch (error) { console.error(error); }
      handleActivity();
    };
    document.addEventListener('visibilitychange', checkOnReturn);
    window.addEventListener('focus', checkOnReturn);
    return () => { clearInterval(lockPoll); document.removeEventListener('visibilitychange', checkOnReturn); window.removeEventListener('focus', checkOnReturn); sessionGeneration.invalidate(); closeStorageMigrationModal(); cancelBreachCheck(); clipboardController?.cancel(); close2FASetup(); closeEditor(); };
  });

  function generatePassword(options) {
    const { length = 16, numbers = true, symbols = true } = options || {};
    let chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (numbers) chars += '0123456789';
    if (symbols) chars += '!@#$%^&*()_+-=?';
    const bytes = new Uint32Array(length); window.crypto.getRandomValues(bytes);
    newPass = Array.from(bytes, value => chars[value % chars.length]).join('');
  }

  async function copyData(text) {
    try {
      const ok = await clipboardController.copy(text);
      if (!ok) throw new Error('clipboard write denied');
      toastMessage = 'Скопировано!'; setTimeout(() => toastMessage = '', 2000);
    } catch (err) { console.error(err); }
  }

  // --- ОБНОВЛЕННЫЕ ФУНКЦИИ ВХОДА (2FA) ---
  async function handleCreateV2() {
    if (setupBusy || !confirmNewVault || storageMigrationBusy || showStorageMigrationModal || vaultStatus.state !== 'uninitialized') return;
    if (setupMasterPassword.length < 12) {
      errorMessage = 'Мастер-пароль должен содержать минимум 12 символов.';
      return;
    }
    if (setupMasterPassword !== setupConfirmPassword) {
      errorMessage = 'Мастер-пароли не совпадают.';
      return;
    }
    const generation = sessionGeneration.capture();
    setupBusy = true;
    const password = setupMasterPassword;
    setupMasterPassword = '';
    setupConfirmPassword = '';
    try {
      await CreateV2Vault(password);
      if (!sessionGeneration.isCurrent(generation)) return;
      errorMessage = '';
      await refreshVaultStatus();
      // Unlock through the ordinary v2 login flow; no v1 writes.
      if (!sessionGeneration.isCurrent(generation)) return;
      if (vaultStatus.state !== 'v2-active') throw new Error('v2 initialization status could not be confirmed');
      const requires2FA = await LoginV2(password);
      if (!sessionGeneration.isCurrent(generation)) return;
      totpEnabled = requires2FA;
      if (requires2FA) show2FAInput = true;
      else { sessionGeneration.advance(); setupBusy = false; isLoggedIn = true; lockReason = ''; loadAccounts(); }
    } catch (err) {
      if (sessionGeneration.isCurrent(generation)) { errorMessage = friendlyBackendError(err); await refreshVaultStatus(); }
    } finally {
      if (sessionGeneration.isCurrent(generation)) setupBusy = false;
    }
  }

  async function handleLogin() {
    if (authBusy) return;
    loginFormat = loginModeForVaultStatus(vaultStatus);
    if (!['v1', 'v2'].includes(loginFormat)) return;
    const generation = sessionGeneration.capture();
    const password = masterPassword;
    masterPassword = ''; authBusy = true;
    try {
      const requires2FA = loginFormat === 'v2' ? await LoginV2(password) : await Login(password);
      if (!sessionGeneration.isCurrent(generation)) return;
      totpEnabled = requires2FA;
      errorMessage = '';
      if (requires2FA) show2FAInput = true;
      else { sessionGeneration.advance(); isLoggedIn = true; lockReason = ''; authBusy = false; loadAccounts(); }
    } catch (err) {
      if (!sessionGeneration.isCurrent(generation)) return;
      if (loginFormat === 'v2') { errorMessage = friendlyBackendError(err); await refreshVaultStatus(); return; }
      try {
        const recoveryToken = await PrepareVaultRecovery(password);
        if (!sessionGeneration.isCurrent(generation)) { CancelVaultRecovery(recoveryToken).catch(() => {}); return; }
        showConfirm('Восстановить резервную копию?', 'Резервная копия проверена этим мастер-паролем. Повреждённый основной файл будет сохранён для диагностики. Настройки TOTP также восстановятся из копии.', async () => {
          if (!sessionGeneration.isCurrent(generation)) return;
          try {
            const requires2FA = await ConfirmVaultRecovery(recoveryToken);
            if (!sessionGeneration.isCurrent(generation)) return;
            totpEnabled = requires2FA; errorMessage = '';
            if (requires2FA) show2FAInput = true;
            else { sessionGeneration.advance(); isLoggedIn = true; loadAccounts(); }
          } catch (error) { if (sessionGeneration.isCurrent(generation)) errorMessage = friendlyBackendError(error); }
        }, () => CancelVaultRecovery(recoveryToken).catch(() => {}));
      } catch { if (sessionGeneration.isCurrent(generation)) errorMessage = friendlyBackendError(err); }
    } finally { if (sessionGeneration.isCurrent(generation)) authBusy = false; }
  }

  async function handleV2Recovery() {
    if (recoveryBusy) return;
    const generation = sessionGeneration.capture();
    const password = masterPassword;
    masterPassword = '';
    recoveryBusy = true;
    try {
      const token = await PrepareV2VaultRecovery(password);
      if (!sessionGeneration.isCurrent(generation) || isLoggedIn) {
        CancelV2VaultRecovery(token);
        return;
      }
      showConfirm(
        'Восстановить хранилище v2?',
        'Резервная копия проверена этим мастер-паролем. Текущее основное хранилище будет сохранено рядом для диагностики, затем его заменит копия. Изменения после создания копии могут быть потеряны. Настройки защиты тоже восстановятся из копии: если она создана до включения TOTP, после восстановления TOTP останется выключен. Полный доступ к локальным файлам позволяет подменить или откатить и хранилище, и селектор; приложение не может гарантировать защиту от такого отката. Селектор останется на v2; автоматического перехода на v1 не будет.',
        async () => {
          if (!sessionGeneration.isCurrent(generation)) return;
          try {
            const requires2FA = await ConfirmV2VaultRecovery(token);
            if (!sessionGeneration.isCurrent(generation)) return;
            errorMessage = '';
            totpEnabled = requires2FA;
      if (requires2FA) {
              show2FAInput = true;
            } else {
              sessionGeneration.advance();
              isLoggedIn = true;
              lockReason = '';
              loadAccounts();
            }
            await refreshVaultStatus();
          } catch (recoveryErr) {
            if (sessionGeneration.isCurrent(generation)) errorMessage = friendlyBackendError(recoveryErr);
          } finally {
            if (sessionGeneration.isCurrent(generation)) recoveryBusy = false;
          }
        },
        () => {
          CancelV2VaultRecovery(token);
          if (sessionGeneration.isCurrent(generation)) recoveryBusy = false;
        }
      );
    } catch (err) {
      if (sessionGeneration.isCurrent(generation)) errorMessage = friendlyBackendError(err);
      recoveryBusy = false;
    }
  }

  async function handleVerify2FA() {
    if (authBusy) return;
    const generation = sessionGeneration.capture();
    const code = twoFACode; twoFACode = ''; authBusy = true;
    try {
      await Verify2FA(code);
      if (!sessionGeneration.isCurrent(generation)) return;
      sessionGeneration.advance(); isLoggedIn = true; totpEnabled = true;
      show2FAInput = false; masterPassword = ''; errorMessage = ''; lockReason = ''; authBusy = false;
      loadAccounts();
    } catch (err) { if (sessionGeneration.isCurrent(generation)) { errorMessage = friendlyBackendError(err); masterPassword = ''; } }
    finally { if (sessionGeneration.isCurrent(generation)) authBusy = false; }
  }

  async function handleLogout(reason = '') {
    clearSensitiveState(reason);
    try { await Logout(); } catch (error) { console.error(error); }
    await refreshVaultStatus();
  }

  async function handleReset() {
    const generation = sessionGeneration.capture();
    try {
      const resetToken = await BeginVaultReset();
      if (!sessionGeneration.isCurrent(generation)) { CancelVaultReset(resetToken).catch(() => {}); return; }
      showConfirm("Сброс хранилища", "ВНИМАНИЕ! Это действие навсегда удалит все зашифрованные пароли и резервную копию.\nВы уверены?", async () => {
        try {
          await ResetVault(resetToken);
          clearSensitiveState(); errorMessage = ''; lockReason = '';
          showAlert("Успешно", "Ваше хранилище было полностью сброшено.");
        } catch (err) { errorMessage = friendlyBackendError(err); }
      }, () => CancelVaultReset(resetToken));
    } catch (err) { errorMessage = friendlyBackendError(err); }
  }

  async function loadAccounts() {
    const token = sessionGeneration.capture();
    try {
      await resolveForGeneration(GetAccounts(), sessionGeneration, token, result => {
        if (!isLoggedIn) return;
        cancelBreachCheck(); breachState = 'idle';
        accounts = result || []; breachedCount = 0;
      });
    } catch (err) {
      if (sessionGeneration.isCurrent(token) && isLoggedIn) await reportBackendFailure(err);
    }
  }

  async function reportBackendFailure(error) {
    const message = friendlyBackendError(error);
    try {
      if (await IsLocked()) {
        clearSensitiveState('Сессия закрыта. Войдите повторно.');
        errorMessage = message;
        return;
      }
    } catch (_) {}
    toastMessage = message;
    setTimeout(() => toastMessage = '', 4500);
  }

  async function handleSave() {
    if (!isLoggedIn || editorBusy) return;
    const generation = sessionGeneration.capture();
    if (!newTitle || !newLogin || !newPass) { showAlert("Внимание", "Заполните все поля перед сохранением."); return; }
    editorBusy = true;
    const combinedTitle = `${newTitle}|||${selectedCategory}`;
    try {
      if (editingId) { await UpdateAccount(editingId, combinedTitle, newLogin, newPass); }
      else { await AddAccount(combinedTitle, newLogin, newPass); }
      if (!sessionGeneration.isCurrent(generation) || !isLoggedIn) return;
      editorOpen = false; cancelEdit(); loadAccounts(); await refreshVaultStatus();
    } catch (err) { if (sessionGeneration.isCurrent(generation)) await reportBackendFailure(err); }
    finally { if (sessionGeneration.isCurrent(generation)) editorBusy = false; }
  }

  function startEdit(acc) {
    editingId = acc.id; const [title, category] = acc.title.split('|||');
    newTitle = title; newLogin = acc.login; newPass = acc.password; selectedCategory = category || 'Общие';

    editorOpen = true;
  }

  function addRecord() { cancelEdit(); editorOpen = true; }
  function closeEditor() { editorOpen = false; cancelEdit(); }

  function cancelEdit() { editingId = null; newTitle = ''; newLogin = ''; newPass = ''; selectedCategory = 'Общие'; }

  function togglePassword(id) {
    visiblePasswordIDs = toggleSecretVisibility(visiblePasswordIDs, id);
  }

  function close2FASetup() { show2FASetupModal = false; totpSecret = ''; totpQRCode = ''; setupCode = ''; }

  async function handleDelete(id) {
    const generation = sessionGeneration.capture();
    showConfirm("Удаление", "Удалить эту запись безвозвратно?", async () => {
      if (!sessionGeneration.isCurrent(generation) || !isLoggedIn) return;
      try { await DeleteAccount(id); if (!sessionGeneration.isCurrent(generation) || !isLoggedIn) return; if(editingId === id) cancelEdit(); loadAccounts(); } catch (err) { await reportBackendFailure(err); }
    });
  }

  // --- ФУНКЦИИ НАСТРОЙКИ 2FA ---
  async function open2FASetup() {
    const generation = sessionGeneration.capture();
    try {
      const setupData = await Generate2FA();
      if (!sessionGeneration.isCurrent(generation) || !isLoggedIn) return;
      totpSecret = setupData.secret;
      totpQRCode = setupData.qrCode;
      show2FASetupModal = true;
    } catch (err) { if (sessionGeneration.isCurrent(generation) && isLoggedIn) showAlert('Ошибка', friendlyBackendError(err)); }
  }

  async function handleConfirm2FA() {
    const generation = sessionGeneration.capture();
    try {
      await ConfirmAndEnable2FA(totpSecret, setupCode);
      if (!sessionGeneration.isCurrent(generation) || !isLoggedIn) return;
      totpEnabled = true;
      showAlert("Успешно", "Двухфакторная аутентификация успешно включена!");
      show2FASetupModal = false;
      close2FASetup();
      loadAccounts();
    } catch (err) { if (sessionGeneration.isCurrent(generation) && isLoggedIn) showAlert('Ошибка', friendlyBackendError(err)); }
  }

  async function refreshVaultStatus() {
    if (!componentAlive) return;
    const request = statusGeneration.advance();
    const session = sessionGeneration.capture();
    const [storage, vault] = await Promise.allSettled([
      Promise.resolve().then(GetStorageLocationStatus),
      Promise.resolve().then(GetVaultStatus),
    ]);
    // Public metadata still needs ordering/lifetime guards: an older snapshot
    // must not replace a newer reconciliation or cross an authentication epoch.
    if (!componentAlive || !statusGeneration.isCurrent(request) || !sessionGeneration.isCurrent(session)) return;
    storageStatus = storage.status === 'fulfilled' ? storage.value : { state:'error', path:'', legacyPaths:[] };
    vaultStatus = vault.status === 'fulfilled' ? vault.value : { state:'ambiguous', v2ContainerPresent:false, v2BackupPresent:false, preparationFresh:false };
  }

  function openStorageMigrationModal() {
    closeStorageMigrationModal();
    storageMigrationSource = storageStatus.legacyPaths?.[0] || '';
    storageMigrationTarget = storageStatus.path;
    showStorageMigrationModal = true;
  }

  async function selectExistingStorage() {
    if (storageMigrationBusy || show2FAInput || setupBusy) return;
    closeStorageMigrationModal();
    confirmNewVault = false; setupMasterPassword = ''; setupConfirmPassword = '';
    const generation = storageMigrationGeneration.capture();
    storageMigrationBusy = true; errorMessage = '';
    try {
      await resolveCapabilityForGeneration(SelectLegacyStorageDirectory(), storageMigrationGeneration, generation,
        result => result.token ? CancelLegacyStorageSelection(result.token) : Promise.resolve(),
        result => {
          if (!result.token) return; // native dialog cancellation
          storageSelectionToken = result.token;
          storageMigrationSource = result.path;
          storageMigrationTarget = result.targetPath;
          showStorageMigrationModal = true;
        });
    } catch (error) {
      if (storageMigrationGeneration.isCurrent(generation)) errorMessage = friendlyBackendError(error);
    } finally {
      if (storageMigrationGeneration.isCurrent(generation)) storageMigrationBusy = false;
    }
  }

  async function prepareStorageLocationMigration() {
    if (storageMigrationBusy || !storageMigrationPassword) return;
    const generation = storageMigrationGeneration.capture();
    storageMigrationBusy = true; storageMigrationError = '';
    const password = storageMigrationPassword;
    const code = storageMigrationTotp;
    storageMigrationPassword = ''; storageMigrationTotp = '';
    try {
      const request = storageSelectionToken
        ? PrepareSelectedStorageLocationMigration(storageSelectionToken, password, code)
        : PrepareStorageLocationMigration(password, code);
      await resolveCapabilityForGeneration(request, storageMigrationGeneration, generation,
        token => CancelStorageLocationMigration(token),
        token => {
          storageSelectionToken = ''; // consumed by backend after authentication
          storageMigrationToken = token;
          storageMigrationStage = 'confirm';
        });
    } catch (error) {
      if (storageMigrationGeneration.isCurrent(generation)) storageMigrationError = friendlyBackendError(error);
    } finally {
      if (storageMigrationGeneration.isCurrent(generation)) storageMigrationBusy = false;
    }
  }

  async function confirmStorageLocationMigration() {
    if (storageMigrationBusy || !storageMigrationToken) return;
    const generation = storageMigrationGeneration.capture();
    const token = storageMigrationToken;
    storageMigrationBusy = true; storageMigrationError = '';
    try {
      await ConfirmStorageLocationMigration(token);
      if (!storageMigrationGeneration.isCurrent(generation)) return;
      storageMigrationToken = '';
      closeStorageMigrationModal();
      await refreshVaultStatus();
    } catch (error) {
      if (storageMigrationGeneration.isCurrent(generation)) {
        storageMigrationError = friendlyBackendError(error);
        await refreshVaultStatus();
      }
    } finally {
      if (storageMigrationGeneration.isCurrent(generation)) storageMigrationBusy = false;
    }
  }

  function closeStorageMigrationModal() {
    storageMigrationGeneration.invalidate();
    if (storageMigrationToken) CancelStorageLocationMigration(storageMigrationToken).catch(() => {});
    if (storageSelectionToken) CancelLegacyStorageSelection(storageSelectionToken).catch(() => {});
    storageSelectionToken = ''; storageMigrationSource = ''; storageMigrationTarget = '';
    showStorageMigrationModal = false; storageMigrationStage = 'verify';
    storageMigrationPassword = ''; storageMigrationTotp = ''; storageMigrationToken = '';
    storageMigrationBusy = false; storageMigrationError = '';
  }

  async function openVaultFolder(legacy = false) {
    try {
      if (legacy) await OpenLegacyStorageFolder();
      else await OpenStorageFolder();
    } catch (error) {
      toastMessage = 'Не удалось открыть папку хранилища';
      setTimeout(() => toastMessage = '', 3500);
    }
  }

  function openMigrationModal() {
    closeMigrationModal();
    migrationStage = 'reauth'; migrationPassword = ''; migrationTotp = '';
    activationPassword = ''; activationTotp = ''; activationToken = ''; migrationError = '';
    showMigrationModal = true;
  }

  async function prepareV2Migration() {
    if (migrationBusy) return;
    const modalToken = migrationGeneration.capture();
    const sessionToken = sessionGeneration.capture();
    migrationBusy = true; migrationError = '';
    const password = migrationPassword;
    const code = migrationTotp;
    migrationPassword = ''; migrationTotp = '';
    try {
      const token = await PrepareV2Migration(password, code);
      if (!componentAlive || !sessionGeneration.isCurrent(sessionToken) || !migrationGeneration.isCurrent(modalToken) || !isLoggedIn) return;
      activationToken = token;
      migrationStage = 'activate';
    } catch (error) {
      if (componentAlive && sessionGeneration.isCurrent(sessionToken) && migrationGeneration.isCurrent(modalToken) && isLoggedIn) migrationError = friendlyBackendError(error);
    } finally {
      if (sessionGeneration.isCurrent(sessionToken) && migrationGeneration.isCurrent(modalToken)) migrationBusy = false;
      // Preparing can durably change the selector even if the dialog closed
      // or the call failed/expired. Read CURRENT public metadata in a fresh
      // request, independently of the discarded token/password and old epoch.
      // This never reopens the modal or restores authorization; unmount is a no-op.
      await refreshVaultStatus();
    }
  }

  async function confirmV2Migration() {
    if (migrationBusy || !activationToken) return;
    const modalToken = migrationGeneration.capture();
    const sessionToken = sessionGeneration.capture();
    migrationBusy = true; migrationError = '';
    const password = activationPassword;
    const code = activationTotp;
    activationPassword = ''; activationTotp = '';
    try {
      await ConfirmV2Migration(activationToken, password, code);
      if (!sessionGeneration.isCurrent(sessionToken) || !migrationGeneration.isCurrent(modalToken) || !isLoggedIn) return;
      activationToken = '';
      showMigrationModal = false;
      clearSensitiveState('Хранилище обновлено до v2. Войдите повторно.');
      await refreshVaultStatus();
    } catch (error) {
      if (!sessionGeneration.isCurrent(sessionToken) || !migrationGeneration.isCurrent(modalToken) || !isLoggedIn) return;
      const message = friendlyBackendError(error);
      migrationError = message;
      activationToken = '';
      try {
        if (await IsLocked()) {
          if (!sessionGeneration.isCurrent(sessionToken)) return;
          clearSensitiveState('');
          errorMessage = message;
        }
      } catch (_) {}
      if (sessionGeneration.isCurrent(sessionToken)) await refreshVaultStatus();
    } finally {
      if (sessionGeneration.isCurrent(sessionToken) && migrationGeneration.isCurrent(modalToken)) migrationBusy = false;
    }
  }

  async function beginCancelV2Preparation() {
    if (migrationBusy) return;
    const modalToken = migrationGeneration.capture();
    const sessionToken = sessionGeneration.capture();
    migrationBusy = true; migrationError = '';
    try {
      const token = await BeginCancelV2Preparation();
      if (!sessionGeneration.isCurrent(sessionToken) || !migrationGeneration.isCurrent(modalToken)) return;
      activationToken = token;
      migrationStage = 'cancel';
      showMigrationModal = true;
    } catch (error) { if (sessionGeneration.isCurrent(sessionToken) && migrationGeneration.isCurrent(modalToken)) migrationError = friendlyBackendError(error); }
    finally { if (sessionGeneration.isCurrent(sessionToken) && migrationGeneration.isCurrent(modalToken)) migrationBusy = false; }
  }

  async function confirmCancelV2Preparation() {
    if (migrationBusy || !activationToken) return;
    const modalToken = migrationGeneration.capture();
    const sessionToken = sessionGeneration.capture();
    migrationBusy = true; migrationError = '';
    try {
      await ConfirmCancelV2Preparation(activationToken);
      if (!sessionGeneration.isCurrent(sessionToken) || !migrationGeneration.isCurrent(modalToken)) return;
      activationToken = ''; showMigrationModal = false; migrationStage = 'reauth';
      await refreshVaultStatus();
      toastMessage = 'Подготовка отменена. Исходные файлы сохранены.';
      setTimeout(() => toastMessage = '', 3000);
    } catch (error) { if (sessionGeneration.isCurrent(sessionToken) && migrationGeneration.isCurrent(modalToken)) { migrationError = friendlyBackendError(error); await refreshVaultStatus(); } }
    finally { if (sessionGeneration.isCurrent(sessionToken) && migrationGeneration.isCurrent(modalToken)) migrationBusy = false; }
  }

  function closeMigrationModal() {
    migrationGeneration.invalidate(); migrationBusy = false;
    showMigrationModal = false; migrationPassword = ''; migrationTotp = '';
    activationPassword = ''; activationTotp = ''; activationToken = ''; migrationError = '';
  }
</script>

<svelte:window on:mousemove={handleActivity} on:keydown={handleActivity} on:click={handleActivity} on:touchstart={handleActivity} on:wheel={handleActivity}/>
{#if toastMessage}<div class="toast" role="status">{toastMessage}</div>{/if}
{#if !isLoggedIn}
  <LoginView {theme} on:change={e => setTheme(e.detail)}>
    <StorageDiagnostics status={storageStatus} on:click={() => openVaultFolder(false)}/>
      {#if lockReason}
        <p class="lock-warning">{lockReason}</p>
      {/if}

      {#if storageStatus.state === 'loading'}
        <p class="subtitle">Проверка состояния хранилища…</p>
      {:else if storageStatus.state === 'migration-required'}
        <div class="storage-route-panel">
          <p class="warning-text">Найдено старое зашифрованное хранилище. Перед переносом потребуется проверить мастер-пароль и код TOTP, если он включён. Копия будет проверена по байтам; исходные файлы останутся на месте.</p>
          <p><strong>Старое расположение:</strong><br><code>{storageStatus.legacyPaths?.[0]}</code></p>
          <p><strong>Новое расположение:</strong><br><code>{storageStatus.path}</code></p>
          <p>Формат: {storageStatus.format || 'не определён'}; резервная копия: {storageStatus.backupPresent ? 'есть' : 'нет'}.</p>
          <button class="btn-primary" on:click={openStorageMigrationModal}>Проверить и перенести зашифрованное хранилище</button>
          <button class="btn-secondary" on:click={() => openVaultFolder(true)}>Открыть старую папку</button>
        </div>
      {:else if storageStatus.state === 'conflict'}
        <div class="storage-route-panel">
          <p class="error">Найдены файлы хранилища в нескольких расположениях. PasswordSaver ничего не выбрал и не перезаписал. Разрешите конфликт вручную, сохранив обе копии.</p>
          <p><strong>AppData:</strong><br><code>{storageStatus.path}</code></p>
          {#each storageStatus.legacyPaths || [] as path}<p><strong>Старое расположение:</strong><br><code>{path}</code></p>{/each}
          <button class="btn-secondary" on:click={() => openVaultFolder(false)}>Открыть папку AppData</button>
          {#if storageStatus.legacyPaths?.length}<button class="btn-secondary" on:click={() => openVaultFolder(true)}>Открыть старую папку</button>{/if}
        </div>
      {:else if storageStatus.state === 'incomplete-write'}
        <p class="error">Незавершённая запись требует проверки файлов. Временные файлы автоматически не открываются и не заменяют хранилище.</p>
      {:else if storageStatus.state === 'error'}
        <p class="error">Не удалось безопасно проверить каталог хранилища. Вход и создание отключены до устранения ошибки доступа или файловой системы.</p>
      {:else if vaultStatus.state === 'uninitialized'}
        <p class="subtitle">Создайте новое хранилище v2 (AES-256-GCM).</p>
      {:else if vaultStatus.state === 'ambiguous'}
        <p class="error">Состояние формата хранилища неоднозначно или повреждено. Автоматический переход между форматами отключён.</p>
      {:else if vaultStatus.state === 'v2-active' && !vaultStatus.v2ContainerPresent}
        <p class="error">Активный контейнер v2 отсутствует. Вход в v1 не предлагается.</p>
      {:else}
        <p class="subtitle">Активное хранилище: {vaultStatus.state === 'v2-active' ? 'v2' : vaultStatus.state === 'v1-prepared' ? 'v1 (v2 подготовлен)' : 'v1'}</p>
      {/if}

      {#if !show2FAInput && storageStatus.state !== 'loading'}
        <button class="btn-secondary" disabled={storageMigrationBusy || setupBusy || showStorageMigrationModal} on:click={selectExistingStorage}>Не нашли своё хранилище? Указать расположение вручную</button>
      {/if}

      {#if storageStatus.state === 'ready' && vaultStatus.state === 'uninitialized'}
        <p class="warning-text">Ранее использовали PasswordSaver? Сначала укажите папку старого хранилища, включая рабочую папку ярлыка версии 2.0.0. Она не выбирается автоматически.</p>
        <label class="check-container"><input type="checkbox" bind:checked={confirmNewVault} />Создать отдельное пустое хранилище; перенос сейчас не требуется</label>
        <div class="input-group">
          <input type="password" bind:value={setupMasterPassword} aria-label="Новый мастер-пароль" placeholder="Новый мастер-пароль (от 12 символов)" autocomplete="new-password" />
          <input type="password" bind:value={setupConfirmPassword} aria-label="Повторите мастер-пароль" placeholder="Повторите мастер-пароль" autocomplete="new-password" on:keydown={(e) => e.key === 'Enter' && handleCreateV2()} />
          <button class="btn-primary" disabled={setupBusy || !confirmNewVault || storageMigrationBusy || showStorageMigrationModal || !setupMasterPassword || !setupConfirmPassword} on:click={handleCreateV2}>{setupBusy ? 'Создание хранилища…' : 'Создать хранилище v2'}</button>
        </div>
      {:else if storageStatus.state === 'ready' && loginModeForVaultStatus(vaultStatus) === 'blocked'}
        {#if vaultStatus.state === 'v1-prepared'}
          <p class="warning-text">Незавершённую подготовку можно безопасно отменить. Файлы при отмене сохраняются.</p>
          <button class="btn-secondary" disabled={migrationBusy} on:click={beginCancelV2Preparation}>Отменить подготовку v2</button>
        {/if}
      {:else if storageStatus.state === 'ready' && !show2FAInput && loginModeForVaultStatus(vaultStatus) !== 'blocked'}
        <div class="input-group">
          <input type="password" bind:value={masterPassword} aria-label="Мастер-пароль" placeholder="Введите мастер-пароль" autocomplete="current-password" on:keydown={(e) => e.key === 'Enter' && handleLogin()}/>
          <button class="btn-primary" disabled={authBusy || vaultStatus.state === 'loading' || (vaultStatus.state === 'v2-active' && !vaultStatus.v2ContainerPresent)} on:click={handleLogin}>Разблокировать</button>
        </div>
      {:else if storageStatus.state === 'ready' && show2FAInput}
        <div class="input-group">
          <p class="accent-text" style="margin: 0; font-size: 0.9rem;">Включена двухфакторная защита</p>
          <input type="text" bind:value={twoFACode} aria-label="Код TOTP" placeholder="Введите 6-значный код TOTP" maxlength="6" style="text-align: center; letter-spacing: 4px; font-size: 1.2rem;" on:keydown={(e) => e.key === 'Enter' && handleVerify2FA()}/>
          <button class="submit-btn" style="height: 42px;" disabled={authBusy} on:click={handleVerify2FA}>Подтвердить код</button>
          <button class="btn-micro" style="margin-top: 0;" on:click={() => handleLogout('')}>Назад к паролю</button>
        </div>
      {/if}

      {#if storageStatus.state === 'ready' && canOfferV2BackupRecovery(vaultStatus) && !show2FAInput}
        <button class="btn-secondary" disabled={recoveryBusy} on:click={handleV2Recovery}>
          {recoveryBusy ? 'Проверка резервной копии…' : 'Восстановить из резервной копии v2'}
        </button>
      {/if}

      {#if errorMessage}
        <p class="error">{errorMessage}</p>
      {/if}

      {#if storageStatus.state === 'ready' && vaultStatus.state === 'v1-active'}
        <div class="reset-zone">
          <button class="btn-outline-danger" on:click={handleReset}>Сбросить хранилище (Удалить всё)</button>
        </div>
      {/if}

  </LoginView>
{:else}
  <AppShell active={activeView} on:navigate={e => navigate(e.detail)} on:lock={() => handleLogout('Хранилище заблокировано')}>
    <StorageDiagnostics status={storageStatus} on:click={() => openVaultFolder(false)}/>
    {#if activeView === 'passwords'}
      <div class="password-page">
        <header class="page-heading"><div><h1>Мои пароли</h1><p>{accounts.length} записей в хранилище «Основное»</p></div><button class="primary-button" on:click={addRecord}><Icon name="plus" size={19}/>Добавить</button></header>
        <SearchAndFilters {accounts} bind:query={searchQuery} bind:category={activeFilter} bind:risk={riskFilter}/>
        {#if riskFilter !== 'all'}<div class="risk-summary"><span>Фильтр безопасности: {{ weak:'слабые', reused:'повторяющиеся', old:'старше 180 дней', breached:'найденные в утечках' }[riskFilter]}</span><button class="text-button" on:click={() => riskFilter = 'all'}>Сбросить</button></div>{/if}
        <PasswordList accounts={filteredAccounts} total={accounts.length} visibleIDs={visiblePasswordIDs} on:copy={e => copyData(e.detail)} on:toggle={e => togglePassword(e.detail)} on:edit={e => startEdit(e.detail)} on:delete={e => handleDelete(e.detail)}/>
        <StorageStatusBar storage={storageStatus} on:click={() => handleLogout('Хранилище заблокировано')}/>
      </div>
    {:else if activeView === 'vaults'}
      <StorageView storage={storageStatus} vault={vaultStatus} on:click={() => openVaultFolder(false)}>
        {#if vaultStatus.state === 'v1-active' || vaultStatus.state === 'v1-prepared'}
          <div class="button-row"><button class="primary-button" disabled={migrationBusy || (vaultStatus.state === 'v1-prepared' && !vaultStatus.v2ContainerPresent)} on:click={openMigrationModal}>Подготовить переход на v2</button>{#if vaultStatus.state === 'v1-prepared'}<button class="secondary-button" disabled={migrationBusy} on:click={beginCancelV2Preparation}>Отменить подготовку v2</button>{/if}</div>
        {/if}
      </StorageView>
    {:else if activeView === 'security'}
      <SecurityView {audit} total={accounts.length} breached={breachedCount} {breachState} {totpEnabled} format={storageStatus.format} on:risk={e => showRisk(e.detail)} on:totp={open2FASetup} on:cancel={() => { cancelBreachCheck(); breachState = 'idle'; }} on:check={() => showConfirm('Проверка через интернет', 'HIBP получит первые 5 символов локально вычисленного SHA-1 хеша каждого пароля. Открытые пароли не отправляются. Разрешить сетевую проверку?', checkBreaches)}/>
    {:else if activeView === 'settings'}
      <SettingsView {theme} {idleMinutes} {clipboardSeconds} on:theme={e => setTheme(e.detail)} on:idle={e => setIdlePreference(e.detail)} on:clipboard={e => setClipboardPreference(e.detail)} on:about={() => showAbout = true}/>
    {:else if activeView === 'devices'}
      <header class="page-heading"><div><h1>Устройства</h1><p>Ваши пароли сейчас доступны на этом устройстве</p></div></header>
      <section class="panel future-feature"><span class="future-icon"><Icon name="devices" size={45}/></span><span class="edition-badge">PASSWORDSAVER 3.0</span><h2>Ваши устройства. Одно безопасное пространство.</h2><p class="muted">Подключение устройств и телефона по QR-коду появится в PasswordSaver 3.0. В этой версии нет синхронизации, USB-ключей и подключённых мобильных устройств.</p></section>
    {/if}
    <svelte:fragment slot="security"><SecurityCenter {totpEnabled} backupPresent={storageStatus.backupPresent} weak={weakCount} reused={reusedCount} on:security={() => navigate('security')} on:vaults={() => navigate('vaults')} on:phone={() => navigate('devices')}/></svelte:fragment>
  </AppShell>
{/if}
{#if editorOpen && isLoggedIn}<PasswordEditor bind:title={newTitle} bind:login={newLogin} bind:password={newPass} bind:category={selectedCategory} editing={!!editingId} busy={editorBusy} on:save={handleSave} on:close={closeEditor} on:generate={e => generatePassword(e.detail)}/>{/if}
{#if dialog.show}
  <Modal title={dialog.title} on:close={closeDialog}><p class="dialog-message">{dialog.message}</p><div class="dialog-buttons"><button class="secondary-button" on:click={closeDialog}>{dialog.type === 'confirm' ? 'Отмена' : 'Понятно'}</button>{#if dialog.type === 'confirm'}<button class="primary-button" on:click={confirmDialog}>Подтвердить</button>{/if}</div></Modal>
{/if}

{#if showMigrationModal}
<Modal title="Миграция формата хранилища" busy={migrationBusy && migrationStage !== 'reauth'} on:close={closeMigrationModal}>
        {#if migrationStage === 'reauth'}
          <h3 class="dialog-title">Подготовка хранилища v2</h3>
          <p class="dialog-message">Будет создан отдельный зашифрованный контейнер. Исходные файлы v1 и резервная копия сохранятся. После проверки контейнер останется неактивным до отдельного подтверждения.</p>
          <label class="migration-label">Повторно введите мастер-пароль
            <input type="password" bind:value={migrationPassword} autocomplete="current-password" />
          </label>
          <label class="migration-label">Код TOTP, если включена 2FA
            <input type="text" bind:value={migrationTotp} inputmode="numeric" maxlength="6" autocomplete="one-time-code" />
          </label>
          {#if migrationError}<p class="error">{migrationError}</p>{/if}
          <div class="dialog-buttons">
            <button class="btn-cancel" disabled={migrationBusy} on:click={closeMigrationModal}>Закрыть</button>
            <button class="submit-btn" disabled={migrationBusy || !migrationPassword} on:click={prepareV2Migration}>{migrationBusy ? 'Проверка…' : 'Создать и проверить контейнер'}</button>
          </div>
        {:else if migrationStage === 'activate'}
          <h3 class="dialog-title">Контейнер v2 проверен</h3>
          <p class="dialog-message">Backend повторно открыл контейнер и сверил записи, настройки 2FA и секрет TOTP с активным хранилищем. Подтвердите активацию повторным вводом мастер-пароля и кода TOTP. После активации потребуется войти снова.</p>
          <label class="migration-label">Мастер-пароль для подтверждения
            <input type="password" bind:value={activationPassword} autocomplete="current-password" />
          </label>
          <label class="migration-label">Код TOTP, если включена 2FA
            <input type="text" bind:value={activationTotp} inputmode="numeric" maxlength="6" autocomplete="one-time-code" />
          </label>
          {#if migrationError}<p class="error">{migrationError}</p>{/if}
          <div class="dialog-buttons migration-buttons">
            <button class="btn-cancel" disabled={migrationBusy} on:click={closeMigrationModal}>Оставить подготовку</button>
            <button class="btn-danger-solid" disabled={migrationBusy} on:click={beginCancelV2Preparation}>Отменить переход…</button>
            <button class="submit-btn" disabled={migrationBusy || !activationPassword || !activationToken} on:click={confirmV2Migration}>{migrationBusy ? 'Активация…' : 'Явно активировать v2'}</button>
          </div>
        {:else if migrationStage === 'cancel'}
          <h3 class="dialog-title">Подтвердите отмену подготовки</h3>
          <p class="dialog-message">Активным останется формат v1. Файл v2, основной файл v1 и резервная копия не будут изменены или удалены. Продолжить отмену?</p>
          {#if migrationError}<p class="error">{migrationError}</p>{/if}
          <div class="dialog-buttons">
            <button class="btn-cancel" disabled={migrationBusy} on:click={closeMigrationModal}>Оставить подготовку</button>
            <button class="btn-danger-solid" disabled={migrationBusy || !activationToken} on:click={confirmCancelV2Preparation}>{migrationBusy ? 'Отмена…' : 'Подтвердить отмену'}</button>
          </div>
        {/if}

</Modal>
{/if}

{#if showStorageMigrationModal}
<Modal title="Перенос в AppData" busy={storageMigrationBusy && storageMigrationStage === 'confirm'} on:close={closeStorageMigrationModal}>
        {#if storageMigrationStage === 'verify'}
          <h3 class="dialog-title">Перенос в AppData</h3>
          <p class="dialog-message">Будут скопированы текущий зашифрованный контейнер, резервные копии и селектор формата. Приложение проверит активное хранилище мастер-паролем и TOTP, если он включён. Если основной файл повреждён, перенос разрешается только после проверки резервной копии; после копирования её восстановление остаётся отдельной подтверждаемой операцией. Исходные файлы останутся без изменений; перенос не удаляет и не объединяет данные.</p>
          <p><strong>Источник:</strong><br><code>{storageMigrationSource}</code></p>
          <p><strong>Назначение:</strong><br><code>{storageMigrationTarget}</code></p>
          <label class="migration-label">Мастер-пароль
            <input type="password" bind:value={storageMigrationPassword} autocomplete="current-password" />
          </label>
          <label class="migration-label">Код TOTP, если включена 2FA
            <input type="text" bind:value={storageMigrationTotp} inputmode="numeric" maxlength="6" autocomplete="one-time-code" />
          </label>
          {#if storageMigrationError}<p class="error">{storageMigrationError}</p>{/if}
          <div class="dialog-buttons">
            <button class="btn-cancel" disabled={storageMigrationBusy} on:click={closeStorageMigrationModal}>Отмена</button>
            <button class="submit-btn" disabled={storageMigrationBusy || !storageMigrationPassword} on:click={prepareStorageLocationMigration}>{storageMigrationBusy ? 'Проверка…' : 'Проверить хранилище'}</button>
          </div>
        {:else}
          <h3 class="dialog-title">Подтвердите копирование</h3>
          <p><strong>Источник:</strong><br><code>{storageMigrationSource}</code></p>
          <p><strong>Назначение:</strong><br><code>{storageMigrationTarget}</code></p>
          <p class="dialog-message">Аутентификация пройдена. PasswordSaver создаст зашифрованную копию в AppData, сверит каждый файл по байтам и только затем переключит приложение на неё. Старые файлы и пользовательские данные останутся в исходной папке. Подтверждение действует ограниченное время.</p>
          {#if storageMigrationError}<p class="error">{storageMigrationError}</p>{/if}
          <div class="dialog-buttons">
            <button class="btn-cancel" disabled={storageMigrationBusy} on:click={closeStorageMigrationModal}>Не переносить</button>
            <button class="submit-btn" disabled={storageMigrationBusy || !storageMigrationToken} on:click={confirmStorageLocationMigration}>{storageMigrationBusy ? 'Копирование…' : 'Подтвердить копирование'}</button>
          </div>
        {/if}

</Modal>
{/if}

{#if show2FASetupModal && isLoggedIn}
  <Modal title="Настройка TOTP" on:close={close2FASetup}>
    <p class="muted">Отсканируйте QR-код в приложении аутентификации, затем подтвердите код.</p>
    {#if totpQRCode}<img class="totp-qr" src={totpQRCode} alt="QR-код настройки TOTP"/>{/if}
    <div class="field"><span>Секрет TOTP</span><code class="secret-code">{totpSecret}</code></div>
    <label>Код подтверждения<input bind:value={setupCode} inputmode="numeric" maxlength="6" autocomplete="one-time-code"/></label>
    <div class="dialog-buttons"><button class="secondary-button" on:click={close2FASetup}>Отмена</button><button class="primary-button" on:click={handleConfirm2FA}>Включить TOTP</button></div>
  </Modal>
{/if}
{#if showAbout}<Modal title="О PasswordSaver" on:close={() => showAbout = false}><p>PasswordSaver Standard — локальный менеджер паролей.</p><p class="muted">Разработано студентами МТУСИ: Дрейман Артём, Лосев Илья, Егоров Семен.</p><p class="muted">Интерфейс 2.5. Редакция Standard использует AES-256-GCM и Argon2id. Подключение устройств планируется в 3.0.</p></Modal>{/if}
