<script>
  import { onMount } from 'svelte';
  import { fade, slide, fly } from 'svelte/transition';
  import { flip } from 'svelte/animate';
  import { 
    Login, Logout, GetAccounts, AddAccount, DeleteAccount, ResetVault, UpdateAccount,
    Generate2FA, ConfirmAndEnable2FA, Verify2FA 
  } from '../wailsjs/go/main/App.js';

  import logoImg from './assets/images/logo.png';

  let isLoggedIn = false;
  let masterPassword = '';
  let errorMessage = '';
  let lockReason = ''; 

  let accounts = [];
  
  let newTitle = '';
  let newLogin = '';
  let newPass = '';
  let selectedCategory = 'Общие';
  let editingId = null; 
  
  let showAbout = false;

  // --- ЛОГИКА 2FA ---
  let show2FAInput = false; 
  let twoFACode = '';
  
  let show2FASetupModal = false;
  let totpSecret = '';
  let totpQRCode = '';
  let setupCode = '';
  
  // --- ЛОГИКА ТЕМЫ ---
  let isDarkMode = true;

  onMount(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light') {
      isDarkMode = false;
      document.body.classList.add('light-theme');
    }
  });

  function toggleTheme() {
    isDarkMode = !isDarkMode;
    if (isDarkMode) {
      document.body.classList.remove('light-theme');
      localStorage.setItem('theme', 'dark');
    } else {
      document.body.classList.add('light-theme');
      localStorage.setItem('theme', 'light');
    }
  }

  // Кастомные диалоговые окна
  let dialog = { show: false, type: 'alert', title: '', message: '', onConfirm: null };

  function showAlert(title, message) { dialog = { show: true, type: 'alert', title, message, onConfirm: null }; }
  function showConfirm(title, message, onConfirmCallback) { dialog = { show: true, type: 'confirm', title, message, onConfirm: onConfirmCallback }; }
  function closeDialog() { dialog.show = false; }
  function confirmDialog() { if (dialog.onConfirm) dialog.onConfirm(); closeDialog(); }

  const categories = ['Общие', 'Работа', 'Соцсети', 'Игры', 'Финансы'];
  const categoryColors = { 'Общие': '#8b949e', 'Работа': '#58a6ff', 'Соцсети': '#3fb950', 'Игры': '#e3b341', 'Финансы': '#f85149' };

  let genLength = 16;
  let genNumbers = true;
  let genSymbols = true;

  let toastMessage = '';
  let searchQuery = '';
  let activeFilter = 'Все';

  const SIX_MONTHS_SEC = 180 * 24 * 60 * 60;
  function isPasswordOld(updatedAt) {
    if (!updatedAt || updatedAt === 0) return false; 
    const now = Math.floor(Date.now() / 1000);
    return (now - updatedAt) > SIX_MONTHS_SEC;
  }

  $: oldPassCount = accounts.filter(acc => isPasswordOld(acc.updatedAt)).length;
  $: filteredAccounts = accounts.filter(acc => {
    const [title, category] = acc.title.split('|||');
    const actualCategory = category || 'Общие';
    const matchesSearch = title.toLowerCase().includes(searchQuery.toLowerCase()) || acc.login.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesFilter = activeFilter === 'Все' || actualCategory === activeFilter;
    return matchesSearch && matchesFilter;
  });
  $: weakCount = accounts.filter(acc => acc.password.length < 8 || !/[0-9]/.test(acc.password) || !/[^a-zA-Z0-9]/.test(acc.password)).length;
  $: reusedCount = (() => {
    let counts = {};
    accounts.forEach(a => counts[a.password] = (counts[a.password] || 0) + 1);
    return accounts.filter(a => counts[a.password] > 1).length;
  })();

  let isCheckingBreaches = false;
  let breachChecked = false;
  let breachedCount = 0;

  async function checkBreaches() {
    isCheckingBreaches = true; breachedCount = 0;
    for (let acc of accounts) {
      const encoder = new TextEncoder();
      const data = encoder.encode(acc.password);
      const hashBuffer = await window.crypto.subtle.digest('SHA-1', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      const prefix = hashHex.substring(0, 5); const suffix = hashHex.substring(5);
      try {
        const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const text = await res.text();
        let found = false;
        for (let line of text.split('\n')) {
          if (line.split(':')[0] === suffix) { breachedCount++; found = true; acc.isBreached = true; break; }
        }
        if (!found) acc.isBreached = false;
      } catch (e) { console.error(e); }
    }
    accounts = [...accounts]; isCheckingBreaches = false; breachChecked = true;
  }

  let idleTimer;
  const IDLE_TIME_MS = 1 * 60 * 1000; 
  function resetTimer() {
    if (!isLoggedIn) return;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => { lockReason = 'Хранилище заблокировано из-за неактивности (1 мин)'; handleLogout(); }, IDLE_TIME_MS);
  }
  $: if (isLoggedIn) { resetTimer(); lockReason = ''; } else { clearTimeout(idleTimer); }

  let strengthColor = 'transparent';
  $: {
    if (!newPass) strengthColor = 'transparent';
    else if (newPass.length < 8) strengthColor = '#f85149'; 
    else if (newPass.length < 12 || !/[0-9]/.test(newPass) || !/[^a-zA-Z0-9]/.test(newPass)) strengthColor = '#e3b341'; 
    else strengthColor = '#3fb950'; 
  }

  function generatePassword() {
    const lower = "abcdefghijklmnopqrstuvwxyz"; const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789"; const symbols = "!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let chars = lower + upper;
    if (genNumbers) chars += numbers; if (genSymbols) chars += symbols;
    let pass = ""; const array = new Uint32Array(genLength); window.crypto.getRandomValues(array);
    for (let i = 0; i < genLength; i++) { pass += chars[array[i] % chars.length]; }
    newPass = pass;
  }

  async function copyData(text) {
    try {
      await navigator.clipboard.writeText(text);
      toastMessage = 'Скопировано!'; setTimeout(() => toastMessage = '', 2000);
      setTimeout(() => { navigator.clipboard.writeText(''); }, 15000);
    } catch (err) { console.error(err); }
  }

  function getFaviconUrl(serviceName) {
    if (!serviceName) return '';
    let realName = serviceName.split('|||')[0];
    let domain = realName.toLowerCase().trim().replace(/\s+/g, '');
    if (!domain.includes('.')) {
      if (domain === 'vk' || domain === 'вк') domain = 'vk.com';
      else if (domain === 'mail' || domain === 'мэйл') domain = 'mail.ru';
      else if (domain === 'yandex' || domain === 'яндекс') domain = 'ya.ru';
      else if (domain === 'gosuslugi' || domain === 'госуслуги') domain = 'gosuslugi.ru';
      else domain += '.com';
    }
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;
  }

  // --- ОБНОВЛЕННЫЕ ФУНКЦИИ ВХОДА (2FA) ---
  async function handleLogin() {
    try {
      const requires2FA = await Login(masterPassword); 
      if (requires2FA) {
        show2FAInput = true;
        errorMessage = '';
      } else {
        isLoggedIn = true;
        errorMessage = '';
        lockReason = '';
        masterPassword = '';
        loadAccounts();      
      }
    } catch (err) { errorMessage = err; }
  }

  async function handleVerify2FA() {
    try {
      await Verify2FA(twoFACode);
      isLoggedIn = true;
      show2FAInput = false;
      twoFACode = '';
      masterPassword = '';
      errorMessage = '';
      lockReason = '';
      loadAccounts();
    } catch (err) { errorMessage = err; }
  }

  async function handleLogout() {
    await Logout(); 
    isLoggedIn = false; show2FAInput = false; twoFACode = ''; accounts = []; 
    searchQuery = ''; breachChecked = false; breachedCount = 0; activeFilter = 'Все'; 
    cancelEdit(); showAbout = false;
  }

  function handleReset() {
    showConfirm("Сброс хранилища", "ВНИМАНИЕ! Это действие навсегда удалит все зашифрованные пароли.\nВы уверены?", async () => {
      try { 
        await ResetVault(true);
        errorMessage = ''; lockReason = ''; masterPassword = ''; show2FAInput = false;
        showAlert("Успешно", "Ваше хранилище было полностью сброшено."); 
      } catch (err) { errorMessage = err; }
    });
  }

  async function loadAccounts() {
    try { accounts = await GetAccounts() || []; breachChecked = false; breachedCount = 0; } catch (err) { console.error(err); }
  }

  async function handleSave() {
    if (!newTitle || !newLogin || !newPass) { showAlert("Внимание", "Заполните все поля перед сохранением."); return; }
    const combinedTitle = `${newTitle}|||${selectedCategory}`;
    try {
      if (editingId) { await UpdateAccount(editingId, combinedTitle, newLogin, newPass); editingId = null; } 
      else { await AddAccount(combinedTitle, newLogin, newPass); }
      newTitle = ''; newLogin = ''; newPass = ''; selectedCategory = 'Общие'; loadAccounts();
    } catch (err) { console.error(err); }
  }

  function startEdit(acc) {
    editingId = acc.id; const [title, category] = acc.title.split('|||');
    newTitle = title; newLogin = acc.login; newPass = acc.password; selectedCategory = category || 'Общие';
    window.scrollTo({ top: 0, behavior: 'smooth' }); 
  }

  function cancelEdit() { editingId = null; newTitle = ''; newLogin = ''; newPass = ''; selectedCategory = 'Общие'; }

  async function handleDelete(id) {
    showConfirm("Удаление", "Удалить эту запись безвозвратно?", async () => {
      try { await DeleteAccount(id); if(editingId === id) cancelEdit(); loadAccounts(); } catch (err) { console.error(err); }
    });
  }

  // --- ФУНКЦИИ НАСТРОЙКИ 2FA ---
  async function open2FASetup() {
    try {
      const setupData = await Generate2FA();
      totpSecret = setupData.secret;
      totpQRCode = setupData.qrCode;
      show2FASetupModal = true;
    } catch (err) { showAlert("Ошибка", err); }
  }

  async function handleConfirm2FA() {
    try {
      await ConfirmAndEnable2FA(totpSecret, setupCode);
      showAlert("Успешно", "Двухфакторная аутентификация успешно включена!");
      show2FASetupModal = false;
      setupCode = '';
      loadAccounts(); 
    } catch (err) { showAlert("Ошибка", err); }
  }
</script>

<svelte:window on:mousemove={resetTimer} on:keydown={resetTimer} on:click={resetTimer} />

<div class="app-background"></div>

<main class="container">
  {#if toastMessage}
    <div class="toast glass-panel" transition:fly={{ y: -20, duration: 300 }}>{toastMessage}</div>
  {/if}

  {#if !isLoggedIn}
    <div class="login-box glass-panel glass-blur" in:fade={{duration: 400}} out:fade={{duration: 200}}>
      <div class="theme-toggle-login">
        <button class="btn-theme-small" on:click={toggleTheme} title="Переключить тему">{isDarkMode ? '☀️' : '🌙'}</button>
      </div>

      <img src={logoImg} alt="PasswordSaver Logo" class="login-logo" />
      <h2>PasswordSaver</h2>
      <p class="subtitle">Локальное зашифрованное хранилище</p>
      
      {#if lockReason}
        <p class="lock-warning" transition:slide>🔒 {lockReason}</p>
      {/if}

      {#if !show2FAInput}
        <div class="input-group" transition:fade>
          <input type="password" bind:value={masterPassword} placeholder="Введите мастер-пароль" on:keydown={(e) => e.key === 'Enter' && handleLogin()}/>
          <button class="btn-primary" on:click={handleLogin}>Разблокировать</button>
        </div>
      {:else}
        <div class="input-group" transition:fly={{ y: 20 }}>
          <p class="accent-text" style="margin: 0; font-size: 0.9rem;">Включена двухфакторная защита</p>
          <input type="text" bind:value={twoFACode} placeholder="Введите 6-значный код TOTP" maxlength="6" style="text-align: center; letter-spacing: 4px; font-size: 1.2rem;" on:keydown={(e) => e.key === 'Enter' && handleVerify2FA()}/>
          <button class="submit-btn" style="height: 42px;" on:click={handleVerify2FA}>Подтвердить код</button>
          <button class="btn-micro" style="margin-top: 0;" on:click={() => { show2FAInput = false; twoFACode = ''; }}>← Назад к паролю</button>
        </div>
      {/if}
      
      {#if errorMessage}
        <p class="error" transition:slide>{errorMessage}</p>
      {/if}

      <div class="reset-zone">
        <button class="btn-outline-danger" on:click={handleReset}>Сбросить хранилище (Удалить всё)</button>
      </div>
    </div>
  {:else}
    <div class="vault-box glass-panel" in:fade={{duration: 400}}>
      <div class="header">
        <div class="header-title">
          <img src={logoImg} alt="Logo" class="header-logo" />
          <h2>Мои пароли</h2>
        </div>
        <div class="header-actions">
          <button class="btn-theme" on:click={toggleTheme} title="Переключить тему">{isDarkMode ? '☀️' : '🌙'}</button>
          <button class="btn-about" style="border-color: var(--accent-color); color: var(--accent-color);" on:click={open2FASetup}>🛡️ Настроить 2FA</button>
          <button class="btn-about" on:click={() => showAbout = true}>ℹ️ О проекте</button>
          <button class="btn-lock" on:click={handleLogout}>🔒 Заблокировать хранилище</button>
        </div>
      </div>

      {#if accounts.length > 0}
        <div class="dashboard" transition:slide>
          <div class="stat-card"><div class="stat-value">{accounts.length}</div><div class="stat-label">Всего</div></div>
          <div class="stat-card {weakCount > 0 ? 'danger' : 'safe'}"><div class="stat-value">{weakCount}</div><div class="stat-label">Слабых</div></div>
          <div class="stat-card {reusedCount > 0 ? 'warning' : 'safe'}"><div class="stat-value">{reusedCount}</div><div class="stat-label">Повторов</div></div>
          <div class="stat-card {oldPassCount > 0 ? 'warning' : 'safe'}"><div class="stat-value">{oldPassCount}</div><div class="stat-label">Старше 180 дн.</div></div>
          <div class="stat-card {breachChecked ? (breachedCount > 0 ? 'danger' : 'safe') : ''}">
            <div class="stat-value">
              {#if isCheckingBreaches}<div class="skeleton-pulse">...</div>{:else if breachChecked}<span in:fade>{breachedCount}</span>{:else}?{/if}
            </div>
            <div class="stat-label">Утечки</div>
            {#if !isCheckingBreaches}<button class="btn-micro" on:click={checkBreaches}>{breachChecked ? 'Обновить' : 'Проверить'}</button>{/if}
          </div>
        </div>
      {/if}

      <div class="generator-panel">
        <div class="gen-header"><span class="gen-title">🔑 Генератор надежных паролей</span></div>
        <div class="gen-controls-wrapper">
          <div class="gen-slider-block">
            <label class="gen-label">Длина: <span class="accent-text">{genLength}</span></label>
            <input type="range" class="custom-slider" min="8" max="32" bind:value={genLength} on:input={generatePassword} style="background: linear-gradient(to right, var(--accent-color) {(genLength - 8) / 24 * 100}%, var(--border-main) {(genLength - 8) / 24 * 100}%);" />
          </div>
          <div class="gen-options-block">
            <label class="check-container"><input type="checkbox" class="custom-checkbox" bind:checked={genNumbers} on:change={generatePassword} /> <span>Цифры</span></label>
            <label class="check-container"><input type="checkbox" class="custom-checkbox" bind:checked={genSymbols} on:change={generatePassword} /> <span>Символы</span></label>
          </div>
          <button class="btn-secondary gen-btn" on:click={generatePassword}>Сгенерировать</button>
        </div>
      </div>

      <div class="add-form-container {editingId ? 'editing-mode' : ''}">
        <div class="grid-row form-grid">
          <input type="text" bind:value={newTitle} placeholder="Название сервиса (например, GitHub)" />
          <input type="text" bind:value={newLogin} placeholder="Логин / Email" />
          <input type="text" bind:value={newPass} placeholder="Пароль" style="border-bottom: 2px solid {strengthColor}" />
          <select bind:value={selectedCategory} class="category-select">{#each categories as cat}<option value={cat}>{cat}</option>{/each}</select>
          <div class="form-buttons">
            <button class="submit-btn" on:click={handleSave}>{editingId ? 'Сохранить' : 'Добавить'}</button>
            {#if editingId}<button class="btn-icon-cancel" on:click={cancelEdit} title="Отменить редактирование">✖</button>{/if}
          </div>
        </div>
      </div>

      <div class="accounts-list">
        {#if accounts.length > 0}
          <div class="search-zone" transition:slide>
            <div class="search-bar">
              <span class="search-icon">🔍</span>
              <input type="text" bind:value={searchQuery} placeholder="Поиск по названию или логину..." />
            </div>
            <div class="filter-tags">
              {#each ['Все', ...categories] as filter}
                <button class="tag-filter-btn {activeFilter === filter ? 'active' : ''}" style="--tag-color: {categoryColors[filter] || '#58a6ff'}" on:click={() => activeFilter = filter}>{filter}</button>
              {/each}
            </div>
          </div>
        {/if}

        {#if accounts.length === 0}
          <div class="empty-state" in:fade><span class="empty-icon">🗄️</span><p class="empty">Ваше хранилище пока пусто.</p></div>
        {:else if filteredAccounts.length === 0}
          <div class="empty-state" in:fade><p class="empty">По вашему запросу ничего не найдено.</p></div>
        {:else}
          <div class="grid-row list-header">
            <span>Сервис</span><span>Логин</span><span>Пароль</span><span>Категория</span><span class="align-right">Действия</span>
          </div>
          {#each filteredAccounts as acc (acc.id)}
            <div animate:flip={{duration: 300}} in:fly={{ y: 20, duration: 300 }} out:slide={{ duration: 200 }} class="grid-row account-card {editingId === acc.id ? 'row-editing' : ''}">
              <span class="acc-title">
                <img src={getFaviconUrl(acc.title)} alt="" class="favicon" />
                <div class="title-meta">
                  <span class="main-title" title={acc.title.split('|||')[0]}>{acc.title.split('|||')[0]}</span>
                  {#if isPasswordOld(acc.updatedAt)}<span class="old-badge" title="Пароль не обновлялся более 180 дней">⌛ Устарел</span>{/if}
                </div>
              </span>
              <span class="acc-login action-text" on:click={() => copyData(acc.login)} title="Скопировать логин">{acc.login} <span class="copy-icon">📋</span></span>
              <span class="acc-pass action-text {acc.isBreached ? 'breached-text' : ''}" on:click={() => copyData(acc.password)} title="Скопировать пароль">
                {#if acc.isBreached}⚠️{/if} {acc.password} <span class="copy-icon">📋</span>
              </span>
              <span class="acc-category">
                <span class="category-badge" style="background-color: {categoryColors[acc.title.split('|||')[1] || 'Общие']}1A; color: {categoryColors[acc.title.split('|||')[1] || 'Общие']}; border: 1px solid {categoryColors[acc.title.split('|||')[1] || 'Общие']}40;">{acc.title.split('|||')[1] || 'Общие'}</span>
              </span>
              <div class="actions-cell">
                <button class="action-icon-btn edit-icon" on:click={() => startEdit(acc)} title="Редактировать">✏️</button>
                <button class="action-icon-btn delete-icon" on:click={() => handleDelete(acc.id)} title="Удалить">🗑️</button>
              </div>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  {/if}

  {#if dialog.show}
    <div class="modal-overlay" transition:fade on:click|self={closeDialog}>
      <div class="modal-content glass-panel" transition:fly={{y: -20}}>
        <h3 class="dialog-title">{dialog.title}</h3>
        <p class="dialog-message">{dialog.message}</p>
        <div class="dialog-buttons">
          {#if dialog.type === 'confirm'}
            <button class="btn-cancel" on:click={closeDialog}>Отмена</button>
            <button class="btn-danger-solid" on:click={confirmDialog}>Да, уверен</button>
          {:else}
            <button class="btn-primary" on:click={closeDialog}>OK</button>
          {/if}
        </div>
      </div>
    </div>
  {/if}

  {#if show2FASetupModal}
    <div class="modal-overlay" transition:fade on:click|self={() => show2FASetupModal = false}>
      <div class="modal-content glass-panel" style="text-align: center; max-width: 400px;" transition:fly={{y: 20}}>
        <button class="close-btn" on:click={() => show2FASetupModal = false}>✖</button>
        <h3 class="dialog-title">Настройка 2FA</h3>
        <p style="font-size: 0.9rem; color: var(--text-muted);">
          Отсканируйте этот QR-код в приложении Google Authenticator или Яндекс Ключ
        </p>
        
        {#if totpQRCode}
          <img src={totpQRCode} alt="QR Code 2FA" style="border: 8px solid white; border-radius: 8px; margin: 15px auto; display: block; width: 200px; height: 200px;" />
        {/if}
        
        <p style="font-family: monospace; font-size: 0.85rem; background: var(--input-bg); padding: 8px; border-radius: 4px; border: 1px solid var(--border-main); user-select: all;">
          Секрет: {totpSecret}
        </p>

        <div style="margin-top: 20px;">
          <input type="text" bind:value={setupCode} placeholder="Введите код из приложения" maxlength="6" style="text-align: center; margin-bottom: 15px; letter-spacing: 2px;" />
          <div class="dialog-buttons">
            <button class="btn-cancel" on:click={() => show2FASetupModal = false}>Отмена</button>
            <button class="submit-btn" style="height: 38px;" on:click={handleConfirm2FA}>Включить защиту</button>
          </div>
        </div>
      </div>
    </div>
  {/if}

  {#if showAbout}
    <div class="modal-overlay" transition:fade on:click|self={() => showAbout = false}>
      <div class="modal-content glass-panel about-modal" transition:fly={{y: 20}}>
        <button class="close-btn" on:click={() => showAbout = false}>✖</button>
        <h3>О проекте</h3>
        <div class="about-body">
          <p class="about-love">Разработано студентами МТУСИ для пользователей с любовью ❤️</p>
          <p class="team-names">Команда: Дрейман Артём, Лосев Илья, Егоров Семен</p>
          <p class="about-text">Мы создали этот проект, чтобы сделать управление вашими данными простым, безопасным и по-настоящему удобным.</p>
          <p class="warm-vibe">
            Мы искренне рады, что наш PasswordSaver помогает вам хранить пароли в порядке.<br>
            Каждый клик, который вы делаете в этом приложении — это шаг к вашей цифровой безопасности.<br>
            Спасибо, что доверяете нам! 🚀
          </p>
        </div>
        <button class="btn-primary" on:click={() => showAbout = false}>Понятно</button>
      </div>
    </div>
  {/if}
</main>

<style>
  /* --- CSS ПЕРЕМЕННЫЕ (СИСТЕМА ТЕМ) --- */
  :root {
    --bg-color: #0d1117;
    --bg-gradient: radial-gradient(circle at 50% 0%, #1f242c 0%, #0d1117 70%);
    --panel-bg: rgba(22, 27, 34, 0.75);
    --text-main: #c9d1d9;
    --text-heading: #ffffff;
    --text-muted: #8b949e;
    --accent-color: #58a6ff;
    --border-main: #30363d;
    --border-hover: #484f58;
    --input-bg: #0d1117;
    --input-focus-bg: #161b22;
    --btn-bg: #21262d;
    --btn-hover: #30363d;
    --card-bg: rgba(33, 38, 45, 0.4);
    --card-hover: rgba(33, 38, 45, 0.8);
    --shadow-color: rgba(0, 0, 0, 0.5);
    --modal-overlay: rgba(0,0,0,0.75);
    --modal-bg: #161b22;
  }

  :global(body.light-theme) {
    --bg-color: #f6f8fa;
    --bg-gradient: radial-gradient(circle at 50% 0%, #ffffff 0%, #e1e4e8 80%);
    --panel-bg: rgba(255, 255, 255, 0.9);
    --text-main: #24292f;
    --text-heading: #1f2328;
    --text-muted: #57606a;
    --accent-color: #0969da;
    --border-main: #d0d7de;
    --border-hover: #afb8c1;
    --input-bg: #ffffff;
    --input-focus-bg: #f6f8fa;
    --btn-bg: #f3f4f6;
    --btn-hover: #e5e7eb;
    --card-bg: rgba(255, 255, 255, 0.6);
    --card-hover: rgba(255, 255, 255, 1);
    --shadow-color: rgba(0, 0, 0, 0.08);
    --modal-overlay: rgba(31, 35, 40, 0.5);
    --modal-bg: #ffffff;
  }

  /* --- БАЗОВЫЕ СТИЛИ --- */
  :global(body) { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg-color); color: var(--text-main); overflow-y: scroll; transition: background-color 0.3s ease, color 0.3s ease; }
  :global(*){ box-sizing: border-box; }
  :global(::-webkit-scrollbar) { width: 8px; height: 8px; }
  :global(::-webkit-scrollbar-track) { background: var(--bg-color); }
  :global(::-webkit-scrollbar-thumb) { background: var(--border-main); border-radius: 4px; }
  :global(::-webkit-scrollbar-thumb:hover) { background: var(--text-muted); }

  .app-background { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: var(--bg-gradient); z-index: -1; transition: background 0.3s ease; }
  .container { display: flex; justify-content: center; padding: 40px 20px; min-height: 100vh; }
  
  .glass-panel { background: var(--panel-bg); border: 1px solid var(--border-main); box-shadow: 0 10px 30px var(--shadow-color); border-radius: 12px; transition: background 0.3s, border-color 0.3s, box-shadow 0.3s; }
  .glass-blur { backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); }

  /* --- ЭКРАН ВХОДА --- */
  .login-box { width: 100%; max-width: 420px; padding: 40px; text-align: center; height: max-content; margin-top: 5vh; position: relative; }
  .theme-toggle-login { position: absolute; top: 15px; right: 15px; }
  .btn-theme-small { background: transparent; border: none; color: var(--text-muted); font-size: 1.2rem; cursor: pointer; transition: 0.2s; }
  .btn-theme-small:hover { transform: scale(1.1); color: var(--text-heading); }
  .login-logo { width: 140px; height: 140px; object-fit: contain; margin-bottom: 15px; border-radius: 16px; }
  h2 { margin-top: 0; margin-bottom: 5px; font-size: 1.8rem; font-weight: 600; color: var(--text-heading); letter-spacing: -0.5px; }
  .subtitle { color: var(--text-muted); margin-bottom: 30px; font-size: 0.95rem; }
  .input-group { display: flex; flex-direction: column; gap: 15px; }
  
  /* --- ШАПКА ХРАНИЛИЩА --- */
  .vault-box { width: 100%; max-width: 1000px; padding: 30px; height: max-content; }
  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; border-bottom: 1px solid var(--border-main); padding-bottom: 15px; }
  .header-title { display: flex; align-items: center; gap: 12px; }
  .header-logo { width: 48px; height: 48px; object-fit: contain; border-radius: 8px; }
  .header-actions { display: flex; align-items: center; gap: 10px; }

  /* --- СЕТКА --- */
  .grid-row { display: grid; grid-template-columns: minmax(120px, 1.5fr) minmax(100px, 1.2fr) minmax(100px, 1.2fr) 110px 130px; gap: 15px; align-items: center; }
  
  /* --- ФОРМА ДОБАВЛЕНИЯ --- */
  .add-form-container { background: var(--card-bg); padding: 15px; border-radius: 8px; margin-bottom: 30px; border: 1px solid var(--border-main); transition: all 0.3s ease; }
  .editing-mode { border-color: #58a6ff; box-shadow: 0 0 15px rgba(88, 166, 255, 0.1); background: rgba(88, 166, 255, 0.05); }
  
  .form-buttons { display: flex; gap: 8px; width: 100%; align-items: center; }
  .submit-btn { flex: 1; height: 38px; border: none; border-radius: 6px; font-weight: 600; font-size: 0.95rem; background: #238636; color: white; cursor: pointer; transition: 0.2s; white-space: nowrap; display: flex; align-items: center; justify-content: center; }
  .submit-btn:hover { background: #2ea043; }
  .btn-icon-cancel { width: 38px; height: 38px; background: var(--btn-bg); color: var(--text-muted); border: 1px solid var(--border-main); border-radius: 6px; cursor: pointer; transition: 0.2s; font-weight: bold; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .btn-icon-cancel:hover { background: #f85149; color: white; border-color: #f85149; }

  input[type="text"], input[type="password"], .category-select { padding: 10px 15px; background: var(--input-bg); border: 1px solid var(--border-main); color: var(--text-main); border-radius: 6px; width: 100%; font-size: 0.95rem; height: 38px; transition: all 0.2s; }
  input[type="text"]:focus, input[type="password"]:focus, .category-select:focus { outline: none; border-color: var(--accent-color); box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.15); background: var(--input-focus-bg); }
  .category-select { cursor: pointer; color: var(--text-muted); appearance: none; }

  /* --- ДАШБОРД --- */
  .dashboard { display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 25px; }
  .stat-card { flex: 1; min-width: 120px; background: var(--card-bg); padding: 15px; border-radius: 8px; text-align: center; border-bottom: 3px solid var(--border-main); border-top: 1px solid var(--border-main); border-left: 1px solid var(--border-main); border-right: 1px solid var(--border-main); display: flex; flex-direction: column; justify-content: center; align-items: center; transition: background 0.3s; }
  .stat-value { font-size: 1.8rem; font-weight: 700; margin-bottom: 5px; color: var(--text-heading); }
  .stat-label { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
  
  .stat-card.safe { border-bottom-color: #3fb950; } .stat-card.safe .stat-value { color: #3fb950; }
  .stat-card.warning { border-bottom-color: #e3b341; } .stat-card.warning .stat-value { color: #e3b341; }
  .stat-card.danger { border-bottom-color: #f85149; } .stat-card.danger .stat-value { color: #f85149; }

  .skeleton-pulse { color: var(--text-muted); font-weight: bold; font-size: 1.4rem; animation: pulse 1.5s infinite alternate; }
  @keyframes pulse { 0% { opacity: 0.3; transform: scale(0.95); } 100% { opacity: 1; transform: scale(1.05); } }

  .btn-micro { background: var(--btn-bg); color: var(--text-main); border: 1px solid var(--border-main); padding: 4px 12px; font-size: 0.75rem; border-radius: 6px; cursor: pointer; margin-top: 10px; transition: all 0.2s; font-weight: 500; }
  .btn-micro:hover { background: var(--btn-hover); border-color: var(--text-muted); }

  /* --- ГЕНЕРАТОР ПАРОЛЕЙ --- */
  .generator-panel { background: var(--card-bg); padding: 15px 20px; border-radius: 8px; margin-bottom: 25px; border: 1px solid var(--border-main); box-shadow: inset 0 2px 4px rgba(0,0,0,0.05); transition: background 0.3s; }
  .gen-header { margin-bottom: 12px; border-bottom: 1px solid var(--border-main); padding-bottom: 8px; }
  .gen-title { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
  
  .gen-controls-wrapper { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 15px; }
  .gen-slider-block { display: flex; align-items: center; gap: 15px; flex: 1; min-width: 200px; }
  .gen-label { font-size: 0.95rem; color: var(--text-main); display: flex; align-items: center; gap: 5px; white-space: nowrap; }
  .accent-text { color: var(--accent-color); font-weight: bold; display: inline-block; width: 22px; text-align: center; }
  
  .custom-slider { -webkit-appearance: none; width: 100%; max-width: 250px; height: 6px; border-radius: 3px; outline: none; transition: opacity .2s; }
  .custom-slider::-webkit-slider-thumb { -webkit-appearance: none; appearance: none; width: 16px; height: 16px; border-radius: 50%; background: #ffffff; border: 2px solid var(--accent-color); cursor: pointer; box-shadow: 0 0 8px rgba(88, 166, 255, 0.8); }
  .custom-slider::-webkit-slider-thumb:hover { transform: scale(1.1); }
  
  .gen-options-block { display: flex; align-items: center; gap: 20px; border-left: 1px solid var(--border-main); padding-left: 20px; }
  .check-container { display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 0.95rem; color: var(--text-main); user-select: none; }
  .custom-checkbox { width: 18px; height: 18px; accent-color: var(--accent-color); cursor: pointer; }
  
  .gen-btn { padding: 10px 20px; white-space: nowrap; height: 38px; display: flex; align-items: center; justify-content: center; }

  /* --- ОБЩИЕ КНОПКИ --- */
  button { border: none; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.95rem; transition: all 0.2s; }
  button:active { transform: scale(0.97); }
  
  .btn-primary { background: #238636; color: white; padding: 10px 20px; border: 1px solid rgba(255,255,255,0.1); width: 100%; height: 38px; }
  .btn-primary:hover { background: #2ea043; box-shadow: 0 0 15px rgba(46, 160, 67, 0.4); }
  
  .btn-secondary { background: var(--btn-bg); color: var(--text-main); border: 1px solid var(--border-main); padding: 10px 16px; }
  .btn-secondary:hover { background: var(--btn-hover); border-color: var(--text-muted); }
  
  .btn-about, .btn-lock, .btn-theme { background: transparent; color: var(--text-muted); border: 1px solid var(--border-main); padding: 8px 16px; font-size: 0.9rem; border-radius: 20px; cursor: pointer; transition: 0.2s; }
  .btn-about:hover, .btn-lock:hover, .btn-theme:hover { background: var(--btn-bg); color: var(--text-heading); border-color: var(--text-muted); }

  /* --- ПОИСК И ФИЛЬТРЫ --- */
  .search-zone { margin-bottom: 25px; background: var(--card-bg); padding: 15px; border-radius: 8px; border: 1px solid var(--border-main); transition: background 0.3s; }
  .search-bar { margin-bottom: 15px; position: relative; }
  .search-icon { position: absolute; left: 15px; top: 50%; transform: translateY(-50%); opacity: 0.5; font-size: 1.1rem; color: var(--text-main); }
  .search-bar input { background: var(--input-bg); border: 1px solid var(--border-main); border-radius: 25px; padding: 12px 20px 12px 45px; font-size: 0.95rem; box-shadow: inset 0 2px 4px rgba(0,0,0,0.05); }
  
  .filter-tags { display: flex; gap: 8px; flex-wrap: wrap; }
  .tag-filter-btn { padding: 6px 14px; font-size: 0.8rem; background: var(--btn-bg); color: var(--text-muted); border-radius: 20px; border: 1px solid var(--border-main); font-weight: 500; }
  .tag-filter-btn:hover { background: var(--btn-hover); color: var(--text-main); }
  .tag-filter-btn.active { background: var(--tag-color); color: #fff; border-color: var(--tag-color); font-weight: bold; }

  /* --- СПИСОК АККАУНТОВ --- */
  .list-header { padding: 0 15px 10px 15px; color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border-main); margin-bottom: 10px; font-weight: 600; }
  .align-right { text-align: right; }
  
  .account-card { padding: 12px 15px; background: var(--card-bg); margin-bottom: 8px; border-radius: 8px; border: 1px solid transparent; transition: all 0.2s ease; }
  .account-card:hover { background: var(--card-hover); border-color: var(--border-hover); box-shadow: 0 4px 12px var(--shadow-color); }
  .row-editing { border-color: var(--accent-color); background: rgba(88, 166, 255, 0.05); }

  .acc-title { display: flex; align-items: center; gap: 12px; overflow: hidden; }
  .title-meta { display: flex; flex-direction: column; gap: 4px; overflow: hidden; justify-content: center; }
  .main-title { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text-heading); font-size: 1rem; }
  
  .badge-group { display: flex; gap: 6px; align-items: center; }
  .category-badge { font-size: 0.65rem; padding: 2px 8px; border-radius: 12px; font-weight: 700; width: max-content; text-transform: uppercase; letter-spacing: 0.5px; }
  .old-badge { font-size: 0.65rem; padding: 2px 6px; border-radius: 12px; font-weight: 700; background: rgba(227, 179, 65, 0.15); color: #e3b341; border: 1px solid rgba(227, 179, 65, 0.4); white-space: nowrap; cursor: help; }
  
  .favicon { width: 22px; height: 22px; border-radius: 4px; background-color: #fff; padding: 2px; flex-shrink: 0; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
  
  .action-text { cursor: pointer; user-select: none; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; padding: 6px 0; font-family: 'Courier New', Courier, monospace; font-size: 0.95rem; transition: color 0.2s; }
  .action-text:hover { color: var(--accent-color); }
  .copy-icon { font-size: 0.8rem; opacity: 0.3; margin-left: 6px; transition: opacity 0.2s; }
  .action-text:hover .copy-icon { opacity: 1; }
  
  .actions-cell { display: flex; gap: 8px; justify-content: flex-end; }
  .action-icon-btn { background: var(--btn-bg); width: 36px; height: 36px; border-radius: 6px; font-size: 1rem; border: 1px solid var(--border-main); display: flex; align-items: center; justify-content: center; color: var(--text-main); }
  .edit-icon:hover { background: rgba(88, 166, 255, 0.1); border-color: var(--accent-color); color: var(--accent-color); }
  .delete-icon { opacity: 0.8; }
  .delete-icon:hover { background: rgba(248, 81, 73, 0.1); border-color: #f85149; color: #f85149; opacity: 1; }

  .breached-text { color: #f85149 !important; text-decoration: line-through; opacity: 0.8; }
  .empty-state { text-align: center; padding: 50px 0; background: var(--card-bg); border-radius: 8px; border: 1px dashed var(--border-main); }
  .empty-icon { font-size: 3rem; opacity: 0.5; display: block; margin-bottom: 15px; }
  .empty { color: var(--text-muted); font-size: 1.05rem; margin: 0; }
  .error { color: #f85149; text-align: center; margin-top: 15px; font-weight: 500; font-size: 0.9rem; }
  .lock-warning { color: #e3b341; text-align: center; margin-bottom: 20px; font-size: 0.9rem; background: rgba(227, 179, 65, 0.1); padding: 12px; border-radius: 6px; border: 1px solid rgba(227, 179, 65, 0.2); }
  
  .reset-zone { margin-top: 30px; padding-top: 25px; border-top: 1px solid var(--border-main); text-align: center; }
  .btn-outline-danger { background: transparent; border: 1px solid var(--border-hover); color: var(--text-muted); padding: 8px 20px; font-size: 0.85rem; }
  .btn-outline-danger:hover { border-color: #f85149; color: #f85149; background: rgba(248, 81, 73, 0.1); }
  
  .toast { position: fixed; top: 30px; left: 50%; transform: translateX(-50%); background: rgba(46, 160, 67, 0.95); backdrop-filter: blur(10px); color: white; padding: 12px 30px; border-radius: 30px; font-weight: 600; z-index: 1000; box-shadow: 0 10px 30px rgba(46, 160, 67, 0.4); border: 1px solid rgba(255,255,255,0.2); font-size: 1rem; }

  /* --- МОДАЛЬНЫЕ ОКНА --- */
  .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: var(--modal-overlay); backdrop-filter: blur(5px); display: flex; align-items: center; justify-content: center; z-index: 2000; transition: background 0.3s; }
  .modal-content { padding: 35px 40px; max-width: 450px; width: 100%; position: relative; border: 1px solid var(--border-main); background: var(--modal-bg); border-radius: 12px; box-shadow: 0 20px 40px var(--shadow-color); transition: background 0.3s, border-color 0.3s; }
  
  .about-modal { max-width: 500px; }
  .about-body { margin: 25px 0; line-height: 1.6; color: var(--text-main); text-align: center; }
  .about-love { font-size: 1.05rem; margin-bottom: 8px; color: var(--text-heading); font-weight: bold; }
  .team-names { font-size: 0.95rem; color: var(--text-muted); margin-top: 0; margin-bottom: 25px; }
  .about-text { margin-bottom: 15px; }
  .warm-vibe { font-style: italic; color: var(--accent-color); margin-top: 20px; line-height: 1.7; }
  .close-btn { position: absolute; top: 15px; right: 15px; background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 1.2rem; }
  .close-btn:hover { color: var(--text-heading); }

  .dialog-title { margin-top: 0; margin-bottom: 15px; font-size: 1.4rem; color: var(--text-heading); text-align: center; }
  .dialog-message { color: var(--text-main); font-size: 1rem; text-align: center; margin-bottom: 25px; white-space: pre-line; line-height: 1.5; }
  .dialog-buttons { display: flex; gap: 15px; justify-content: center; }
  
  .btn-cancel { background: var(--btn-bg); color: var(--text-main); border: 1px solid var(--border-main); padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; flex: 1; height: 38px; display: flex; align-items: center; justify-content: center; transition: 0.2s; }
  .btn-cancel:hover { background: var(--btn-hover); border-color: var(--text-muted); }
  .btn-danger-solid { background: #da3633; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; flex: 1; transition: 0.2s; height: 38px; display: flex; align-items: center; justify-content: center; }
  .btn-danger-solid:hover { background: #b32d2a; }
</style>
