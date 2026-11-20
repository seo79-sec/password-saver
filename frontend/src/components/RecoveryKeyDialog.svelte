<script>
  import { createEventDispatcher, onDestroy } from 'svelte';
  import Modal from './Modal.svelte';
  import { friendlyBackendError } from '../security.js';
  import {
    CreateRecoveryKey, VerifyRecoveryKey, DisableRecoveryKey, PrepareRecoveryKeyReset,
    ConfirmRecoveryKeyReset, CancelRecoveryKeyReset, IsLocked,
  } from '../../wailsjs/go/main/App.js';

  export let recover = false;
  export let totpEnabled = false;
  const dispatch = createEventDispatcher();
  let action = 'create';
  let password = '';
  let confirmation = '';
  let code = '';
  let key = '';
  let printedKey = '';
  let fromBackup = false;
  let token = '';
  let busy = false;
  let alive = true;
  let message = '';
  let error = '';

  function unsetCredentials() {
    password = confirmation = code = key = '';
  }

  function cancelToken(value) {
    if (value) CancelRecoveryKeyReset(value).catch(() => {});
  }

  onDestroy(() => {
    alive = false;
    cancelToken(token);
    token = printedKey = '';
    unsetCredentials();
  });

  function chooseAction(event) {
    action = event.currentTarget.value;
    unsetCredentials();
    error = message = '';
  }

  function formatError(failure) {
    const text = String(failure?.message ?? failure ?? '');
    if (text.includes('ключ восстановления не был настроен')) return 'Для этой версии хранилища ключ восстановления не настроен.';
    if (text.includes('не удалось аутентифицировать ключ восстановления')) return 'Не удалось проверить ключ и контейнер. Проверьте ключ для выбранной версии хранилища.';
    if (text.includes('основной файл доступен')) return 'Основной файл доступен. Снимите отметку о восстановлении из резервной копии.';
    if (text.includes('результат операции с ключом восстановления не подтверждён')) {
      return 'Результат записи не подтверждён. Проверьте вход перед повтором. Если основной файл не открывается, проверьте вход из резервной копии.';
    }
    if (text.includes('подтверждение восстановления по ключу истекло')) return 'Подтверждение истекло. Начните проверку заново.';
    if (text.includes('не совпадают')) return 'Новый мастер-пароль и подтверждение не совпадают.';
    if (text.includes('слишком много неверных кодов')) return 'Слишком много неверных кодов TOTP. Повторите попытку позже.';
    return friendlyBackendError(failure);
  }

  async function submit() {
    if (busy || token || !password || ((recover || action === 'verify') && !key)) return;
    busy = true;
    error = message = '';
    try {
      const pending = recover ? PrepareRecoveryKeyReset(key.trim(), code, password, confirmation, fromBackup)
        : action === 'create' ? CreateRecoveryKey(password, code)
        : action === 'verify' ? VerifyRecoveryKey(password, code, key.trim())
        : DisableRecoveryKey(password, code);
      unsetCredentials();
      const result = await pending;
      if (!alive) { if (recover) cancelToken(result); return; }
      if (recover) token = result;
      else if (action === 'create') printedKey = result;
      else message = action === 'verify' ? 'Ключ подходит к текущему хранилищу.' : 'Восстановление по ключу отключено.';
    } catch (failure) {
      if (!alive) return;
      error = formatError(failure);
      if (!recover) {
        try {
          if (await IsLocked() && alive) dispatch('locked', error);
        } catch { /* Keep diagnostic feedback if the lock status is unavailable. */ }
      }
    } finally {
      if (alive) { busy = false; unsetCredentials(); }
    }
  }

  async function confirmReset() {
    if (!token || busy) return;
    busy = true;
    error = '';
    const confirmationToken = token;
    try {
      await ConfirmRecoveryKeyReset(confirmationToken);
      if (alive) dispatch('reset');
    } catch (failure) {
      if (alive) error = formatError(failure);
    } finally {
      if (alive) { cancelToken(confirmationToken); token = ''; busy = false; }
    }
  }
</script>

<Modal title={recover ? 'Восстановление по ключу' : 'Ключ восстановления'} {busy} on:close>
  {#if printedKey}
    <p>Сохраните ключ вне этого компьютера. PasswordSaver показывает его один раз.</p>
    <label>Новый ключ восстановления
      <input class="key-display" type="text" value={printedKey} readonly autocomplete="off" spellcheck="false" />
    </label>
    <p class="muted">Ключ открывает зашифрованные копии, в которых был настроен. Храните его отдельно от копий.</p>
  {:else if token}
    <p>Контейнер и данные доступа проверены. Подтвердите запись нового мастер-пароля. Использованный ключ перестанет открывать текущее хранилище.</p>
    {#if fromBackup}<p class="warning-text">Записи и настройки TOTP будут восстановлены из .bak. Изменения, сделанные после этой копии, могут отсутствовать.</p>{/if}
  {:else}
    <form id="recovery-key-form" on:submit|preventDefault={submit}>
      {#if recover}
        <p>Введите ключ, который сохранили заранее. Если мастер-пароль забыт и ключа нет, восстановить доступ невозможно.</p>
        <label class="backup-choice">
          <input type="checkbox" bind:checked={fromBackup} disabled={busy} />Использовать .bak, если основной файл отсутствует или повреждён
        </label>
      {:else}
        <label>Действие
          <select value={action} on:change={chooseAction} disabled={busy}>
            <option value="create">Создать или заменить ключ</option>
            <option value="verify">Проверить сохранённый ключ</option>
            <option value="disable">Отключить восстановление по ключу</option>
          </select>
        </label>
        {#if action !== 'verify'}
          <p class="muted">Ранее экспортированные копии и диагностические архивы остаются читаемыми с прежними данными доступа.</p>
        {/if}
      {/if}
      {#if recover || action === 'verify'}
        <label>Сохранённый ключ восстановления
          <input type="password" bind:value={key} autocomplete="off" maxlength="80" disabled={busy} />
        </label>
      {/if}
      <label>{recover ? 'Новый мастер-пароль' : 'Текущий мастер-пароль'}
        <input type="password" bind:value={password} autocomplete={recover ? 'new-password' : 'current-password'} disabled={busy} />
      </label>
      {#if recover}
        <label>Повторите новый мастер-пароль
          <input type="password" bind:value={confirmation} autocomplete="new-password" disabled={busy} />
        </label>
      {/if}
      {#if recover || totpEnabled}
        <label>{recover ? 'Код TOTP выбранной версии, если он включён' : 'Код TOTP'}
          <input type="text" inputmode="numeric" maxlength="6" bind:value={code} autocomplete="one-time-code" disabled={busy} />
        </label>
      {/if}
    </form>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if message}<p role="status">{message}</p>{/if}
  <div class="dialog-buttons">
    <button class="secondary-button" disabled={busy} on:click={() => dispatch('close')}>{printedKey ? 'Готово' : 'Отмена'}</button>
    {#if token}
      <button class="primary-button" disabled={busy} on:click={confirmReset}>Подтвердить смену пароля</button>
    {:else if !printedKey}
      <button type="submit" form="recovery-key-form" class="primary-button"
        disabled={busy || !password || ((recover || action === 'verify') && !key) || (recover && !confirmation)}>
        {busy ? 'Проверка…' : recover ? 'Проверить и подготовить' : action === 'create' ? 'Создать ключ' : action === 'verify' ? 'Проверить ключ' : 'Отключить ключ'}
      </button>
    {/if}
  </div>
</Modal>

<style>
  .backup-choice { display: flex; flex-direction: row; align-items: flex-start; gap: 8px; }
  .key-display { font-family: monospace; }
</style>
