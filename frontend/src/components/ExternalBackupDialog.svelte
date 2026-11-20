<script>
  import { createEventDispatcher, onDestroy } from 'svelte';
  import Modal from './Modal.svelte';
  import { accountLabel } from '../ui.js';
  import { friendlyBackendError } from '../security.js';
  import {
    SelectExternalV2Import, CheckSelectedExternalV2Backup, ConfirmExternalV2Import, CancelExternalV2Import, IsLocked,
  } from '../../wailsjs/go/main/App.js';

  export let forImport = false;
  const dispatch = createEventDispatcher();
  let alive = true;
  let busy = false;
  let selection;
  let review;
  let password = '';
  let code = '';
  let error = '';
  let chosen = {};
  let separate = {};
  $: hasChoices = review?.records?.some(row => chosen[row.index]);

  function cancelToken(token) {
    if (token) CancelExternalV2Import(token).catch(() => {});
  }

  onDestroy(() => {
    alive = false;
    cancelToken(review?.token || selection?.token);
    password = code = '';
    selection = review = null;
    chosen = separate = {};
  });

  async function showFailure(failure) {
    if (!alive) return;
    const message = String(failure?.message ?? failure ?? '');
    if (message.includes('v2 vault authentication failed')) {
      error = 'Не удалось аутентифицировать копию. Проверьте пароль и исходный файл.';
    } else if (message.includes('слишком много неверных кодов 2FA')) {
      error = 'Слишком много неверных кодов TOTP. Повторите попытку позже.';
    } else if (message.includes('синхронизация каталога не подтверждена')) {
      error = 'Результат записи не подтверждён. Проверьте записи после входа перед повтором импорта.';
    } else if (message.includes('выберите файл заново')) {
      error = 'Проверка копии истекла. Выберите файл заново.';
    } else if (message.includes('10 000 записей')) {
      error = 'В копии больше 10 000 записей. Предпросмотр импорта недоступен.';
    } else {
      error = friendlyBackendError(failure);
    }
    try {
      if (await IsLocked() && alive) dispatch('locked', error);
    } catch { /* Keep the current error if the lock state cannot be queried. */ }
  }

  async function pickFile() {
    if (busy || selection || review) return;
    busy = true;
    error = '';
    try {
      const picked = await SelectExternalV2Import(forImport);
      if (!alive) { cancelToken(picked?.token); return; }
      if (picked?.token) selection = picked;
    } catch (failure) {
      await showFailure(failure);
    } finally {
      if (alive) busy = false;
    }
  }

  async function checkFile() {
    if (busy || !selection || !password) return;
    busy = true;
    error = '';
    try {
      const pending = CheckSelectedExternalV2Backup(selection.token, password, code);
      password = code = '';
      const result = await pending;
      if (!alive) { cancelToken(result?.token); return; }
      review = result;
      selection = null;
    } catch (failure) {
      if (alive) {
        cancelToken(selection?.token);
        selection = null;
        await showFailure(failure);
      }
    } finally {
      if (alive) {
        busy = false;
        password = code = '';
      }
    }
  }

  async function importChoices() {
    if (busy || !review?.token || !hasChoices) return;
    busy = true;
    error = '';
    const token = review.token;
    const choices = review.records.filter(row => chosen[row.index])
      .map(row => ({ index: row.index, separate: separate[row.index] === true }));
    dispatch('writing', true);
    try {
      const count = await ConfirmExternalV2Import(token, choices);
      if (alive) dispatch('complete', count);
    } catch (failure) {
      if (alive) {
        cancelToken(token);
        review = null;
        chosen = separate = {};
        await showFailure(failure);
      }
    } finally {
      if (alive) {
        busy = false;
        dispatch('writing', false);
      }
    }
  }
</script>

<Modal title={forImport ? 'Импорт записей из копии v2' : 'Проверка целостности копии v2'} {busy} on:close>
  {#if review}
    <p class="dialog-message">Проверенная копия <strong>{review.fileName}</strong>. Записей: {review.accountCount}. TOTP: {review.totpEnabled ? 'включён' : 'выключен'}.</p>
    {#if forImport}
      {#if review.accountCount > 0}
        <p class="dialog-message">Выберите записи. Совпадения ищутся по названию и логину. Существующие записи и настройки хранилища сохраняются.</p>
        <ul class="import-records">
          {#each review.records as row (row.index)}
            {@const label = accountLabel(row)}
            <li>
              <label class="choice">
                <input type="checkbox" bind:checked={chosen[row.index]} disabled={busy} />
                <span><strong>{label.title || 'Без названия'}</strong>{#if row.login}<br />{row.login}{/if}</span>
              </label>
              {#if row.conflict}
                <label class="conflict">Совпадение
                  <select bind:value={separate[row.index]} disabled={busy || !chosen[row.index]}>
                    <option value={false}>Пропустить при совпадении</option>
                    <option value={true}>Создать отдельную запись</option>
                  </select>
                </label>
              {/if}
            </li>
          {/each}
        </ul>
      {:else}
        <p>В копии нет записей для импорта.</p>
      {/if}
    {:else}
      <p role="status">Целостность копии подтверждена. Файлы не менялись.</p>
    {/if}
  {:else if selection}
    <p class="dialog-message">{selection.fileName}</p>
    <form id="external-backup-check" on:submit|preventDefault={checkFile}>
      <label>Мастер-пароль копии
        <input type="password" bind:value={password} autocomplete="current-password" disabled={busy} />
      </label>
      <label>Код TOTP копии, если он был включён
        <input type="text" bind:value={code} inputmode="numeric" maxlength="6" autocomplete="one-time-code" disabled={busy} />
      </label>
    </form>
  {:else}
    <p class="dialog-message">{forImport ? 'Выберите внешнюю зашифрованную копию. Запись начнётся только после отдельного подтверждения.' : 'Выберите внешнюю зашифрованную копию для проверки без записи.'}</p>
    <button type="button" class="secondary-button" disabled={busy} on:click={pickFile}>Выбрать файл</button>
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <div class="dialog-buttons">
    <button type="button" class="secondary-button" disabled={busy} on:click={() => dispatch('close')}>{review && !forImport ? 'Готово' : 'Отмена'}</button>
    {#if review && forImport && review.accountCount > 0}
      <button class="primary-button" disabled={busy || !hasChoices} on:click={importChoices}>{busy ? 'Импорт…' : 'Подтвердить импорт'}</button>
    {:else if selection}
      <button type="submit" form="external-backup-check" class="primary-button" disabled={busy || !password}>Проверить копию</button>
    {/if}
  </div>
</Modal>

<style>
  .import-records { list-style: none; padding: 0; margin: 0; }
  .import-records li { border-top: 1px solid var(--border); padding: 12px 0; overflow-wrap: anywhere; }
  .choice { display: flex; flex-direction: row; align-items: flex-start; gap: 10px; margin: 0; }
  .conflict { margin: 8px 0 0 24px; color: var(--warning); }
</style>
