<script>
  import { createEventDispatcher } from 'svelte';
  import Modal from './Modal.svelte';

  export let requiresTOTP = false;
  export let busy = false;

  const dispatch = createEventDispatcher();
  let code = '';
  $: canConfirm = !busy && (!requiresTOTP || /^\d{6}$/.test(code));

  function confirm() {
    if (!canConfirm) return;
    const submittedCode = code;
    code = '';
    dispatch('confirm', submittedCode);
  }
</script>

<Modal title="Восстановить хранилище v2?" {busy} on:close>
  <p class="dialog-message">Резервная копия проверена этим мастер-паролем. Текущий основной файл будет сохранён для диагностики, затем его заменит копия. Изменения после создания копии могут быть потеряны. Настройки защиты будут восстановлены из копии. Селектор останется на v2.</p>
  {#if !requiresTOTP}
    <p class="warning-text">В этой копии TOTP выключен. После восстановления он останется выключенным, даже если был включён в основном хранилище.</p>
  {/if}
  <form on:submit|preventDefault={confirm}>
    {#if requiresTOTP}
      <label class="migration-label">Код TOTP
        <input type="text" bind:value={code} inputmode="numeric" maxlength="6" autocomplete="one-time-code" disabled={busy} />
      </label>
    {/if}
    <div class="dialog-buttons">
      <button type="button" class="secondary-button" disabled={busy} on:click={() => dispatch('close')}>Отмена</button>
      <button class="primary-button" disabled={!canConfirm}>{busy ? 'Восстановление…' : 'Подтвердить'}</button>
    </div>
  </form>
</Modal>
