<script>
  import { createEventDispatcher } from 'svelte';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';

  export let busy = false;
  export let error = '';
  export let totpEnabled = false;

  const dispatch = createEventDispatcher();
  const fields = [
    { key: 'current', label: 'Текущий мастер-пароль', autocomplete: 'current-password' },
    { key: 'next', label: 'Новый мастер-пароль', autocomplete: 'new-password' },
    { key: 'confirmation', label: 'Повтор нового мастер-пароля', autocomplete: 'new-password' },
  ];
  let passwords = { current: '', next: '', confirmation: '' };
  let visible = {};
  let totpCode = '';
  let validationError = '';

  function submit() {
    if (busy) return;
    if (!passwords.current) validationError = 'Введите текущий мастер-пароль.';
    else if ([...passwords.next].length < 12) validationError = 'Введите не менее 12 символов для нового пароля.';
    else if (passwords.next === passwords.current) validationError = 'Новый мастер-пароль должен отличаться от текущего.';
    else if (passwords.confirmation !== passwords.next) validationError = 'Новые пароли не совпадают.';
    else if (totpEnabled && !/^\d{6}$/.test(totpCode)) validationError = 'Введите шестизначный код TOTP.';
    else {
      validationError = '';
      const request = { ...passwords, totpCode };
      passwords = { current: '', next: '', confirmation: '' };
      totpCode = '';
      visible = {};
      dispatch('changePassword', request);
    }
  }
</script>

<Modal title="Изменить мастер-пароль" {busy} on:close>
  <p class="dialog-message">Резервная копия будет обновлена до текущего состояния хранилища. После смены войдите с новым паролем. Старый пароль по-прежнему может открывать копии, сделанные до смены.</p>
  <form on:submit|preventDefault={submit}>
    {#each fields as field}
      <label class="migration-label" for={'master-change-' + field.key}>{field.label}</label>
      <span class="input-with-action">
        <input id={'master-change-' + field.key} type={visible[field.key] ? 'text' : 'password'} autocomplete={field.autocomplete}
          value={passwords[field.key]} on:input={event => passwords[field.key] = event.currentTarget.value} disabled={busy} />
        <button type="button" class="icon-button" disabled={busy} aria-pressed={!!visible[field.key]}
          aria-label={(visible[field.key] ? 'Скрыть: ' : 'Показать: ') + field.label}
          on:click={() => visible[field.key] = !visible[field.key]}>
          <Icon name={visible[field.key] ? 'eyeOff' : 'eye'}/>
        </button>
      </span>
    {/each}
    {#if totpEnabled}
      <label class="migration-label">Код TOTP
        <input type="text" bind:value={totpCode} inputmode="numeric" maxlength="6" autocomplete="one-time-code" disabled={busy} />
      </label>
    {/if}
    {#if validationError || error}<p class="error" role="alert">{validationError || error}</p>{/if}
    <footer class="dialog-buttons">
      <button class="secondary-button" type="button" disabled={busy} on:click={() => dispatch('close')}>Отмена</button>
      <button class="primary-button" disabled={busy}>{busy ? 'Смена пароля…' : 'Сменить пароль'}</button>
    </footer>
  </form>
</Modal>
