<script>
  import ThemeSelector from './ThemeSelector.svelte';
  import { createEventDispatcher } from 'svelte';
  import { IDLE_MINUTES, CLIPBOARD_SECONDS } from '../security.js';
  export let theme, idleMinutes, clipboardSeconds;
  export let canChangeMasterPassword = false;
  export let vaultState = '';
  const dispatch = createEventDispatcher();
</script>
<header class="page-heading"><div><h1>Настройки</h1><p>Подстройте PasswordSaver под себя</p></div></header>
<section class="panel settings-section">
  <h2>Безопасность аккаунта</h2>
  {#if vaultState === 'v1-active' || vaultState === 'v1-prepared'}
    <p class="muted">Для смены мастер-пароля сначала перейдите на формат v2 во вкладке «Хранилища».</p>
  {/if}
  <button class="secondary-button" disabled={!canChangeMasterPassword} on:click={() => dispatch('changePassword')}>Изменить мастер-пароль</button>
</section>
<section class="panel settings-section"><h2>Оформление</h2><p class="muted">System автоматически следует цветовой схеме устройства.</p><ThemeSelector value={theme} on:change={e => dispatch('theme', e.detail)}/></section>
<section class="panel settings-section"><h2>Блокировка и буфер обмена</h2><label>Автоматическая блокировка<select value={idleMinutes} on:change={e => dispatch('idle', Number(e.currentTarget.value))}>{#each IDLE_MINUTES as minutes}<option value={minutes}>{minutes} мин.</option>{/each}</select></label><label>Очистка скопированного пароля<select value={clipboardSeconds} on:change={e => dispatch('clipboard', Number(e.currentTarget.value))}>{#each CLIPBOARD_SECONDS as seconds}<option value={seconds}>{seconds} сек.</option>{/each}</select></label><p class="muted">Буфер очищается, только если в нём остался тот же пароль.</p></section>
<section class="panel settings-section"><h2>О программе</h2><p>PasswordSaver Standard · AES-256-GCM</p><p class="muted">Локальный менеджер паролей. Интерфейс 2.5; подключение устройств планируется в 3.0.</p><button class="secondary-button" on:click={() => dispatch('about')}>Информация о проекте</button></section>
