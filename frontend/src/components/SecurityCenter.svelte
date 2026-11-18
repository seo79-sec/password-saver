<script>
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  export let totpEnabled = false;
  export let backupPresent = false;
  export let weak = 0;
  export let reused = 0;
  const dispatch = createEventDispatcher();
</script>
<section class="security-card">
  <header class="security-heading"><span class="shield-mark"><Icon name="shield" size={28}/></span><div><h2>Центр безопасности</h2><p>Сессия разблокирована</p></div></header>
  <button class="security-item" on:click={() => dispatch('security')}><span class="item-icon"><Icon name="qr"/></span><span><strong>TOTP</strong><small>{totpEnabled ? 'Двухфакторная защита включена' : 'Двухфакторная защита не включена'}</small></span><Icon name={totpEnabled ? 'check' : 'chevron'}/></button>
  <button class="security-item" on:click={() => dispatch('vaults')}><span class="item-icon"><Icon name="database"/></span><span><strong>Резервная копия</strong><small>{backupPresent ? 'Копия имеется на устройстве' : 'Наличие копии не подтверждено'}</small></span><Icon name={backupPresent ? 'check' : 'warning'}/></button>
  <button class="security-item" on:click={() => dispatch('security')}><span class="item-icon"><Icon name="key"/></span><span><strong>Анализ паролей</strong><small>{weak} слабых · {reused} повторяющихся</small></span><Icon name="chevron"/></button>
  <p class="security-footnote">Наличие копии не подтверждает её целостность.</p>
</section>
<button class="phone-card" on:click={() => dispatch('phone')}><Icon name="qr" size={33}/><span><strong>Подключить телефон</strong><small>Безопасное подключение по QR-коду — PasswordSaver 3.0</small></span><Icon name="chevron"/></button>
