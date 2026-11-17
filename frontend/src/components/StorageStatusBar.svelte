<script>
  import Icon from './Icon.svelte';
  export let storage;
  export let locked = false;
</script>
<footer class="storage-status">
  <span class="status-lock"><Icon name="lock" size={23}/></span>
  <div><div class="storage-name">Хранилище: <strong>Основное</strong></div><small>Формат: {storage?.format || 'не определён'} <span class="separator">|</span> Алгоритм: {storage?.algorithm || (storage?.format?.startsWith('v1') ? 'AES-256-GCM (v1)' : 'не определён')}</small></div>
  <button class="lock-status" on:click aria-label="Заблокировать хранилище"><span class="status-dot" class:locked></span>{locked ? 'Заблокировано' : 'Разблокировано'}<Icon name="lock" size={18}/></button>
</footer>
