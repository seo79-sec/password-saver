<script>
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  import StorageDiagnostics from './StorageDiagnostics.svelte';
  export let storage;
  export let vault;
  export let exportBusy = false;
  const dispatch = createEventDispatcher();
</script>
<header class="page-heading"><div><h1>Хранилища</h1><p>Текущее локальное хранилище</p></div></header>
<section class="panel storage-panel"><div class="section-heading"><span class="brand-mark"><Icon name="lock"/></span><div><h2>Основное</h2><p class="muted">Стандартный vault на этом устройстве</p></div><span class="state-chip positive">Разблокировано</span></div>
  <dl class="storage-details"><div><dt>Расположение</dt><dd><code>{storage?.path || 'Не удалось определить'}</code></dd></div><div><dt>Формат</dt><dd>{storage?.format || 'Не определён'}</dd></div><div><dt>Алгоритм</dt><dd>AES-256-GCM</dd></div><div><dt>Резервная копия</dt><dd>{storage?.backupPresent ? 'Имеется на устройстве' : 'Наличие не подтверждено'}</dd></div><div><dt>Служебные файлы</dt><dd>{storage?.temporaryFiles || 0}</dd></div></dl>
  <p class="muted">Наличие backup не подтверждает её целостность или актуальность. Восстановление доступно на экране входа и требует отдельного подтверждения.</p><button class="secondary-button" on:click><Icon name="folder" size={18}/>Открыть папку хранилища</button>
  {#if vault?.state === 'v2-active'}
    <button class="secondary-button" disabled={exportBusy} on:click={() => dispatch('export')}>
      {exportBusy ? 'Сохранение копии…' : 'Экспортировать зашифрованную копию'}
    </button>
    <p class="muted">Копия открывается мастер-паролем, действовавшим при экспорте. Храните её отдельно и удаляйте устаревшие копии самостоятельно.</p>
  {/if}
</section>
<section class="panel storage-panel"><h2>Формат хранилища</h2><p class="muted">{vault?.state === 'v2-active' ? 'Активен v2. Автоматического отката к v1 не будет.' : vault?.state === 'v1-prepared' ? 'Переход к v2 подготовлен и ожидает вашего решения.' : 'Активен совместимый формат v1.'}</p><slot/></section>
<section class="panel storage-panel"><h2>Один vault, ваши данные</h2><p class="muted">«Основное» — название текущего стандартного хранилища. Несколько хранилищ и подключение устройств здесь пока не поддерживаются.</p></section>
