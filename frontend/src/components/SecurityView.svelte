<script>
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  export let audit = { weak: 0, reused: 0, old: 0 };
  export let total = 0;
  export let breached = 0;
  export let breachState = 'idle';
  export let totpEnabled = false;
  export let format = '';
  const dispatch = createEventDispatcher();
</script>
<header class="page-heading"><div><h1>Безопасность</h1><p>Проверьте пароли и настройки защиты</p></div><span class="heading-icon"><Icon name="shield" size={28}/></span></header>
<div class="audit-grid">
  {#each [{ id:'weak', label:'Слабые пароли', value:audit.weak, icon:'warning' }, { id:'reused', label:'Повторяющиеся', value:audit.reused, icon:'copy' }, { id:'old', label:'Старше 180 дней', value:audit.old, icon:'clock' }] as item}
    <button class="audit-card" on:click={() => dispatch('risk', item.id)}><span class="audit-icon" class:attention={item.value > 0}><Icon name={item.icon}/></span><strong class="audit-number">{item.value}</strong><span>{item.label}</span><small>Посмотреть записи <Icon name="chevron" size={14}/></small></button>
  {/each}
</div>
<section class="panel security-section">
  <div class="section-heading"><span class="item-icon"><Icon name="shield"/></span><div><h2>Пароли в утечках</h2><p class="muted">Сетевая проверка Have I Been Pwned</p></div><strong class="breach-number">{['complete','partial'].includes(breachState) ? breached : '—'}</strong></div>
  <p>Проверка выполняется только с вашего согласия. На сервер отправляются первые 5 символов SHA-1 хеша, вычисленного на устройстве. Открытые пароли не отправляются.</p>
  <p class="muted" role="status">{breachState === 'checking' ? 'Проверяем пароли через интернет…' : breachState === 'complete' ? 'Проверка завершена. Результат относится к текущим записям и доступным данным HIBP.' : breachState === 'partial' ? 'Проверка завершена частично: некоторые запросы не удались. Найденные совпадения показаны, остальные пароли не проверены.' : breachState === 'error' ? 'Не удалось завершить проверку. Проверьте подключение и повторите запрос.' : 'Пароли ещё не проверены. Отсутствие результата не означает отсутствие утечек.'}</p>
  <div class="button-row"><button class="primary-button" disabled={breachState === 'checking' || !total} on:click={() => dispatch('check')}><Icon name="search" size={18}/>{breachState === 'checking' ? 'Проверка…' : 'Проверить через интернет'}</button>{#if breachState === 'checking'}<button class="secondary-button" on:click={() => dispatch('cancel')}>Остановить</button>{/if}{#if breached > 0}<button class="secondary-button" on:click={() => dispatch('risk', 'breached')}>Показать найденные</button>{/if}</div>
</section>
<section class="panel security-section"><div class="section-heading"><span class="item-icon"><Icon name="qr"/></span><div><h2>Двухфакторная аутентификация</h2><p class="muted">{totpEnabled ? 'TOTP включён для открытого хранилища.' : 'TOTP пока не включён.'}</p></div><span class="state-chip" class:positive={totpEnabled}>{totpEnabled ? 'Включена' : 'Не включена'}</span></div>{#if !totpEnabled}<button class="secondary-button" on:click={() => dispatch('totp')}>Настроить TOTP</button>{/if}<p class="muted">Для входа используется мастер-пароль{totpEnabled ? ' и код TOTP' : ''}. Восстановление второго фактора — отдельный будущий этап.</p></section>
<section class="panel security-section"><h2>Шифрование и локальная защита</h2><p>Формат: {format || 'не определён'} · AES-256-GCM · Argon2id</p><p class="muted">Хранилище находится на вашем устройстве. Резервную копию следует хранить отдельно. Копия и временные файлы не считаются проверенными до успешной аутентификации.</p><p class="muted">Локальный анализ слабости — эвристика: длина, цифры и символы. Он не гарантирует стойкость пароля.</p></section>
