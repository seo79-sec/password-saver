<script>
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  import { accountLabel, CATEGORIES } from '../ui.js';
  export let accounts = [];
  export let query = '';
  export let category = 'Все';
  export let risk = 'all';
  let filtersOpen = false;
  const dispatch = createEventDispatcher();
  $: categories = ['Все', ...new Set([...CATEGORIES, ...accounts.map(a => accountLabel(a).category)])];
</script>
<div class="search-line"><label class="search-input"><Icon name="search" size={22}/><input aria-label="Поиск по записям" placeholder="Поиск по записям…" bind:value={query}/></label><button class="filter-button" class:chosen={filtersOpen || risk !== 'all'} aria-expanded={filtersOpen} aria-label="Фильтрация записей" on:click={() => filtersOpen = !filtersOpen}><Icon name="filter"/></button></div>
{#if filtersOpen}<label class="risk-filter">Состояние пароля<select bind:value={risk}><option value="all">Любое</option><option value="weak">Слабые</option><option value="reused">Повторяющиеся</option><option value="old">Старше 180 дней</option><option value="breached">Найденные в утечках</option></select></label>{/if}
<div class="category-filters" role="group" aria-label="Категории записей">{#each categories as name}<button class:active={category === name} aria-pressed={category === name} on:click={() => category = name}><Icon name={name === 'Все' ? 'layers' : name === 'Финансы' ? 'database' : 'globe'} size={16}/>{name}<span>({name === 'Все' ? accounts.length : accounts.filter(a => accountLabel(a).category === name).length})</span></button>{/each}</div>
