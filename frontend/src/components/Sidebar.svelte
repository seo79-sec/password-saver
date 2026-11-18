<script>
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  import { NAVIGATION } from '../ui.js';
  export let active = 'passwords';
  const dispatch = createEventDispatcher();
</script>
<aside class="sidebar">
  <a class="brand" href="#passwords" on:click|preventDefault={() => dispatch('navigate', 'passwords')}><span class="brand-mark"><Icon name="lock" size={23}/></span><strong>PasswordSaver</strong></a>
  <nav aria-label="Основная навигация">
    {#each NAVIGATION as item}
      <button class:active={active === item.id} aria-current={active === item.id ? 'page' : undefined} on:click={() => dispatch('navigate', item.id)} title={item.label}><Icon name={item.icon} size={23}/><span>{item.label}</span></button>
    {/each}
  </nav>
  <div class="sidebar-bottom"><span class="edition-badge">STANDARD</span><small>Локально. Под вашим контролем.</small><button class="text-button" on:click={() => dispatch('lock')}><Icon name="logout" size={18}/><span>Заблокировать</span></button></div>
</aside>
