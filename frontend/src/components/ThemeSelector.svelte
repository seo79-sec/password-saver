<script>
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  export let value = 'light';
  const dispatch = createEventDispatcher();
</script>
<div class="theme-options" role="group" aria-label="Тема оформления">
  {#each [{ value:'light', label:'Light', icon:'sun' }, { value:'dark', label:'Dark', icon:'moon' }, { value:'system', label:'System', icon:'devices' }] as theme}
    <button class:chosen={value === theme.value} aria-pressed={value === theme.value} on:click={() => dispatch('change', theme.value)}><Icon name={theme.icon}/>{theme.label}</button>
  {/each}
</div>
