<script>
  import Icon from './Icon.svelte';
  import { storageDiagnosticNotice } from '../security.js';
  export let status;
  $: notice = storageDiagnosticNotice(status);
</script>
{#if notice}
  <section class="notice" class:danger={notice.kind === 'blocked'} role="status"><Icon name="warning"/><div><strong>Диагностика хранилища</strong><p>{notice.message}</p>{#if notice.canOpenFolder}<button class="text-button" on:click>Открыть папку хранилища</button>{/if}</div></section>
{/if}
