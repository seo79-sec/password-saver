<script>
  import Sidebar from './Sidebar.svelte';
  export let active;
</script>
<div class="app-shell">
  <Sidebar {active} on:navigate on:lock/>
  <main class="workspace"><slot/></main>
  <aside class="security-rail" aria-label="Центр безопасности"><slot name="security"/></aside>
</div>
