<script>
  import Icon from './Icon.svelte';
  import ThemeSelector from './ThemeSelector.svelte';
  export let theme = 'light';
</script>
<main class="login-layout">
  <header class="login-brand brand"><span class="brand-mark"><Icon name="lock" size={25}/></span><strong>PasswordSaver <span class="version">2.5</span></strong></header>
  <section class="login-card">
    <div class="login-lock"><Icon name="lock" size={32}/></div>
    <h1>Ваши пароли.<br>Только у вас.</h1>
    <p class="muted">Локальное хранилище PasswordSaver Standard</p>
    <slot/>
  </section>
  <footer class="login-footer"><span>Хранится на этом устройстве</span><ThemeSelector value={theme} on:change/></footer>
</main>
