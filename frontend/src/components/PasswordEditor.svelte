<script>
  import { createEventDispatcher } from 'svelte';
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import { CATEGORIES } from '../ui.js';
  export let title = '';
  export let login = '';
  export let password = '';
  export let category = 'Общие';
  export let editing = false;
  export let busy = false;
  let visible = false;
  let genLength = 16, genNumbers = true, genSymbols = true;
  const dispatch = createEventDispatcher();
</script>
<Modal title={editing ? 'Редактировать запись' : 'Добавить пароль'} {busy} on:close>
  <form on:submit|preventDefault={() => dispatch('save')}>
    <label>Название<input bind:value={title} autocomplete="off" required placeholder="Например, GitHub"/></label>
    <label>Логин<input bind:value={login} autocomplete="off" required placeholder="Имя пользователя или email"/></label>
    <label>Пароль<span class="input-with-action"><input type={visible ? 'text' : 'password'} value={password} on:input={e => password = e.target.value} autocomplete="new-password" required/><button type="button" class="icon-button" aria-label={visible ? 'Скрыть пароль в форме' : 'Показать пароль в форме'} on:click={() => visible = !visible}><Icon name={visible ? 'eyeOff' : 'eye'}/></button></span></label>
    <label>Категория<select bind:value={category}>{#each [...new Set([...CATEGORIES, category])] as value}<option>{value}</option>{/each}</select></label>
    <details class="generator"><summary><Icon name="key" size={17}/>Генератор паролей</summary><label>Длина: {genLength}<input type="range" min="8" max="32" bind:value={genLength}/></label><div class="checkbox-row"><label><input type="checkbox" bind:checked={genNumbers}/>Цифры</label><label><input type="checkbox" bind:checked={genSymbols}/>Символы</label></div><button type="button" class="secondary-button" on:click={() => dispatch('generate', { length: genLength, numbers: genNumbers, symbols: genSymbols })}>Сгенерировать</button></details>
    <footer class="dialog-buttons"><button type="button" class="secondary-button" disabled={busy} on:click={() => dispatch('close')}>Отмена</button><button class="primary-button" disabled={busy}>{busy ? 'Сохранение…' : 'Сохранить запись'}</button></footer>
  </form>
</Modal>
