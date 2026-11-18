<script>
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  import { accountLabel } from '../ui.js';
  export let account;
  export let visible = false;
  const dispatch = createEventDispatcher();
  $: label = accountLabel(account);
  function action(event, name, value) { event.currentTarget.closest('details').open = false; dispatch(name, value); }
</script>
<tr>
  <td><div class="service-cell"><span class="service-icon" class:github={label.title.toLowerCase() === 'github'}><Icon name={label.title.toLowerCase() === 'github' ? 'github' : 'globe'} size={27}/></span><div><strong>{label.title}</strong><small>{label.category}</small></div></div></td>
  <td><button class="login-copy" on:click={() => dispatch('copy', account.login)} title="Скопировать логин"><span>{account.login}</span></button></td>
  <td><div class="password-cell"><span class:exposed={visible} class="password-value">{visible ? account.password : '•••••••••••'}</span><button class="icon-button" aria-label={visible ? 'Скрыть пароль' : 'Показать пароль'} aria-pressed={visible} on:click={() => dispatch('toggle', account.id)}><Icon name={visible ? 'eyeOff' : 'eye'} size={19}/></button><button class="icon-button" aria-label="Скопировать пароль" on:click={() => dispatch('copy', account.password)}><Icon name="copy" size={19}/></button></div></td>
  <td class="row-actions"><details><summary class="icon-button" aria-label="Действия с записью"><Icon name="more"/></summary><div class="row-menu"><button on:click={event => action(event, 'edit', account)}><Icon name="edit" size={17}/>Редактировать</button><button class="danger-text" on:click={event => action(event, 'delete', account.id)}><Icon name="trash" size={17}/>Удалить</button></div></details></td>
</tr>
