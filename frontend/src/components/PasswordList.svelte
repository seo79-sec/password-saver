<script>
  import Icon from './Icon.svelte';
  import PasswordRow from './PasswordRow.svelte';
  export let accounts = [];
  export let total = 0;
  export let visibleIDs = new Set();
</script>
<div class="table-container">
  <table><thead><tr><th scope="col">Название</th><th scope="col">Логин</th><th scope="col">Пароль</th><th scope="col"><span class="sr-only">Действия</span></th></tr></thead>
    <tbody>{#each accounts as account (account.id)}<PasswordRow {account} visible={visibleIDs.has(account.id)} on:copy on:toggle on:edit on:delete/>{/each}</tbody>
  </table>
  {#if !accounts.length}<div class="empty-state"><Icon name={total ? 'search' : 'key'} size={35}/><h3>{total ? 'Ничего не найдено' : 'Здесь будут ваши пароли'}</h3><p>{total ? 'Попробуйте другой запрос или категорию.' : 'Добавьте первую запись. Она сохранится только в локальном хранилище.'}</p></div>{/if}
</div>
