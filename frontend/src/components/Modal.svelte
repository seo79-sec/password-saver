<script context="module">
  const overlays = new Set();
  const originalInert = new Map();
  let originalOverflow;
  function updateBackground(root) {
    const top = [...overlays].at(-1);
    if (top) {
      for (const node of root.children) {
        if (!originalInert.has(node)) originalInert.set(node, node.inert);
        node.inert = node !== top;
      }
    } else {
      for (const [node, value] of originalInert) node.inert = value;
      originalInert.clear();
      document.body.style.overflow = originalOverflow;
    }
  }
</script>
<script>
  import { createEventDispatcher, onMount, tick } from 'svelte';
  import Icon from './Icon.svelte';
  export let title = '';
  export let busy = false;
  const dispatch = createEventDispatcher();
  let panel;
  const close = () => { if (!busy) dispatch('close'); };
  onMount(() => {
    const active = document.activeElement;
    const previous = active?.closest('details')?.querySelector('summary') || active;
    const overlay = panel.closest('.modal-overlay');
    if (!overlays.size) originalOverflow = document.body.style.overflow;
    overlays.add(overlay); updateBackground(overlay.parentElement);
    // aria-modal plus focus trapping keeps keyboard navigation in this dialog.
    tick().then(() => panel?.querySelector('input, select, textarea, button:not(.modal-close)')?.focus());
    const keydown = event => {
      if ([...overlays].at(-1) !== overlay) return;
      if (event.key === 'Escape') { event.preventDefault(); event.stopImmediatePropagation(); close(); }
      if (event.key !== 'Tab') return;
      const focusable = [...panel.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]')].filter(el => el.getClientRects().length);
      if (!focusable.length) { event.preventDefault(); panel.focus(); return; }
      const first = focusable[0], last = focusable[focusable.length-1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.body.style.overflow = 'hidden';
    document.addEventListener('keydown', keydown, true);
    return () => {
      document.removeEventListener('keydown', keydown, true);
      overlays.delete(overlay); updateBackground(overlay.parentElement);
      if (previous?.isConnected) previous.focus();
    };
  });
</script>
<div class="modal-overlay" role="presentation" on:click|self={close}>
  <section bind:this={panel} class="modal-panel" role="dialog" aria-modal="true" aria-label={title} tabindex="-1">
    <header class="modal-header"><h2>{title}</h2><button class="icon-button modal-close" aria-label="Закрыть окно" disabled={busy} on:click={close}><Icon name="close"/></button></header>
    <slot/>
  </section>
</div>
