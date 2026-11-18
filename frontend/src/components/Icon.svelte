<script>
  export let name = 'lock';
  export let size = 20;
  const paths = {
    lock: 'M6 10V7a6 6 0 0 1 12 0v3M5 10h14v12H5zM12 14v4',
    home: 'm3 10 9-7 9 7M5 9v12h5v-7h4v7h5V9',
    layers: 'm3 7 9-5 9 5-9 5-9-5m0 5 9 5 9-5m-18 5 9 5 9-5',
    shield: 'm12 2 9 4v6c0 5-5 9-9 10-4-1-9-5-9-10V6l9-4zm-4 10 3 3 5-6',
    devices: 'M3 4h15v12H3zM7 20h7m-3-4v4m8-11h3v12h-5V9z',
    settings: 'm10 3 4 0 1 3 3 1 3-1 2 4-2 2v3l2 2-2 4-3-1-3 1-1 3h-4l-1-3-3-1-3 1-2-4 2-2v-3l-2-2 2-4 3 1 3-1 1-3zm2 7a4 4 0 1 0 0 8 4 4 0 0 0 0-8',
    search: 'M21 21l-5-5M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14',
    filter: 'M3 4h18l-7 8v7l-4 2v-9L3 4z',
    plus: 'M12 4v16M4 12h16',
    eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zm10-3a3 3 0 1 0 0 6 3 3 0 0 0 0-6',
    eyeOff: 'm3 3 18 18M9 5c7-2 13 7 13 7s-2 3-5 5M6 6c-3 2-4 6-4 6s4 7 10 7l3-1M10 10l4 4',
    copy: 'M9 8h11v13H9zM5 16H3V3h12v2',
    more: 'M5 12h.01M12 12h.01M19 12h.01',
    edit: 'm15 4 5 5-11 11-6 1 1-6L15 4zm-2 2 5 5',
    trash: 'M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7',
    check: 'm5 12 4 4L19 6',
    chevron: 'm9 5 7 7-7 7',
    down: 'm6 9 6 6 6-6',
    close: 'm6 6 12 12M6 18 18 6',
    globe: 'M2 12h20M12 2c6 6 6 14 0 20-6-6-6-14 0-20zm0 0a10 10 0 1 0 0 20 10 10 0 0 0 0-20',
    key: 'M14 4a6 6 0 1 1-3 10l-7 7H2v-4l7-7a6 6 0 0 1 5-6zm2 4h.01',
    qr: 'M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h2v2h4v4h-6v-2m6-7v1m-9 0v7',
    database: 'M3 6c0-5 18-5 18 0s-18 5-18 0zm0 0v12c0 5 18 5 18 0V6M3 12c0 5 18 5 18 0',
    folder: 'M2 6h8l2 3h10v12H2V6z',
    warning: 'm12 3 10 18H2L12 3zm0 6v5m0 3v.01',
    clock: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 4v6l4 2',
    sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 1v3m0 16v3M1 12h3m16 0h3M4 4l2 2m12 12 2 2M4 20l2-2M18 6l2-2',
    moon: 'M20 15A9 9 0 0 1 9 4a9 9 0 1 0 11 11',
    info: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 8v7m0-10v.01',
    logout: 'M9 3H3v18h6m5-14 5 5-5 5M8 12h13',
    github: 'M9 19c-4 1-4-2-6-2m12 5v-4c0-1-1-2-1-2 4 0 7-2 7-6 0-2-1-3-2-4 0-1 0-2-1-3-2 0-4 2-4 2h-4s-2-2-4-2c-1 1-1 2-1 3-1 1-2 2-2 4 0 4 3 6 7 6 0 0-1 1-1 2v4',
  };
</script>
<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={paths[name] || paths.lock}/></svg>
