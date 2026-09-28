function setupCatalog() {
  const query = document.querySelector<HTMLInputElement>('#catalog-query');
  if (!query) return;
  const kind = document.querySelector<HTMLSelectElement>('#catalog-kind')!;
  const formatter = document.querySelector<HTMLSelectElement>('#catalog-formatter')!;
  const cards = [...document.querySelectorAll<HTMLElement>('.module-card')];
  function filter() {
    const words = query!.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
    let count = 0;
    for (const card of cards) {
      card.hidden = !(words.every(word => card.dataset.search!.includes(word)) &&
        (!kind.value || card.dataset.kind === kind.value) &&
        (!formatter.value || JSON.parse(card.dataset.formatters!).includes(formatter.value)));
      if (!card.hidden) count++;
    }
    document.querySelector('#catalog-count')!.textContent = `${count} of ${cards.length} modules`;
    document.querySelector<HTMLElement>('#catalog-empty')!.hidden = count !== 0;
  }
  function restore() {
    const params = new URLSearchParams(location.search);
    query!.value = params.get('q') || '';
    kind.value = params.get('type') || '';
    const requested = params.get('formatter') || '';
    // Existing shared links use both Json.Net and the catalog's Json.NET spelling.
    const canonical = [...formatter.options].find(option => option.value.toLowerCase() === requested.toLowerCase());
    if (requested && !canonical) formatter.add(new Option(requested, requested));
    formatter.value = canonical?.value ?? requested;
    filter();
  }
  document.querySelector<HTMLElement>('#catalog-filters')!.hidden = false;
  for (const input of [query, kind, formatter]) input.addEventListener('input', () => {
    const params = new URLSearchParams();
    if (query.value) params.set('q', query.value);
    if (kind.value) params.set('type', kind.value);
    if (formatter.value) params.set('formatter', formatter.value);
    history.pushState(null, '', location.pathname + (params.size ? '?' + params : ''));
    filter();
  });
  addEventListener('popstate', restore);
  restore();
}

async function setupSearch() {
  const form = document.querySelector<HTMLFormElement>('#search-form');
  if (!form) return;
  const query = document.querySelector<HTMLInputElement>('#search-query')!;
  const status = document.querySelector('#search-status')!;
  const list = document.querySelector('#search-results')!;
  const base = import.meta.env.BASE_URL;
  let pagefind: any;
  let request = 0;
  async function search() {
    const current = ++request;
    list.replaceChildren();
    if (!query.value.trim()) { status.textContent = 'Enter a few words to find a guide or module.'; return; }
    status.textContent = 'Searching...';
    try {
      pagefind ??= await import(/* @vite-ignore */ base + 'pagefind/pagefind.js');
      const found = await pagefind.search(query.value);
      const results = await Promise.all(found.results.slice(0, 40).map((r: any) => r.data()));
      if (current !== request) return;
      status.textContent = found.results.length ? `${found.results.length} results` : 'No results. Try fewer words or browse All guides.';
      for (const result of results) {
        const url = new URL(result.url, location.origin);
        if (url.origin !== location.origin || !url.pathname.startsWith(base)) throw new Error('Non-local search target');
        const li = document.createElement('li'), link = document.createElement('a'), summary = document.createElement('p');
        link.href = url.href; link.textContent = result.meta.title;
        // Pagefind excerpts contain highlights. Keep only text, never insert index HTML.
        summary.textContent = new DOMParser().parseFromString(result.excerpt, 'text/html').body.textContent;
        li.append(link, summary); list.append(li);
      }
    } catch { if (current === request) status.textContent = 'Search could not load. Try again, or browse All guides.'; }
  }
  function restore() { query.value = new URLSearchParams(location.search).get('q') || ''; search(); }
  form.addEventListener('submit', event => {
    event.preventDefault();
    const params = new URLSearchParams(); if (query.value) params.set('q', query.value);
    history.pushState(null, '', location.pathname + (params.size ? '?' + params : '')); search();
  });
  addEventListener('popstate', restore); restore();
}
setupCatalog(); setupSearch();
document.addEventListener('keydown', event => {
  if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey ||
      (event.target as Element)?.closest('input, textarea, select, [contenteditable="true"]')) return;
  event.preventDefault();
  const input = document.querySelector<HTMLInputElement>('#search-query');
  if (input) input.focus(); else location.href = import.meta.env.BASE_URL + 'search/';
});
