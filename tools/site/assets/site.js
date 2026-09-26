'use strict';
(() => {
  const base = document.body.dataset.base;
  const theme = document.querySelector('#theme');
  const themeNames = ['system', 'light', 'dark'];
  function themeLabel() {
    const current = document.documentElement.dataset.theme;
    theme.textContent = `Theme: ${current}`;
    theme.setAttribute('aria-label', `Color theme: ${current}. Switch to ${themeNames[(themeNames.indexOf(current) + 1) % 3]}.`);
  }
  theme.hidden = false;
  themeLabel();
  theme.addEventListener('click', () => {
    const next = themeNames[(themeNames.indexOf(document.documentElement.dataset.theme) + 1) % 3];
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('ysonet-theme', next); } catch (_) { /* Preference lasts this page. */ }
    themeLabel();
  });
  const navigation = document.querySelector('.navigation');
  const narrow = matchMedia('(max-width: 850px)');
  function setNavigation() {
    navigation.open = !narrow.matches;
    document.querySelectorAll('.contents').forEach(contents => { contents.open = !narrow.matches; });
  }
  setNavigation();
  narrow.addEventListener('change', setNavigation);
  document.addEventListener('keydown', event => {
    if (event.key === '/' && !event.ctrlKey && !event.metaKey && !event.altKey &&
        !event.target.closest('input, textarea, select, [contenteditable="true"]')) {
      event.preventDefault();
      const input = document.querySelector('#search-query');
      if (input) input.focus(); else location.href = base + 'search/';
    }
  });
  // Copy exactly the displayed code; never execute it.
  document.querySelectorAll('pre > code').forEach(code => {
    if (!navigator.clipboard) return;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy';
    button.textContent = 'Copy';
    button.setAttribute('aria-label', 'Copy code');
    button.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(code.textContent); button.textContent = 'Copied'; }
      catch (_) { button.textContent = 'Select text to copy'; }
      setTimeout(() => { button.textContent = 'Copy'; }, 2000);
    });
    code.parentElement.append(button);
  });
  const query = document.querySelector('#catalog-query');
  if (query) {
    const kind = document.querySelector('#catalog-kind');
    const formatter = document.querySelector('#catalog-formatter');
    const cards = [...document.querySelectorAll('.module-card')];
    const params = new URLSearchParams(location.search);
    query.value = params.get('q') || '';
    kind.value = params.get('type') || '';
    formatter.value = params.get('formatter') || '';
    function filter(updateUrl = true) {
      const words = query.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
      let count = 0;
      cards.forEach(card => {
        card.hidden = !(words.every(word => card.dataset.search.includes(word)) &&
          (!kind.value || card.dataset.kind === kind.value) &&
          (!formatter.value || JSON.parse(card.dataset.formatters).includes(formatter.value)));
        if (!card.hidden) count++;
      });
      document.querySelector('#catalog-count').textContent = `${count} of ${cards.length} modules`;
      document.querySelector('#catalog-empty').hidden = count !== 0;
      if (updateUrl) {
        const state = new URLSearchParams();
        if (query.value) state.set('q', query.value);
        if (kind.value) state.set('type', kind.value);
        if (formatter.value) state.set('formatter', formatter.value);
        history.replaceState(null, '', location.pathname + (state.size ? '?' + state : ''));
      }
    }
    document.querySelector('#catalog-filters').hidden = false;
    [query, kind, formatter].forEach(input => input.addEventListener('input', () => filter()));
    filter(false);
  }
  const form = document.querySelector('#search-form');
  if (form) {
    const input = document.querySelector('#search-query');
    const status = document.querySelector('#search-status');
    const list = document.querySelector('#search-results');
    let index;
    let request = 0;
    input.value = new URLSearchParams(location.search).get('q') || '';
    async function search() {
      const current = ++request;
      const terms = input.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
      list.replaceChildren();
      const params = new URLSearchParams();
      if (input.value) params.set('q', input.value);
      history.replaceState(null, '', location.pathname + (params.size ? '?' + params : ''));
      if (!terms.length) { status.textContent = 'Enter a few words to find a guide or module.'; return; }
      status.textContent = 'Searching...';
      try {
        if (!index) {
          const response = await fetch(base + 'search-index.json');
          if (!response.ok) throw new Error('Search unavailable');
          index = await response.json();
        }
        if (current !== request) return;
        const matches = index.map(page => ({page, title: page.title.toLocaleLowerCase(), text: page.text.toLocaleLowerCase()}))
          .filter(row => terms.every(term => (row.title + ' ' + row.text).includes(term)))
          .sort((a, b) => terms.filter(t => b.title.includes(t)).length - terms.filter(t => a.title.includes(t)).length);
        status.textContent = matches.length ? `${matches.length} results${matches.length > 40 ? ' (showing the first 40)' : ''}` : 'No results. Try fewer words or browse All guides.';
        matches.slice(0, 40).forEach(({page, text}) => {
          const li = document.createElement('li');
          const link = document.createElement('a');
          // The build creates only local URLs. Keep this boundary if the index is replaced.
          if (!page.url.startsWith(base) || page.url.startsWith('//')) return;
          link.href = page.url;
          link.textContent = page.title;
          const summary = document.createElement('p');
          const offset = Math.max(0, text.indexOf(terms[0]) - 65);
          summary.textContent = (offset ? '... ' : '') + page.text.slice(offset, offset + 220) + '...';
          li.append(link, summary);
          list.append(li);
        });
      } catch (_) {
        if (current === request) status.textContent = 'Search could not load. Try again, or browse All guides.';
      }
    }
    form.addEventListener('submit', event => { event.preventDefault(); search(); });
    search();
  }
})();
