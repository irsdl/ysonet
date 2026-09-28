import path from 'node:path';
import {parseFragment} from 'parse5';

// Work on syntax nodes: examples, fenced code and literal URLs are never rewritten.
export function canonicalMarkdown(manifest) {
  return (tree, file) => {
    const source = file.data.astro?.frontmatter?.source;
    if (!source || file.data.astro.frontmatter.generated || !(source in manifest.documents)) return;
    const publicFiles = new Set(manifest.publicFiles);
    function rewrite(value, image = false) {
      if (/^(?:[a-z][a-z\d+.-]*:|\/\/|#)/i.test(value)) return value;
      const parts = value.match(/^([^?#]*)(.*)$/);
      if (!parts[1]) return value;
      const target = path.posix.normalize(parts[1].startsWith('/') ? decodeURIComponent(parts[1]).slice(1)
        : path.posix.join(path.posix.dirname(source), decodeURIComponent(parts[1])));
      if (manifest.documents[target]) return manifest.base + manifest.documents[target] + '/' + parts[2];
      if (manifest.assets[target]) return manifest.base + manifest.assets[target] + parts[2];
      if (image) throw new Error(`Image must be explicitly published: ${source}: ${target}`);
      if (!publicFiles.has(target) && ![...publicFiles].some(p => p.startsWith(target + '/')))
        throw new Error(`Missing or unpublished repository target: ${source}: ${target}`);
      return manifest.repository + '/blob/' + manifest.sourceRef + '/' + target.split('/').map(encodeURIComponent).join('/') + parts[2];
    }
    const text = node => node.value ?? (node.children || []).map(text).join('');
    const used = new Set();
    function rewriteHtml(value) {
      const replacements = [];
      function walk(node) {
        if (['a', 'img'].includes(node.tagName)) {
          for (const attr of node.attrs || []) {
            if (!(node.tagName === 'a' && attr.name === 'href') && !(node.tagName === 'img' && attr.name === 'src')) continue;
            const location = node.sourceCodeLocation?.attrs?.[attr.name];
            if (!location) continue;
            const url = rewrite(attr.value, node.tagName === 'img').replaceAll('&', '&amp;').replaceAll('"', '&quot;');
            replacements.push({start: location.startOffset, end: location.endOffset, value: `${attr.name}="${url}"`});
          }
        }
        for (const child of node.childNodes || []) walk(child);
      }
      walk(parseFragment(value, {sourceCodeLocationInfo: true}));
      for (const r of replacements.sort((a, b) => b.start - a.start)) value = value.slice(0, r.start) + r.value + value.slice(r.end);
      return value;
    }
    function visit(node) {
      if (node.type === 'html') node.value = rewriteHtml(node.value);
      if (['link', 'image', 'definition'].includes(node.type)) node.url = rewrite(node.url, node.type === 'image');
      if (node.type === 'heading') {
        // Preserve old public heading IDs, including punctuation and duplicate suffixes.
        const base = text(node).toLowerCase().replace(/[^\p{L}\p{N}_\-\s]/gu, '').replace(/[ \t]/g, '-');
        let id = base, n = 0;
        while (used.has(id)) id = base + '-' + (++n);
        used.add(id);
        node.data = {...node.data, hProperties: {...node.data?.hProperties, id}};
        if (node.depth === 1) {
          // Starlight supplies the visible H1. Keep the canonical title's deep link.
          node.type = 'html'; node.value = `<span id="${id}"></span>`; delete node.children;
        }
      }
      for (const child of node.children || []) visit(child);
    }
    visit(tree);
  };
}
