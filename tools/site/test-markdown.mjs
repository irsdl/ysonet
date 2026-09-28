import test from 'node:test';
import assert from 'node:assert/strict';
import {unified} from '@astrojs/markdown-remark';
import {canonicalMarkdown} from './markdown.mjs';
const manifest = {documents: {'docs/source.md': 'source', 'docs/guide.md': 'guide'},
  assets: {'docs/logo.svg': 'assets/logo.svg'}, publicFiles: ['docs/other.md'],
  base: '/project/', repository: 'https://github.com/irsdl/ysonet', sourceRef: 'a'.repeat(40)};
const renderer = await unified({smartypants: false, remarkPlugins: [[canonicalMarkdown, manifest]]})
  .createRenderer({syntaxHighlight: false});
const render = text => renderer.render(text, {frontmatter: {source: 'docs/source.md'}});
test('structural links, reference definitions, HTML, queries, fragments and literal examples', async () => {
  const text = '# Title.NET\n\n[Guide][g]\n\n[g]: guide.md?q=a#heading\n\n![Logo](logo.svg)\n\n' +
    '<a href="other.md#topic">Source</a>\n\n<img src="logo.svg" alt="Logo">\n\n' +
    '`[literal](guide.md)`\n\n```xml\n<root xmlns="http://example.test/ns">[literal](guide.md)</root>\n```\n\n' +
    'https://example.com/?q=guide.md\n\n## Repeated & heading\n\n## Repeated & heading';
  const {code} = await render(text);
  assert.ok(code.includes('href="/project/guide/?q=a#heading"'));
  assert.ok(code.includes('src="/project/assets/logo.svg"'));
  assert.ok(code.includes('/blob/' + 'a'.repeat(40) + '/docs/other.md#topic'));
  assert.ok(code.includes('[literal](guide.md)'));
  assert.ok(code.includes('http://example.test/ns'));
  assert.ok(code.includes('https://example.com/?q=guide.md'));
  assert.ok(code.includes('id="titlenet"'));
  assert.ok(code.includes('id="repeated--heading-1"'));
  assert.ok(!code.includes('<h1'));
});
test('broken links and unapproved images fail instead of falling back to stale content', async () => {
  await assert.rejects(render('[bad](missing.md)'), /Missing or unpublished/);
  await assert.rejects(render('![bad](other.md)'), /Image must be explicitly published/);
});
