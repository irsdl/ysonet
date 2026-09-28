// Validate before replacing staging or a valid published artifact. A content loader
// can retain an old cached entry after a parse error, so validation must fail itself.
import {unified} from '@astrojs/markdown-remark';
import {canonicalMarkdown} from './markdown.mjs';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const {manifest, pages} = JSON.parse(input);
const renderer = await unified({smartypants: false, remarkPlugins: [[canonicalMarkdown, manifest]]})
  .createRenderer({syntaxHighlight: false});
for (const [frontmatter, body] of pages) await renderer.render(body, {frontmatter});
