import {defineConfig} from 'astro/config';
import starlight from '@astrojs/starlight';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {canonicalMarkdown} from './markdown.mjs';
import {unified} from '@astrojs/markdown-remark';

const prepared = JSON.parse(readFileSync(new URL('./generated/manifest.json', import.meta.url)));
const socialImage = new URL(`${prepared.base}assets/logo-social.png`, prepared.siteUrl).href;
export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  outDir: new URL('../../dist/site/', import.meta.url),
  site: prepared.siteUrl,
  base: prepared.base,
  trailingSlash: 'always',
  output: 'static',
  markdown: {processor: unified({smartypants: false, remarkPlugins: [[canonicalMarkdown, prepared]]})},
  integrations: [starlight({
    title: 'YSoNet',
    description: '.NET deserialization research: installation, usage, module declarations and runtime evidence.',
    logo: {src: './public/assets/logo-header.svg'},
    favicon: '/assets/logo.svg',
    head: [
      {tag: 'meta', attrs: {name: 'twitter:card', content: 'summary'}},
      {tag: 'meta', attrs: {property: 'og:image', content: socialImage}},
      {tag: 'meta', attrs: {property: 'og:image:type', content: 'image/png'}},
      {tag: 'meta', attrs: {property: 'og:image:width', content: '1254'}},
      {tag: 'meta', attrs: {property: 'og:image:height', content: '1254'}},
      {tag: 'meta', attrs: {property: 'og:image:alt', content: 'YSoNet logo'}},
      {tag: 'meta', attrs: {name: 'twitter:image', content: socialImage}},
      {tag: 'meta', attrs: {name: 'twitter:image:alt', content: 'YSoNet logo'}},
    ],
    social: [
      {icon: 'github', label: 'GitHub', href: 'https://github.com/irsdl/ysonet'},
      {icon: 'x.com', label: 'Follow @irsdl on X', href: 'https://x.com/irsdl'},
    ],
    sidebar: prepared.sidebar,
    lastUpdated: false,
    pagination: false,
    disable404Route: true,
    customCss: ['./src/styles/site.css'],
    components: {Footer: './src/components/Footer.astro', Head: './src/components/Head.astro',
      Header: './src/components/Header.astro', SocialIcons: './src/components/SocialIcons.astro',
      ThemeProvider: './src/components/ThemeProvider.astro',
      ThemeSelect: './src/components/ThemeSelect.astro'},
  })],
});
