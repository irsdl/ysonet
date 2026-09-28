import {defineConfig} from 'astro/config';
import starlight from '@astrojs/starlight';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {canonicalMarkdown} from './markdown.mjs';
import {unified} from '@astrojs/markdown-remark';

const prepared = JSON.parse(readFileSync(new URL('./generated/manifest.json', import.meta.url)));
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
    logo: {src: '../../docs/images/logo/transparent.svg'},
    favicon: '/assets/logo.svg',
    social: [{icon: 'github', label: 'GitHub', href: 'https://github.com/irsdl/ysonet'}],
    sidebar: prepared.sidebar,
    lastUpdated: false,
    pagination: false,
    disable404Route: true,
    customCss: ['./src/styles/site.css'],
    components: {Footer: './src/components/Footer.astro', Head: './src/components/Head.astro',
      Header: './src/components/Header.astro', ThemeProvider: './src/components/ThemeProvider.astro',
      ThemeSelect: './src/components/ThemeSelect.astro'},
  })],
});
