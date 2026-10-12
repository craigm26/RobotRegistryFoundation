import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://robotregistryfoundation.org',
  integrations: [tailwind(), sitemap()],
  // Markdown pages here render normative text (the Bounded Embodiment method): show its quotes and
  // dashes as written instead of typographic substitutes.
  markdown: { smartypants: false },
});
