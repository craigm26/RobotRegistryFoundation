import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  site: 'https://robotregistryfoundation.org',
  integrations: [tailwind()],
});
