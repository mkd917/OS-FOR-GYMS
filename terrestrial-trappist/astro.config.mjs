// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';

// https://astro.build/config
export default defineConfig({
	site: 'https://gymopssaas.com',
	vite: {
		plugins: [tailwindcss()],
		server: {
			// allow the public Cloudflare tunnel hostname to reach the dev server
			allowedHosts: ['.trycloudflare.com'],
		},
	},
});
