import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// Use desktop-specific Svelte config
process.env.SVELTE_CONFIG = 'svelte.config.desktop.js';

export default defineConfig({
	plugins: [sveltekit()],
	build: {
		target: 'esnext',
		minify: 'esbuild'
	}
});
