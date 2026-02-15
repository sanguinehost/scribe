import adapter from '@sveltejs/adapter-node';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({
			// Default output directory for adapter-node is 'build'
			// This matches what the Containerfile expects
		}),
		paths: {
			base: '',
			assets: ''
		}
	}
};

export default config;
