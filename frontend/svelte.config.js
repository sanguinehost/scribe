import adapter from '@sveltejs/adapter-vercel';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	// Consult https://svelte.dev/docs/kit/integrations
	// for more information about preprocessors
	preprocess: vitePreprocess(),

	kit: {
		adapter: adapter({
			runtime: 'nodejs22.x'
		}),
		typescript: {
			config: (config) => {
				// Skip type checking during build in production environments
				if (process.env.VITE_BUILD_SKIP_TYPE_CHECK === 'true') {
					config.compilerOptions = {
						...config.compilerOptions,
						checkJs: false,
						skipLibCheck: true
					};
				}
				return config;
			}
		}
	}
};

export default config;
