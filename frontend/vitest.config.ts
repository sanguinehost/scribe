import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import path from 'path'; // Import path module

export default defineConfig({
	plugins: [svelte({ hot: !process.env.VITEST })], // Svelte plugin for Vitest
	test: {
		globals: true, // Use Vitest globals (describe, it, expect, etc.)
		environment: 'jsdom', // Simulate a browser environment
		setupFiles: ['./src/vitest-setup.ts'], // Path to your setup file
		include: ['src/**/*.{test,spec}.{js,ts}'], // Glob pattern for test files
		alias: {
			// Alias for $lib
			$lib: path.resolve(__dirname, './src/lib'),
			// Alias for SvelteKit's $app modules to point to our mocks
			$app: path.resolve(__dirname, './src/__mocks__/$app'),
			// Alias for SvelteKit's $env modules to point to our mocks
			$env: path.resolve(__dirname, './src/__mocks__/$env')
		}
	},
	// Configure resolver conditions for Vitest as per Svelte docs
	resolve: process.env.VITEST
		? {
				conditions: ['browser']
			}
		: undefined
});
