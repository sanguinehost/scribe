import tailwindcss from '@tailwindcss/vite';
import { svelteTesting } from '@testing-library/svelte/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, searchForWorkspaceRoot } from 'vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	test: {
		workspace: [
			{
				extends: './vite.config.ts',
				plugins: [svelteTesting()],
				test: {
					name: 'client',
					environment: 'jsdom',
					clearMocks: true,
					include: ['src/**/*.{test,spec}.{js,ts}'],
					exclude: ['src/lib/server/**'],
					setupFiles: ['./vitest-setup-client.ts']
				}
			},
			{
				extends: './vite.config.ts',
				test: {
					name: 'server',
					environment: 'node',
					include: ['src/**/*.{test,spec}.{js,ts}'],
					exclude: [
						'src/**/*.svelte.{test,spec}.{js,ts}', // Files like Component.svelte.test.ts
						'src/routes/**/*.{test,spec}.{js,ts}', // Tests for routes (often client-side)
						'src/lib/components/**/*.{test,spec}.{js,ts}' // Exclude component tests from server env
					]
				}
			}
		]
	},
	server: {
		proxy: {
			'/api': {
				target: 'http://127.0.0.1:8080',
				changeOrigin: true,
			}
		},
		fs: {
			allow: [searchForWorkspaceRoot(process.cwd())]
		}
	}
});
