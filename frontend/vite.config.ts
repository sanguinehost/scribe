import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import fs from 'fs';
import path from 'path';

// Get the directory of the current file (vite.config.ts)
const __dirname = path.dirname(new URL(import.meta.url).pathname);
// Construct absolute paths to the certs in the parent directory
const keyPath = path.resolve(__dirname, '../.certs/key.pem');
const certPath = path.resolve(__dirname, '../.certs/cert.pem');

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		https: {
			key: fs.readFileSync(keyPath),
			cert: fs.readFileSync(certPath)
		},
		proxy: {
			'/api': {
				target: 'https://localhost:8080',
				changeOrigin: true,
				secure: false,
				cookieDomainRewrite: 'localhost',
				headers: {
					Host: 'localhost:5173',
					Origin: 'https://localhost:5173'
				}
			}
		}
	}
});
