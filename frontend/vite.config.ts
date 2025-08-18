import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import fs from 'fs';
import path from 'path';

// Get the directory of the current file (vite.config.ts)
const __dirname = path.dirname(new URL(import.meta.url).pathname);
// Construct absolute paths to the certs in the parent directory
const keyPath = path.resolve(__dirname, '../.certs/frontend-key.pem');
const certPath = path.resolve(__dirname, '../.certs/cert.pem');

// Check if we're in a development environment and certs exist
const isDev = process.env.NODE_ENV !== 'production';
const certsExist = isDev && fs.existsSync(keyPath) && fs.existsSync(certPath);

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		host: true, // Listen on all network interfaces
		...(certsExist && {
			https: {
				key: fs.readFileSync(keyPath),
				cert: fs.readFileSync(certPath)
			}
		}),
		proxy: {
			'/api': {
				target: 'https://localhost:8080',
				changeOrigin: true,
				secure: false,
				cookieDomainRewrite: 'localhost',
				headers: {
					Host: 'localhost:5173',
					Origin: 'https://localhost:5173'
				},
				// Exclude frontend-only endpoints from being proxied to backend
				bypass: (req) => {
					// Let SvelteKit handle invalidate-session
					if (req.url?.includes('/api/invalidate-session')) {
						return req.url;
					}
					// All other /api requests go to backend
					return null;
				}
			}
		}
	}
});
