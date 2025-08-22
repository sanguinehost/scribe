import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import fs from 'fs';
import path from 'path';

// Get the directory of the current file (vite.config.ts)
const __dirname = path.dirname(new URL(import.meta.url).pathname);

// Check if we're in a development environment
const isDev = process.env.NODE_ENV !== 'production';

// Try .certs-dev/ first (for local development), then fall back to .certs/ (for containers)
const devKeyPath = path.resolve(__dirname, '../.certs-dev/key.pem');
const devCertPath = path.resolve(__dirname, '../.certs-dev/cert.pem');
const containerKeyPath = path.resolve(__dirname, '../.certs/key.pem');
const containerCertPath = path.resolve(__dirname, '../.certs/cert.pem');

// Check which certificate directory exists and is accessible
let keyPath: string;
let certPath: string;
let certsExist = false;

if (isDev) {
	// Try .certs-dev/ first (local development)
	if (fs.existsSync(devKeyPath) && fs.existsSync(devCertPath)) {
		keyPath = devKeyPath;
		certPath = devCertPath;
		certsExist = true;
	}
	// Fall back to .certs/ (container development)
	else if (fs.existsSync(containerKeyPath) && fs.existsSync(containerCertPath)) {
		keyPath = containerKeyPath;
		certPath = containerCertPath;
		certsExist = true;
	}
}

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		host: true, // Listen on all network interfaces
		...(certsExist && {
			https: {
				key: fs.readFileSync(keyPath!),
				cert: fs.readFileSync(certPath!)
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
