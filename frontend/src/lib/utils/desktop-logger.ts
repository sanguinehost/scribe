/**
 * Desktop logger - forwards frontend console output to backend log files
 * Uses tauri-plugin-log to safely send logs to the backend via IPC
 *
 * CRITICAL: This allows us to see frontend logs even when the WebView is frozen
 */

export async function initDesktopLogger() {
	try {
		// Import tauri-plugin-log API
		const { info, warn, error, debug } = await import('@tauri-apps/plugin-log');

		// Test IPC readiness with a probe call
		// This prevents hanging if IPC isn't ready yet
		await info('[Desktop Logger] IPC probe - testing connection...');

		// IPC is ready! Safe to override console methods
		const originalConsole = {
			log: console.log.bind(console),
			info: console.info.bind(console),
			warn: console.warn.bind(console),
			error: console.error.bind(console),
			debug: console.debug.bind(console)
		};

		// Override console methods to forward to backend
		// Use fire-and-forget with .catch(() => {}) to prevent blocking
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		console.log = (...args: any[]) => {
			originalConsole.log(...args);
			info(`[console.log] ${args.map(String).join(' ')}`).catch(() => {});
		};

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		console.info = (...args: any[]) => {
			originalConsole.info(...args);
			info(`[console.info] ${args.map(String).join(' ')}`).catch(() => {});
		};

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		console.warn = (...args: any[]) => {
			originalConsole.warn(...args);
			warn(`[console.warn] ${args.map(String).join(' ')}`).catch(() => {});
		};

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		console.error = (...args: any[]) => {
			originalConsole.error(...args);
			error(`[console.error] ${args.map(String).join(' ')}`).catch(() => {});
		};

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		console.debug = (...args: any[]) => {
			originalConsole.debug(...args);
			debug(`[console.debug] ${args.map(String).join(' ')}`).catch(() => {});
		};

		// Confirm initialization
		await info(
			'[Desktop Logger] Console override installed successfully - all frontend logs will now appear in backend logs'
		);

		return true;
	} catch (e) {
		// IPC not ready or plugin not available - fall back to native console
		console.error(
			'[Desktop Logger] Failed to initialize - IPC not ready or plugin unavailable:',
			e
		);
		console.error(
			'[Desktop Logger] Falling back to native console only (logs will not be captured)'
		);
		return false;
	}
}
