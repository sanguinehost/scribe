/**
 * Centralized logging utility with structured logging support
 *
 * Features:
 * - Environment-aware logging (dev vs production)
 * - Desktop mode integration (sends logs to backend via Tauri)
 * - Structured logging with timestamps and context
 * - Multiple log levels: trace, debug, info, warn, error
 *
 * In development: All logs are output to console
 * In production: Only warnings and errors are logged to console
 * In desktop mode: Logs are also sent to backend for file-based logging
 *
 * Usage:
 *   import { logger } from '$lib/utils/logger';
 *   logger.debug('component', 'Debug message', { key: 'value' });
 *   logger.info('api', 'Info message', { response: data });
 *   logger.warn('auth', 'Warning message', { userId: 123 });
 *   logger.error('network', 'Error message', error);
 */

import { dev, browser } from '$app/environment';
import { PUBLIC_ENVIRONMENT } from '$env/static/public';

/** Log level enum matching backend tracing levels */
export enum LogLevel {
	TRACE = 'trace',
	DEBUG = 'debug',
	INFO = 'info',
	WARN = 'warn',
	ERROR = 'error'
}

/** Structured log entry */
interface LogEntry {
	timestamp: string;
	level: LogLevel;
	component: string;
	message: string;
	context?: Record<string, unknown>;
}

/** Desktop mode check */
function isDesktopMode(): boolean {
	return PUBLIC_ENVIRONMENT === 'desktop';
}

/**
 * Format timestamp in ISO 8601 format to match backend
 */
function formatTimestamp(): string {
	return new Date().toISOString();
}

/**
 * Format log entry for console output
 */
function formatForConsole(entry: LogEntry): string {
	const time = entry.timestamp.split('T')[1]?.split('.')[0] || '';
	return `[${time}] [${entry.level.toUpperCase()}] [${entry.component}] ${entry.message}`;
}

/**
 * Send log to backend via Tauri command (desktop mode only)
 */
async function sendToBackend(entry: LogEntry): Promise<void> {
	if (!browser || !isDesktopMode()) return;

	try {
		// Dynamically import Tauri to avoid bundling in web mode
		const { invoke } = await import('@tauri-apps/api/core');
		await invoke('log_frontend_message', {
			level: entry.level,
			component: entry.component,
			message: entry.message,
			context: entry.context ? JSON.stringify(entry.context) : null
		});
	} catch {
		// Silently fail - don't log to avoid infinite loop
		// The backend command might not be available yet during startup
	}
}

/**
 * Core logging function
 */
function log(
	level: LogLevel,
	component: string,
	message: string,
	context?: Record<string, unknown> | Error
): void {
	// Convert Error objects to plain objects with stack trace
	let contextObj: Record<string, unknown> | undefined;
	if (context instanceof Error) {
		contextObj = {
			name: context.name,
			message: context.message,
			stack: context.stack
		};
	} else {
		contextObj = context;
	}

	const entry: LogEntry = {
		timestamp: formatTimestamp(),
		level,
		component,
		message,
		context: contextObj
	};

	// Determine if we should log to console based on environment and level
	const shouldLogToConsole = dev || level === LogLevel.WARN || level === LogLevel.ERROR;

	if (shouldLogToConsole) {
		const formatted = formatForConsole(entry);

		switch (level) {
			case LogLevel.TRACE:
			case LogLevel.DEBUG:
			case LogLevel.INFO:
				console.log(formatted, contextObj || '');
				break;
			case LogLevel.WARN:
				console.warn(formatted, contextObj || '');
				break;
			case LogLevel.ERROR:
				console.error(formatted, contextObj || '');
				break;
		}
	}

	// Send to backend in desktop mode (async, fire-and-forget)
	if (isDesktopMode()) {
		sendToBackend(entry).catch(() => {
			// Silently ignore errors to avoid logging loops
		});
	}
}

/**
 * Centralized logger with structured logging support
 */
export const logger = {
	/**
	 * Trace-level logging (only in development)
	 * Use for very detailed diagnostic information
	 */
	trace: (component: string, message: string, context?: Record<string, unknown>) => {
		if (dev) {
			log(LogLevel.TRACE, component, message, context);
		}
	},

	/**
	 * Debug-level logging (only in development)
	 * Use for detailed diagnostic information
	 */
	debug: (component: string, message: string, context?: Record<string, unknown>) => {
		if (dev) {
			log(LogLevel.DEBUG, component, message, context);
		}
	},

	/**
	 * Info-level logging (only in development)
	 * Use for general informational messages
	 */
	info: (component: string, message: string, context?: Record<string, unknown>) => {
		if (dev) {
			log(LogLevel.INFO, component, message, context);
		}
	},

	/**
	 * Warning-level logging (always logged)
	 * Use for potentially problematic situations
	 */
	warn: (component: string, message: string, context?: Record<string, unknown>) => {
		log(LogLevel.WARN, component, message, context);
	},

	/**
	 * Error-level logging (always logged)
	 * Use for error conditions
	 */
	error: (component: string, message: string, error?: Error | Record<string, unknown>) => {
		log(LogLevel.ERROR, component, message, error);
	}
};
