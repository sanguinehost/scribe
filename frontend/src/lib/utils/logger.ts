/**
 * Environment-aware logging utility for development vs production
 *
 * In development: All logs are output to console
 * In production: Only errors are logged to console
 *
 * Usage:
 *   import { logger } from '$lib/utils/logger';
 *   logger.debug('Debug message', data);
 *   logger.info('Info message', data);
 *   logger.warn('Warning message', data);
 *   logger.error('Error message', error);
 */

import { dev } from '$app/environment';

export const logger = {
	/**
	 * Debug-level logging (only in development)
	 * Use for detailed diagnostic information
	 */
	debug: (...args: unknown[]) => {
		if (dev) {
			console.log('[DEBUG]', ...args);
		}
	},

	/**
	 * Info-level logging (only in development)
	 * Use for general informational messages
	 */
	info: (...args: unknown[]) => {
		if (dev) {
			console.log('[INFO]', ...args);
		}
	},

	/**
	 * Warning-level logging (always logged)
	 * Use for potentially problematic situations
	 */
	warn: (...args: unknown[]) => {
		console.warn('[WARN]', ...args);
	},

	/**
	 * Error-level logging (always logged)
	 * Use for error conditions
	 */
	error: (...args: unknown[]) => {
		console.error('[ERROR]', ...args);
	}
};
