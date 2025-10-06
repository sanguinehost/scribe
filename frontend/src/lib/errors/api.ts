export type ApiError =
	| ApiClientError
	| ApiResponseError
	| ApiNetworkError
	| ApiServerRestartError
	| ApiAuthError
	| ApiDekMissingError;

export class ApiClientError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'ApiClientError';
	}
}

export class ApiResponseError extends Error {
	statusCode: number;

	constructor(statusCode: number, message: string) {
		super(message);
		this.name = 'ApiResponseError';
		this.statusCode = statusCode;
	}
}

export class ApiNetworkError extends Error {
	cause?: Error;

	constructor(message: string, cause?: Error) {
		super(message);
		this.name = 'ApiNetworkError';
		if (cause) {
			this.cause = cause;
		}
	}
}

/**
 * Error indicating the backend server is restarting or temporarily unavailable (503, 5xx errors)
 * The session is still valid and should not be invalidated - retry later
 */
export class ApiServerRestartError extends Error {
	statusCode: number;

	constructor(message: string, statusCode: number = 503) {
		super(message);
		this.name = 'ApiServerRestartError';
		this.statusCode = statusCode;
	}
}

/**
 * Error indicating authentication/authorization failure (401, 403)
 * The session is invalid and user should be logged out
 */
export class ApiAuthError extends Error {
	statusCode: number;

	constructor(message: string, statusCode: number) {
		super(message);
		this.name = 'ApiAuthError';
		this.statusCode = statusCode;
	}
}

/**
 * Error indicating Data Encryption Key (DEK) is missing after backend restart
 * Session is valid but encryption key was cleared from memory
 * User needs to re-authenticate to derive DEK from password
 */
export class ApiDekMissingError extends Error {
	statusCode: number = 401;

	constructor(message: string = 'Encryption key missing - please sign in again') {
		super(message);
		this.name = 'ApiDekMissingError';
	}
}
