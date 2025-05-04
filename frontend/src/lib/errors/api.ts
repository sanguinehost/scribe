export type ApiError = ApiClientError | ApiResponseError | ApiNetworkError;

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
	cause: Error;

	constructor(message: string, cause: Error) {
		super(message);
		this.name = 'ApiNetworkError';
		this.cause = cause;
	}
} 