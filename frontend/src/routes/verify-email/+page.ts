import { browser } from '$app/environment';
import { error } from '@sveltejs/kit';
import type { PageLoad } from './$types';
import { apiClient } from '$lib/api';

export const load: PageLoad = async ({ url }) => {
	if (!browser) {
		return {
			status: 'loading',
			message: 'Please wait...'
		};
	}

	const token = url.searchParams.get('token');

	if (!token) {
		throw error(400, 'Verification token is missing.');
	}

	try {
		const result = await apiClient.verifyEmail(token);

		if (result.isOk()) {
			return {
				status: 'success',
				message: result.value.message
			};
		}
		// The fetch method in apiClient already handles non-200 responses,
		// so we just need to handle the error case from the Result.
		return {
			status: 'error',
			message: result.error.message
		};
	} catch (e) {
		// This catch block might be redundant if the API client handles all errors,
		// but it's good for catching unexpected issues.
		let errorMessage = 'An unknown error occurred during verification.';
		if (e instanceof Error) {
			errorMessage = e.message;
		}
		return {
			status: 'error',
			message: errorMessage
		};
	}
};
