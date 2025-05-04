import {
	generateSessionToken,
	setSessionTokenCookie,
	createSession
} from '$lib/server/auth/index.js';
import { fail, redirect, type ActionFailure } from '@sveltejs/kit';
import { z } from 'zod';
import { apiClient } from '$lib/api';
import { ApiResponseError } from '$lib/errors/api';

// Define a type for the data returned on failure, matching FormFailureData
type AuthErrorData = {
	success: false;
	message: string;
	email?: string; // Used for repopulating email or identifier field
	username?: string; // Used for repopulating username field
};

export function load({ locals }) {
	// Note: Until app.d.ts is updated with proper types, this will show as an error
	// but it's expected to work at runtime as the handle hook sets this property
	if (locals.session) {
		return redirect(307, '/');
	}
}

const emailSchema = z.string().email({ message: 'Invalid email address.' });
const passwordSchema = z.string().min(8, { message: 'Password must be at least 8 characters long.' });
const usernameSchema = z
	.string()
	.min(3, { message: 'Username must be at least 3 characters long.' })
	.max(32, { message: 'Username cannot be longer than 32 characters.' });
const identifierSchema = z.string().min(1, { message: 'Email or Username is required.' });

// Export ActionData type for +page.svelte, representing only the failure case data
export type ActionData = AuthErrorData | undefined;

export const actions = {
	default: async ({ request, params, cookies, fetch }): Promise<ActionFailure<AuthErrorData> | void | import('@sveltejs/kit').Redirect> => {
		const formData = await request.formData();
		const authType = params.authType; // 'signin' or 'signup'

		// --- Shared Password Validation ---
		const rawPassword = formData.get('password');
		const passwordResult = passwordSchema.safeParse(rawPassword);
		if (!passwordResult.success) {
			const errorData: AuthErrorData = {
				success: false,
				message: passwordResult.error.errors[0]?.message ?? 'Invalid password.'
			};
			// Repopulate other fields on password error
			if (authType === 'signup') {
				errorData.email = formData.get('email') as string | undefined;
				errorData.username = formData.get('username') as string | undefined;
			} else {
				errorData.email = formData.get('identifier') as string | undefined; // Use 'email' key for repopulation
			}
			return fail(400, errorData);
		}
		const password = passwordResult.data;

		try {
			let userId: string; // Store the user ID after auth

			if (authType === 'signup') {
				// --- Signup Specific Validation ---
				const rawEmail = formData.get('email');
				const emailResult = emailSchema.safeParse(rawEmail);
				if (!emailResult.success) {
					return fail(400, {
						success: false,
						message: emailResult.error.errors[0]?.message ?? 'Invalid email.',
						email: rawEmail as string | undefined,
						username: formData.get('username') as string | undefined // Repopulate username
					});
				}
				const email = emailResult.data;

				const rawUsername = formData.get('username');
				const usernameResult = usernameSchema.safeParse(rawUsername);
				if (!usernameResult.success) {
					// Still validate username
					return fail(400, {
						success: false,
						message: usernameResult.error.errors[0]?.message ?? 'Invalid username.',
						email: email, // Repopulate email
						username: rawUsername as string | undefined
					});
				}
				const username = usernameResult.data; // Use the validated username

				// --- Signup API Call using apiClient ---
				const signupResult = await apiClient.createUser({ email, username, password }, fetch);

				if (signupResult.isErr()) {
					const apiError = signupResult.error;
					let errorMessage = 'Failed to create user';
					if (apiError instanceof ApiResponseError) {
						errorMessage = apiError.message || errorMessage;
					}
					console.error('Signup API error:', apiError);
					return fail(apiError instanceof ApiResponseError ? apiError.statusCode : 500, {
						success: false,
						message: errorMessage,
						email,
						username
					});
				}

				// Assuming createUser returns AuthUser with a 'user_id' property
				const createdUser = signupResult.value;
				userId = createdUser.user_id; // Use .user_id property
				if (!userId) {
					console.error('Signup response missing user ID:', createdUser);
					return fail(500, { success: false, message: 'Signup failed: User ID missing in response.', email, username });
				}
				console.log('User registered successfully via apiClient:', createdUser);

			} else {
				// --- Signin Specific Validation ---
				const rawIdentifier = formData.get('identifier');
				const identifierResult = identifierSchema.safeParse(rawIdentifier);
				if (!identifierResult.success) {
					return fail(400, {
						success: false,
						message: identifierResult.error.errors[0]?.message ?? 'Identifier required.',
						email: rawIdentifier as string | undefined // Repopulate identifier field (using 'email' key)
					});
				}
				const identifier = identifierResult.data;

				// --- Signin API Call using apiClient ---
				// Use a hypothetical 'authenticateUser' method. We'll need to add this to ApiClient.
				const loginResult = await apiClient.authenticateUser({ identifier, password }, fetch);

				if (loginResult.isErr()) {
					const apiError = loginResult.error;
					let errorMessage = 'Invalid credentials.';
					if (apiError instanceof ApiResponseError) {
						errorMessage = apiError.message || errorMessage;
					}
					console.error('Login API error:', apiError);
					return fail(apiError instanceof ApiResponseError ? apiError.statusCode : 401, { // Use 401 for login failure
						success: false,
						message: errorMessage,
						email: identifier // Repopulate identifier field
					});
				}

				// Assuming authenticateUser returns AuthUser with a 'user_id' property
				const loggedInUser = loginResult.value;
				userId = loggedInUser.user_id; // Use .user_id property
				if (!userId) {
					console.error('Login response missing user ID:', loggedInUser);
					return fail(500, { success: false, message: 'Login failed: User ID missing in response.', email: identifier });
				}
				console.log('User logged in successfully via apiClient:', loggedInUser);
			}

			// --- Session Creation using createSession helper ---
			// Generate a temporary token (will be hashed by createSession for ID)
			// Ideally, the backend should generate the session ID/token entirely.
			// But for now, we follow the existing createSession pattern.
			const frontendToken = generateSessionToken();

			const sessionResult = await createSession(frontendToken, userId, fetch);

			if (sessionResult.isErr()) {
				const apiError = sessionResult.error;
				console.error('Session creation error:', apiError);
				const errorData: AuthErrorData = {
					success: false,
					message: `Session creation failed (${apiError.name}). Please try again later.`
				};
				// Repopulate form based on authType
				if (authType === 'signup') {
					errorData.email = formData.get('email') as string | undefined;
					errorData.username = formData.get('username') as string | undefined;
				} else {
					errorData.email = formData.get('identifier') as string | undefined;
				}
				return fail(500, errorData);
			}

			// Session created successfully by the backend via createSession -> apiClient.createSession
			const backendSession = sessionResult.value;

			// Set cookie using the original frontendToken (as the handle hook expects this)
			// and the expiry from the backend response
			setSessionTokenCookie(cookies, frontendToken, backendSession.expires_at);

			// Redirect to home
			console.log('Session created and cookie set successfully.');
			return redirect(303, '/');

		} catch (error) {
			// Re-throw redirect responses by checking shape, handle other errors
			// SvelteKit throws an object with status and location for redirects
			if (typeof error === 'object' && error !== null && 'status' in error && 'location' in error) {
				throw error; // Re-throw if it looks like a redirect
			}

			// Catch unexpected errors during the process
			console.error('Unexpected auth action error:', error);
			const errorData: AuthErrorData = {
				success: false,
				message: `An unexpected error occurred during ${authType === 'signup' ? 'sign up' : 'sign in'}.`
			};
			if (authType === 'signup') {
				errorData.email = formData.get('email') as string | undefined;
				errorData.username = formData.get('username') as string | undefined;
			} else {
				errorData.email = formData.get('identifier') as string | undefined;
			}
			return fail(500, errorData);
		}
	}
};
