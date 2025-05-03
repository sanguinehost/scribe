import { writable } from 'svelte/store';
// Import the API client functions and User type
import * as apiClient from '$lib/services/apiClient';
import type { User } from '$lib/services/apiClient'; // Use the User type from apiClient

interface AuthState {
	isAuthenticated: boolean;
	user: User | null;
	isLoading: boolean;
	error: string | null;
}

const initialState: AuthState = {
	isAuthenticated: false,
	user: null,
	isLoading: false,
	error: null
};

const { subscribe, update, set } = writable<AuthState>(initialState);

// Remove simulation delay
// const API_DELAY = 1000; // 1 second

const login = async (username: string, password: string): Promise<boolean> => { // Use username for login
	update((state) => ({ ...state, isLoading: true, error: null }));
	try {
		await apiClient.login(username, password); // Pass username to apiClient.login (user data now set by checkAuthStatus)
		// Login API call successful, now verify auth status with the backend
		// to ensure the session cookie is set and recognized.
		console.log('Login API call successful for:', username, 'Verifying auth status...');
		try {
			await checkAuthStatus(); // Call checkAuthStatus to confirm
			let loggedIn = false;
			subscribe(state => { loggedIn = state.isAuthenticated })(); // Check the updated state
			if (loggedIn) {
				console.log('Auth status verified after login for:', username);
				// State is already updated by checkAuthStatus on success
				update((state) => ({ ...state, isLoading: false })); // Ensure loading is false
				return true; // Indicate success
			} else {
				// This case should ideally not happen if checkAuthStatus works correctly
				// but handle it defensively.
				console.error('Login flow error: checkAuthStatus did not set authenticated state for:', username);
				update((state) => ({
					...state,
					isAuthenticated: false,
					user: null,
					isLoading: false,
					error: 'Authentication check failed after login.'
				}));
				return false; // Indicate failure
			}
		} catch (checkAuthError: unknown) {
			const checkErrorMessage = checkAuthError instanceof Error ? checkAuthError.message : 'Auth status check failed after login';
			console.error('Error during post-login auth check:', checkErrorMessage);
			update((state) => ({
				...state,
				isAuthenticated: false,
				user: null,
				isLoading: false,
				error: checkErrorMessage
			}));
			return false; // Indicate failure
		}
	} catch (error: unknown) {
		      const errorMessage = error instanceof Error ? error.message : 'Login failed';
		console.error('Login failed:', errorMessage);
		update((state) => ({
			...state,
			isAuthenticated: false,
			user: null,
			isLoading: false,
			error: errorMessage
		}));
		return false; // Indicate failure
	}
};

const register = async (username: string, email: string, password: string): Promise<boolean> => { // Add email parameter
	update((state) => ({ ...state, isLoading: true, error: null }));
	try {
		await apiClient.register(username, email, password); // Pass email to apiClient.register (user data now set by checkAuthStatus)
		// Registration API call successful, now verify auth status with the backend
		// to ensure the session cookie is set and recognized (auto-login).
		console.log('Registration API call successful for:', username, 'Verifying auth status...');
		try {
			await checkAuthStatus(); // Call checkAuthStatus to confirm
			let registeredAndLoggedIn = false;
			subscribe(state => { registeredAndLoggedIn = state.isAuthenticated })(); // Check the updated state
			if (registeredAndLoggedIn) {
				console.log('Auth status verified after registration for:', username);
				// State is already updated by checkAuthStatus on success
				update((state) => ({ ...state, isLoading: false })); // Ensure loading is false
				return true; // Indicate success
			} else {
				console.error('Registration flow error: checkAuthStatus did not set authenticated state for:', username);
				update((state) => ({
					...state,
					isAuthenticated: false,
					user: null,
					isLoading: false,
					error: 'Authentication check failed after registration.'
				}));
				return false; // Indicate failure
			}
		} catch (checkAuthError: unknown) {
			const checkErrorMessage = checkAuthError instanceof Error ? checkAuthError.message : 'Auth status check failed after registration';
			console.error('Error during post-registration auth check:', checkErrorMessage);
			update((state) => ({
				...state,
				isAuthenticated: false,
				user: null,
				isLoading: false,
				error: checkErrorMessage
			}));
			return false; // Indicate failure
		}
	} catch (error: unknown) {
		      const errorMessage = error instanceof Error ? error.message : 'Registration failed';
		console.error('Registration failed:', errorMessage);
		update((state) => ({
			...state,
			isAuthenticated: false,
			user: null,
			isLoading: false,
			error: errorMessage
		}));
		return false; // Indicate failure
	}
};

const logout = async () => {
	try {
		await apiClient.logout();
		console.log('Logout API call successful');
	} catch (error: unknown) {
		// Log the error but proceed with client-side state reset
	       const errorMessage = error instanceof Error ? error.message : 'Unknown logout error';
		console.error('Logout API call failed:', errorMessage);
	} finally {
		// Always reset the local state
		set(initialState);
		console.log('Auth state reset');
	}
};

const checkAuthStatus = async () => {
	// Don't run check if already authenticated (e.g., after login/register)
	// This prevents unnecessary checks during the same session lifecycle.
	// A more robust solution might involve checking timestamps or specific flags.
	// Removed the check for alreadyAuthenticated to allow this function
	// to be explicitly called after login/register to verify cookie setting.

	update((state) => ({ ...state, isLoading: true, error: null }));
	try {
		const user = await apiClient.checkAuthStatus();
		if (user) {
			update((state) => ({
				...state,
				isAuthenticated: true,
				user: user,
				isLoading: false,
				error: null
			}));
			console.log('Auth status checked: User is authenticated', user);
		} else {
			// Not authenticated, ensure state is reset (might be redundant but safe)
			set(initialState);
			console.log('Auth status checked: User is not authenticated');
		}
	} catch (error: unknown) {
			     const errorMessage = error instanceof Error ? error.message : 'Unknown error during auth check';
		console.error('Error during checkAuthStatus:', errorMessage);
		// Ensure logged out state on error
		set(initialState);
	} finally {
		// Ensure loading is always set to false eventually
		update((state) => ({ ...state, isLoading: false }));
	}
};


export const authStore = {
	subscribe,
	login,
	register,
	logout,
	checkAuthStatus
};