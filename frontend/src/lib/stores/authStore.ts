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

const login = async (username: string, password: string): Promise<boolean> => { // Password is required
	update((state) => ({ ...state, isLoading: true, error: null }));
	try {
		const user = await apiClient.login(username, password);
		update((state) => ({
			...state,
			isAuthenticated: true,
			user: user,
			isLoading: false,
			error: null
		}));
		console.log('Login successful for:', username);
		return true; // Indicate success for potential navigation trigger
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

const register = async (username: string, password: string): Promise<boolean> => { // Password is required
	update((state) => ({ ...state, isLoading: true, error: null }));
	try {
		const user = await apiClient.register(username, password);
		// Assume backend handles session creation on registration (auto-login)
		update((state) => ({
			...state,
			isAuthenticated: true,
			user: user,
			isLoading: false,
			error: null
		}));
		console.log('Registration successful for:', username);
		return true; // Indicate success for potential navigation trigger
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
	let alreadyAuthenticated = false;
	subscribe(state => { alreadyAuthenticated = state.isAuthenticated })(); // Quick check
	if (alreadyAuthenticated) {
		console.log('Skipping checkAuthStatus, already authenticated.');
		return;
	}

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