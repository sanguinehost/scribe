// frontend/src/lib/stores/authStore.spec.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';
// Import the store itself and its functions via the exported object
import { authStore } from './authStore';
import * as apiClient from '$lib/services/apiClient'; // Import the actual module to mock its exports

// Mock the entire apiClient module
vi.mock('$lib/services/apiClient');

// Helper function to simulate an action requiring authentication
const fetchProtectedData = async () => {
	try {
		// Use the mocked apiClient
		const response = await apiClient.listCharacters(); // Example protected call
		console.log('Mock fetchProtectedData succeeded:', response);
		return { success: true, data: response };
	} catch (error: unknown) { // Use unknown instead of any
		const errorMessage = error instanceof Error ? error.message : String(error);
		console.error('Mock fetchProtectedData failed:', errorMessage);
		// Simulate throwing an error similar to a 401
		if (errorMessage.includes('401') || errorMessage.includes('Unauthorized')) {
			throw new Error('401 Unauthorized - Mock');
		}
		throw error; // Re-throw other errors
	}
};

describe('authStore - Authentication Timing', () => {
	// Use the mocked version of apiClient
	const mockedApiClient = vi.mocked(apiClient);

	beforeEach(async () => {
		// Reset mocks before each test
		vi.clearAllMocks();
		// Reset store state by mocking checkAuthStatus to return null (logged out)
		// and then calling the store's checkAuthStatus to initialize it.
		mockedApiClient.checkAuthStatus.mockResolvedValue(null);
		await authStore.checkAuthStatus(); // Initialize store to logged-out state
		// Clear mocks again AFTER initialization call if needed, though clearAllMocks should suffice
		vi.clearAllMocks();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('should allow authenticated API calls immediately after successful login completes', async () => {
		// --- Mock Setup ---
		const mockLoginCredentials = { username: 'testuser', password: 'password' };
		const mockUserData = { id: 'user-123', username: 'testuser' };
		const mockCharacterData = [{ id: 'char-1', name: 'Test Character', description: 'Desc', greeting: 'Hi' }];

		// 1. Mock successful login API call (resolves without specific data)
		mockedApiClient.login.mockResolvedValue(mockUserData); // Login itself might return user, but we rely on checkAuthStatus now

		// 2. Mock successful checkAuthStatus call (resolves with user data)
		// This is called *internally* by the authStore.login function after apiClient.login succeeds.
		mockedApiClient.checkAuthStatus.mockResolvedValue(mockUserData);

		// 3. Mock the protected API call (e.g., listCharacters)
		// It should only succeed *after* the auth state is confirmed true by checkAuthStatus.
		mockedApiClient.listCharacters.mockImplementation(async () => {
			// Check the store's state *at the time of this call*
			const state = get(authStore);
			console.log('Mock listCharacters called. Current auth state:', state.isAuthenticated);
			if (state.isAuthenticated && state.user?.id === mockUserData.id) {
				return mockCharacterData;
			} else {
				// Simulate failure if called when not authenticated
				throw new Error('401 Unauthorized - Mocked listCharacters');
			}
		});

		// --- Test Execution ---
		// Trigger login using the exported store method.
		// The authStore.login function now internally calls apiClient.login
		// and then apiClient.checkAuthStatus before resolving.
		const loginPromise = authStore.login(mockLoginCredentials.username, mockLoginCredentials.password);

		// Assert initial state AFTER initialization in beforeEach, but before login completes
		// It should be logged out here.
		expect(get(authStore).isAuthenticated).toBe(false);
		expect(get(authStore).isLoading).toBe(true); // Login sets loading to true

		// Wait for the entire login process (including the internal checkAuthStatus) to complete
		await loginPromise;

		// Assert state after login promise resolves (checkAuthStatus should have updated it)
		const finalAuthState = get(authStore);
		expect(finalAuthState.isAuthenticated).toBe(true);
		expect(finalAuthState.user).toEqual(mockUserData);
		expect(finalAuthState.isLoading).toBe(false); // Should be false after completion
		expect(finalAuthState.error).toBeNull();

		// --- Verification ---
		// Immediately attempt the authenticated action *after* login resolves.
		// This simulates the race condition scenario.
		// We expect this to succeed because the internal checkAuthStatus awaited in login()
		// should have updated the state correctly *before* loginPromise resolved.
		await expect(fetchProtectedData()).resolves.toEqual({
			success: true,
			data: mockCharacterData,
		});

		// Verify mocks were called as expected
		expect(mockedApiClient.login).toHaveBeenCalledTimes(1);
		expect(mockedApiClient.login).toHaveBeenCalledWith(mockLoginCredentials.username, mockLoginCredentials.password);
		// checkAuthStatus is called internally by the login function in the store
		expect(mockedApiClient.checkAuthStatus).toHaveBeenCalledTimes(1);
		// listCharacters should have been called once successfully by fetchProtectedData
		expect(mockedApiClient.listCharacters).toHaveBeenCalledTimes(1);
	});

    // Optional: Add a similar test for the register function if needed
    it('should allow authenticated API calls immediately after successful registration completes', async () => {
        // --- Mock Setup ---
		const mockRegisterCredentials = { username: 'newuser', email: 'new@test.com', password: 'newpassword' };
		const mockUserData = { id: 'user-456', username: 'newuser' };
		const mockCharacterData = [{ id: 'char-2', name: 'Another Character', description: 'Desc2', greeting: 'Yo' }];

        // 1. Mock successful register API call
        mockedApiClient.register.mockResolvedValue(mockUserData); // Register might return user

        // 2. Mock successful checkAuthStatus call (called internally by authStore.register)
		mockedApiClient.checkAuthStatus.mockResolvedValue(mockUserData);

        // 3. Mock the protected API call
		mockedApiClient.listCharacters.mockImplementation(async () => {
			const state = get(authStore);
			if (state.isAuthenticated && state.user?.id === mockUserData.id) {
				return mockCharacterData;
			} else {
				throw new Error('401 Unauthorized - Mocked listCharacters');
			}
		});

		      // --- Test Execution ---
		      // Trigger register using the exported store method
		      const registerPromise = authStore.register(mockRegisterCredentials.username, mockRegisterCredentials.email, mockRegisterCredentials.password);
		      await registerPromise;

		      // Assert state after registration completes
        const finalAuthState = get(authStore);
		expect(finalAuthState.isAuthenticated).toBe(true);
		expect(finalAuthState.user).toEqual(mockUserData);
		expect(finalAuthState.isLoading).toBe(false);
		expect(finalAuthState.error).toBeNull();

        // --- Verification ---
        await expect(fetchProtectedData()).resolves.toEqual({
			success: true,
			data: mockCharacterData,
		});

        // Verify mocks
        expect(mockedApiClient.register).toHaveBeenCalledTimes(1);
        expect(mockedApiClient.register).toHaveBeenCalledWith(mockRegisterCredentials.username, mockRegisterCredentials.email, mockRegisterCredentials.password);
        expect(mockedApiClient.checkAuthStatus).toHaveBeenCalledTimes(1);
        expect(mockedApiClient.listCharacters).toHaveBeenCalledTimes(1);
    });
});