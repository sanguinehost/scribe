// frontend/src/lib/components/auth/LoginForm.spec.ts
import { render, fireEvent, screen } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import { writable, type Writable } from 'svelte/store'; // Import writable directly

// Mock the goto function from $app/navigation
vi.mock('$app/navigation', () => {
	return {
		goto: vi.fn()
	};
});

// Define interface for mock store for better type checking
interface MockAuthStore {
	login: Mock;
	update: Mock;
	isLoading: Writable<boolean>;
	error: Writable<string | null>;
}

// Mock the authStore - must be before importing LoginForm
vi.mock('$lib/stores/authStore', () => {
	const mockLogin = vi.fn().mockResolvedValue(true);
	const mockUpdate = vi.fn();
	const mockIsLoading = writable(false);
	const mockError = writable<string | null>(null);

	// Create a mock store object that *is* a store (has subscribe)
	// and includes the methods/state needed by the component
	const mockStore = {
		// Provide the subscribe method based on the state the component uses
		subscribe: vi.fn((run) => {
			const state: { isLoading: boolean; error: string | null } = { isLoading: false, error: null };
			const unsubLoading = mockIsLoading.subscribe(val => { state.isLoading = val; run(state); });
			const unsubError = mockError.subscribe(val => { state.error = val; run(state); });
			// Return the unsubscribe function
			return () => { unsubLoading(); unsubError(); };
		}),
		// Provide the mocked methods
		login: mockLogin,
		update: mockUpdate,
		// Expose mocks for manipulation in tests
		__mocks: {
			login: mockLogin,
			update: mockUpdate,
			isLoading: mockIsLoading,
			error: mockError
		}
	};

	return { authStore: mockStore };
});

// Import component AFTER mocking dependencies
import LoginForm from './LoginForm.svelte';

// Get access to the mocks for manipulation in tests
const { __mocks: mockedAuthStore } = vi.mocked(
	await import('$lib/stores/authStore')
).authStore as unknown as { __mocks: MockAuthStore };

describe('LoginForm.svelte', () => {
	// Reset mocks and store states before each test for isolation
	beforeEach(() => {
		vi.clearAllMocks();
		// Reset writable store values via the exposed mocks
		mockedAuthStore.error.set(null);
		mockedAuthStore.isLoading.set(false);
		mockedAuthStore.login.mockClear(); // Clear the mock function calls
		mockedAuthStore.update.mockClear();
		// Configure update to set error when needed
		mockedAuthStore.update.mockImplementation(callback => {
			const currentState = { isLoading: false, error: null };
			const newState = callback(currentState);
			mockedAuthStore.error.set(newState.error);
			return newState;
		});
	});

	it('renders the login form correctly', () => {
		render(LoginForm);
		expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
		expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument();
	});

	it('updates input values on change', async () => {
		render(LoginForm);
		const usernameInput = screen.getByLabelText(/username/i);
		const passwordInput = screen.getByLabelText(/password/i);

		await fireEvent.input(usernameInput, { target: { value: 'testuser' } });
		await fireEvent.input(passwordInput, { target: { value: 'password123' } });

		expect(usernameInput).toHaveValue('testuser');
		expect(passwordInput).toHaveValue('password123');
	});

	it('calls authStore.login on form submission', async () => {
		render(LoginForm);
		const usernameInput = screen.getByLabelText(/username/i);
		const passwordInput = screen.getByLabelText(/password/i);
		const loginButton = screen.getByRole('button', { name: /login/i });

		await fireEvent.input(usernameInput, { target: { value: 'testuser' } });
		await fireEvent.input(passwordInput, { target: { value: 'password123' } });
		await fireEvent.click(loginButton);

		expect(mockedAuthStore.login).toHaveBeenCalledTimes(1);
		expect(mockedAuthStore.login).toHaveBeenCalledWith('testuser', 'password123');
	});

	it('disables the button when loading', async () => {
		mockedAuthStore.isLoading.set(true);
		render(LoginForm);
		const loginButton = screen.getByRole('button', { name: /logging in/i });
		expect(loginButton).toBeDisabled();
	});

	it('enables the button when not loading', async () => {
		mockedAuthStore.isLoading.set(false);
		render(LoginForm);
		const loginButton = screen.getByRole('button', { name: /login/i });
		expect(loginButton).not.toBeDisabled();
	});
});