import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';
import LoginForm from './LoginForm.svelte';
import { authStore } from '$lib/stores/authStore'; // Mock this later if needed

// Mock the authStore login method
const mockLogin = vi.fn();
authStore.login = mockLogin;

// Mock $app/navigation
vi.mock('$app/navigation', () => ({
	goto: vi.fn()
}));

describe('LoginForm.svelte', () => {
	it('renders the login form with username, password inputs and a submit button', () => {
		render(LoginForm);

		expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
		expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument();
	});

	it('requires username and password', async () => {
		render(LoginForm);
		const loginButton = screen.getByRole('button', { name: /login/i });

		await fireEvent.click(loginButton);

		// Expect the login function NOT to be called if fields are empty
		// (Actual validation logic might show error messages, but for now, check call)
		expect(mockLogin).not.toHaveBeenCalled();
		// Optionally, check for validation messages if implemented
		// expect(screen.getByText(/email is required/i)).toBeInTheDocument();
		// expect(screen.getByText(/password is required/i)).toBeInTheDocument();
	});

	it('calls authStore.login with credentials on valid submission', async () => {
		render(LoginForm);

		const usernameInput = screen.getByLabelText(/username/i);
		const passwordInput = screen.getByLabelText(/password/i);
		const loginButton = screen.getByRole('button', { name: /login/i });

		await fireEvent.input(usernameInput, { target: { value: 'testuser' } });
		await fireEvent.input(passwordInput, { target: { value: 'password123' } });
		await fireEvent.click(loginButton);

		expect(mockLogin).toHaveBeenCalledOnce();
		expect(mockLogin).toHaveBeenCalledWith('testuser', 'password123');
	});

	// Add more tests later for error handling, loading states etc.
});