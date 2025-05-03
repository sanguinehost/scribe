import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';
import RegisterForm from './RegisterForm.svelte';
import { authStore } from '$lib/stores/authStore'; // Mock this later if needed

// Mock the authStore register method
const mockRegister = vi.fn();
authStore.register = mockRegister;

// Mock $app/navigation
vi.mock('$app/navigation', () => ({
	goto: vi.fn()
}));

describe('RegisterForm.svelte', () => {
	it('renders the register form with username, email, password inputs and a submit button', () => {
		render(RegisterForm);

		expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
		expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
		expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /register/i })).toBeInTheDocument();
	});

	it('requires username, email and password', async () => {
		render(RegisterForm);
		const registerButton = screen.getByRole('button', { name: /register/i });

		await fireEvent.click(registerButton);

		// Expect the register function NOT to be called if fields are empty
		expect(mockRegister).not.toHaveBeenCalled();
		// Optionally, check for validation messages if implemented
		// expect(screen.getByText(/username is required/i)).toBeInTheDocument();
		// expect(screen.getByText(/email is required/i)).toBeInTheDocument();
		// expect(screen.getByText(/password is required/i)).toBeInTheDocument();
	});

	it('calls authStore.register with credentials on valid submission', async () => {
		render(RegisterForm);

		const usernameInput = screen.getByLabelText(/username/i);
		const emailInput = screen.getByLabelText(/email/i);
		const passwordInput = screen.getByLabelText(/password/i);
		const registerButton = screen.getByRole('button', { name: /register/i });

		await fireEvent.input(usernameInput, { target: { value: 'testuser' } });
		await fireEvent.input(emailInput, { target: { value: 'test@example.com' } });
		await fireEvent.input(passwordInput, { target: { value: 'password123' } });
		await fireEvent.click(registerButton);

		expect(mockRegister).toHaveBeenCalledOnce();
		expect(mockRegister).toHaveBeenCalledWith('testuser', 'test@example.com', 'password123');
	});

	// Add more tests later for error handling, loading states, password confirmation etc.
});