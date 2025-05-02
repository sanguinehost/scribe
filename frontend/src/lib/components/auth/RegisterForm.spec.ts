// frontend/src/lib/components/auth/RegisterForm.spec.ts
import { render, fireEvent, screen, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ComponentType } from 'svelte';

// Mock setup - moved before component import and properly initialized
vi.mock('$app/navigation', () => {
	return {
		goto: vi.fn()
	};
});

// Create an appropriate mock for the apiClient
// The actual module exports individual functions, but the component imports an "apiClient" object
vi.mock('$lib/services/apiClient', () => {
	// Create a mock for the register function
	const registerMock = vi.fn();
	
	// Return the expected structure
	return {
		// Export register as a standalone function
		register: registerMock,
		
		// Also export an apiClient object with register method
		apiClient: {
			register: registerMock
		}
	};
});

// Import component AFTER declaring all mocks
import RegisterForm from './RegisterForm.svelte';
import { goto } from '$app/navigation';
// Import the mocked modules with type
import * as apiClientModule from '$lib/services/apiClient';

// Define a type for the mocked module to avoid using 'any'
interface MockApiClientModule {
	apiClient: {
		register: ReturnType<typeof vi.fn>;
	};
}

// Access the mocked functions through the imported modules
const mockGoto = goto as unknown as ReturnType<typeof vi.fn>;
// Get the register function from the mock using proper typing
const mockRegister = (apiClientModule as unknown as MockApiClientModule).apiClient.register;

describe('RegisterForm.svelte', () => {
	// Reset mocks before each test
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it('renders the register form correctly', () => {
		render(RegisterForm as unknown as ComponentType);
		expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
		expect(screen.getByLabelText('Password')).toBeInTheDocument();
		expect(screen.getByLabelText('Confirm Password')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /register/i })).toBeInTheDocument();
	});

	it('updates input values on change', async () => {
		render(RegisterForm as unknown as ComponentType);
		const usernameInput = screen.getByLabelText(/username/i);
		const passwordInput = screen.getByLabelText('Password');
		const confirmPasswordInput = screen.getByLabelText('Confirm Password');

		await fireEvent.input(usernameInput, { target: { value: 'newuser' } });
		await fireEvent.input(passwordInput, { target: { value: 'newpassword123' } });
		await fireEvent.input(confirmPasswordInput, { target: { value: 'newpassword123' } });

		expect(usernameInput).toHaveValue('newuser');
		expect(passwordInput).toHaveValue('newpassword123');
		expect(confirmPasswordInput).toHaveValue('newpassword123');
	});

	it('calls apiClient.register on form submission and navigates on success', async () => {
		// Mock successful registration
		mockRegister.mockResolvedValue({ id: '1', username: 'newuser' });

		render(RegisterForm as unknown as ComponentType);
		const usernameInput = screen.getByLabelText(/username/i);
		const passwordInput = screen.getByLabelText('Password');
		const confirmPasswordInput = screen.getByLabelText('Confirm Password');
		const registerButton = screen.getByRole('button', { name: /register/i });

		await fireEvent.input(usernameInput, { target: { value: 'newuser' } });
		await fireEvent.input(passwordInput, { target: { value: 'newpassword123' } });
		await fireEvent.input(confirmPasswordInput, { target: { value: 'newpassword123' } });
		await fireEvent.click(registerButton);

		// Check if the mocked register function was called
		expect(mockRegister).toHaveBeenCalledTimes(1);
		expect(mockRegister).toHaveBeenCalledWith('newuser', 'newpassword123');

		// Check if navigation occurred after successful registration
		await waitFor(() => {
			expect(mockGoto).toHaveBeenCalledTimes(1);
			expect(mockGoto).toHaveBeenCalledWith('/login', { replaceState: true });
		});
	});

	it('displays an error message on registration failure', async () => {
		const errorMessage = 'Registration failed';
		// Mock failed registration
		mockRegister.mockRejectedValue(new Error(errorMessage));

		render(RegisterForm as unknown as ComponentType);
		const usernameInput = screen.getByLabelText(/username/i);
		const passwordInput = screen.getByLabelText('Password');
		const confirmPasswordInput = screen.getByLabelText('Confirm Password');
		const registerButton = screen.getByRole('button', { name: /register/i });

		await fireEvent.input(usernameInput, { target: { value: 'testuser' } });
		await fireEvent.input(passwordInput, { target: { value: 'password123' } });
		await fireEvent.input(confirmPasswordInput, { target: { value: 'password123' } });
		await fireEvent.click(registerButton);

		// Check if the mocked register function was called
		expect(mockRegister).toHaveBeenCalledTimes(1);
		expect(mockRegister).toHaveBeenCalledWith('testuser', 'password123');

		// Wait for the error message to appear in the DOM
		const errorElement = await screen.findByText(errorMessage);
		expect(errorElement).toBeInTheDocument();

		// Check that navigation did not occur
		expect(mockGoto).not.toHaveBeenCalled();
	});

	it('shows error when passwords do not match', async () => {
		render(RegisterForm as unknown as ComponentType);
		
		const usernameInput = screen.getByLabelText(/username/i);
		const passwordInput = screen.getByLabelText('Password');
		const confirmPasswordInput = screen.getByLabelText('Confirm Password');
		const registerButton = screen.getByRole('button', { name: /register/i });
		
		await fireEvent.input(usernameInput, { target: { value: 'testuser' } });
		await fireEvent.input(passwordInput, { target: { value: 'password123' } });
		await fireEvent.input(confirmPasswordInput, { target: { value: 'differentpassword' } });
		await fireEvent.click(registerButton);
		
		// Register should not be called if passwords don't match
		expect(mockRegister).not.toHaveBeenCalled();
		
		// Error message should be displayed
		const errorElement = await screen.findByText('Passwords do not match.');
		expect(errorElement).toBeInTheDocument();
	});
});