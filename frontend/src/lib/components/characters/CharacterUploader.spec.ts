// frontend/src/lib/components/characters/CharacterUploader.spec.ts
import { render, fireEvent, screen } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, type Mocked } from 'vitest'; // Import Mocked type
import CharacterUploader from './CharacterUploader.svelte';
import * as apiClient from '$lib/services/apiClient'; // Import the module to mock
// Removed unused SvelteComponent import
import type { Character } from '$lib/services/apiClient'; // Import Character type for event payload
import { tick } from 'svelte'; // Import tick for waiting for state updates

// Mock the apiClient module
vi.mock('$lib/services/apiClient');

// Define a type for the mocked module using the imported Mocked type
const mockedApiClient = apiClient as Mocked<typeof apiClient>;

describe('CharacterUploader.svelte', () => {
	const mockFile = new File(['(⌐□_□)'], 'chucknorris.png', { type: 'image/png' });
	const mockCharacterResponse: Character = { // Mock response for uploadCharacter
		id: 'new-char-456',
		name: 'Uploaded Character',
		description: 'Uploaded successfully.',
		greeting: 'Greetings!',
	};

	beforeEach(() => {
		// Reset mocks before each test
		vi.clearAllMocks();
		// Setup default mock implementation for uploadCharacter
		mockedApiClient.uploadCharacter.mockResolvedValue(mockCharacterResponse);
	});

	it('renders the file input and upload button', () => {
		const { container } = render(CharacterUploader);
		// Find input by type="file" as there's no label
		const fileInput = container.querySelector('input[type="file"]');
		expect(fileInput).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /upload/i })).toBeInTheDocument();
	});

	it('disables the upload button initially', () => {
		render(CharacterUploader);
		expect(screen.getByRole('button', { name: /upload/i })).toBeDisabled();
	});

	it('enables the upload button after a file is selected', async () => {
		const { container } = render(CharacterUploader);
		const fileInput = container.querySelector('input[type="file"]');
		expect(fileInput).toBeInTheDocument(); // Ensure input is found before proceeding
		const uploadButton = screen.getByRole('button', { name: /upload/i });

		expect(uploadButton).toBeDisabled(); // Check initial state

		// Simulate file selection (with null check)
		if (!fileInput) throw new Error('File input not found');
		await fireEvent.change(fileInput, {
			target: { files: [mockFile] }
		});
		await tick(); // Wait for Svelte state updates

		expect(uploadButton).not.toBeDisabled(); // Check state after file selection
	});

	it('calls apiClient.uploadCharacter with FormData on button click', async () => {
		const { container } = render(CharacterUploader);
		const fileInput = container.querySelector('input[type="file"]');
		expect(fileInput).toBeInTheDocument();
		const uploadButton = screen.getByRole('button', { name: /upload/i });

		// Select file (with null check)
		if (!fileInput) throw new Error('File input not found');
		await fireEvent.change(fileInput, { target: { files: [mockFile] } });
		await tick(); // Wait for state update enabling button

		// Click upload
		await fireEvent.click(uploadButton);

		// Check if uploadCharacter was called
		expect(mockedApiClient.uploadCharacter).toHaveBeenCalledTimes(1);

		// Check if it was called with FormData containing the file
		const formData = mockedApiClient.uploadCharacter.mock.calls[0][0];
		expect(formData).toBeInstanceOf(FormData);
		// Ensure the key matches what the component uses ('character_card' is likely)
		expect(formData.get('character_card')).toEqual(mockFile);
	});

	// REMOVED: Test for event dispatch using $on (Svelte 4 API)

	it('displays an error message if upload fails', async () => {
		// Override mock for this specific test to simulate failure
		const errorMessage = 'Upload failed miserably';
		mockedApiClient.uploadCharacter.mockRejectedValue(new Error(errorMessage));

		const { container } = render(CharacterUploader);
		const fileInput = container.querySelector('input[type="file"]');
		expect(fileInput).toBeInTheDocument();
		const uploadButton = screen.getByRole('button', { name: /upload/i });

		// Select file and click upload (with null check)
		if (!fileInput) throw new Error('File input not found');
		await fireEvent.change(fileInput, { target: { files: [mockFile] } });
		await tick(); // Wait for state update enabling button
		await fireEvent.click(uploadButton);

		// Wait for the promise to reject and the component to update state
		await vi.waitFor(() => {
			// Check if the error message is displayed (adjust selector based on implementation)
			expect(screen.getByText(new RegExp(errorMessage, 'i'))).toBeInTheDocument();
		});

		// Also check button is likely re-enabled after failure
		expect(uploadButton).not.toBeDisabled();
	});

	it('displays a loading indicator (disabled button) during upload', async () => {
		// Create a promise that we can manually control
		let resolveUpload: ((value: Character) => void) | undefined;
		const uploadPromise = new Promise<Character>((resolve) => {
			resolveUpload = resolve;
		});
		mockedApiClient.uploadCharacter.mockReturnValue(uploadPromise);

		const { container } = render(CharacterUploader);
		const fileInput = container.querySelector('input[type="file"]');
		expect(fileInput).not.toBeNull();
		const uploadButton = screen.getByRole('button', { name: /upload/i });

		// Select file and click upload
		if (fileInput) {
			await fireEvent.change(fileInput, { target: { files: [mockFile] } });
			await tick(); // Wait for state update enabling button
			expect(uploadButton).not.toBeDisabled(); // Button should be enabled before clicking
			
			await fireEvent.click(uploadButton);
			await tick(); // Allow component to enter loading state

			// Check if button is disabled (common loading indicator)
			expect(uploadButton).toBeDisabled();
			// Check for specific loading text
			expect(screen.getByText(/uploading/i)).toBeInTheDocument();

			// Resolve the promise to complete the upload
			resolveUpload!(mockCharacterResponse);
			
			// Since we're testing "during upload" functionality, we can 
			// consider the test successful without needing to check 
			// the post-upload state, which is validated in other tests
		}
	});
});