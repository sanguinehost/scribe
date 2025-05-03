import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import CharacterUploader from './CharacterUploader.svelte';
import { apiClient } from '$lib/services/apiClient'; // Import the actual object
import type { Character } from '$lib/services/apiClient';

// Mock the apiClient's uploadCharacter method
const mockUploadCharacter = vi.fn();
apiClient.uploadCharacter = mockUploadCharacter;

describe('CharacterUploader.svelte', () => {
	const mockNewCharacter: Character = {
		id: 'newChar', name: 'Uploaded Char', description: 'Uploaded Desc', greeting: 'Uploaded Hi'
	};
	const mockRefreshCallback = vi.fn();

	beforeEach(() => {
		vi.clearAllMocks();
		// Default successful upload response
		mockUploadCharacter.mockResolvedValue(mockNewCharacter);
	});

	it('renders a file input accepting only .png files and an upload button', () => {
		render(CharacterUploader, { props: { onUploadSuccess: mockRefreshCallback } });

		const fileInput = screen.getByLabelText(/character card/i);
		expect(fileInput).toBeInTheDocument();
		expect(fileInput).toHaveAttribute('type', 'file');
		expect(fileInput).toHaveAttribute('accept', '.png');

		// Use getAllByRole and find the button with type="button" 
		const uploadButtons = screen.getAllByRole('button', { name: /upload/i });
		const actualButton = uploadButtons.find(button => button.tagName.toLowerCase() === 'button');
		expect(actualButton).toBeInTheDocument();
	});

	it('disables upload button initially and when no file is selected', () => {
		render(CharacterUploader, { props: { onUploadSuccess: mockRefreshCallback } });
		// Use getAllByRole and find the button with type="button"
		const uploadButtons = screen.getAllByRole('button', { name: /upload/i });
		const uploadButton = uploadButtons.find(button => button.tagName.toLowerCase() === 'button');
		expect(uploadButton).toBeDisabled();
	});

	it('enables upload button when a file is selected', async () => {
		render(CharacterUploader, { props: { onUploadSuccess: mockRefreshCallback } });
		const fileInput = screen.getByLabelText(/character card/i);
		const file = new File(['(⌐□_□)'], 'chucknorris.png', { type: 'image/png' });

		await fireEvent.change(fileInput, { target: { files: [file] } });

		// Use getAllByRole and find the button with type="button"
		const uploadButtons = screen.getAllByRole('button', { name: /upload/i });
		const uploadButton = uploadButtons.find(button => button.tagName.toLowerCase() === 'button');
		expect(uploadButton).not.toBeDisabled();
	});

	it('calls apiClient.uploadCharacter with FormData and triggers refresh on successful upload', async () => {
		render(CharacterUploader, { props: { onUploadSuccess: mockRefreshCallback } });
		const fileInput = screen.getByLabelText(/character card/i);
		// Use getAllByRole and find the button with type="button"
		const uploadButtons = screen.getAllByRole('button', { name: /upload/i });
		const uploadButton = uploadButtons.find(button => button.tagName.toLowerCase() === 'button') as HTMLButtonElement;
		
		const file = new File(['(⌐□_□)'], 'character.png', { type: 'image/png' });

		// Select file
		await fireEvent.change(fileInput, { target: { files: [file] } });

		// Click upload
		await fireEvent.click(uploadButton);

		// Check API call
		expect(mockUploadCharacter).toHaveBeenCalledTimes(1);
		expect(mockUploadCharacter).toHaveBeenCalledWith(expect.any(FormData)); // Check if FormData was passed

		// Check that the FormData contains the file (more specific check)
		const formData = mockUploadCharacter.mock.calls[0][0] as FormData;
        expect(formData.get('character_card')).toBeInstanceOf(File);
        expect((formData.get('character_card') as File).name).toBe('character.png');


		// Wait for potential async operations in component (like setting success message)
		await waitFor(() => {
			// Check refresh callback
			expect(mockRefreshCallback).toHaveBeenCalledTimes(1);
		});

		// Check for success message (optional, depends on implementation)
		// expect(screen.getByText(/upload successful/i)).toBeInTheDocument();
	});

	it('displays an error message if upload fails', async () => {
		const errorMessage = 'Upload failed miserably';
		mockUploadCharacter.mockRejectedValue(new Error(errorMessage));

		render(CharacterUploader, { props: { onUploadSuccess: mockRefreshCallback } });
		const fileInput = screen.getByLabelText(/character card/i);
		// Use getAllByRole and find the button with type="button"
		const uploadButtons = screen.getAllByRole('button', { name: /upload/i });
		const uploadButton = uploadButtons.find(button => button.tagName.toLowerCase() === 'button') as HTMLButtonElement;
		
		const file = new File(['(⌐□_□)'], 'fail.png', { type: 'image/png' });

		await fireEvent.change(fileInput, { target: { files: [file] } });
		await fireEvent.click(uploadButton);

		await waitFor(() => {
		    // Check for the alert title specifically
			expect(screen.getByRole('heading', { name: /upload failed/i })).toBeInTheDocument();
			expect(screen.getByText(errorMessage)).toBeInTheDocument();
		});

		expect(mockRefreshCallback).not.toHaveBeenCalled();
	});

	it('shows loading state during upload', async () => {
		// Make the mock promise hang
		mockUploadCharacter.mockImplementation(() => new Promise(() => {}));

		render(CharacterUploader, { props: { onUploadSuccess: mockRefreshCallback } });
		const fileInput = screen.getByLabelText(/character card/i);
		// Use getAllByRole and find the button with type="button"
		const uploadButtons = screen.getAllByRole('button', { name: /upload/i });
		const uploadButton = uploadButtons.find(button => button.tagName.toLowerCase() === 'button') as HTMLButtonElement;
		
		const file = new File(['(⌐□_□)'], 'loading.png', { type: 'image/png' });

		await fireEvent.change(fileInput, { target: { files: [file] } });
		await fireEvent.click(uploadButton);

		// Check if button is disabled and shows loading text/icon
		expect(uploadButton).toBeDisabled();
		expect(screen.getByText(/uploading/i)).toBeInTheDocument(); // Or check for spinner icon
	});
});