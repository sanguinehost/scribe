import { render, screen, waitFor } from '@testing-library/svelte';
import { expect, test, vi, beforeEach } from 'vitest';
import Page from './+page.svelte';

beforeEach(() => {
	// Reset mocks before each test
	vi.resetAllMocks();
});

test('fetches and displays backend health status', async () => {
	// Mock the global fetch function
	const mockFetch = vi.fn().mockResolvedValue({
		ok: true,
		json: async () => ({ status: 'ok' }) // Simulate successful response
	});
	vi.stubGlobal('fetch', mockFetch);

	// Render the component
	render(Page);

	// Check initial state
	expect(screen.getByText(/Checking.../)).toBeInTheDocument();

	// Wait for the fetch call to be made and the component to update
	await waitFor(() => {
		expect(mockFetch).toHaveBeenCalledOnce();
		expect(mockFetch).toHaveBeenCalledWith('/api/health');
	});

	// Wait for the component to update with the fetched status
	await waitFor(() => {
		// Check for the final state (use a flexible query)
		const statusElement = screen.getByText(/Backend Health Status:/);
		expect(statusElement).toBeInTheDocument();
		// Check that the strong tag contains 'ok'
		const strongElement = statusElement.querySelector('strong');
		expect(strongElement).toHaveTextContent('ok');
		// Ensure error message is not present
		expect(screen.queryByText(/Error details:/)).not.toBeInTheDocument();
	});
});

test('displays error message on failed health check', async () => {
	// Mock fetch to simulate an error
	const mockFetch = vi.fn().mockRejectedValue(new Error('Network failure'));
	vi.stubGlobal('fetch', mockFetch);

	render(Page);

	// Check initial state
	expect(screen.getByText(/Checking.../)).toBeInTheDocument();

	// Wait for the fetch call to be made and the component to update
	await waitFor(() => {
		expect(mockFetch).toHaveBeenCalledOnce();
	});

	// Wait for the component to update with the error state
	await waitFor(() => {
		const statusElement = screen.getByText(/Backend Health Status:/);
		expect(statusElement).toBeInTheDocument();
		const strongElement = statusElement.querySelector('strong');
		expect(strongElement).toHaveTextContent('Error'); // Component should show 'Error'
		expect(screen.getByText(/Error details:/)).toBeInTheDocument(); // Error message should appear
		expect(screen.getByText(/Network failure/)).toBeInTheDocument(); // Specific error message
	});
});
