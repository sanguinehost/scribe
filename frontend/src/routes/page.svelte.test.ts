import { describe, test, expect, vi, beforeEach } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import Page from './+page.svelte';

beforeEach(() => {
	vi.resetAllMocks();
});

describe('/+page.svelte', () => {
	test('should render h1 and fetch health', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: async () => ({ status: 'ok' })
		});
		vi.stubGlobal('fetch', mockFetch);

		render(Page);

		expect(screen.getByText(/Checking.../)).toBeInTheDocument();

		await waitFor(() => {
			expect(mockFetch).toHaveBeenCalledOnce();
			expect(mockFetch).toHaveBeenCalledWith('/api/health');
		});

		await waitFor(() => {
			expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument();
			expect(screen.getByText(/Backend Health Status:/)).toHaveTextContent('ok');
		});
	});
});
