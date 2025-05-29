import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import SidebarUserNav from './sidebar-user-nav.svelte';
import type { User } from '$lib/types';
import { apiClient as actualApiClient } from '$lib/api'; // Import actual to spy on its methods
import { ok, err } from 'neverthrow';
import { ApiResponseError } from '$lib/errors/api';

// Mock dependencies
vi.mock('$lib/api', async (importOriginal) => {
	const actual = await importOriginal<typeof import('$lib/api')>();
	return {
		...actual,
		apiClient: {
			...actual.apiClient,
			logout: vi.fn()
		}
	};
});

vi.mock('$app/navigation', () => ({
	goto: vi.fn()
}));

vi.mock('$app/stores', () => ({
	page: {
		subscribe: vi.fn(() => () => {}), // Minimal mock for page store subscription
		// Add other properties if page store is used more extensively
	}
}));

vi.mock('@sejohnson/svelte-themes', () => ({
	getTheme: vi.fn(() => ({
		selectedTheme: 'light',
		resolvedTheme: 'light',
		// Mock any other properties/methods used by the component if necessary
	}))
}));

describe('SidebarUserNav', () => {
	const mockUser: User = {
		user_id: 'test-user-123',
		email: 'user@example.com',
		username: 'testuser'
	};

	let originalWindowLocation: Location;

	beforeEach(() => {
		// @ts-expect-error - apiClient is mocked, this is a common pattern for Vitest mocks
		(actualApiClient.logout as vi.Mock).mockClear();
		vi.mocked(actualApiClient.logout).mockResolvedValue(ok(undefined));


		originalWindowLocation = window.location;
		// @ts-expect-error - Cannot assign to 'location' because it is a read-only property.
		delete window.location;
		window.location = { ...originalWindowLocation, assign: vi.fn(), href: '' };
	});

	afterEach(() => {
		window.location = originalWindowLocation;
		vi.restoreAllMocks();
	});

	it('renders user email and sign out option when user is provided', async () => {
		render(SidebarUserNav, { props: { user: mockUser } });

		// Check for user email within the trigger button
		const triggerButton = screen.getByRole('button', { name: new RegExp(mockUser.email) });
		expect(triggerButton).toBeInTheDocument();
		expect(screen.getByText(mockUser.email)).toBeInTheDocument();

		// Click the trigger to open the dropdown
		await fireEvent.click(triggerButton);

		// Check for "Sign out" text in the dropdown
		expect(screen.getByText('Sign out')).toBeInTheDocument();
	});

	it('calls apiClient.logout and sets window.location.href on sign out', async () => {
		const { apiClient } = await import('$lib/api'); // Get the mocked version
		render(SidebarUserNav, { props: { user: mockUser } });

		// Open the dropdown menu
		const triggerButton = screen.getByRole('button', { name: new RegExp(mockUser.email) });
		await fireEvent.click(triggerButton);

		// Click the "Sign out" menu item
		const signOutMenuItem = screen.getByText('Sign out');
		await fireEvent.click(signOutMenuItem);

		expect(apiClient.logout).toHaveBeenCalledTimes(1);
		expect(window.location.href).toBe('/auth/login');
	});

    it('handles logout failure gracefully', async () => {
		const { apiClient } = await import('$lib/api'); // Get the mocked version
        vi.mocked(apiClient.logout).mockResolvedValue(err(new ApiResponseError(500, 'Logout failed miserably')));
        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

		render(SidebarUserNav, { props: { user: mockUser } });

		const triggerButton = screen.getByRole('button', { name: new RegExp(mockUser.email) });
		await fireEvent.click(triggerButton);

		const signOutMenuItem = screen.getByText('Sign out');
		await fireEvent.click(signOutMenuItem);

		expect(apiClient.logout).toHaveBeenCalledTimes(1);
		expect(window.location.href).toBe(''); // Should not have redirected
        expect(consoleErrorSpy).toHaveBeenCalledWith('Logout failed:', new ApiResponseError(500, 'Logout failed miserably'));
        
        consoleErrorSpy.mockRestore();
	});
});