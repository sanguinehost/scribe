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
		subscribe: vi.fn(() => () => {}) // Minimal mock for page store subscription
		// Add other properties if page store is used more extensively
	}
}));

vi.mock('$lib/auth.svelte', () => {
	const mockUser: User = {
		id: 'test-user-123',
		email: 'user@example.com',
		username: 'testuser'
	};

	return {
		getCurrentUser: () => mockUser,
		getIsAuthenticated: () => true,
		getHasConnectionError: () => false,
		setUnauthenticated: vi.fn()
	};
});

vi.mock('@sejohnson/svelte-themes', () => ({
	getTheme: vi.fn(() => ({
		selectedTheme: 'light',
		resolvedTheme: 'light'
		// Mock any other properties/methods used by the component if necessary
	}))
}));

describe('SidebarUserNav', () => {
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

	it('renders user email when authenticated', async () => {
		render(SidebarUserNav, { props: {} });

		// Check for user email within the trigger button
		expect(screen.getByText('user@example.com')).toBeInTheDocument();

		// Verify the avatar image is present
		const avatar = screen.getByRole('img', { name: 'user@example.com' });
		expect(avatar).toBeInTheDocument();
		expect(avatar).toHaveAttribute('src', 'https://avatar.vercel.sh/user@example.com');
	});

	// Note: Testing the dropdown interaction is complex with bits-ui components in a test environment.
	// The auth logic is tested in the auth.svelte.ts module and API client tests.
	// For now, we focus on basic rendering functionality.
});
