import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import CreditPackageSelector from '../CreditPackageSelector.svelte';
import { creditStore } from '$lib/stores/credits';
import type { CreditPackage } from '$lib/types/payment';

// Mock the credit store
vi.mock('$lib/stores/credits', () => ({
	creditStore: {
		fetchPackages: vi.fn(),
		subscribe: vi.fn()
	}
}));

// Mock toast notifications
vi.mock('svelte-sonner', () => ({
	toast: {
		error: vi.fn(),
		success: vi.fn()
	}
}));

describe('CreditPackageSelector', () => {
	const mockPackages: CreditPackage[] = [
		{
			package_id: 'pkg1',
			name: 'Starter Pack',
			credits: 1000,
			price_cents: 999,
			currency: 'USD',
			active: true,
			display_order: 1,
			bonus_percentage: 0
		},
		{
			package_id: 'pkg2',
			name: 'Popular Pack',
			credits: 5000,
			price_cents: 4499,
			currency: 'USD',
			active: true,
			display_order: 2,
			bonus_percentage: 10
		},
		{
			package_id: 'pkg3',
			name: 'Best Value Pack',
			credits: 10000,
			price_cents: 7999,
			currency: 'USD',
			active: true,
			display_order: 3,
			bonus_percentage: 25
		}
	];

	beforeEach(() => {
		vi.clearAllMocks();
		// Mock the store subscription to return mock packages
		vi.mocked(creditStore.subscribe).mockImplementation((callback) => {
			callback({
				packages: mockPackages,
				isLoading: false,
				error: null,
				balance: null,
				transactions: [],
				dailyUsage: null,
				lastFetch: null
			});
			return vi.fn(); // unsubscribe function
		});
	});

	it('renders available credit packages', async () => {
		render(CreditPackageSelector, {
			props: {
				onPackageSelect: vi.fn(),
				selectedPackageId: null
			}
		});

		// Check if packages are displayed
		expect(screen.getByText('Starter Pack')).toBeInTheDocument();
		expect(screen.getByText('Popular Pack')).toBeInTheDocument();
		expect(screen.getByText('Best Value Pack')).toBeInTheDocument();

		// Check pricing displays
		expect(screen.getByText('$9.99')).toBeInTheDocument();
		expect(screen.getByText('$44.99')).toBeInTheDocument();
		expect(screen.getByText('$79.99')).toBeInTheDocument();

		// Check credit amounts
		expect(screen.getByText('1,000 credits')).toBeInTheDocument();
		expect(screen.getByText('5,000 credits')).toBeInTheDocument();
		expect(screen.getByText('10,000 credits')).toBeInTheDocument();
	});

	it('displays bonus percentages when available', async () => {
		render(CreditPackageSelector, {
			props: {
				onPackageSelect: vi.fn(),
				selectedPackageId: null
			}
		});

		// Check bonus displays
		expect(screen.getByText('+10% bonus credits')).toBeInTheDocument();
		expect(screen.getByText('+25% bonus credits')).toBeInTheDocument();

		// Starter pack should not have bonus text (0%)
		expect(screen.queryByText('+0% bonus credits')).not.toBeInTheDocument();
	});

	it('calls onPackageSelect when select button is clicked', async () => {
		const mockOnSelect = vi.fn();
		render(CreditPackageSelector, {
			props: {
				onPackageSelect: mockOnSelect,
				selectedPackageId: null
			}
		});

		// Click on a select button
		const selectButtons = screen.getAllByText('Select Package');
		await fireEvent.click(selectButtons[0]);

		expect(mockOnSelect).toHaveBeenCalledWith(mockPackages[0]);
	});

	it('highlights selected package', async () => {
		render(CreditPackageSelector, {
			props: {
				onPackageSelect: vi.fn(),
				selectedPackageId: 'pkg2'
			}
		});

		// Find the selected package button
		const selectedButton = screen.getByText('Selected');
		expect(selectedButton).toBeInTheDocument();

		// Find non-selected package buttons
		const selectButtons = screen.getAllByText('Select Package');
		expect(selectButtons).toHaveLength(2); // Two other packages
	});

	it('displays badges for best value and popular packages', async () => {
		const { container } = render(CreditPackageSelector, {
			props: {
				onPackageSelect: vi.fn(),
				selectedPackageId: null
			}
		});

		// Check for badges (they should appear based on logic)
		const badges = container.querySelectorAll('.absolute');
		expect(badges.length).toBeGreaterThan(0);
	});

	it('shows loading state', async () => {
		// Mock loading state
		vi.mocked(creditStore.subscribe).mockImplementation((callback) => {
			callback({
				packages: [],
				isLoading: true,
				error: null,
				balance: null,
				transactions: [],
				dailyUsage: null,
				lastFetch: null
			});
			return vi.fn();
		});

		render(CreditPackageSelector, {
			props: {
				onPackageSelect: vi.fn(),
				selectedPackageId: null
			}
		});

		expect(screen.getByText('Loading packages...')).toBeInTheDocument();
	});

	it('shows error state with retry button', async () => {
		const mockError = 'Failed to load packages';

		// Mock error state
		vi.mocked(creditStore.subscribe).mockImplementation((callback) => {
			callback({
				packages: [],
				isLoading: false,
				error: mockError,
				balance: null,
				transactions: [],
				dailyUsage: null,
				lastFetch: null
			});
			return vi.fn();
		});

		render(CreditPackageSelector, {
			props: {
				onPackageSelect: vi.fn(),
				selectedPackageId: null
			}
		});

		expect(screen.getByText(`Failed to load credit packages: ${mockError}`)).toBeInTheDocument();
		expect(screen.getByText('Retry')).toBeInTheDocument();

		// Test retry functionality
		const retryButton = screen.getByText('Retry');
		await fireEvent.click(retryButton);
		expect(creditStore.fetchPackages).toHaveBeenCalled();
	});

	it('shows empty state when no packages available', async () => {
		// Mock empty state
		vi.mocked(creditStore.subscribe).mockImplementation((callback) => {
			callback({
				packages: [],
				isLoading: false,
				error: null,
				balance: null,
				transactions: [],
				dailyUsage: null,
				lastFetch: null
			});
			return vi.fn();
		});

		render(CreditPackageSelector, {
			props: {
				onPackageSelect: vi.fn(),
				selectedPackageId: null
			}
		});

		expect(screen.getByText('No credit packages available')).toBeInTheDocument();
	});
});
