import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import NarrativeStyleConfigurator from '../NarrativeStyleConfigurator.svelte';
import { apiClient } from '$lib/api';
import { toast } from 'svelte-sonner';
import type { TemplatePreferenceResponse } from '$lib/types';
import { ok, err } from 'neverthrow';
import { ApiResponseError } from '$lib/errors/api';

// Mock API client
vi.mock('$lib/api', () => ({
	apiClient: {
		getTemplatePreferences: vi.fn(),
		updateTemplatePreferences: vi.fn(),
		deleteTemplatePreferences: vi.fn()
	}
}));

// Mock toast
vi.mock('svelte-sonner', () => ({
	toast: {
		success: vi.fn(),
		error: vi.fn(),
		info: vi.fn()
	}
}));

describe('NarrativeStyleConfigurator', () => {
	const mockPreferences: TemplatePreferenceResponse = {
		id: 'pref-123',
		user_id: 'user-456',
		character_id: null,
		template_id: null,
		tense: 'past-tense',
		narration: 'third-person',
		perspective: 'omniscient',
		length: 'flexible',
		enable_info_box: false,
		enable_stats_tracker: false,
		enable_thinking: false,
		created_at: '2025-10-16T00:00:00Z',
		updated_at: '2025-10-16T00:00:00Z'
	};

	beforeEach(() => {
		vi.clearAllMocks();
		vi.useFakeTimers();
		vi.mocked(apiClient.getTemplatePreferences).mockResolvedValue(ok(mockPreferences));
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(ok(mockPreferences));
		vi.mocked(apiClient.deleteTemplatePreferences).mockResolvedValue(ok(undefined));
	});

	afterEach(() => {
		vi.runOnlyPendingTimers();
		vi.useRealTimers();
	});

	it('shows loading state initially', () => {
		const { getByText } = render(NarrativeStyleConfigurator);

		expect(getByText('Loading writing style preferences...')).toBeInTheDocument();
	});

	it('loads and displays preferences on mount', async () => {
		const { getByText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Writing Style Preferences')).toBeInTheDocument();
		});

		// Verify API was called
		expect(apiClient.getTemplatePreferences).toHaveBeenCalledTimes(1);
		expect(apiClient.getTemplatePreferences).toHaveBeenCalledWith();
	});

	it('displays all three expandable sections', async () => {
		const { getByText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Narrative Voice')).toBeInTheDocument();
		});

		expect(getByText('Response Style')).toBeInTheDocument();
		expect(getByText('Advanced Features')).toBeInTheDocument();
	});

	it('shows correct default values from loaded preferences', async () => {
		const { getByText } = render(NarrativeStyleConfigurator);

		// Wait for component to load preferences
		await waitFor(() => {
			expect(getByText('Writing Style Preferences')).toBeInTheDocument();
		});

		// Verify sections are displayed with default preferences
		expect(getByText('Past Tense')).toBeInTheDocument();
		expect(getByText('Third Person')).toBeInTheDocument();
		expect(getByText('Omniscient')).toBeInTheDocument();
		expect(getByText('Flexible')).toBeInTheDocument();
	});

	it('updates tense preference when radio button is clicked', async () => {
		const updatedPrefs = { ...mockPreferences, tense: 'present-tense' as const };
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(ok(updatedPrefs));

		const { getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByLabelText('Present Tense')).toBeInTheDocument();
		});

		const presentTenseRadio = getByLabelText('Present Tense');
		await fireEvent.click(presentTenseRadio);

		// Wait for debounce (500ms)
		vi.advanceTimersByTime(500);

		await waitFor(() => {
			expect(apiClient.updateTemplatePreferences).toHaveBeenCalledWith(undefined, {
				tense: 'present-tense'
			});
		});
	});

	it('updates narration preference when radio button is clicked', async () => {
		const updatedPrefs = { ...mockPreferences, narration: 'first-person' as const };
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(ok(updatedPrefs));

		const { getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByLabelText('First Person')).toBeInTheDocument();
		});

		const firstPersonRadio = getByLabelText('First Person');
		await fireEvent.click(firstPersonRadio);

		// Wait for debounce (500ms)
		vi.advanceTimersByTime(500);

		await waitFor(() => {
			expect(apiClient.updateTemplatePreferences).toHaveBeenCalledWith(undefined, {
				narration: 'first-person'
			});
		});
	});

	it('updates perspective preference when radio button is clicked', async () => {
		const updatedPrefs = { ...mockPreferences, perspective: 'character-pov' as const };
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(ok(updatedPrefs));

		const { getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByLabelText('Character POV')).toBeInTheDocument();
		});

		const characterPovRadio = getByLabelText('Character POV');
		await fireEvent.click(characterPovRadio);

		// Wait for debounce (500ms)
		vi.advanceTimersByTime(500);

		await waitFor(() => {
			expect(apiClient.updateTemplatePreferences).toHaveBeenCalledWith(undefined, {
				perspective: 'character-pov'
			});
		});
	});

	it('updates length preference when radio button is clicked', async () => {
		const updatedPrefs = { ...mockPreferences, length: 'concise' as const };
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(ok(updatedPrefs));

		const { getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByLabelText('Concise')).toBeInTheDocument();
		});

		const conciseRadio = getByLabelText('Concise');
		await fireEvent.click(conciseRadio);

		// Wait for debounce (500ms)
		vi.advanceTimersByTime(500);

		await waitFor(() => {
			expect(apiClient.updateTemplatePreferences).toHaveBeenCalledWith(undefined, {
				length: 'concise'
			});
		});
	});

	it('toggles Advanced Features section when clicked', async () => {
		const { getByText, queryByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Advanced Features')).toBeInTheDocument();
		});

		// Advanced Features should be collapsed by default
		expect(queryByLabelText('Enable Info Box')).not.toBeInTheDocument();

		// Click to expand
		const advancedHeader = getByText('Advanced Features');
		await fireEvent.click(advancedHeader);

		// Should now be visible
		await waitFor(() => {
			expect(queryByLabelText('Enable Info Box')).toBeInTheDocument();
		});
	});

	it('updates info box preference when checkbox is toggled', async () => {
		const updatedPrefs = { ...mockPreferences, enable_info_box: true };
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(ok(updatedPrefs));

		const { getByText, getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Advanced Features')).toBeInTheDocument();
		});

		// Expand Advanced Features section
		const advancedHeader = getByText('Advanced Features');
		await fireEvent.click(advancedHeader);

		await waitFor(() => {
			expect(getByLabelText('Enable Info Box')).toBeInTheDocument();
		});

		const infoBoxCheckbox = getByLabelText('Enable Info Box');
		await fireEvent.click(infoBoxCheckbox);

		// Wait for debounce (500ms)
		vi.advanceTimersByTime(500);

		await waitFor(() => {
			expect(apiClient.updateTemplatePreferences).toHaveBeenCalledWith(undefined, {
				enable_info_box: true
			});
		});
	});

	it('updates stats tracker preference when checkbox is toggled', async () => {
		const updatedPrefs = { ...mockPreferences, enable_stats_tracker: true };
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(ok(updatedPrefs));

		const { getByText, getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Advanced Features')).toBeInTheDocument();
		});

		// Expand Advanced Features section
		const advancedHeader = getByText('Advanced Features');
		await fireEvent.click(advancedHeader);

		await waitFor(() => {
			expect(getByLabelText('Enable Stats Tracker')).toBeInTheDocument();
		});

		const statsTrackerCheckbox = getByLabelText('Enable Stats Tracker');
		await fireEvent.click(statsTrackerCheckbox);

		// Wait for debounce (500ms)
		vi.advanceTimersByTime(500);

		await waitFor(() => {
			expect(apiClient.updateTemplatePreferences).toHaveBeenCalledWith(undefined, {
				enable_stats_tracker: true
			});
		});
	});

	it('updates thinking mode preference when checkbox is toggled', async () => {
		const updatedPrefs = { ...mockPreferences, enable_thinking: true };
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(ok(updatedPrefs));

		const { getByText, getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Advanced Features')).toBeInTheDocument();
		});

		// Expand Advanced Features section
		const advancedHeader = getByText('Advanced Features');
		await fireEvent.click(advancedHeader);

		await waitFor(() => {
			expect(getByLabelText('Enable Thinking Mode')).toBeInTheDocument();
		});

		const thinkingModeCheckbox = getByLabelText('Enable Thinking Mode');
		await fireEvent.click(thinkingModeCheckbox);

		// Wait for debounce (500ms)
		vi.advanceTimersByTime(500);

		await waitFor(() => {
			expect(apiClient.updateTemplatePreferences).toHaveBeenCalledWith(undefined, {
				enable_thinking: true
			});
		});
	});

	it('debounces multiple rapid changes', async () => {
		const { getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByLabelText('Present Tense')).toBeInTheDocument();
		});

		// Make multiple rapid changes
		const presentTenseRadio = getByLabelText('Present Tense');
		const futureTenseRadio = getByLabelText('Future Tense');

		await fireEvent.click(presentTenseRadio);
		vi.advanceTimersByTime(200); // Not enough time to trigger
		await fireEvent.click(futureTenseRadio);

		// Wait for debounce to complete
		vi.advanceTimersByTime(500);

		// Should only call API once with the last change
		await waitFor(() => {
			expect(apiClient.updateTemplatePreferences).toHaveBeenCalledTimes(1);
			expect(apiClient.updateTemplatePreferences).toHaveBeenCalledWith(undefined, {
				tense: 'future-tense'
			});
		});
	});

	it('calls reset API when Reset to Defaults button is clicked', async () => {
		const { getByText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Reset to Defaults')).toBeInTheDocument();
		});

		const resetButton = getByText('Reset to Defaults');
		await fireEvent.click(resetButton);

		await waitFor(() => {
			expect(apiClient.deleteTemplatePreferences).toHaveBeenCalledWith();
			// Should reload preferences after reset
			expect(apiClient.getTemplatePreferences).toHaveBeenCalledTimes(2);
		});
	});

	it('handles API error when loading preferences', async () => {
		vi.mocked(apiClient.getTemplatePreferences).mockResolvedValue(
			err(new ApiResponseError(500, 'Failed to load preferences'))
		);

		render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(toast.error).toHaveBeenCalledWith(
				'Failed to load preferences: Failed to load preferences'
			);
		});
	});

	it('handles API error when updating preferences', async () => {
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(
			err(new ApiResponseError(500, 'Update failed'))
		);

		const { getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByLabelText('Present Tense')).toBeInTheDocument();
		});

		const presentTenseRadio = getByLabelText('Present Tense');
		await fireEvent.click(presentTenseRadio);

		// Wait for debounce and flush promises
		await vi.advanceTimersByTimeAsync(500);

		await waitFor(() => {
			expect(toast.error).toHaveBeenCalledWith('Failed to update: Update failed');
		});
	});

	it('handles API error when resetting preferences', async () => {
		vi.mocked(apiClient.deleteTemplatePreferences).mockResolvedValue(
			err(new ApiResponseError(500, 'Delete failed'))
		);

		const { getByText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Reset to Defaults')).toBeInTheDocument();
		});

		const resetButton = getByText('Reset to Defaults');
		await fireEvent.click(resetButton);

		await waitFor(() => {
			expect(toast.error).toHaveBeenCalledWith('Failed to reset: Delete failed');
		});
	});

	it('shows retry button when preferences fail to load', async () => {
		vi.mocked(apiClient.getTemplatePreferences).mockResolvedValue(
			err(new ApiResponseError(500, 'Failed to load'))
		);

		const { getByText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Failed to load preferences')).toBeInTheDocument();
		});

		expect(getByText('Retry')).toBeInTheDocument();
	});

	it('retries loading preferences when retry button is clicked', async () => {
		// First call fails
		vi.mocked(apiClient.getTemplatePreferences).mockResolvedValueOnce(
			err(new ApiResponseError(500, 'Failed to load'))
		);
		// Second call succeeds
		vi.mocked(apiClient.getTemplatePreferences).mockResolvedValueOnce(ok(mockPreferences));

		const { getByText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Retry')).toBeInTheDocument();
		});

		const retryButton = getByText('Retry');
		await fireEvent.click(retryButton);

		await waitFor(() => {
			expect(getByText('Writing Style Preferences')).toBeInTheDocument();
			expect(apiClient.getTemplatePreferences).toHaveBeenCalledTimes(2);
		});
	});

	it('shows success toast when preferences are updated', async () => {
		const updatedPrefs = { ...mockPreferences, tense: 'present-tense' as const };
		vi.mocked(apiClient.updateTemplatePreferences).mockResolvedValue(ok(updatedPrefs));

		const { getByLabelText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByLabelText('Present Tense')).toBeInTheDocument();
		});

		const presentTenseRadio = getByLabelText('Present Tense');
		await fireEvent.click(presentTenseRadio);

		// Wait for debounce and flush promises
		await vi.advanceTimersByTimeAsync(500);

		await waitFor(() => {
			expect(toast.success).toHaveBeenCalledWith('Preferences updated');
		});
	});

	it('shows info toast when preferences are reset', async () => {
		// Use real timers for this test since reset doesn't use debouncing
		vi.useRealTimers();

		const { getByText } = render(NarrativeStyleConfigurator);

		await waitFor(() => {
			expect(getByText('Reset to Defaults')).toBeInTheDocument();
		});

		const resetButton = getByText('Reset to Defaults');
		await fireEvent.click(resetButton);

		// Wait for the async operation to complete (no debounce, but async API calls)
		await waitFor(() => {
			expect(toast.info).toHaveBeenCalledWith('Reset to system defaults');
		});

		// Restore fake timers for other tests
		vi.useFakeTimers();
	});
});
