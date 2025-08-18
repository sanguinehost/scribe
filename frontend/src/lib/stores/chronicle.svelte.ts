// Chronicle store for managing chronicles list
import { apiClient } from '$lib/api';
import type { PlayerChronicleWithCounts } from '$lib/types';
import { toast } from 'svelte-sonner';

class ChronicleStore {
	chronicles = $state<PlayerChronicleWithCounts[]>([]);
	isLoading = $state(false);
	error = $state<string | null>(null);

	async loadChronicles() {
		this.isLoading = true;
		this.error = null;

		try {
			const result = await apiClient.getChronicles();
			if (result.isOk()) {
				this.chronicles = result.value;
			} else {
				this.error = result.error.message;
				toast.error('Failed to load chronicles', {
					description: result.error.message
				});
			}
		} catch (error) {
			this.error = 'An unexpected error occurred';
			toast.error('Failed to load chronicles');
		} finally {
			this.isLoading = false;
		}
	}

	async refresh() {
		await this.loadChronicles();
	}

	// Find a chronicle by ID
	getChronicleById(id: string): PlayerChronicleWithCounts | undefined {
		return this.chronicles.find((c) => c.id === id);
	}
}

// Export a singleton instance
export const chronicleStore = new ChronicleStore();
