import { apiClient } from '$lib/api';
import type { 
	Lorebook, 
	LorebookEntry, 
	CreateLorebookPayload, 
	UpdateLorebookPayload,
	CreateLorebookEntryPayload,
	UpdateLorebookEntryPayload 
} from '$lib/types';

interface LorebookStore {
	lorebooks: Lorebook[];
	selectedLorebook: Lorebook | null;
	entries: LorebookEntry[];
	isLoading: boolean;
	error: string | null;
}

function createLorebookStore() {
	let state = $state<LorebookStore>({
		lorebooks: [],
		selectedLorebook: null,
		entries: [],
		isLoading: false,
		error: null
	});

	return {
		get lorebooks() { return state.lorebooks; },
		get selectedLorebook() { return state.selectedLorebook; },
		get entries() { return state.entries; },
		get isLoading() { return state.isLoading; },
		get error() { return state.error; },

		// Actions
		async loadLorebooks() {
			state.isLoading = true;
			state.error = null;
			const result = await apiClient.getLorebooks();
			if (result.isOk()) {
				state.lorebooks = result.value;
			} else {
				state.error = result.error.message;
			}
			state.isLoading = false;
		},

		async createLorebook(payload: CreateLorebookPayload): Promise<Lorebook | null> {
			state.isLoading = true;
			state.error = null;
			const result = await apiClient.createLorebook(payload);
			if (result.isOk()) {
				const newLorebook = result.value;
				state.lorebooks.push(newLorebook);
				state.isLoading = false;
				return newLorebook;
			} else {
				state.error = result.error.message;
				state.isLoading = false;
				return null;
			}
		},

		async updateLorebook(id: string, payload: UpdateLorebookPayload): Promise<boolean> {
			state.isLoading = true;
			state.error = null;
			const result = await apiClient.updateLorebook(id, payload);
			if (result.isOk()) {
				const updatedLorebook = result.value;
				
				const index = state.lorebooks.findIndex(l => l.id === id);
				if (index !== -1) {
					state.lorebooks[index] = updatedLorebook;
				}
				
				if (state.selectedLorebook?.id === id) {
					state.selectedLorebook = updatedLorebook;
				}
				state.isLoading = false;
				return true;
			} else {
				state.error = result.error.message;
				state.isLoading = false;
				return false;
			}
		},

		async deleteLorebook(id: string): Promise<boolean> {
			state.isLoading = true;
			state.error = null;
			const result = await apiClient.deleteLorebook(id);
			if (result.isOk()) {
				state.lorebooks = state.lorebooks.filter(l => l.id !== id);
				
				if (state.selectedLorebook?.id === id) {
					state.selectedLorebook = null;
					state.entries = [];
				}
				state.isLoading = false;
				return true;
			} else {
				state.error = result.error.message;
				state.isLoading = false;
				return false;
			}
		},

		async selectLorebook(lorebook: Lorebook | null) {
			state.selectedLorebook = lorebook;
			if (lorebook) {
				await this.loadEntries(lorebook.id);
			} else {
				state.entries = [];
			}
		},

		async loadEntries(lorebookId: string) {
			state.isLoading = true;
			state.error = null;
			const result = await apiClient.getLorebookEntries(lorebookId);
			if (result.isOk()) {
				state.entries = result.value;
			} else {
				state.error = result.error.message;
			}
			state.isLoading = false;
		},

		async createEntry(lorebookId: string, payload: CreateLorebookEntryPayload): Promise<LorebookEntry | null> {
			state.isLoading = true;
			state.error = null;
			const result = await apiClient.createLorebookEntry(lorebookId, payload);
			if (result.isOk()) {
				const newEntry = result.value;
				state.entries.push(newEntry);
				state.isLoading = false;
				return newEntry;
			} else {
				state.error = result.error.message;
				state.isLoading = false;
				return null;
			}
		},

		async updateEntry(lorebookId: string, entryId: string, payload: UpdateLorebookEntryPayload): Promise<boolean> {
			state.isLoading = true;
			state.error = null;
			const result = await apiClient.updateLorebookEntry(lorebookId, entryId, payload);
			if (result.isOk()) {
				const updatedEntry = result.value;
				
				const index = state.entries.findIndex(e => e.id === entryId);
				if (index !== -1) {
					state.entries[index] = updatedEntry;
				}
				state.isLoading = false;
				return true;
			} else {
				state.error = result.error.message;
				state.isLoading = false;
				return false;
			}
		},

		async deleteEntry(lorebookId: string, entryId: string): Promise<boolean> {
			state.isLoading = true;
			state.error = null;
			const result = await apiClient.deleteLorebookEntry(lorebookId, entryId);
			if (result.isOk()) {
				state.entries = state.entries.filter(e => e.id !== entryId);
				state.isLoading = false;
				return true;
			} else {
				state.error = result.error.message;
				state.isLoading = false;
				return false;
			}
		},

		clearError() {
			state.error = null;
		}
	};
}

export const lorebookStore = createLorebookStore();