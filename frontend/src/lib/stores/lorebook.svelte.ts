import { apiClient as _apiClient } from '$lib/api';
import type {
	Lorebook,
	LorebookEntry,
	CreateLorebookPayload,
	UpdateLorebookPayload,
	CreateLorebookEntryPayload,
	UpdateLorebookEntryPayload,
	LorebookUploadPayload
} from '$lib/types';

interface SillyTavernLorebookFormat {
	name?: string;
	description?: string;
	entries?: Record<string, unknown>;
	[key: string]: unknown;
}

interface LorebookStore {
	lorebooks: Lorebook[];
	selectedLorebook: Lorebook | null;
	entries: LorebookEntry[];
	isLoading: boolean;
	isLoadingEntries: boolean;
	error: string | null;
}

function createLorebookStore() {
	const state = $state<LorebookStore>({
		lorebooks: [],
		selectedLorebook: null,
		entries: [],
		isLoading: false,
		isLoadingEntries: false,
		error: null
	});

	return {
		get lorebooks() {
			return state.lorebooks;
		},
		get selectedLorebook() {
			return state.selectedLorebook;
		},
		get entries() {
			return state.entries;
		},
		get isLoading() {
			return state.isLoading;
		},
		get isLoadingEntries() {
			return state.isLoadingEntries;
		},
		get error() {
			return state.error;
		},

		// Actions
		async loadLorebooks() {
			state.isLoading = true;
			state.error = null;
			const result = await _apiClient.getLorebooks();
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
			const result = await _apiClient.createLorebook(payload);
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
			const result = await _apiClient.updateLorebook(id, payload);
			if (result.isOk()) {
				const updatedLorebook = result.value;

				const index = state.lorebooks.findIndex((l) => l.id === id);
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
			const result = await _apiClient.deleteLorebook(id);
			if (result.isOk()) {
				state.lorebooks = state.lorebooks.filter((l) => l.id !== id);

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

		async selectLorebook(_lorebook: Lorebook | null) {
			state.selectedLorebook = _lorebook;
			if (_lorebook) {
				await this.loadEntries(_lorebook.id);
			} else {
				state.entries = [];
			}
		},

		async loadEntries(lorebookId: string) {
			state.isLoadingEntries = true;
			state.error = null;
			const result = await _apiClient.getLorebookEntries(lorebookId);
			if (result.isOk()) {
				state.entries = result.value;
			} else {
				state.error = result.error.message;
			}
			state.isLoadingEntries = false;
		},

		async createEntry(
			lorebookId: string,
			payload: CreateLorebookEntryPayload
		): Promise<LorebookEntry | null> {
			state.isLoadingEntries = true;
			state.error = null;
			const result = await _apiClient.createLorebookEntry(lorebookId, payload);
			if (result.isOk()) {
				const newEntry = result.value;
				state.entries.push(newEntry);
				state.isLoadingEntries = false;
				return newEntry;
			} else {
				state.error = result.error.message;
				state.isLoadingEntries = false;
				return null;
			}
		},

		async updateEntry(
			lorebookId: string,
			entryId: string,
			payload: UpdateLorebookEntryPayload
		): Promise<boolean> {
			state.isLoadingEntries = true;
			state.error = null;
			const result = await _apiClient.updateLorebookEntry(lorebookId, entryId, payload);
			if (result.isOk()) {
				const updatedEntry = result.value;

				const index = state.entries.findIndex((e) => e.id === entryId);
				if (index !== -1) {
					state.entries[index] = updatedEntry;
				}
				state.isLoadingEntries = false;
				return true;
			} else {
				state.error = result.error.message;
				state.isLoadingEntries = false;
				return false;
			}
		},

		async deleteEntry(lorebookId: string, entryId: string): Promise<boolean> {
			state.isLoadingEntries = true;
			state.error = null;
			const result = await _apiClient.deleteLorebookEntry(lorebookId, entryId);
			if (result.isOk()) {
				state.entries = state.entries.filter((e) => e.id !== entryId);
				state.isLoadingEntries = false;
				return true;
			} else {
				state.error = result.error.message;
				state.isLoadingEntries = false;
				return false;
			}
		},

		clearError() {
			state.error = null;
		},

		async exportLorebook(
			lorebookId: string,
			format: 'scribe_minimal' | 'silly_tavern_full' = 'silly_tavern_full'
		): Promise<unknown | null> {
			state.isLoading = true;
			state.error = null;
			const result = await _apiClient.exportLorebook(lorebookId, format);
			if (result.isOk()) {
				state.isLoading = false;
				return result.value;
			} else {
				state.error = result.error.message;
				state.isLoading = false;
				return null;
			}
		},

		async importLorebook(_data: Record<string, unknown>): Promise<Lorebook | null> {
			state.isLoading = true;
			state.error = null;

			// Convert the SillyTavern format to our upload payload
			const sillyTavernData = _data as SillyTavernLorebookFormat;
			const payload: LorebookUploadPayload = {
				name: sillyTavernData.name || 'Imported Lorebook',
				description: sillyTavernData.description || undefined,
				entries: Object.values(sillyTavernData.entries || {}).map((entry: unknown) => {
					const e = entry as {
						name?: string;
						title?: string;
						content?: string;
						keys?: string[];
						keywords?: string[];
					};
					return {
						name: e.name || e.title || 'Unnamed Entry',
						content: e.content || '',
						keywords: e.keys || e.keywords || []
					};
				})
			};

			const result = await _apiClient.importLorebook(payload);
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
		}
	};
}

export const lorebookStore = createLorebookStore();
