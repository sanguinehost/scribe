/**
 * Character Store for Scribe
 * Simplified version for character creation/editing in dialogs
 * Uses Character Card V3 format internally, converts to scribe format for backend
 */

import type {
	CharacterCardV3,
	LorebookEntry,
	Lorebook,
	ScribeCharacterExtensions
} from '$lib/types/character';
import { apiClient } from '$lib/api';

interface ValidationError {
	path: string;
	message: string;
}

class CharacterStore {
	character = $state<CharacterCardV3 | null>(null);
	baseImage = $state<string | null>(null);
	validationErrors = $state<ValidationError[]>([]);
	private initialCharacter = $state<CharacterCardV3 | null>(null);

	/**
	 * Check if character has unsaved changes
	 */
	get hasChanges(): boolean {
		if (!this.character || !this.initialCharacter) return false;
		return JSON.stringify(this.character) !== JSON.stringify(this.initialCharacter);
	}

	/**
	 * Check if character is valid (has required fields)
	 */
	get isValid(): boolean {
		if (!this.character) return false;
		return !!(
			this.character.data.name?.trim() &&
			this.character.data.description?.trim() &&
			this.character.data.first_mes?.trim()
		);
	}

	/**
	 * Create a new blank character
	 */
	createNew() {
		const newCharacter: CharacterCardV3 = {
			spec: 'chara_card_v3',
			spec_version: '3.0',
			data: {
				name: '',
				description: '',
				personality: '',
				scenario: '',
				first_mes: '',
				mes_example: '',
				creator_notes: '',
				system_prompt: '',
				post_history_instructions: '',
				alternate_greetings: [],
				tags: [],
				creator: '',
				character_version: '',
				group_only_greetings: [],
				extensions: {}
			}
		};
		this.character = newCharacter;
		this.initialCharacter = structuredClone(newCharacter);
	}

	/**
	 * Load an existing character (for editing)
	 */
	load(character: CharacterCardV3) {
		this.character = structuredClone(character);
		this.initialCharacter = structuredClone(character);
	}

	/**
	 * Update a specific field
	 */
	updateField<K extends keyof CharacterCardV3['data']>(
		field: K,
		value: CharacterCardV3['data'][K]
	) {
		if (!this.character) return;
		this.character.data[field] = value;
	}

	/**
	 * Update the character data
	 */
	update(updates: Partial<CharacterCardV3['data']>) {
		if (!this.character) return;
		this.character.data = { ...this.character.data, ...updates };
	}

	/**
	 * Set base image (avatar)
	 */
	setBaseImage(dataUrl: string | null) {
		this.baseImage = dataUrl;
	}

	/**
	 * Clear the store
	 */
	clear() {
		this.character = null;
		this.initialCharacter = null;
		this.baseImage = null;
		this.validationErrors = [];
	}

	// ============================================================================
	// Lorebook Methods
	// ============================================================================

	/**
	 * Update lorebook settings
	 */
	updateLorebookSettings(settings: Partial<Omit<Lorebook, 'entries'>>) {
		if (!this.character) return;

		if (!this.character.data.character_book) {
			this.character.data.character_book = {
				entries: [],
				extensions: {}
			};
		}

		this.character.data.character_book = {
			...this.character.data.character_book,
			...settings
		};
	}

	/**
	 * Add a new lorebook entry
	 */
	addLorebookEntry(entry: LorebookEntry) {
		if (!this.character) return;

		if (!this.character.data.character_book) {
			this.character.data.character_book = {
				entries: [],
				extensions: {}
			};
		}

		this.character.data.character_book.entries = [
			...this.character.data.character_book.entries,
			entry
		];
	}

	/**
	 * Update an existing lorebook entry
	 */
	updateLorebookEntry(index: number, updates: Partial<LorebookEntry>) {
		if (!this.character?.data.character_book?.entries) return;
		if (index < 0 || index >= this.character.data.character_book.entries.length) return;

		this.character.data.character_book.entries[index] = {
			...this.character.data.character_book.entries[index],
			...updates
		};
	}

	/**
	 * Delete a lorebook entry
	 */
	deleteLorebookEntry(index: number) {
		if (!this.character?.data.character_book?.entries) return;
		if (index < 0 || index >= this.character.data.character_book.entries.length) return;

		this.character.data.character_book.entries.splice(index, 1);
	}

	/**
	 * Toggle enabled state of a lorebook entry
	 */
	toggleLorebookEntry(index: number) {
		if (!this.character?.data.character_book?.entries) return;
		if (index < 0 || index >= this.character.data.character_book.entries.length) return;

		this.character.data.character_book.entries[index].enabled =
			!this.character.data.character_book.entries[index].enabled;
	}

	// ============================================================================
	// Lorebook Reference Methods (for standalone lorebooks)
	// ============================================================================

	/**
	 * Link a standalone lorebook by reference (stores in extensions)
	 */
	linkLorebookReference(lorebookId: string) {
		if (!this.character) return;

		// Initialize extensions if needed
		if (!this.character.data.extensions) {
			this.character.data.extensions = {};
		}

		// Get or create the lorebook refs array
		const extensions = this.character.data.extensions as ScribeCharacterExtensions;
		if (!extensions.scribe_lorebook_refs) {
			extensions.scribe_lorebook_refs = [];
		}

		// Check if already linked
		if (extensions.scribe_lorebook_refs.some((ref) => ref.lorebook_id === lorebookId)) {
			return; // Already linked
		}

		// Add the reference
		extensions.scribe_lorebook_refs.push({
			lorebook_id: lorebookId,
			import_all: false
		});
	}

	/**
	 * Unlink a standalone lorebook reference
	 */
	unlinkLorebookReference(lorebookId: string) {
		if (!this.character) return;

		const extensions = this.character.data.extensions as ScribeCharacterExtensions;
		if (!extensions?.scribe_lorebook_refs) return;

		// Remove the reference
		extensions.scribe_lorebook_refs = extensions.scribe_lorebook_refs.filter(
			(ref) => ref.lorebook_id !== lorebookId
		);
	}

	/**
	 * Import lorebook entries into the character's embedded lorebook
	 */
	async importLorebookEntries(lorebookId: string) {
		if (!this.character) return;

		// Fetch the lorebook entries from the API
		const entriesResult = await apiClient.getLorebookEntries(lorebookId);
		if (entriesResult.isErr()) {
			console.error('Failed to fetch lorebook entries:', entriesResult.error);
			return;
		}

		const lorebookEntries = entriesResult.value;

		// Initialize character_book if needed
		if (!this.character.data.character_book) {
			this.character.data.character_book = {
				entries: [],
				extensions: {}
			};
		}

		// Convert LorebookEntry (backend format) to LorebookEntry (character card format)
		// Note: The character.ts types for lorebook entries need to match V3 spec
		if (lorebookEntries && lorebookEntries.length > 0) {
			const convertedEntries = lorebookEntries.map((entry) => ({
				keys: entry.keys_text ? entry.keys_text.split(',').map((k) => k.trim()) : [],
				content: entry.content,
				extensions: {},
				enabled: entry.is_enabled,
				insertion_order: entry.insertion_order,
				use_regex: false,
				constant: entry.is_constant,
				name: entry.entry_title,
				comment: entry.comment || undefined
			}));

			this.character.data.character_book.entries = [
				...this.character.data.character_book.entries,
				...convertedEntries
			];
		}
	}
}

// Create a singleton instance
export const characterStore = new CharacterStore();
