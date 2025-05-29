import { getContext, setContext } from 'svelte';

const SELECTED_CHARACTER_KEY = Symbol('selected-character');

export class SelectedCharacterStore {
	characterId = $state<string | null>(null);

	select(characterId: string | null) {
		this.characterId = characterId;
	}

	clear() {
		this.characterId = null;
	}

	setContext() {
		setContext(SELECTED_CHARACTER_KEY, this);
	}

	static fromContext() {
		return getContext<SelectedCharacterStore>(SELECTED_CHARACTER_KEY);
	}
}