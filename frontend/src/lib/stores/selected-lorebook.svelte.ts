import { getContext, setContext } from 'svelte';

const SELECTED_LOREBOOK_KEY = Symbol('selected-lorebook');

export class SelectedLorebookStore {
	lorebookId = $state<string | null>(null);
	viewMode = $state<'list' | 'detail' | 'none'>('none');
	refreshTrigger = $state(0); // Used to trigger refreshes

	selectLorebook(lorebookId: string | null) {
		this.lorebookId = lorebookId;
		this.viewMode = lorebookId ? 'detail' : 'list';
	}

	showList() {
		this.lorebookId = null;
		this.viewMode = 'list';
	}

	clear() {
		this.lorebookId = null;
		this.viewMode = 'none';
	}

	triggerRefresh() {
		this.refreshTrigger++;
	}

	setContext() {
		setContext(SELECTED_LOREBOOK_KEY, this);
	}

	static fromContext() {
		return getContext<SelectedLorebookStore>(SELECTED_LOREBOOK_KEY);
	}
}