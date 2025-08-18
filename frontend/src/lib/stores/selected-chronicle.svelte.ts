// Store for managing the selected chronicle state
import { getContext, setContext } from 'svelte';

class SelectedChronicleStore {
	selectedChronicleId = $state<string | null>(null);
	isCreating = $state(false);
	isShowingList = $state(false);

	selectChronicle(chronicleId: string) {
		this.selectedChronicleId = chronicleId;
		this.isCreating = false;
		this.isShowingList = false;
		console.log('[SelectedChronicleStore] Chronicle selected:', chronicleId);
	}

	showCreating() {
		this.selectedChronicleId = null;
		this.isCreating = true;
		this.isShowingList = false;
		console.log('[SelectedChronicleStore] Showing chronicle creation');
	}

	showList() {
		this.selectedChronicleId = null;
		this.isCreating = false;
		this.isShowingList = true;
		console.log('[SelectedChronicleStore] Showing chronicle list');
	}

	clear() {
		this.selectedChronicleId = null;
		this.isCreating = false;
		this.isShowingList = false;
		console.log('[SelectedChronicleStore] Cleared chronicle selection');
	}

	// Context API for sharing the store
	static readonly CONTEXT_KEY = Symbol('selected-chronicle-store');

	static fromContext(): SelectedChronicleStore {
		const store = getContext<SelectedChronicleStore>(SelectedChronicleStore.CONTEXT_KEY);
		if (!store) {
			throw new Error('SelectedChronicleStore not found in context. Did you forget to set it?');
		}
		return store;
	}

	setInContext() {
		setContext(SelectedChronicleStore.CONTEXT_KEY, this);
	}
}

export { SelectedChronicleStore };
