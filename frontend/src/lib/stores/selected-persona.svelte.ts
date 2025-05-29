import { getContext, setContext } from 'svelte';

const SELECTED_PERSONA_KEY = Symbol('selected-persona');

export class SelectedPersonaStore {
	personaId = $state<string | null>(null);
	viewMode = $state<'list' | 'overview' | 'creating'>('list');
	refreshTrigger = $state(0); // Used to trigger refreshes

	selectPersona(personaId: string | null) {
		this.personaId = personaId;
		this.viewMode = personaId ? 'overview' : 'list';
	}

	showList() {
		this.personaId = null;
		this.viewMode = 'list';
	}

	showCreating() {
		this.personaId = null;
		this.viewMode = 'creating';
	}

	clear() {
		this.personaId = null;
		this.viewMode = 'list';
	}

	triggerRefresh() {
		this.refreshTrigger++;
	}

	setContext() {
		setContext(SELECTED_PERSONA_KEY, this);
	}

	static fromContext() {
		return getContext<SelectedPersonaStore>(SELECTED_PERSONA_KEY);
	}
}