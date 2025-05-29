import { getContext, setContext } from 'svelte';

export class SettingsStore {
	isVisible = $state(false);
	viewMode = $state<'overview' | 'defaults' | 'advanced'>('overview');

	show() {
		this.isVisible = true;
		this.viewMode = 'overview';
	}

	hide() {
		this.isVisible = false;
	}

	setViewMode(mode: 'overview' | 'defaults' | 'advanced') {
		this.viewMode = mode;
	}

	static fromContext(): SettingsStore {
		const store = getContext<SettingsStore>('settingsStore');
		if (!store) {
			throw new Error('SettingsStore not found in context');
		}
		return store;
	}

	static toContext(store: SettingsStore): SettingsStore {
		setContext('settingsStore', store);
		return store;
	}
}