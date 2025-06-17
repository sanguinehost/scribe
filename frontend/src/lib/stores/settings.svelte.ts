import { getContext, setContext } from 'svelte';

export class SettingsStore {
	isVisible = $state(false);
	isTransitioning = $state(false);

	show() {
		this.isTransitioning = true;
		// Small delay to prevent flashing of other content
		setTimeout(() => {
			this.isVisible = true;
			this.isTransitioning = false;
		}, 50);
	}

	hide() {
		this.isTransitioning = true;
		setTimeout(() => {
			this.isVisible = false;
			this.isTransitioning = false;
		}, 300); // Match fade out duration
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
