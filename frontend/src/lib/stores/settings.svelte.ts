import { getContext, setContext } from 'svelte';
import { apiClient as _apiClient } from '$lib/api';
import { logger } from '$lib/utils/logger';

export class SettingsStore {
	isVisible = $state(false);
	isTransitioning = $state(false);
	viewMode = $state<'overview' | 'consolidated'>('overview');
	typingSpeed = $state(30); // milliseconds between characters for streaming text

	async loadTypingSpeed() {
		try {
			const result = await _apiClient.getUserSettings();
			if (result.isOk()) {
				this.typingSpeed = result.value.typing_speed ?? 30;
			}
		} catch (_error) {
			logger.warn('settings-store', 'Failed to load typing speed setting, using default', {
				error: _error as Error
			});
		}
	}

	async saveTypingSpeed() {
		try {
			const result = await _apiClient.updateUserSettings({
				typing_speed: this.typingSpeed
			});
			if (result.isOk()) {
				logger.debug('settings-store', 'Typing speed saved successfully');
			}
		} catch (_error) {
			logger.warn('settings-store', 'Failed to save typing speed setting', {
				error: _error as Error
			});
		}
	}

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

	setViewMode(mode: 'overview' | 'consolidated') {
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
