import { getContext, setContext } from 'svelte';
import { DEFAULT_CHAT_MODEL } from '$lib/ai/models'; // Import the default model constant

const contextKey = Symbol('SelectedModel');
const defaultModel = DEFAULT_CHAT_MODEL; // Use the imported default

export class SelectedModel {
	value = $state<string>(defaultModel);

	constructor(initialValue?: string) {
		// TODO: Consider loading initial value from localStorage on client-side if persistence is needed
		this.value = initialValue ?? defaultModel;
	}

	set(newValue: string) {
		this.value = newValue;
		// TODO: Consider saving to localStorage on client-side if persistence is needed
	}

	setContext() {
		setContext(contextKey, this);
	}

	static fromContext(): SelectedModel {
		const context = getContext<SelectedModel | undefined>(contextKey);
		if (!context) {
			// This might happen during SSR if not set up correctly in a layout
			console.warn('SelectedModel context not found, creating default instance.');
			return new SelectedModel(); // Return a default instance
		}
		return context;
	}
}
