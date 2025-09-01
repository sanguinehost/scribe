// frontend/src/lib/stores/modelLifecycle.svelte.ts

import { browser } from '$app/environment';
import { getContext, setContext } from 'svelte';
import { apiClient } from '$lib/api';
import { toast } from 'svelte-sonner';

interface ModelLifecycleState {
	activeModel: string | null;
	isActivating: boolean;
	lastActivityTime: number | null;
	inactivityTimer: number | null;
}

export class ModelLifecycleStore {
	private state = $state<ModelLifecycleState>({
		activeModel: null,
		isActivating: false,
		lastActivityTime: null,
		inactivityTimer: null
	});

	private readonly INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15 minutes in milliseconds

	get activeModel() {
		return this.state.activeModel;
	}

	get isActivating() {
		return this.state.isActivating;
	}

	get lastActivityTime() {
		return this.state.lastActivityTime;
	}

	/**
	 * Activate a local model
	 */
	async activateModel(modelId: string): Promise<boolean> {
		if (!browser) return false;

		this.state.isActivating = true;
		
		try {
			const response = await fetch(`/api/llm/models/${modelId}/activate`, {
				method: 'POST',
				credentials: 'include'
			});

			if (!response.ok) {
				throw new Error(`Failed to activate model: ${response.statusText}`);
			}

			const result = await response.json();
			
			if (result.success) {
				this.state.activeModel = modelId;
				this.resetInactivityTimer();
				return true;
			} else {
				throw new Error(result.message || 'Failed to activate model');
			}
		} catch (error) {
			console.error('Failed to activate model:', error);
			toast.error('Failed to start local model');
			return false;
		} finally {
			this.state.isActivating = false;
		}
	}

	/**
	 * Deactivate the current model
	 */
	async deactivateModel(): Promise<void> {
		if (!browser || !this.state.activeModel) return;

		try {
			const response = await fetch('/api/llm/models/deactivate', {
				method: 'POST',
				credentials: 'include'
			});

			if (!response.ok) {
				throw new Error(`Failed to deactivate model: ${response.statusText}`);
			}

			const result = await response.json();
			
			if (result.success) {
				this.state.activeModel = null;
				this.clearInactivityTimer();
				toast.info('Local model stopped due to inactivity');
			} else {
				console.error('Failed to deactivate model:', result.message);
			}
		} catch (error) {
			console.error('Failed to deactivate model:', error);
		}
	}

	/**
	 * Reset the inactivity timer (call on message send)
	 */
	resetInactivityTimer(): void {
		if (!browser) return;

		this.state.lastActivityTime = Date.now();
		this.clearInactivityTimer();

		// Set new timer
		this.state.inactivityTimer = window.setTimeout(() => {
			this.deactivateModel();
		}, this.INACTIVITY_TIMEOUT);
	}

	/**
	 * Clear the inactivity timer
	 */
	private clearInactivityTimer(): void {
		if (this.state.inactivityTimer) {
			window.clearTimeout(this.state.inactivityTimer);
			this.state.inactivityTimer = null;
		}
	}

	/**
	 * Check if a model is currently active
	 */
	isModelActive(modelId: string): boolean {
		return this.state.activeModel === modelId;
	}

	/**
	 * Get time remaining before deactivation (in milliseconds)
	 */
	getTimeUntilDeactivation(): number | null {
		if (!this.state.lastActivityTime || !this.state.activeModel) {
			return null;
		}

		const elapsed = Date.now() - this.state.lastActivityTime;
		const remaining = this.INACTIVITY_TIMEOUT - elapsed;
		
		return Math.max(0, remaining);
	}

	/**
	 * Clean up resources
	 */
	cleanup(): void {
		this.clearInactivityTimer();
	}

	/**
	 * Get ModelLifecycleStore from Svelte context
	 */
	static fromContext(): ModelLifecycleStore {
		const store = getContext<ModelLifecycleStore>('modelLifecycleStore');
		if (!store) {
			throw new Error('ModelLifecycleStore not found in context');
		}
		return store;
	}

	/**
	 * Set ModelLifecycleStore in Svelte context
	 */
	static toContext(store: ModelLifecycleStore): ModelLifecycleStore {
		setContext('modelLifecycleStore', store);
		return store;
	}
}

export const modelLifecycleStore = new ModelLifecycleStore();

// Global store management
let globalModelLifecycleStore: ModelLifecycleStore | null = null;

export function initGlobalModelLifecycleStore(): void {
	if (!globalModelLifecycleStore) {
		globalModelLifecycleStore = new ModelLifecycleStore();
	}
}

export function getGlobalModelLifecycleStore(): ModelLifecycleStore | null {
	return globalModelLifecycleStore;
}