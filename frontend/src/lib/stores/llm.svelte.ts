// frontend/src/lib/stores/llm.svelte.ts
import { browser } from '$app/environment';
import { getContext, setContext } from 'svelte';
import { apiClient } from '$lib/api';
import type { ModelCapabilities, ModelInfo, RecommendedContextSettings } from '$lib/types';

interface HardwareInfo {
	cpu_cores: number;
	available_ram_gb: number;
	gpu_info?: Array<{
		name: string;
		vram_gb: number;
		device_id: number;
		cuda_capable: boolean;
	}>;
	has_cuda: boolean;
}

// Use the existing DownloadProgressInfo type instead of defining our own
import type { DownloadProgressInfo } from '$lib/types';

interface LLMState {
	models: Record<string, ModelInfo>;
	capabilities: Record<string, ModelCapabilities>;
	recommendedSettings: Record<string, RecommendedContextSettings>;
	loading: boolean;
	error: string | null;
	lastFetched: number | null;
	localLlmEnabled: boolean;
}

export class LLMStore {
	private state = $state<LLMState>({
		models: {},
		capabilities: {},
		recommendedSettings: {},
		loading: false,
		error: null,
		lastFetched: null,
		localLlmEnabled: false
	});

	get capabilities() {
		return this.state.capabilities;
	}

	get recommendedSettings() {
		return this.state.recommendedSettings;
	}

	get error() {
		return this.state.error;
	}

	get isStale() {
		// Consider data stale after 5 minutes
		return !this.state.lastFetched || Date.now() - this.state.lastFetched > 5 * 60 * 1000;
	}

	/**
	 * Fetch all available models and their capabilities from the API
	 */
	async fetchModels(force = false) {
		if (!browser) return;

		// Skip if already loading or recently fetched
		if (this.state.loading || (!force && !this.isStale)) {
			return;
		}

		this.state.loading = true;
		this.state.error = null;

		try {
			const result = await apiClient.getAllModels();

			if (!result.isOk()) {
				throw new Error(`Failed to fetch models: ${result.error.message}`);
			}

			const modelsData = result.value;

			// Transform the response into our store format
			const models: Record<string, ModelInfo> = {};
			const capabilities: Record<string, ModelCapabilities> = {};
			const recommendedSettings: Record<string, RecommendedContextSettings> = {};

			for (const [modelId, data] of Object.entries(modelsData)) {
				const modelData = data as any;

				models[modelId] = {
					id: modelId,
					name: this.getModelDisplayName(modelId),
					description: this.getModelDescription(modelId, modelData),
					isLocal: modelData.is_local,
					capabilities: modelData,
					recommended_settings: undefined, // Will be fetched separately if needed
					// Map backend fields to expected ModelInfo fields
					downloaded: modelData.is_local ? modelData.is_available : true, // Local models are downloaded if available, cloud models are always "available"
					compatible: modelData.is_local ? this.calculateCompatibility(modelId, modelData) : true, // Local models need compatibility check, cloud models are always compatible
					active: false, // TODO: Get actual active status
					size_gb: parseFloat(modelData.metadata?.size_gb) || 0,
					vram_required: this.getVramRequirement(modelId, modelData),
					filename: modelData.metadata?.filename
				};

				capabilities[modelId] = {
					context_window_size: modelData.context_window_size,
					max_output_tokens: modelData.max_output_tokens,
					provider: modelData.provider,
					is_local: modelData.is_local,
					is_available: modelData.is_available,
					metadata: modelData.metadata || {}
				};
			}

			this.state.models = models;
			this.state.capabilities = capabilities;
			this.state.lastFetched = Date.now();
		} catch (error) {
			console.error('Failed to fetch models:', error);
			this.state.error = error instanceof Error ? error.message : 'Unknown error occurred';
		} finally {
			this.state.loading = false;
		}
	}

	/**
	 * Get capabilities for a specific model
	 */
	getModelCapabilities(modelId: string): ModelCapabilities | null {
		return this.state.capabilities[modelId] || null;
	}

	/**
	 * Get recommended context settings for a specific model
	 */
	async getRecommendedSettings(modelId: string): Promise<RecommendedContextSettings | null> {
		if (!browser) return null;

		// Return cached settings if available
		if (this.state.recommendedSettings[modelId]) {
			return this.state.recommendedSettings[modelId];
		}

		try {
			const response = await fetch(`/api/llm/models/${modelId}/capabilities`);

			if (!response.ok) {
				console.warn(`Failed to fetch capabilities for model ${modelId}: ${response.statusText}`);
				return null;
			}

			const data = await response.json();

			if (data.recommended_settings) {
				this.state.recommendedSettings[modelId] = data.recommended_settings;
				return data.recommended_settings;
			}
		} catch (error) {
			console.error(`Failed to fetch recommended settings for ${modelId}:`, error);
		}

		return null;
	}

	/**
	 * Check if a model is available
	 */
	isModelAvailable(modelId: string): boolean {
		const capabilities = this.getModelCapabilities(modelId);
		return capabilities?.is_available ?? false;
	}

	/**
	 * Get the maximum context window size for a model
	 */
	getMaxContextSize(modelId: string): number | null {
		const capabilities = this.getModelCapabilities(modelId);
		return capabilities?.context_window_size ?? null;
	}

	/**
	 * Get a user-friendly display name for a model
	 */
	private getModelDisplayName(modelId: string): string {
		const nameMap: Record<string, string> = {
			'gemini-2.5-pro': 'Gemini 2.5 Pro',
			'gemini-2.5-flash': 'Gemini 2.5 Flash',
			'gemini-2.5-flash-lite-preview-06-17': 'Gemini 2.5 Flash Lite',
			'gpt-oss-20b-q4': 'GPT-OSS 20B (Q4)',
			'qwen3-30b-a3b-thinking-q4': 'Qwen3 30B A3B Thinking (Q4)',
			'qwen3-30b-a3b-instruct-q4': 'Qwen3 30B A3B Instruct (Q4)',
			'gemma3-27b-it-q4': 'Gemma3 27B IT (Q4)'
		};

		return nameMap[modelId] || modelId;
	}

	/**
	 * Calculate compatibility for local models
	 */
	private calculateCompatibility(modelId: string, data: any): boolean {
		// For now, assume all local models are compatible
		// This could be enhanced with hardware detection
		return true;
	}

	/**
	 * Get VRAM requirement for a model
	 */
	private getVramRequirement(modelId: string, data: any): number {
		// Try to get from metadata first
		if (data.metadata?.vram_required) {
			return data.metadata.vram_required;
		}
		
		// Fallback to estimates based on model ID
		const vramEstimates: Record<string, number> = {
			'gpt-oss-20b-q4': 16,
			'qwen3-30b-a3b-thinking-q4': 20,
			'qwen3-30b-a3b-instruct-q4': 20,
			'gemma3-27b-it-q4': 18
		};
		
		return vramEstimates[modelId] || 0;
	}

	/**
	 * Get a description for a model
	 */
	private getModelDescription(modelId: string, data: any): string {
		// Try to get description from metadata or use defaults
		if (data.metadata?.description) {
			return data.metadata.description;
		}

		const descriptionMap: Record<string, string> = {
			'gemini-2.5-pro': 'Most capable model with advanced reasoning',
			'gemini-2.5-flash': 'Fast and efficient model for most tasks',
			'gemini-2.5-flash-lite-preview-06-17': 'Ultra-fast model for simple tasks',
			'gpt-oss-20b-q4': 'High-quality open-source model (20B parameters)',
			'qwen3-30b-a3b-thinking-q4': 'MoE reasoning model with 30B total parameters',
			'qwen3-30b-a3b-instruct-q4': 'MoE instruction-following model with 30B total parameters',
			'gemma3-27b-it-q4': "Google's instruction-tuned model (27B parameters)"
		};

		return descriptionMap[modelId] || `${data.is_local ? 'Local' : 'Cloud'} model`;
	}

	/**
	 * Retry fetching models after authentication success
	 */
	retryAfterAuth() {
		// Clear any existing error and retry fetching
		this.state.error = null;
		this.fetchModels(true).catch((error) => {
			console.warn('Retry after auth failed:', error);
		});
	}

	/**
	 * Clear all cached data
	 */
	clear() {
		this.state.models = {};
		this.state.capabilities = {};
		this.state.recommendedSettings = {};
		this.state.error = null;
		this.state.lastFetched = null;
		this.state.localLlmEnabled = false;
	}

	// Compatibility properties for existing components
	get loading() {
		return this.state.loading;
	}

	get isLoading() {
		return this.state.loading;
	}

	get models() {
		return Object.values(this.state.models);
	}

	get downloadedModels() {
		return Object.values(this.state.models).filter((m) => m.isLocal && this.isModelAvailable(m.id)) as any[];
	}

	get activeModel() {
		return null; // TODO: Implement active model tracking
	}

	get activeModelInfo() {
		return null; // TODO: Implement active model info
	}

	get hardwareInfo(): HardwareInfo | null {
		return null; // TODO: Implement hardware info
	}

	get topRecommendation() {
		return null; // TODO: Implement recommendations
	}

	get localLlmEnabled() {
		return this.state.localLlmEnabled;
	}

	get localLlmFeatureAvailable() {
		return true; // Feature is available when backend supports it
	}

	get recommendations() {
		return []; // TODO: Implement recommendations
	}

	get showRecommendations() {
		return false; // TODO: Implement show recommendations state
	}

	// Compatibility methods for existing components
	isModelDownloading(modelId: string): boolean {
		return false; // TODO: Implement download tracking
	}

	getDownloadProgress(modelId: string): DownloadProgressInfo | null {
		return null; // TODO: Implement download progress
	}

	async activateModel(modelId: string): Promise<void> {
		if (!browser) return;
		
		try {
			const response = await fetch(`/api/llm/models/${modelId}/activate`, {
				method: 'POST',
				credentials: 'include'
			});
			
			if (!response.ok) {
				throw new Error(`Failed to activate model: ${response.statusText}`);
			}
			
			// Refresh models to get updated active status
			await this.fetchModels(true);
		} catch (error) {
			console.error('Failed to activate model:', error);
			throw error;
		}
	}

	async deactivateModel(): Promise<void> {
		if (!browser) return;
		
		try {
			const response = await fetch('/api/llm/models/deactivate', {
				method: 'POST',
				credentials: 'include'
			});
			
			if (!response.ok) {
				throw new Error(`Failed to deactivate model: ${response.statusText}`);
			}
			
			// Refresh models to get updated active status
			await this.fetchModels(true);
		} catch (error) {
			console.error('Failed to deactivate model:', error);
			throw error;
		}
	}

	deleteModel(modelId: string): Promise<void> {
		console.warn('deleteModel not implemented yet for', modelId);
		return Promise.resolve();
	}

	downloadModel(modelId: string): Promise<void> {
		console.warn('downloadModel not implemented yet for', modelId);
		return Promise.resolve();
	}

	refreshModels(): Promise<void> {
		return this.fetchModels(true);
	}

	loadRecommendations(): Promise<void> {
		console.warn('loadRecommendations not implemented yet');
		return Promise.resolve();
	}

	downloadBestModel(): Promise<void> {
		console.warn('downloadBestModel not implemented yet');
		return Promise.resolve();
	}

	async checkLocalLlmSupport(): Promise<void> {
		if (!browser) return;

		try {
			const result = await apiClient.getLlmInfo();
			if (result.isOk()) {
				this.state.localLlmEnabled = result.value.local_llm_enabled;
				if (result.value.local_llm_enabled) {
					console.log('Local LLM support detected');
				} else {
					console.log('Local LLM support not available');
				}
			} else {
				console.log('Local LLM support not available:', result.error);
				this.state.localLlmEnabled = false;
			}
		} catch (error) {
			console.error('Failed to check local LLM support:', error);
			this.state.localLlmEnabled = false;
		}
	}

	cleanup(): void {
		console.warn('cleanup not implemented yet');
	}

	clearError(): void {
		this.state.error = null;
	}

	toggleRecommendations(): void {
		console.warn('toggleRecommendations not implemented yet');
	}

	/**
	 * Get LLMStore from Svelte context
	 */
	static fromContext(): LLMStore {
		const store = getContext<LLMStore>('llmStore');
		if (!store) {
			throw new Error('LLMStore not found in context');
		}
		return store;
	}

	/**
	 * Set LLMStore in Svelte context
	 */
	static toContext(store: LLMStore): LLMStore {
		setContext('llmStore', store);
		return store;
	}
}

export const llmStore = new LLMStore();

// Global store management
let globalLlmStore: LLMStore | null = null;

export function initGlobalLlmStore(): void {
	if (!globalLlmStore) {
		globalLlmStore = new LLMStore();
		// Initialize by checking local LLM support and fetching models
		globalLlmStore.checkLocalLlmSupport().catch((error) => {
			console.warn('Initial LLM support check failed:', error);
		});
		globalLlmStore.fetchModels().catch((error) => {
			console.warn('Initial LLM model fetch failed:', error);
		});
	}
}

export function getGlobalLlmStore(): LLMStore | null {
	return globalLlmStore;
}
