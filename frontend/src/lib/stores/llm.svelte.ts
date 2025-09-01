// frontend/src/lib/stores/llm.svelte.ts
import { browser } from '$app/environment';
import { getContext, setContext } from 'svelte';
import { apiClient } from '$lib/api';
import type { ModelCapabilities, ModelInfo, RecommendedContextSettings, GroupedModelInfo } from '$lib/types';

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
	groupedModels: GroupedModelInfo[];
	capabilities: Record<string, ModelCapabilities>;
	recommendedSettings: Record<string, RecommendedContextSettings>;
	loading: boolean;
	error: string | null;
	lastFetched: number | null;
	localLlmEnabled: boolean;
	activeModelId: string | null;
	downloadingModels: Set<string>;
	downloadProgress: Record<string, DownloadProgressInfo>;
	hardwareCapabilities: HardwareInfo | null;
}

export class LLMStore {
	private state = $state<LLMState>({
		models: {},
		groupedModels: [],
		capabilities: {},
		recommendedSettings: {},
		loading: false,
		error: null,
		lastFetched: null,
		localLlmEnabled: false,
		activeModelId: null,
		downloadingModels: new Set<string>(),
		downloadProgress: {},
		hardwareCapabilities: null
	});
	
	private progressEventSource: EventSource | null = null;

	get capabilities() {
		return this.state.capabilities;
	}

	get recommendedSettings() {
		return this.state.recommendedSettings;
	}

	get groupedModels() {
		return this.state.groupedModels;
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
	 * Fetch grouped models from the API
	 */
	async fetchGroupedModels(force = false, filters?: {
		show_incompatible?: boolean;
		only_downloaded?: boolean;
		only_recommended?: boolean;
	}) {
		if (!browser) return;

		// Skip if already loading or recently fetched (unless filters are provided)
		if (this.state.loading || (!force && !filters && !this.isStale)) {
			return;
		}

		this.state.loading = true;
		this.state.error = null;

		try {
			const result = await apiClient.getGroupedModels(filters);

			if (!result.isOk()) {
				throw new Error(`Failed to fetch grouped models: ${result.error.message}`);
			}

			this.state.groupedModels = result.value;
			
			// Extract active model from grouped models response
			for (const group of result.value) {
				for (const variant of group.variants) {
					if (variant.active) {
						this.state.activeModelId = variant.id;
						break;
					}
				}
			}
			
			this.state.lastFetched = Date.now();
		} catch (error) {
			console.error('Failed to fetch grouped models:', error);
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
			'gemma-3-27b-it-q4': 'Gemma 3 27B IT (Q4)'
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
			'gemma-3-27b-it-q4': 18
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
			'gemma-3-27b-it-q4': "Google's multimodal instruction-tuned model (27B parameters)"
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
		this.state.groupedModels = [];
		this.state.capabilities = {};
		this.state.recommendedSettings = {};
		this.state.error = null;
		this.state.lastFetched = null;
		this.state.localLlmEnabled = false;
		this.state.activeModelId = null;
		this.state.downloadingModels.clear();
		this.state.downloadProgress = {};
		this.state.hardwareCapabilities = null;
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
		return Object.values(this.state.models).filter((m) => m.isLocal && m.downloaded) as any[];
	}

	get activeModel() {
		return this.state.activeModelId;
	}

	get activeModelInfo() {
		if (!this.state.activeModelId) return null;
		return this.state.models[this.state.activeModelId] || null;
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
		return this.state.downloadingModels.has(modelId);
	}

	getDownloadProgress(modelId: string): DownloadProgressInfo | null {
		return this.state.downloadProgress[modelId] || null;
	}

	async activateModel(modelId: string): Promise<void> {
		if (!browser) return;
		
		try {
			const result = await apiClient.activateModel(modelId);
			
			if (!result.isOk()) {
				throw new Error(`Failed to activate model: ${result.error.message}`);
			}
			
			// Update active model state
			this.state.activeModelId = modelId;
			
			// Refresh models to get updated active status
			await Promise.all([
				this.fetchModels(true),
				this.fetchGroupedModels(true)
			]);
		} catch (error) {
			console.error('Failed to activate model:', error);
			this.state.error = error instanceof Error ? error.message : 'Activation failed';
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

	async deleteModel(modelId: string): Promise<void> {
		if (!browser) return;
		
		try {
			const result = await apiClient.deleteModel(modelId);
			
			if (!result.isOk()) {
				throw new Error(`Failed to delete model: ${result.error.message}`);
			}
			
			// If this was the active model, clear the active status
			if (this.state.activeModelId === modelId) {
				this.state.activeModelId = null;
			}
			
			// Refresh models to get updated status
			await Promise.all([
				this.fetchModels(true),
				this.fetchGroupedModels(true)
			]);
		} catch (error) {
			console.error('Failed to delete model:', error);
			this.state.error = error instanceof Error ? error.message : 'Delete failed';
			throw error;
		}
	}

	async downloadModel(modelId: string): Promise<void> {
		if (!browser) return;
		
		try {
			console.log(`Starting download for model: ${modelId}`);
			// Add to downloading models set
			this.state.downloadingModels.add(modelId);
			console.log('Added model to downloading set:', Array.from(this.state.downloadingModels));
			// Note: SSE stream disabled for now due to placeholder backend implementation
			// this.startDownloadProgressStream();
			
			const result = await apiClient.downloadModel(modelId);
			
			if (!result.isOk()) {
				throw new Error(`Failed to download model: ${result.error.message}`);
			}
			
			// Check if the backend reports download success
			if (!result.value.success) {
				throw new Error(`Download failed: ${result.value.message}`);
			}
			
			console.log(`Download request succeeded for ${modelId}`);
			// Download request succeeded - start polling for completion
			this.pollDownloadCompletion(modelId);
		} catch (error) {
			console.error('Failed to download model:', error);
			this.state.error = error instanceof Error ? error.message : 'Download failed';
			// Remove from downloading set on error
			this.state.downloadingModels.delete(modelId);
			throw error;
		}
	}

	async refreshModels(): Promise<void> {
		await Promise.all([
			this.fetchModels(true),
			this.fetchGroupedModels(true)
		]);
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
					// Start progress stream to catch any ongoing downloads
					this.startDownloadProgressStream();
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

	/**
	 * Poll for download completion by checking model status
	 */
	private async pollDownloadCompletion(modelId: string): Promise<void> {
		const maxAttempts = 40; // 5 minutes with 7.5 second intervals
		let attempts = 0;
		let consecutiveNoProgressAttempts = 0;
		let lastRefreshAttempt = 0;
		
		const poll = async (): Promise<void> => {
			attempts++;
			console.log(`Polling download status for ${modelId} (attempt ${attempts}/${maxAttempts})`);
			
			try {
				// Only refresh every 3rd attempt (every ~22 seconds) to reduce UI thrashing
				// Always refresh on first attempt and when we're close to completion
				const shouldRefresh = attempts === 1 || attempts % 3 === 0 || attempts > maxAttempts - 5;
				
				if (shouldRefresh) {
					console.log(`Refreshing models for ${modelId} (refresh ${++lastRefreshAttempt})`);
					await this.fetchModels(true);
					await this.fetchGroupedModels(true);
				}
				
				// Check if model is now downloaded (check both individual and grouped models)
				const model = this.state.models?.[modelId];
				
				// Also check grouped models for the variant
				let variantDownloaded = false;
				if (this.state.groupedModels) {
					for (const group of this.state.groupedModels) {
						const variant = group.variants.find(v => v.id === modelId);
						if (variant?.downloaded) {
							variantDownloaded = true;
							console.log(`Found downloaded variant ${modelId} in group ${group.base_model_name}`);
							break;
						}
					}
				}
				
				// Check if download completed in either location
				if (model?.downloaded || variantDownloaded) {
					console.log(`✅ Download completed for ${modelId}, cleaning up states`);
					this.state.downloadingModels.delete(modelId);
					
					// Clean up any download progress data
					if (this.state.downloadProgress[modelId]) {
						delete this.state.downloadProgress[modelId];
					}
					
					// Do one final refresh to ensure UI is fully updated
					// Always refresh on completion
					await this.fetchModels(true);
					await this.fetchGroupedModels(true);
					
					console.log(`🎉 Download process complete for ${modelId}`);
					return;
				}
				
				// Check if we're still in progress (model exists but not downloaded)
				const modelExists = model || this.state.groupedModels?.some(g => 
					g.variants.some(v => v.id === modelId)
				);
				
				if (modelExists) {
					consecutiveNoProgressAttempts = 0; // Reset counter if model exists
				} else {
					consecutiveNoProgressAttempts++;
					console.log(`No model found for ${modelId}, consecutive attempts: ${consecutiveNoProgressAttempts}`);
				}
				
				// If we haven't seen progress for too long, assume failure
				if (consecutiveNoProgressAttempts >= 6) { // ~45 seconds of no progress
					console.error(`Download appears to have failed for ${modelId} - no model found for too long`);
					this.state.downloadingModels.delete(modelId);
					// Clean up download progress on failure
					if (this.state.downloadProgress[modelId]) {
						delete this.state.downloadProgress[modelId];
					}
					this.state.error = `Download failed for ${modelId} - model not found in system`;
					return;
				}
				
				// Continue polling if not completed and under max attempts
				if (attempts < maxAttempts) {
					setTimeout(poll, 7500); // Poll every 7.5 seconds to reduce load
				} else {
					console.warn(`Download polling timed out for ${modelId} after ${maxAttempts} attempts`);
					this.state.downloadingModels.delete(modelId);
					// Clean up download progress on timeout
					if (this.state.downloadProgress[modelId]) {
						delete this.state.downloadProgress[modelId];
					}
					this.state.error = `Download timed out for ${modelId} - please check server logs`;
				}
			} catch (error) {
				console.error(`Error polling download status for ${modelId}:`, error);
				this.state.downloadingModels.delete(modelId);
				// Clean up download progress on error too
				if (this.state.downloadProgress[modelId]) {
					delete this.state.downloadProgress[modelId];
				}
				this.state.error = `Error checking download status: ${error instanceof Error ? error.message : 'Unknown error'}`;
			}
		};
		
		// Start polling after initial delay
		setTimeout(poll, 3000); // Wait 3 seconds before first poll
	}

	/**
	 * Start listening for download progress updates via SSE
	 */
	private startDownloadProgressStream(): void {
		if (!browser || this.progressEventSource) return;
		
		console.log('Starting download progress stream...');
		this.progressEventSource = apiClient.createDownloadProgressStream();
		if (!this.progressEventSource) {
			console.warn('Failed to create download progress stream');
			return;
		}
		
		console.log('Download progress stream created successfully');
		
		this.progressEventSource.onopen = () => {
			console.log('Download progress stream connected');
		};
		
		this.progressEventSource.onmessage = (event) => {
			console.log('Download progress received:', event.data);
			try {
				const progressData: DownloadProgressInfo = JSON.parse(event.data);
				console.log('Parsed progress data:', progressData);
				this.state.downloadProgress[progressData.model_id] = progressData;
				
				// If download is complete (100%), remove from downloading set and refresh models
				if (progressData.percentage >= 100) {
					console.log(`Download complete for ${progressData.model_id}`);
					this.state.downloadingModels.delete(progressData.model_id);
					delete this.state.downloadProgress[progressData.model_id];
					
					// Refresh models in background to update status
					this.fetchModels(true).catch(console.error);
					this.fetchGroupedModels(true).catch(console.error);
				}
			} catch (error) {
				console.error('Error parsing download progress:', error);
			}
		};
		
		this.progressEventSource.onerror = (error) => {
			console.error('Download progress stream error:', error);
			this.stopDownloadProgressStream();
		};
	}
	
	/**
	 * Stop listening for download progress updates
	 */
	private stopDownloadProgressStream(): void {
		if (this.progressEventSource) {
			this.progressEventSource.close();
			this.progressEventSource = null;
		}
	}

	cleanup(): void {
		this.stopDownloadProgressStream();
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
		globalLlmStore.fetchGroupedModels().catch((error) => {
			console.warn('Initial grouped models fetch failed:', error);
		});
	}
}

export function getGlobalLlmStore(): LLMStore | null {
	return globalLlmStore;
}
