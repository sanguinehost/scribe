import { SvelteSet } from 'svelte/reactivity';
// frontend/src/lib/stores/llm.svelte.ts
import { browser as _browser } from '$app/environment';
import { getContext, setContext } from 'svelte';
import { apiClient as _apiClient } from '$lib/api';
import { logger } from '$lib/utils/logger';
import type {
	ModelCapabilities,
	ModelInfo,
	RecommendedContextSettings,
	GroupedModelInfo
} from '$lib/types';

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

interface ModelMetadata {
	size_gb?: string | number;
	filename?: string;
	[key: string]: unknown;
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
		downloadingModels: new SvelteSet<string>(),
		downloadProgress: {},
		hardwareCapabilities: null
	});

	// Polling configuration constants
	private static readonly MAX_POLL_ATTEMPTS = 40; // 5 minutes with 7.5 second intervals
	private static readonly POLL_INTERVAL_MS = 7500; // Poll every 7.5 seconds to reduce load
	private static readonly INITIAL_POLL_DELAY_MS = 3000; // Wait 3 seconds before first poll
	private static readonly MAX_NO_PROGRESS_ATTEMPTS = 6; // ~45 seconds of no progress

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
		if (!_browser) return;

		// Skip if already loading or recently fetched
		if (this.state.loading || (!force && !this.isStale)) {
			return;
		}

		this.state.loading = true;
		this.state.error = null;

		try {
			const result = await _apiClient.getAllModels();

			if (!result.isOk()) {
				throw new Error(`Failed to fetch models: ${result.error.message}`);
			}

			const modelsData = result.value;

			// Transform the response into our store format
			const models: Record<string, ModelInfo> = {};
			const capabilities: Record<string, ModelCapabilities> = {};
			const _recommendedSettings: Record<string, RecommendedContextSettings> = {};

			for (const [_modelId, data] of Object.entries(modelsData)) {
				const modelData = data as Record<string, unknown>;

				models[_modelId] = {
					id: _modelId,
					name: this.getModelDisplayName(_modelId),
					description: this.getModelDescription(_modelId, modelData),
					isLocal: modelData.is_local as boolean,
					capabilities: modelData as unknown as ModelCapabilities,
					recommended_settings: undefined, // Will be fetched separately if needed
					// Map backend fields to expected ModelInfo fields
					downloaded: modelData.is_local ? (modelData.is_available as boolean) : true, // Local models are downloaded if available, cloud models are always "available"
					compatible: (modelData.is_local as boolean)
						? this.calculateCompatibility(_modelId, modelData)
						: true, // Local models need compatibility check, cloud models are always compatible
					active: false, // TODO: Get actual active status
					size_gb:
						parseFloat((modelData.metadata as ModelMetadata)?.size_gb?.toString() || '0') || 0,
					vram_required: this.getVramRequirement(_modelId, modelData),
					filename: (modelData.metadata as ModelMetadata)?.filename
				};

				capabilities[_modelId] = {
					context_window_size: modelData.context_window_size as number,
					max_output_tokens: modelData.max_output_tokens as number,
					provider: modelData.provider as string,
					is_local: modelData.is_local as boolean,
					is_available: modelData.is_available as boolean,
					metadata: Object.fromEntries(
						Object.entries((modelData.metadata as ModelMetadata) || {}).map(([key, value]) => [
							key,
							String(value ?? '')
						])
					)
				};
			}

			this.state.models = models;
			this.state.capabilities = capabilities;
			this.state.lastFetched = Date.now();
		} catch (_error) {
			logger.error('llm-store', 'Failed to fetch models', _error as Error);
			this.state.error = _error instanceof Error ? _error.message : 'Unknown error occurred';
		} finally {
			this.state.loading = false;
		}
	}

	/**
	 * Fetch grouped models from the API
	 */
	async fetchGroupedModels(
		force = false,
		filters?: {
			show_incompatible?: boolean;
			only_downloaded?: boolean;
			only_recommended?: boolean;
		}
	) {
		if (!_browser) return;

		// Skip if already loading or recently fetched (unless filters are provided)
		if (this.state.loading || (!force && !filters && !this.isStale)) {
			return;
		}

		this.state.loading = true;
		this.state.error = null;

		try {
			const result = await _apiClient.getGroupedModels(filters);

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
		} catch (_error) {
			logger.error('llm-store', 'Failed to fetch grouped models', _error as Error);
			this.state.error = _error instanceof Error ? _error.message : 'Unknown error occurred';
		} finally {
			this.state.loading = false;
		}
	}

	/**
	 * Get capabilities for a specific model
	 */
	getModelCapabilities(_modelId: string): ModelCapabilities | null {
		return this.state.capabilities[_modelId] || null;
	}

	/**
	 * Get recommended context settings for a specific model
	 */
	async getRecommendedSettings(_modelId: string): Promise<RecommendedContextSettings | null> {
		if (!_browser) return null;

		// Return cached settings if available
		if (this.state.recommendedSettings[_modelId]) {
			return this.state.recommendedSettings[_modelId];
		}

		try {
			const response = await fetch(`/api/llm/models/${_modelId}/capabilities`);

			if (!response.ok) {
				logger.warn('llm-store', `Failed to fetch capabilities for model ${_modelId}`, {
					status: response.statusText
				});
				return null;
			}

			const data = await response.json();

			if (data.recommended_settings) {
				this.state.recommendedSettings[_modelId] = data.recommended_settings;
				return data.recommended_settings;
			}
		} catch (_error) {
			logger.error(
				'llm-store',
				`Failed to fetch recommended settings for ${_modelId}`,
				_error as Error
			);
		}

		return null;
	}

	/**
	 * Check if a model is available
	 */
	isModelAvailable(_modelId: string): boolean {
		const capabilities = this.getModelCapabilities(_modelId);
		return capabilities?.is_available ?? false;
	}

	/**
	 * Get the maximum context window size for a model
	 */
	getMaxContextSize(_modelId: string): number | null {
		const capabilities = this.getModelCapabilities(_modelId);
		return capabilities?.context_window_size ?? null;
	}

	/**
	 * Get a user-friendly display name for a model
	 */
	private getModelDisplayName(_modelId: string): string {
		const nameMap: Record<string, string> = {
			'gemini-2.5-pro': 'Gemini 2.5 Pro',
			'gemini-2.5-flash': 'Gemini 2.5 Flash',
			'gemini-2.5-flash-preview-09-2025': 'Gemini 2.5 Flash Preview',
			'gemini-2.5-flash-lite-preview-09-2025': 'Gemini 2.5 Flash Lite',
			'gemini-2.5-flash-image': 'Gemini 2.5 Flash Image',
			'gpt-oss-20b-q4': 'GPT-OSS 20B (Q4)',
			'qwen3-30b-a3b-thinking-q4': 'Qwen3 30B A3B Thinking (Q4)',
			'qwen3-30b-a3b-instruct-q4': 'Qwen3 30B A3B Instruct (Q4)',
			'gemma-3-27b-it-q4': 'Gemma 3 27B IT (Q4)'
		};

		return nameMap[_modelId] || _modelId;
	}

	/**
	 * Calculate compatibility for local models
	 */
	private calculateCompatibility(_modelId: string, _data: Record<string, unknown>): boolean {
		// For now, assume all local models are compatible
		// This could be enhanced with hardware detection
		return true;
	}

	/**
	 * Get VRAM requirement for a model
	 */
	private getVramRequirement(_modelId: string, data: Record<string, unknown>): number {
		// Try to get from metadata first
		if (
			data.metadata &&
			typeof data.metadata === 'object' &&
			data.metadata !== null &&
			'vram_required' in data.metadata
		) {
			return data.metadata.vram_required as number;
		}

		// Fallback to estimates based on model ID
		const vramEstimates: Record<string, number> = {
			'gpt-oss-20b-q4': 16,
			'qwen3-30b-a3b-thinking-q4': 20,
			'qwen3-30b-a3b-instruct-q4': 20,
			'gemma-3-27b-it-q4': 18
		};

		return vramEstimates[_modelId] || 0;
	}

	/**
	 * Get a description for a model
	 */
	private getModelDescription(_modelId: string, data: Record<string, unknown>): string {
		// Try to get description from metadata or use defaults
		if (
			data.metadata &&
			typeof data.metadata === 'object' &&
			data.metadata !== null &&
			'description' in data.metadata
		) {
			return data.metadata.description as string;
		}

		const descriptionMap: Record<string, string> = {
			'gemini-2.5-pro': 'Most capable model with advanced reasoning',
			'gemini-2.5-flash': 'Fast and efficient model for most tasks',
			'gemini-2.5-flash-preview-09-2025': 'Latest preview with enhanced capabilities',
			'gemini-2.5-flash-lite-preview-09-2025': 'Ultra-fast and cost-effective model (FREE)',
			'gemini-2.5-flash-image': 'Chat model with image generation support',
			'gpt-oss-20b-q4': 'High-quality open-source model (20B parameters)',
			'qwen3-30b-a3b-thinking-q4': 'MoE reasoning model with 30B total parameters',
			'qwen3-30b-a3b-instruct-q4': 'MoE instruction-following model with 30B total parameters',
			'gemma-3-27b-it-q4': "Google's multimodal instruction-tuned model (27B parameters)"
		};

		return descriptionMap[_modelId] || `${data.is_local ? 'Local' : 'Cloud'} model`;
	}

	/**
	 * Retry fetching models after authentication success
	 */
	retryAfterAuth() {
		// Clear any existing error and retry fetching
		this.state.error = null;
		this.fetchModels(true).catch((error) => {
			logger.warn('llm-store', 'Retry after auth failed', { error });
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
		return Object.values(this.state.models).filter((m) => m.isLocal && m.downloaded) as unknown[];
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
	isModelDownloading(_modelId: string): boolean {
		return this.state.downloadingModels.has(_modelId);
	}

	getDownloadProgress(_modelId: string): DownloadProgressInfo | null {
		return this.state.downloadProgress[_modelId] || null;
	}

	async activateModel(_modelId: string): Promise<void> {
		if (!_browser) return;

		try {
			const result = await _apiClient.activateModel(_modelId);

			if (!result.isOk()) {
				throw new Error(`Failed to activate model: ${result.error.message}`);
			}

			// Update active model state
			this.state.activeModelId = _modelId;

			// Refresh models to get updated active status
			await Promise.all([this.fetchModels(true), this.fetchGroupedModels(true)]);
		} catch (_error) {
			logger.error('llm-store', 'Failed to activate model', _error as Error);
			this.state.error = _error instanceof Error ? _error.message : 'Activation failed';
			throw _error;
		}
	}

	async deactivateModel(): Promise<void> {
		if (!_browser) return;

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
		} catch (_error) {
			logger.error('llm-store', 'Failed to deactivate model', _error as Error);
			throw _error;
		}
	}

	async deleteModel(_modelId: string): Promise<void> {
		if (!_browser) return;

		try {
			const result = await _apiClient.deleteModel(_modelId);

			if (!result.isOk()) {
				throw new Error(`Failed to delete model: ${result.error.message}`);
			}

			// If this was the active model, clear the active status
			if (this.state.activeModelId === _modelId) {
				this.state.activeModelId = null;
			}

			// Refresh models to get updated status
			await Promise.all([this.fetchModels(true), this.fetchGroupedModels(true)]);
		} catch (_error) {
			logger.error('llm-store', 'Failed to delete model', _error as Error);
			this.state.error = _error instanceof Error ? _error.message : 'Delete failed';
			throw _error;
		}
	}

	async downloadModel(_modelId: string): Promise<void> {
		if (!_browser) return;

		try {
			logger.debug('llm-store', `Starting download for model: ${_modelId}`);
			// Add to downloading models set
			this.state.downloadingModels.add(_modelId);
			logger.debug('llm-store', 'Added model to downloading set', {
				downloadingModels: Array.from(this.state.downloadingModels)
			});
			// Note: SSE stream disabled for now due to placeholder backend implementation
			// this.startDownloadProgressStream();

			const result = await _apiClient.downloadModel(_modelId);

			if (!result.isOk()) {
				throw new Error(`Failed to download model: ${result.error.message}`);
			}

			// Check if the backend reports download success
			if (!result.value.success) {
				throw new Error(`Download failed: ${result.value.message}`);
			}

			logger.debug('llm-store', `Download request succeeded for ${_modelId}`);
			// Download request succeeded - start polling for completion
			this.pollDownloadCompletion(_modelId);
		} catch (_error) {
			logger.error('llm-store', 'Failed to download model', _error as Error);
			this.state.error = _error instanceof Error ? _error.message : 'Download failed';
			// Remove from downloading set on error
			this.state.downloadingModels.delete(_modelId);
			throw _error;
		}
	}

	async refreshModels(): Promise<void> {
		await Promise.all([this.fetchModels(true), this.fetchGroupedModels(true)]);
	}

	loadRecommendations(): Promise<void> {
		logger.warn('llm-store', 'loadRecommendations not implemented yet');
		return Promise.resolve();
	}

	downloadBestModel(): Promise<void> {
		logger.warn('llm-store', 'downloadBestModel not implemented yet');
		return Promise.resolve();
	}

	async checkLocalLlmSupport(): Promise<void> {
		if (!_browser) return;

		try {
			const result = await _apiClient.getLlmInfo();
			if (result.isOk()) {
				this.state.localLlmEnabled = result.value.local_llm_enabled;
				if (result.value.local_llm_enabled) {
					logger.debug('llm-store', 'Local LLM support detected');
					// Start progress stream to catch any ongoing downloads
					this.startDownloadProgressStream();
				} else {
					logger.debug('llm-store', 'Local LLM support not available');
				}
			} else {
				logger.debug('llm-store', 'Local LLM support not available', { error: result.error });
				this.state.localLlmEnabled = false;
			}
		} catch (_error) {
			logger.error('llm-store', 'Failed to check local LLM support', _error as Error);
			this.state.localLlmEnabled = false;
		}
	}

	/**
	 * Poll for download completion by checking model status
	 */
	private async pollDownloadCompletion(_modelId: string): Promise<void> {
		let attempts = 0;
		let consecutiveNoProgressAttempts = 0;
		let lastRefreshAttempt = 0;

		const poll = async (): Promise<void> => {
			attempts++;
			logger.debug('llm-store', `Polling download status for ${_modelId}`, {
				attempt: attempts,
				maxAttempts: LLMStore.MAX_POLL_ATTEMPTS
			});

			try {
				// Only refresh every 3rd attempt (every ~22 seconds) to reduce UI thrashing
				// Always refresh on first attempt and when we're close to completion
				const shouldRefresh =
					attempts === 1 || attempts % 3 === 0 || attempts > LLMStore.MAX_POLL_ATTEMPTS - 5;

				if (shouldRefresh) {
					logger.debug('llm-store', `Refreshing models for ${_modelId}`, {
						refreshAttempt: ++lastRefreshAttempt
					});
					await this.fetchModels(true);
					await this.fetchGroupedModels(true);
				}

				// Check if model is now downloaded (check both individual and grouped models)
				const model = this.state.models?.[_modelId];

				// Also check grouped models for the variant
				let variantDownloaded = false;
				if (this.state.groupedModels) {
					for (const group of this.state.groupedModels) {
						const variant = group.variants.find((v) => v.id === _modelId);
						if (variant?.downloaded) {
							variantDownloaded = true;
							logger.debug('llm-store', `Found downloaded variant ${_modelId}`, {
								groupName: group.base_model_name
							});
							break;
						}
					}
				}

				// Check if download completed in either location
				if (model?.downloaded || variantDownloaded) {
					logger.info('llm-store', `Download completed for ${_modelId}, cleaning up states`);
					this.state.downloadingModels.delete(_modelId);

					// Clean up any download progress data
					if (this.state.downloadProgress[_modelId]) {
						delete this.state.downloadProgress[_modelId];
					}

					// Do one final refresh to ensure UI is fully updated
					// Always refresh on completion
					await this.fetchModels(true);
					await this.fetchGroupedModels(true);

					logger.info('llm-store', `Download process complete for ${_modelId}`);
					return;
				}

				// Check if we're still in progress (model exists but not downloaded)
				const modelExists =
					model || this.state.groupedModels?.some((g) => g.variants.some((v) => v.id === _modelId));

				if (modelExists) {
					consecutiveNoProgressAttempts = 0; // Reset counter if model exists
				} else {
					consecutiveNoProgressAttempts++;
					logger.debug('llm-store', `No model found for ${_modelId}`, {
						consecutiveAttempts: consecutiveNoProgressAttempts
					});
				}

				// If we haven't seen progress for too long, assume failure
				if (consecutiveNoProgressAttempts >= LLMStore.MAX_NO_PROGRESS_ATTEMPTS) {
					logger.error(
						'llm-store',
						`Download appears to have failed for ${_modelId} - no model found for too long`
					);
					this.state.downloadingModels.delete(_modelId);
					// Clean up download progress on failure
					if (this.state.downloadProgress[_modelId]) {
						delete this.state.downloadProgress[_modelId];
					}
					this.state.error = `Download failed for ${_modelId} - model not found in system`;
					return;
				}

				// Continue polling if not completed and under max attempts
				if (attempts < LLMStore.MAX_POLL_ATTEMPTS) {
					setTimeout(poll, LLMStore.POLL_INTERVAL_MS);
				} else {
					logger.warn('llm-store', `Download polling timed out for ${_modelId}`, {
						attempts: LLMStore.MAX_POLL_ATTEMPTS
					});
					this.state.downloadingModels.delete(_modelId);
					// Clean up download progress on timeout
					if (this.state.downloadProgress[_modelId]) {
						delete this.state.downloadProgress[_modelId];
					}
					this.state.error = `Download timed out for ${_modelId} - please check server logs`;
				}
			} catch (_error) {
				logger.error('llm-store', `Error polling download status for ${_modelId}`, _error as Error);
				this.state.downloadingModels.delete(_modelId);
				// Clean up download progress on error too
				if (this.state.downloadProgress[_modelId]) {
					delete this.state.downloadProgress[_modelId];
				}
				this.state.error = `Error checking download status: ${_error instanceof Error ? _error.message : 'Unknown error'}`;
			}
		};

		// Start polling after initial delay
		setTimeout(poll, LLMStore.INITIAL_POLL_DELAY_MS);
	}

	/**
	 * Start listening for download progress updates via SSE
	 */
	private startDownloadProgressStream(): void {
		if (!_browser || this.progressEventSource) return;

		logger.debug('llm-store', 'Starting download progress stream');
		this.progressEventSource = _apiClient.createDownloadProgressStream();
		if (!this.progressEventSource) {
			logger.warn('llm-store', 'Failed to create download progress stream');
			return;
		}

		logger.debug('llm-store', 'Download progress stream created successfully');

		this.progressEventSource.onopen = () => {
			logger.debug('llm-store', 'Download progress stream connected');
		};

		this.progressEventSource.onmessage = (event) => {
			logger.debug('llm-store', 'Download progress received', { data: event.data });
			try {
				const progressData: DownloadProgressInfo = JSON.parse(event.data);
				logger.debug('llm-store', 'Parsed progress data', { progressData });
				this.state.downloadProgress[progressData.model_id] = progressData;

				// If download is complete (100%), remove from downloading set and refresh models
				if (progressData.percentage >= 100) {
					logger.info('llm-store', `Download complete for ${progressData.model_id}`);
					this.state.downloadingModels.delete(progressData.model_id);
					delete this.state.downloadProgress[progressData.model_id];

					// Refresh models in background to update status
					this.fetchModels(true).catch((error) =>
						logger.error('llm-store', 'Failed to refresh models after download', error)
					);
					this.fetchGroupedModels(true).catch((error) =>
						logger.error('llm-store', 'Failed to refresh grouped models after download', error)
					);
				}
			} catch (_error) {
				logger.error('llm-store', 'Error parsing download progress', _error as Error);
			}
		};

		this.progressEventSource.onerror = (event) => {
			logger.error('llm-store', 'Download progress stream error', { event });
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
		logger.warn('llm-store', 'toggleRecommendations not implemented yet');
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
			logger.warn('llm-store', 'Initial LLM support check failed', { error });
		});
		globalLlmStore.fetchModels().catch((error) => {
			logger.warn('llm-store', 'Initial LLM model fetch failed', { error });
		});
		globalLlmStore.fetchGroupedModels().catch((error) => {
			logger.warn('llm-store', 'Initial grouped models fetch failed', { error });
		});
	}
}

export function getGlobalLlmStore(): LLMStore | null {
	return globalLlmStore;
}
