/**
 * Agentic Utilities Stub
 *
 * Placeholder for future image generation and research features.
 * These will be implemented when user adds encrypted API keys to server.
 */

export interface WorkflowProgress {
	status: string;
	progress: number;
	percentage?: number;
	currentStep?: string;
	totalSteps?: number;
	message?: string;
	currentAction?: {
		toolName: string;
		parameters?: Record<string, unknown>;
	};
}

export interface WorkflowResult {
	success: boolean;
	result?: unknown;
	toolExecutions: ToolExecution[];
	error?: string;
	output?: Record<string, unknown>;
	totalTimeMs?: number;
	plan?: {
		goal: string;
		reasoning: string;
		totalSteps: number;
	};
}

export interface ToolExecution {
	toolName: string;
	success: boolean;
	result?: unknown;
	error?: string;
	parameters?: Record<string, unknown>;
	executionTimeMs?: number;
}

export interface ImageStyle {
	id: string;
	name: string;
	description: string;
}

/**
 * Image Generation Agent Factory (Stub)
 */
export class ImageGenerationAgentFactory {
	static create(_provider: unknown): ImageGenerationAgent {
		return new ImageGenerationAgent();
	}

	static createImageGenerationAgent(_provider: unknown): ImageGenerationAgent {
		return new ImageGenerationAgent();
	}
}

/**
 * Research Agent Factory (Stub)
 */
export class ResearchAgentFactory {
	static create(_provider: unknown): ResearchAgent {
		return new ResearchAgent();
	}

	static createResearchAgent(_provider: unknown, _config?: Record<string, unknown>): ResearchAgent {
		return new ResearchAgent();
	}

	static getResearchConfig(): Record<string, unknown> {
		return { stub: true };
	}
}

/**
 * Lorebook Agent Factory (Stub)
 */
export class LorebookAgentFactory {
	static create(_provider: unknown): Record<string, unknown> {
		return { stub: true };
	}

	static createLorebookAgent(
		_provider: unknown,
		_config?: Record<string, unknown>
	): Record<string, unknown> {
		return { stub: true };
	}

	static getLorebookConfig(): Record<string, unknown> {
		return { stub: true };
	}
}

/**
 * Image Generation Agent (Stub)
 */
class ImageGenerationAgent {
	async executeWorkflowMultiStage(
		_goal: string,
		_context: Record<string, unknown>,
		_onProgress: (progress: WorkflowProgress) => void
	): Promise<WorkflowResult> {
		throw new Error(
			'Image generation not yet implemented. Coming soon with encrypted API key storage!'
		);
	}
}

/**
 * Research Agent (Stub)
 */
class ResearchAgent {
	async executeWorkflowMultiStage(
		_goal: string,
		_context: Record<string, unknown>,
		_onProgress: (progress: WorkflowProgress) => void
	): Promise<WorkflowResult> {
		throw new Error('Research not yet implemented. Coming soon with Firecrawl integration!');
	}
}

/**
 * Get available image styles (Stub)
 */
export function getAvailableStyles(): ImageStyle[] {
	return [
		{ id: 'anime', name: 'Anime', description: 'Anime/manga style' },
		{ id: 'realistic', name: 'Realistic', description: 'Photorealistic style' },
		{ id: 'fantasy', name: 'Fantasy', description: 'Fantasy art style' }
	];
}

/**
 * Provider functions (Stubs)
 */
export function createProvider(_provider: string, _apiKey: string): Record<string, unknown> {
	return { name: 'stub-provider' };
}

export function getProviderMetadata(_provider: string): Record<string, unknown> {
	return { name: 'Backend Provider', requiresApiKey: false };
}

export function isProviderSupported(_provider: string): boolean {
	return true;
}

export function getSupportedProviders(): string[] {
	return ['backend'];
}

/**
 * Build workflow goal for image generation (Stub)
 */
export function buildImageGenerationWorkflowGoal(
	_userDescription: string,
	_selectedStyle: string,
	_selectedAssetType: string,
	_userGuidance: string
): string {
	return 'Generate character image';
}

/**
 * Build workflow context for image generation (Stub)
 */
export function buildImageGenerationWorkflowContext(
	_userDescription: string,
	_selectedStyle: string,
	_selectedAssetType: string,
	_userGuidance: string
): Record<string, unknown> {
	return { stub: true };
}

/**
 * Build workflow goal for research (Stub)
 */
export function buildResearchWorkflowGoal(_researchQuery: string): string {
	return 'Conduct research';
}

/**
 * Build workflow context for research (Stub)
 */
export function buildResearchWorkflowContext(
	_character: Record<string, unknown>,
	_researchQuery: string
): Record<string, unknown> {
	return { stub: true };
}

/**
 * Get lorebook agent config (Stub)
 */
export function getLorebookAgentConfig(): Record<string, unknown> {
	return { stub: true };
}

/**
 * Generate single lorebook entry goal (Stub)
 */
export function generateSingleEntryGoal(
	_entryName: string,
	_context?: Record<string, unknown>
): string {
	return 'Generate lorebook entry';
}

/**
 * Generate single lorebook entry context (Stub)
 */
export function generateSingleEntryContext(
	_entryName: string,
	_character?: Record<string, unknown>
): Record<string, unknown> {
	return { stub: true };
}

/**
 * Batch generate lorebook entries goal (Stub)
 */
export function batchGenerateEntriesGoal(_count: number, _theme?: string): string {
	return 'Batch generate lorebook entries';
}

/**
 * Batch generate lorebook entries context (Stub)
 */
export function batchGenerateEntriesContext(
	_character: Record<string, unknown> | number,
	_existingEntries?: unknown[] | string
): Record<string, unknown> {
	return { stub: true };
}

/**
 * Enhance lorebook goal (Stub)
 */
export function enhanceLorebookGoal(_maxEntries: number): string {
	return 'Enhance lorebook';
}

/**
 * Enhance lorebook context (Stub)
 */
export function enhanceLorebookContext(_maxEntries: number): Record<string, unknown> {
	return { stub: true };
}
