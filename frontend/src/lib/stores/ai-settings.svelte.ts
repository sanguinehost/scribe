/**
 * AI Settings Store (Stub for Scribe)
 *
 * Scribe uses backend-authenticated AI generation, not client-side API keys.
 * This is a stub to satisfy character-editor component dependencies.
 * Always returns hasApiKey: true since scribe's backend handles authentication.
 */

class AiSettings {
	// In scribe, AI is always available (backend-authenticated)
	get hasApiKey() {
		return true;
	}

	/**
	 * Get API key (stub)
	 * Scribe stores encrypted keys on backend
	 */
	getApiKey(): string {
		return 'backend-managed';
	}

	/**
	 * Get provider name
	 * Scribe uses backend provider
	 */
	get provider() {
		return 'backend' as const;
	}

	get usageStats() {
		return {
			totalRequests: 0,
			totalTokens: 0,
			totalCost: 0
		};
	}

	get selectedModel() {
		return {
			id: 'scribe-backend',
			name: 'Scribe Backend AI'
		};
	}

	/**
	 * Security settings (stub)
	 */
	get securitySettings() {
		return {
			showDebugInfo: false,
			enableSanitization: true
		};
	}
}

export const aiSettings = new AiSettings();
