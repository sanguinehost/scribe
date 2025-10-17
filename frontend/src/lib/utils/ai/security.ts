/**
 * Security utilities for AI generation
 * Stub implementation - scribe handles security on backend
 */

/**
 * Estimate token count for text
 * Simple approximation: 1 token ≈ 4 characters
 */
export function estimateTokenCount(text: string): number {
	return Math.ceil(text.length / 4);
}

/**
 * Sanitize AI output
 * In scribe, backend handles sanitization
 */
export function sanitizeAIOutput(text: string): string {
	return text;
}
