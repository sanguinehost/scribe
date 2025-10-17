/**
 * AI Generation Helper Utilities
 *
 * Smart defaults and validation for character field generation.
 * Ported from character-editor for better UX.
 */

import type { GenerationMode, DescriptionStyle } from '$lib/types';

/**
 * Get recommended max tokens for output based on field
 */
export function getRecommendedMaxTokens(fieldName: string): number {
	// Field-specific recommendations based on real-world character card patterns
	const recommendations: Record<string, number> = {
		name: 50,
		description: 3000, // Often the longest field with full AI instructions
		personality: 1500, // Can be detailed lore or empty
		scenario: 1500, // Often detailed world state
		first_mes: 2000, // Rich, immersive opening scenes
		alternate_greetings: 2000, // Equally detailed as first_mes
		mes_example: 1500, // Full conversation examples
		creator_notes: 800,
		system_prompt: 2000, // Detailed narrator/writing instructions
		depth_prompt: 1500, // Deep character context
		tags: 100
	};

	return recommendations[fieldName] || 2000; // Default to 2000
}

/**
 * Get field-specific style recommendation
 */
export function getRecommendedStyle(fieldName: string): DescriptionStyle {
	const recommendations: Record<string, DescriptionStyle> = {
		name: 'auto',
		description: 'auto', // Most versatile field
		personality: 'traits',
		scenario: 'worldbuilding',
		first_mes: 'narrative',
		alternate_greetings: 'narrative',
		mes_example: 'narrative',
		creator_notes: 'profile',
		system_prompt: 'system',
		depth_prompt: 'worldbuilding',
		tags: 'traits'
	};

	return recommendations[fieldName] || 'auto';
}

/**
 * Check if a field supports a specific generation mode
 */
export function isModeSupported(fieldName: string, mode: GenerationMode): boolean {
	// Name field doesn't support enhance/expand (too short)
	if (fieldName === 'name' && (mode === 'enhance' || mode === 'expand')) {
		return false;
	}

	// Tags don't support expand (they're already lists)
	if (fieldName === 'tags' && mode === 'expand') {
		return false;
	}

	// All other combinations are valid
	return true;
}

/**
 * Get available description styles for a field
 */
export function getAvailableStyles(fieldName: string): DescriptionStyle[] {
	// Tags are special - only traits make sense
	if (fieldName === 'tags') {
		return ['auto', 'traits'];
	}

	// Narrative/immersive fields - pure narrative content only
	if (
		fieldName === 'first_mes' ||
		fieldName === 'alternate_greetings' ||
		fieldName === 'mes_example'
	) {
		return ['auto', 'narrative', 'worldbuilding', 'group'];
	}

	// Description is the most versatile - can use almost any style
	if (fieldName === 'description') {
		return ['auto', 'traits', 'narrative', 'profile', 'worldbuilding', 'system'];
	}

	// Personality can use most styles
	if (fieldName === 'personality') {
		return ['auto', 'traits', 'narrative', 'profile', 'worldbuilding'];
	}

	// Scenario benefits from world-building focus but can use others
	if (fieldName === 'scenario') {
		return ['auto', 'worldbuilding', 'narrative', 'profile', 'system'];
	}

	// Technical/system fields
	if (fieldName === 'system_prompt' || fieldName === 'depth_prompt') {
		return ['auto', 'system', 'profile'];
	}

	// Creator notes - flexible
	if (fieldName === 'creator_notes') {
		return ['auto', 'profile', 'narrative', 'traits'];
	}

	// Default: all styles available - let creators experiment
	return ['auto', 'traits', 'narrative', 'profile', 'group', 'worldbuilding', 'system'];
}

/**
 * Sanitize AI output for security
 * Prevents potential injection attacks or malicious content
 */
export function sanitizeAIOutput(content: string): string {
	// Remove any script tags
	let sanitized = content.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

	// Remove any on* event handlers
	sanitized = sanitized.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, '');

	// Remove javascript: protocol
	sanitized = sanitized.replace(/javascript:/gi, '');

	return sanitized;
}
