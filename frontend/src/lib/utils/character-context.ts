/**
 * Character Context Helper
 *
 * Extracts character data to build context for AI generation.
 * Helps AI understand the full character when generating specific fields.
 */

import type { CharacterCardV3 } from '$lib/types/character';
import type { CharacterContext } from '$lib/types/ai';

/**
 * Build character context from character card
 *
 * Extracts all relevant fields that provide context for AI generation.
 * Used to help AI generate consistent, character-appropriate content.
 *
 * @param character - Character card V3 object
 * @param excludeField - Optional field name to exclude (useful when generating that field)
 * @returns Character context object for AI prompts
 */
export function buildCharacterContext(
	character: CharacterCardV3 | null,
	excludeField?: string
): CharacterContext {
	if (!character) {
		return {};
	}

	const context: CharacterContext = {};

	// Core fields
	if (character.data.name && excludeField !== 'name') {
		context.name = character.data.name;
	}

	if (character.data.description && excludeField !== 'description') {
		context.description = character.data.description;
	}

	if (character.data.personality && excludeField !== 'personality') {
		context.personality = character.data.personality;
	}

	if (character.data.scenario && excludeField !== 'scenario') {
		context.scenario = character.data.scenario;
	}

	if (character.data.first_mes && excludeField !== 'first_mes') {
		context.first_mes = character.data.first_mes;
	}

	if (character.data.mes_example && excludeField !== 'mes_example') {
		context.mes_example = character.data.mes_example;
	}

	if (character.data.system_prompt && excludeField !== 'system_prompt') {
		context.system_prompt = character.data.system_prompt;
	}

	// Tags
	if (character.data.tags && character.data.tags.length > 0 && excludeField !== 'tags') {
		context.tags = character.data.tags;
	}

	// Alternate greetings (exclude if generating alternate greeting)
	if (
		character.data.alternate_greetings &&
		character.data.alternate_greetings.length > 0 &&
		!excludeField?.startsWith('alternate_greeting')
	) {
		context.alternate_greetings = character.data.alternate_greetings.filter((g) => g.trim());
	}

	return context;
}

/**
 * Get character name for AI prompt context
 *
 * Returns character name or fallback if not set.
 * Used in AI prompts to reference the character being created.
 *
 * @param character - Character card V3 object
 * @returns Character name or "this character"
 */
export function getCharacterNameOrDefault(character: CharacterCardV3 | null): string {
	return character?.data.name?.trim() || 'this character';
}

/**
 * Check if character has enough context for generation
 *
 * Determines if character has sufficient information to provide
 * useful context to AI generation (at least name + one other field).
 *
 * @param context - Character context object
 * @returns Whether context has useful information
 */
export function hasUsefulContext(context: CharacterContext): boolean {
	const fieldCount = Object.keys(context).length;
	return fieldCount > 0 && (context.name !== undefined || fieldCount > 1);
}

/**
 * Format character context for display
 *
 * Creates a human-readable summary of character context.
 * Useful for showing users what context is being used.
 *
 * @param context - Character context object
 * @returns Formatted string summary
 */
export function formatContextSummary(context: CharacterContext): string {
	const parts: string[] = [];

	if (context.name) parts.push(`Name: ${context.name}`);
	if (context.description) parts.push(`Description: ${truncate(context.description, 50)}`);
	if (context.personality) parts.push(`Personality: ${truncate(context.personality, 50)}`);
	if (context.scenario) parts.push(`Scenario: ${truncate(context.scenario, 50)}`);
	if (context.tags && context.tags.length > 0) parts.push(`Tags: ${context.tags.join(', ')}`);

	return parts.join('\n');
}

/**
 * Build context for lorebook entry generation
 *
 * Combines character context with entry-specific information
 * to help AI generate relevant, coherent lorebook content.
 *
 * @param character - Character card V3 object
 * @param entryName - Name/title of the lorebook entry
 * @param entryKeys - Keywords that trigger this entry
 * @param existingContent - Current content (for enhance/rewrite modes)
 * @returns Combined context object for AI prompts
 */
export function buildLorebookEntryContext(
	character: CharacterCardV3 | null,
	entryName?: string,
	entryKeys?: string[],
	existingContent?: string
): CharacterContext & {
	entryName?: string;
	entryKeys?: string[];
	entryContent?: string;
} {
	const baseContext = buildCharacterContext(character);

	return {
		...baseContext,
		...(entryName && { entryName }),
		...(entryKeys && entryKeys.length > 0 && { entryKeys }),
		...(existingContent && { entryContent: existingContent })
	};
}

/**
 * Truncate string to max length with ellipsis
 */
function truncate(str: string, maxLength: number): string {
	if (str.length <= maxLength) return str;
	return str.substring(0, maxLength) + '...';
}
