/**
 * Prompt Engineering Utilities
 *
 * Builds system and user prompts for AI generation based on:
 * - Generation mode (create, enhance, expand, rewrite)
 * - Description style (traits, narrative, profile, etc.)
 * - Field type (personality, scenario, first_mes, etc.)
 * - Character context
 *
 * Design: Modular prompt templates with composition.
 */

import type {
	GenerationMode,
	DescriptionStyle,
	GenerationRequest,
	CharacterContext
} from '$lib/types/ai';
import { estimateTokenCount } from './security';

// ============================================================================
// System Prompt Templates
// ============================================================================

/**
 * Base system prompt for all character generation tasks
 */
const BASE_SYSTEM_PROMPT = `You are an expert character designer for creative writing, role-playing games, and interactive fiction. Your expertise includes:
- Deep understanding of character psychology and motivation
- Crafting engaging, multi-dimensional personalities
- Creating immersive scenarios and settings
- Writing natural, character-appropriate dialogue
- Balancing detail with brevity

Focus on quality over quantity. Generate content that feels authentic and engaging.

CRITICAL PLACEHOLDER USAGE:
- {{char}} = The AI character being created by this card (the one you're writing)
- {{user}} = The human player/user (the person using the chatbot)

Examples:
- For a character card about "Alice": {{char}} = Alice, {{user}} = the player talking to Alice
- For a narrator/GM card: {{char}} = the narrator/GM, {{user}} = the player character in the story
- For a world/scenario card: {{char}} = the world/narrator, {{user}} = the player

NEVER mix them up or use them interchangeably. They refer to two different entities.
{{user}} is ALWAYS the human player, not the character you're creating.`;

/**
 * Style-specific system prompt additions
 */
const STYLE_PROMPTS: Record<DescriptionStyle, string> = {
	auto: '', // Auto will be determined by field type

	traits: `Output Format: Write using clear, comma-separated trait lists.
- Use adjectives and short phrases
- Group related traits together
- Include both positive and nuanced traits
- Be specific rather than generic

Example: "Curious and analytical, tends to overthink situations, loyal to close friends but slow to trust, sarcastic humor as a defense mechanism"`,

	narrative: `Output Format: Write in flowing narrative prose.
- Use descriptive, literary language
- Create vivid imagery and atmosphere
- Show personality through actions and reactions
- Include sensory details when relevant
- Use paragraph breaks to separate ideas and scenes
- Each paragraph should be 2-4 sentences

Example: "She moved through the world with quiet observation, her sharp mind always cataloging details others missed. Behind her sardonic wit lay a deep well of loyalty.

Years in the archives had taught her patience, but her restless curiosity still drove her to pursue every lead, no matter how obscure..."`,

	profile: `Output Format: Write in structured profile/instructional format.
- Can use markdown headings, bullet points, or structured sections
- Ideal for AI behavioral instructions, power systems, abilities, rules
- Present information clearly and systematically
- May include technical details, mechanics, or guidelines
- Can be quite detailed and comprehensive

Example: "### Character Behavior:\n- The AI will narrate with rich detail\n- Never judge user choices\n\n### Abilities:\n- Power Level: Godlike\n- Can manipulate matter and energy\n\n### Response Format:\nEnd each reply with current state..."`,

	group: `Output Format: Write for group/party dynamics.
- Focus on interpersonal traits and relationships
- Highlight how character fits into team dynamics
- Note collaboration style and conflict patterns
- Include role within the group

Example: "Often takes on the mediator role, using humor to diffuse tension. Contributes strategic thinking but sometimes holds back due to self-doubt..."`,

	worldbuilding: `Output Format: Write with world/setting integration.
- Connect character to broader world context
- Reference cultural, historical, or political elements
- Show how setting shapes the character
- Include faction/organization affiliations if relevant
- Use paragraph breaks to separate different aspects
- Each paragraph should focus on one aspect of the world/character relationship

Example: "Born in the aftermath of the Collapse, she carries the practical cynicism of the reconstruction era. Her technical skills were honed in the makeshift workshops that sprang up across the Reclaimed Zones.

Despite the scarcity of the early years, she maintained a fierce loyalty to the ideals of the Archives Council, believing knowledge was the only path to preventing another catastrophe..."`,

	system: `Output Format: Write system instructions for AI behavior, game mechanics, or narrator guidelines.
- Focus on HOW the AI should behave, not WHO the character is
- Include game rules, world mechanics, or simulation guidelines
- Specify narrator responsibilities and constraints
- Define response formats, stat tracking, or procedural rules
- Use clear, directive language

Example: "{{char}} is the narrator. {{char}} will control all NPCs and world events. {{char}} will never control {{user}}'s actions. Random encounters occur every 3-5 messages. {{char}} will track stats at the end of each message."`
};

/**
 * Mode-specific instructions
 */
const MODE_INSTRUCTIONS: Record<GenerationMode, string> = {
	create: `Task: Generate NEW content from scratch.
- Start fresh, don't reference existing content
- Create original, creative content
- Ensure internal consistency
- Make it engaging and specific`,

	enhance: `Task: ENHANCE existing content while preserving its core.
- Keep the fundamental concept and tone
- Add depth, detail, and nuance
- Improve clarity and engagement
- Maintain consistency with existing content`,

	expand: `Task: EXPAND existing content with additional detail.
- Elaborate on what's already there
- Add new dimensions without contradicting existing content
- Increase richness and complexity
- Maintain the original voice and style`,

	rewrite: `Task: REWRITE existing content with a fresh perspective.
- Preserve core ideas but change expression
- Improve quality and engagement
- Fix any issues or inconsistencies
- May change style/tone if that improves quality`
};

/**
 * Field-specific context
 */
const FIELD_CONTEXTS: Record<string, { description: string; defaultStyle: DescriptionStyle }> = {
	name: {
		description: 'Character name. Should be memorable, appropriate to setting/culture.',
		defaultStyle: 'auto'
	},
	description: {
		description:
			"The character's core definition - format and content vary widely based on creator intent. Can be: narrative description (appearance, personality, backstory), structured profile (stats, abilities), system instructions (narrator rules, AI behavior), world-building context, or any combination. May use XML-like tags, markdown sections, bullet points, or prose. Length ranges from brief (100 words) to extensive (3000+). This is the most versatile field - match the format to your vision.",
		defaultStyle: 'auto'
	},
	personality: {
		description:
			"Core personality traits, behavioral patterns, motivations, and psychological characteristics. How the character thinks, feels, and reacts. Can be left empty if personality details are already covered in the description field. When used, should focus on the character's mental/emotional makeup rather than physical traits or abilities.",
		defaultStyle: 'traits'
	},
	scenario: {
		description:
			'World state, character relationships, political situations, and context for the roleplay. Can include plot setup, faction dynamics, ongoing conflicts, and relationship histories. Often detailed and substantial (100-1000+ words) to establish rich context.',
		defaultStyle: 'worldbuilding'
	},
	first_mes: {
		description:
			"The opening scene/greeting that starts the roleplay. Should be a rich, immersive narrative (often 200-1000+ words) that establishes atmosphere, setting, character state, and situation. Use vivid sensory details, multiple paragraphs for readability, and a hook that invites user interaction. May include narration (in asterisks), dialogue, internal thoughts, environmental description, and current events. This sets the tone and quality bar for the entire roleplay. IMPORTANT: Use {{user}} consistently to refer to the player character throughout the greeting, and {{char}} to refer to the AI character/narrator you're creating.",
		defaultStyle: 'narrative'
	},
	alternate_greeting: {
		description:
			'Alternative opening scenario with different mood, setting, or situation than the main greeting. Should be equally detailed and immersive (200-1000+ words) but offer variety - different time period, location, relationship dynamic, or crisis. Maintain character consistency while exploring different facets. Use multiple paragraphs and rich narrative detail.',
		defaultStyle: 'narrative'
	},
	mes_example: {
		description:
			'Example conversation exchanges demonstrating the character\'s dialogue style, actions, and personality. MUST follow this format: Multiple conversation examples separated by "<START>" tags. Each example shows back-and-forth dialogue between {{char}} (the character) and {{user}} (the player). Use {{char}}: and {{user}}: labels. Include actions in *asterisks*. Generate 2-3 distinct conversation examples showing different scenarios or moods.',
		defaultStyle: 'narrative'
	},
	creator_notes: {
		description: 'Behind-the-scenes notes about design intent, inspirations, or usage tips.',
		defaultStyle: 'profile'
	},
	system_prompt: {
		description:
			'Technical instructions for AI behavior when playing this character. Clear and specific.',
		defaultStyle: 'system'
	},
	post_history_instructions: {
		description: 'Instructions that apply after conversation history. Technical/mechanical.',
		defaultStyle: 'system'
	},
	tags: {
		description: 'Categorization tags. Short, specific keywords.',
		defaultStyle: 'traits'
	},
	// Lorebook entry fields
	'entry.content': {
		description:
			'Lorebook entry content. Factual, concise information about the specific topic indicated by the entry name and keywords. Should provide relevant context that enriches the roleplay when this topic comes up. Can include descriptions, backstory, relationships, abilities, or world-building details related to the keywords. Keep focused on the topic - avoid generic or overly broad information.',
		defaultStyle: 'profile'
	},
	'entry.comment': {
		description: 'Commentary or metadata about the lorebook entry.',
		defaultStyle: 'profile'
	}
};

// ============================================================================
// Prompt Building Functions
// ============================================================================

/**
 * Build complete system prompt
 */
export function buildSystemPrompt(
	mode: GenerationMode,
	fieldName: string,
	style: DescriptionStyle = 'auto'
): string {
	const parts: string[] = [];

	// 1. Base prompt
	parts.push(BASE_SYSTEM_PROMPT);

	// 2. Field context
	const fieldContext = FIELD_CONTEXTS[fieldName];
	if (fieldContext) {
		parts.push(`\nField: ${fieldName}`);
		parts.push(`Purpose: ${fieldContext.description}`);

		// Use field's default style if auto
		if (style === 'auto') {
			style = fieldContext.defaultStyle;
		}
	}

	// 3. Mode instructions
	parts.push(`\n${MODE_INSTRUCTIONS[mode]}`);

	// 4. Style instructions (if not auto)
	if (style !== 'auto') {
		parts.push(`\n${STYLE_PROMPTS[style]}`);
	}

	// 5. Field-specific formatting requirements
	if (fieldName === 'mes_example') {
		parts.push(`\nCRITICAL FORMAT REQUIREMENT for mes_example:

EVERY SINGLE conversation example MUST start with "<START>" on its own line.
This includes THE VERY FIRST EXAMPLE. Your output must literally begin with <START>.

Generate 2-3 conversation examples using this EXACT structure:

<START>
{{char}}: "Dialogue here." *Action in asterisks.*
{{user}}: "Response here." *Action.*
{{char}}: "Reply." *Action.*
{{user}}: "Final response."
{{char}}: *Reaction and closing.*

<START>
{{char}}: "Different scenario dialogue..." *Different action.*
{{user}}: "Response."
{{char}}: "Reply..."

<START>
{{char}}: "Third example..." *Action.*
[continue...]

CRITICAL: Your output MUST begin with the text "<START>" (not with dialogue or narration).
The first line of your output should be: <START>
Then the conversation begins on the next line.

Use {{char}}: for the AI character and {{user}}: for the player.
Actions go in *asterisks*.
Show different scenarios, moods, or personality aspects.`);
	}

	// 6. Final guidelines
	parts.push(`\nGuidelines:
- Be concise but complete
- Avoid clichés and overused tropes
- Make every word count
- Use paragraph breaks (double newlines) to separate ideas and improve readability
- For longer content, break into 2-4 sentence paragraphs
- Output ONLY the generated content, no meta-commentary
- Do not include field labels or markdown headers in output`);

	return parts.join('\n');
}

/**
 * Build user prompt with character context
 */
export function buildUserPrompt(request: GenerationRequest): string {
	const parts: string[] = [];

	// 1. Current content (if any)
	if (request.fieldValue && request.mode !== 'create') {
		parts.push(`Current ${request.fieldName}:`);
		parts.push(request.fieldValue);
		parts.push(''); // Empty line
	}

	// 2. Character context (if provided)
	if (request.characterContext) {
		const contextStr = formatCharacterContext(request.characterContext);
		if (contextStr) {
			parts.push('Character Context:');
			parts.push(contextStr);
			parts.push(''); // Empty line
		}
	}

	// 3. User's custom prompt (if any)
	if (request.userPrompt) {
		parts.push('Additional Instructions:');
		parts.push(request.userPrompt);
		parts.push(''); // Empty line
	}

	// 4. Final instruction
	const action = getModeAction(request.mode);
	parts.push(`${action} the ${request.fieldName} field.`);

	return parts.join('\n');
}

/**
 * Get action verb for mode
 */
function getModeAction(mode: GenerationMode): string {
	switch (mode) {
		case 'create':
			return 'Generate';
		case 'enhance':
			return 'Enhance';
		case 'expand':
			return 'Expand';
		case 'rewrite':
			return 'Rewrite';
	}
}

/**
 * Format character context for prompt
 */
function formatCharacterContext(context: CharacterContext): string {
	const parts: string[] = [];

	if (context.name) parts.push(`Name: ${context.name}`);
	if (context.description) parts.push(`Description: ${context.description}`);
	if (context.personality) parts.push(`Personality: ${context.personality}`);
	if (context.scenario) parts.push(`Scenario: ${context.scenario}`);

	// Include tags if they provide useful context
	if (context.tags && context.tags.length > 0) {
		parts.push(`Tags: ${context.tags.join(', ')}`);
	}

	// Include lorebook entry-specific context (if present)
	const anyContext = context as Record<string, unknown>;
	if (anyContext.entryName) {
		parts.push(`Entry Name: ${anyContext.entryName}`);
	}
	if (
		anyContext.entryKeys &&
		Array.isArray(anyContext.entryKeys) &&
		anyContext.entryKeys.length > 0
	) {
		parts.push(`Entry Keywords: ${anyContext.entryKeys.join(', ')}`);
	}
	if (anyContext.entryContent && !parts.some((p) => p.startsWith('Current entry.content:'))) {
		// Only include if not already shown as "Current content"
		parts.push(`Existing Entry Content: ${anyContext.entryContent}`);
	}

	return parts.join('\n');
}

// ============================================================================
// Prompt Validation and Utilities
// ============================================================================

/**
 * Estimate total tokens for a request
 */
export function estimateRequestTokens(request: GenerationRequest): {
	systemTokens: number;
	userTokens: number;
	totalTokens: number;
} {
	const systemPrompt = buildSystemPrompt(request.mode, request.fieldName, request.style || 'auto');
	const userPrompt = buildUserPrompt(request);

	const systemTokens = estimateTokenCount(systemPrompt);
	const userTokens = estimateTokenCount(userPrompt);

	return {
		systemTokens,
		userTokens,
		totalTokens: systemTokens + userTokens
	};
}

/**
 * Validate prompt won't exceed context window
 */
export function validatePromptSize(
	request: GenerationRequest,
	maxContextWindow: number
): { valid: boolean; error?: string; estimatedTokens?: number } {
	const { totalTokens } = estimateRequestTokens(request);

	// Reserve 50% for output
	const maxInputTokens = Math.floor(maxContextWindow * 0.5);

	if (totalTokens > maxInputTokens) {
		return {
			valid: false,
			error: `Prompt too large (${totalTokens} tokens, max ${maxInputTokens} for this model)`,
			estimatedTokens: totalTokens
		};
	}

	return { valid: true, estimatedTokens: totalTokens };
}

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
		alternate_greeting: 2000, // Equally detailed as first_mes
		mes_example: 1500, // Full conversation examples
		creator_notes: 800,
		system_prompt: 2000, // Detailed narrator/writing instructions
		post_history_instructions: 1500, // Formatting and behavior rules
		tags: 100,
		'entry.content': 1500,
		'entry.comment': 300
	};

	return recommendations[fieldName] || 1500; // Default to 1500
}

/**
 * Get field-specific style recommendation
 */
export function getRecommendedStyle(fieldName: string): DescriptionStyle {
	const fieldContext = FIELD_CONTEXTS[fieldName];
	return fieldContext?.defaultStyle || 'auto';
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
	// Be permissive - most fields can benefit from multiple styles
	// Only restrict truly incompatible combinations

	// Tags are special - only traits make sense
	if (fieldName === 'tags') {
		return ['auto', 'traits'];
	}

	// Narrative/immersive fields - pure narrative content only
	if (
		fieldName === 'first_mes' ||
		fieldName === 'alternate_greeting' ||
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
	if (fieldName === 'system_prompt' || fieldName === 'post_history_instructions') {
		return ['auto', 'system', 'profile'];
	}

	// Creator notes - flexible
	if (fieldName === 'creator_notes') {
		return ['auto', 'profile', 'narrative', 'traits'];
	}

	// Group-related fields
	if (fieldName.includes('group')) {
		return ['auto', 'narrative', 'group', 'profile', 'worldbuilding'];
	}

	// Lorebook entries
	if (fieldName.startsWith('entry.')) {
		return ['auto', 'profile', 'worldbuilding', 'narrative', 'system'];
	}

	// Default: all styles available - let creators experiment
	return ['auto', 'traits', 'narrative', 'profile', 'group', 'worldbuilding', 'system'];
}

// ============================================================================
// Debug Utilities
// ============================================================================

/**
 * Get full prompt preview for debugging
 */
export function getPromptPreview(request: GenerationRequest): {
	systemPrompt: string;
	userPrompt: string;
	estimatedTokens: number;
} {
	const systemPrompt = buildSystemPrompt(request.mode, request.fieldName, request.style || 'auto');
	const userPrompt = buildUserPrompt(request);
	const { totalTokens } = estimateRequestTokens(request);

	return {
		systemPrompt,
		userPrompt,
		estimatedTokens: totalTokens
	};
}
