/**
 * JSON Schemas for Structured Outputs
 *
 * Defines strict JSON schemas for each character field to enable
 * OpenRouter's structured output feature for type-safe generation.
 *
 * See: https://openrouter.ai/docs/features/structured-outputs
 */

import type { ResponseFormat } from '$lib/types/ai';

/**
 * Schema for personality field
 * Returns: { traits: string[], summary: string }
 */
export const PERSONALITY_SCHEMA: ResponseFormat = {
	type: 'json_schema',
	json_schema: {
		name: 'personality',
		strict: true,
		schema: {
			type: 'object',
			properties: {
				traits: {
					type: 'array',
					description: 'List of personality traits and behavioral patterns',
					items: {
						type: 'string'
					}
				},
				summary: {
					type: 'string',
					description: 'Concise summary of overall personality'
				}
			},
			required: ['traits', 'summary'],
			additionalProperties: false
		}
	}
};

/**
 * Schema for description field
 * Returns: { appearance: string, demeanor: string }
 */
export const DESCRIPTION_SCHEMA: ResponseFormat = {
	type: 'json_schema',
	json_schema: {
		name: 'description',
		strict: true,
		schema: {
			type: 'object',
			properties: {
				appearance: {
					type: 'string',
					description: 'Physical appearance and visual characteristics'
				},
				demeanor: {
					type: 'string',
					description: 'First impression, aura, and outward demeanor'
				}
			},
			required: ['appearance', 'demeanor'],
			additionalProperties: false
		}
	}
};

/**
 * Schema for scenario field
 * Returns: { setting: string, situation: string, context: string }
 */
export const SCENARIO_SCHEMA: ResponseFormat = {
	type: 'json_schema',
	json_schema: {
		name: 'scenario',
		strict: true,
		schema: {
			type: 'object',
			properties: {
				setting: {
					type: 'string',
					description: 'Where and when the scene takes place'
				},
				situation: {
					type: 'string',
					description: 'Current situation and circumstances'
				},
				context: {
					type: 'string',
					description: 'Background context and relevant details'
				}
			},
			required: ['setting', 'situation', 'context'],
			additionalProperties: false
		}
	}
};

/**
 * Schema for tags field
 * Returns: { tags: string[] }
 */
export const TAGS_SCHEMA: ResponseFormat = {
	type: 'json_schema',
	json_schema: {
		name: 'tags',
		strict: true,
		schema: {
			type: 'object',
			properties: {
				tags: {
					type: 'array',
					description: 'List of relevant tags for categorization',
					items: {
						type: 'string'
					}
				}
			},
			required: ['tags'],
			additionalProperties: false
		}
	}
};

/**
 * Map of field names to their schemas
 * Use this to automatically select the right schema for a field
 */
export const FIELD_SCHEMAS: Record<string, ResponseFormat> = {
	personality: PERSONALITY_SCHEMA,
	description: DESCRIPTION_SCHEMA,
	scenario: SCENARIO_SCHEMA,
	tags: TAGS_SCHEMA
	// Note: Fields like first_mes, mes_example, system_prompt are free-form text
	// and don't benefit from structured outputs (use plain text generation)
};

/**
 * Check if a field supports structured output
 */
export function supportsStructuredOutput(fieldName: string): boolean {
	return fieldName in FIELD_SCHEMAS;
}

/**
 * Get schema for a field (if available)
 */
export function getFieldSchema(fieldName: string): ResponseFormat | undefined {
	return FIELD_SCHEMAS[fieldName];
}

/**
 * Parse and flatten structured output response
 * Converts structured JSON back to plain text format
 *
 * @example
 * Input: { traits: ['curious', 'loyal'], summary: 'A kind person' }
 * Output: 'Curious, loyal. A kind person.'
 */
export function flattenStructuredOutput(
	fieldName: string,
	structured: Record<string, unknown>
): string {
	switch (fieldName) {
		case 'personality': {
			const traits = (structured.traits as string[] | undefined)?.join(', ') || '';
			const summary = (structured.summary as string | undefined) || '';
			return traits && summary ? `${traits}. ${summary}` : traits || summary;
		}

		case 'description': {
			const appearance = (structured.appearance as string | undefined) || '';
			const demeanor = (structured.demeanor as string | undefined) || '';
			return appearance && demeanor ? `${appearance}\n\n${demeanor}` : appearance || demeanor;
		}

		case 'scenario': {
			const setting = (structured.setting as string | undefined) || '';
			const situation = (structured.situation as string | undefined) || '';
			const context = (structured.context as string | undefined) || '';
			return [setting, situation, context].filter(Boolean).join('\n\n');
		}

		case 'tags':
			return (structured.tags as string[] | undefined)?.join(', ') || '';

		default:
			// For unknown fields, try to stringify
			return typeof structured === 'string' ? structured : JSON.stringify(structured);
	}
}
