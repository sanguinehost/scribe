/**
 * TypeScript types for Character Card V3 specification
 * Based on: /docs/spec.md and Scribe's implementation
 */

// ============================================================================
// Character Card V3
// ============================================================================

export interface CharacterCardV3 {
	spec: 'chara_card_v3';
	spec_version: '3.0';
	data: CharacterCardDataV3;
}

export interface CharacterCardDataV3 {
	// V2 fields
	name: string;
	description: string;
	tags: string[];
	creator: string;
	character_version: string;
	mes_example: string;
	extensions: Record<string, unknown>;
	system_prompt: string;
	post_history_instructions: string;
	first_mes: string;
	alternate_greetings: string[];
	personality: string;
	scenario: string;

	// Changed from V2
	creator_notes: string;
	character_book?: Lorebook;

	// New in V3
	assets?: Asset[];
	nickname?: string;
	creator_notes_multilingual?: Record<string, string>;
	source?: string[];
	group_only_greetings: string[];
	creation_date?: number; // Unix timestamp in seconds
	modification_date?: number; // Unix timestamp in seconds
}

// ============================================================================
// Character Card V2 (for backwards compatibility)
// ============================================================================

export interface CharacterCardV2 {
	spec: 'chara_card_v2';
	spec_version: '2.0';
	data: CharacterCardDataV2;
}

export interface CharacterCardDataV2 {
	name: string;
	description: string;
	personality: string;
	scenario: string;
	first_mes: string;
	mes_example: string;

	// V2 additions
	creator_notes: string;
	system_prompt: string;
	post_history_instructions: string;
	alternate_greetings: string[];
	character_book?: LorebookV2;

	// May 8th additions
	tags: string[];
	creator: string;
	character_version: string;
	extensions: Record<string, unknown>;
}

// ============================================================================
// Character Card V1 (for backwards compatibility)
// ============================================================================

export interface CharacterCardV1 {
	name: string;
	description: string;
	personality: string;
	scenario: string;
	first_mes: string;
	mes_example: string;
}

// ============================================================================
// Asset Definition
// ============================================================================

export interface Asset {
	type: string; // 'icon' | 'background' | 'emotion' | 'user_icon' | custom
	uri: string; // URL, base64 data URL, 'embeded://', or 'ccdefault:'
	name: string;
	ext: string; // File extension without dot, e.g., 'png', 'jpg', 'webp'
}

// ============================================================================
// Lorebook (V3)
// ============================================================================

export interface Lorebook {
	name?: string;
	description?: string;
	scan_depth?: number;
	token_budget?: number;
	recursive_scanning?: boolean;
	extensions: Record<string, unknown>;
	entries: LorebookEntry[];
}

export interface LorebookEntry {
	keys: string[];
	content: string;
	extensions: Record<string, unknown>;
	enabled: boolean;
	insertion_order: number;
	case_sensitive?: boolean;

	// V3 additions
	use_regex: boolean;
	constant?: boolean;

	// Optional fields
	name?: string;
	priority?: number;
	id?: number | string;
	comment?: string;
	selective?: boolean;
	secondary_keys?: string[];
	position?: 'before_char' | 'after_char';
}

// ============================================================================
// Lorebook V2 (for backwards compatibility)
// ============================================================================

export interface LorebookV2 {
	name?: string;
	description?: string;
	scan_depth?: number;
	token_budget?: number;
	recursive_scanning?: boolean;
	extensions: Record<string, unknown>;
	entries: LorebookEntryV2[];
}

export interface LorebookEntryV2 {
	keys: string[];
	content: string;
	extensions: Record<string, unknown>;
	enabled: boolean;
	insertion_order: number;
	case_sensitive?: boolean;

	// Optional fields
	name?: string;
	priority?: number;
	id?: number | string;
	comment?: string;
	selective?: boolean;
	secondary_keys?: string[];
	constant?: boolean;
	position?: 'before_char' | 'after_char';
}

// ============================================================================
// Standalone Lorebook Export Format
// ============================================================================

export interface StandaloneLorebook {
	spec: 'lorebook_v3';
	data: Lorebook;
}

// ============================================================================
// Decorators (V3 Lorebook Enhancement)
// ============================================================================

export interface Decorator {
	name: string;
	value?: string;
	fallbacks: Decorator[];
}

export type DecoratorRole = 'assistant' | 'system' | 'user';

export type DecoratorPosition = 'after_desc' | 'before_desc' | 'personality' | 'scenario';

export type DecoratorUiPromptType = 'post_history_instructions' | 'system_prompt';

// ============================================================================
// Union Types
// ============================================================================

export type CharacterCard = CharacterCardV1 | CharacterCardV2 | CharacterCardV3;

export type CardVersion = 'v1' | 'v2' | 'v3';

export type FileFormat = 'png' | 'json' | 'charx';

// ============================================================================
// Helper Types
// ============================================================================

export interface ValidationError {
	path: string;
	message: string;
	code?: string;
}

export interface ImportResult {
	success: boolean;
	card?: CharacterCardV3;
	errors?: ValidationError[];
	warnings?: string[];
	version?: CardVersion;
	migrated?: boolean;
}

export interface ExportOptions {
	format: FileFormat;
	version?: 'v2' | 'v3'; // Export as V2 for compatibility or V3
	includeV2Backfill?: boolean; // For PNG: include V2 'chara' chunk
	prettify?: boolean; // For JSON: pretty print
}
