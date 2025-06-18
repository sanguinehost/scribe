// frontend/src/lib/strategies/chat.ts
// Strategy pattern for handling different chat modes

import type { ChatMode, ScribeChatSession, CharacterDataForClient } from '../types';

/**
 * Interface for chat mode strategies
 * Each chat mode implements this interface to provide mode-specific behavior
 */
export interface ChatModeStrategy {
	/**
	 * Get the display name for this chat mode
	 */
	getDisplayName(): string;

	/**
	 * Get a description of what this chat mode does
	 */
	getDescription(): string;

	/**
	 * Determine if the chat interface should be shown
	 * @param session - Current chat session
	 * @param character - Current character (may be null for non-character modes)
	 */
	shouldShowChatInterface(session: ScribeChatSession | null, character: CharacterDataForClient | null): boolean;

	/**
	 * Get the title for a new chat session
	 * @param character - Character data (may be null for non-character modes)
	 */
	generateChatTitle(character: CharacterDataForClient | null): string;

	/**
	 * Get the placeholder text for the message input
	 * @param character - Current character (may be null for non-character modes)
	 */
	getMessageInputPlaceholder(character: CharacterDataForClient | null): string;

	/**
	 * Determine if character selection is required for this mode
	 */
	requiresCharacter(): boolean;

	/**
	 * Get the suggested actions for this chat mode
	 * @param session - Current chat session
	 * @param character - Current character (may be null for non-character modes)
	 */
	getSuggestedActions(session: ScribeChatSession, character: CharacterDataForClient | null): string[];

	/**
	 * Get mode-specific UI elements or customizations
	 */
	getModeSpecificUI(): {
		showCharacterInfo: boolean;
		showSystemPromptEditor: boolean;
		customHeaderText?: string;
		customStyling?: string;
	};

	/**
	 * Validate if this mode can work with the current context
	 * @param session - Current chat session
	 * @param character - Current character (may be null for non-character modes)
	 */
	canOperateWithContext(session: ScribeChatSession, character: CharacterDataForClient | null): boolean;
}

/**
 * Factory function to create the appropriate strategy for a chat mode
 */
export function createChatModeStrategy(mode: ChatMode): ChatModeStrategy {
	switch (mode) {
		case 'Character':
			return new CharacterModeStrategy();
		case 'ScribeAssistant':
			return new ScribeAssistantModeStrategy();
		case 'Rpg':
			return new RpgModeStrategy();
		default:
			// Fallback to Character mode for unknown modes
			console.warn(`Unknown chat mode: ${mode}, falling back to Character mode`);
			return new CharacterModeStrategy();
	}
}

/**
 * Character mode strategy - Traditional character roleplay
 */
export class CharacterModeStrategy implements ChatModeStrategy {
	getDisplayName(): string {
		return 'Character Chat';
	}

	getDescription(): string {
		return 'Chat with AI characters in roleplay scenarios';
	}

	shouldShowChatInterface(session: ScribeChatSession | null, character: CharacterDataForClient | null): boolean {
		// Character mode requires both a session and a character
		return session !== null && character !== null;
	}

	generateChatTitle(character: CharacterDataForClient | null): string {
		if (character) {
			return `Chat with ${character.name}`;
		}
		return 'Character Chat';
	}

	getMessageInputPlaceholder(character: CharacterDataForClient | null): string {
		if (character) {
			return `Message ${character.name}...`;
		}
		return 'Type your message...';
	}

	requiresCharacter(): boolean {
		return true;
	}

	getSuggestedActions(session: ScribeChatSession, character: CharacterDataForClient | null): string[] {
		const actions = ['Continue the conversation'];
		
		if (character?.scenario) {
			actions.push('Ask about the scenario');
		}
		
		if (character?.personality) {
			actions.push('Learn more about their personality');
		}

		actions.push('Start a new topic');
		return actions;
	}

	getModeSpecificUI() {
		return {
			showCharacterInfo: true,
			showSystemPromptEditor: true,
			customHeaderText: undefined,
			customStyling: undefined
		};
	}

	canOperateWithContext(session: ScribeChatSession, character: CharacterDataForClient | null): boolean {
		return session.chat_mode === 'Character' && character !== null && session.character_id === character.id;
	}
}

/**
 * Scribe Assistant mode strategy - Content creation and writing assistance
 */
export class ScribeAssistantModeStrategy implements ChatModeStrategy {
	getDisplayName(): string {
		return 'Scribe Assistant';
	}

	getDescription(): string {
		return 'AI assistant for character creation, worldbuilding, and writing';
	}

	shouldShowChatInterface(session: ScribeChatSession | null, character: CharacterDataForClient | null): boolean {
		// Scribe Assistant mode only requires a session, no character needed
		return session !== null && session.chat_mode === 'ScribeAssistant';
	}

	generateChatTitle(character: CharacterDataForClient | null): string {
		return 'Scribe Assistant Session';
	}

	getMessageInputPlaceholder(character: CharacterDataForClient | null): string {
		return 'Ask me to help with character creation, worldbuilding, or writing...';
	}

	requiresCharacter(): boolean {
		return false;
	}

	getSuggestedActions(session: ScribeChatSession, character: CharacterDataForClient | null): string[] {
		return [
			'Help me create a new character from scratch',
			'Generate a character description based on a concept',
			'Create a scenario or setting for roleplay',
			'Enhance existing character details with more depth',
			'Generate dialogue examples and speech patterns',
			'Create a detailed backstory and history',
			'Suggest character relationships and connections',
			'Design a lorebook entry for this world',
			'Generate character tags and categorization',
			'Create alternate greetings for variety'
		];
	}

	getModeSpecificUI() {
		return {
			showCharacterInfo: false,
			showSystemPromptEditor: false,
			customHeaderText: '✍️ Writing & Creation Assistant',
			customStyling: 'assistant-mode'
		};
	}

	canOperateWithContext(session: ScribeChatSession, character: CharacterDataForClient | null): boolean {
		return session.chat_mode === 'ScribeAssistant';
	}
}

/**
 * RPG mode strategy - Tabletop RPG game master assistance
 */
export class RpgModeStrategy implements ChatModeStrategy {
	getDisplayName(): string {
		return 'RPG Mode';
	}

	getDescription(): string {
		return 'AI Game Master for tabletop RPG sessions and worldbuilding';
	}

	shouldShowChatInterface(session: ScribeChatSession | null, character: CharacterDataForClient | null): boolean {
		// RPG mode only requires a session, no character needed
		return session !== null && session.chat_mode === 'Rpg';
	}

	generateChatTitle(character: CharacterDataForClient | null): string {
		return 'RPG Session';
	}

	getMessageInputPlaceholder(character: CharacterDataForClient | null): string {
		return 'Describe your action or ask the GM a question...';
	}

	requiresCharacter(): boolean {
		return false;
	}

	getSuggestedActions(session: ScribeChatSession, character: CharacterDataForClient | null): string[] {
		return [
			'Start a new adventure',
			'Generate an NPC',
			'Create a dungeon or location',
			'Roll for initiative',
			'Ask about the current situation',
			'Generate a random encounter',
			'Create quest hooks'
		];
	}

	getModeSpecificUI() {
		return {
			showCharacterInfo: false,
			showSystemPromptEditor: true,
			customHeaderText: '🎲 Game Master',
			customStyling: 'rpg-mode'
		};
	}

	canOperateWithContext(session: ScribeChatSession, character: CharacterDataForClient | null): boolean {
		return session.chat_mode === 'Rpg';
	}
}