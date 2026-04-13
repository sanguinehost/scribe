import { SvelteMap } from 'svelte/reactivity';
/**
 * Keyboard Shortcuts System
 *
 * Global keyboard shortcut manager for Character Forge.
 * Handles registration, execution, and organization of keyboard shortcuts.
 */

export type ShortcutKey = string; // e.g., 's', 'k', '/', 'Escape'

export interface ShortcutModifiers {
	ctrl?: boolean;
	shift?: boolean;
	alt?: boolean;
	meta?: boolean; // Cmd on Mac
}

export interface ShortcutDefinition {
	/** Unique ID for the shortcut */
	id: string;
	/** The key to listen for */
	key: ShortcutKey;
	/** Modifier keys required */
	modifiers?: ShortcutModifiers;
	/** Human-readable description */
	description: string;
	/** Category for organization */
	category: 'Navigation' | 'File' | 'AI' | 'Edit' | 'Help';
	/** Handler function to execute */
	handler: () => void | Promise<void>;
	/** Whether the shortcut is enabled */
	enabled?: boolean;
}

/**
 * Keyboard Shortcuts Manager
 */
export class KeyboardShortcuts {
	private shortcuts = $state<Map<string, ShortcutDefinition>>(new SvelteMap());

	/**
	 * Register a new keyboard shortcut
	 */
	register(shortcut: ShortcutDefinition): void {
		this.shortcuts.set(shortcut.id, { ...shortcut, enabled: shortcut.enabled ?? true });
	}

	/**
	 * Unregister a keyboard shortcut
	 */
	unregister(id: string): void {
		this.shortcuts.delete(id);
	}

	/**
	 * Enable a shortcut
	 */
	enable(id: string): void {
		const shortcut = this.shortcuts.get(id);
		if (shortcut) {
			shortcut.enabled = true;
		}
	}

	/**
	 * Disable a shortcut
	 */
	disable(id: string): void {
		const shortcut = this.shortcuts.get(id);
		if (shortcut) {
			shortcut.enabled = false;
		}
	}

	/**
	 * Handle keyboard event and execute matching shortcut
	 */
	handleKeyDown(e: KeyboardEvent): boolean {
		// Don't trigger shortcuts when typing in inputs, textareas, or contenteditable
		const target = e.target as HTMLElement;
		if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
			// Allow Escape key even in inputs
			if (e.key !== 'Escape') {
				return false;
			}
		}

		for (const shortcut of this.shortcuts.values()) {
			if (!shortcut.enabled) continue;

			// Match key (case-insensitive for letters)
			const keyMatches =
				e.key.toLowerCase() === shortcut.key.toLowerCase() || e.key === shortcut.key;

			if (!keyMatches) continue;

			// Match modifiers
			const ctrlMatches = (shortcut.modifiers?.ctrl ?? false) === e.ctrlKey;
			const shiftMatches = (shortcut.modifiers?.shift ?? false) === e.shiftKey;
			const altMatches = (shortcut.modifiers?.alt ?? false) === e.altKey;
			const metaMatches = (shortcut.modifiers?.meta ?? false) === e.metaKey;

			if (ctrlMatches && shiftMatches && altMatches && metaMatches) {
				e.preventDefault();
				e.stopPropagation();
				shortcut.handler();
				return true;
			}
		}

		return false;
	}

	/**
	 * Get all shortcuts grouped by category
	 */
	getShortcutsByCategory(): Record<string, ShortcutDefinition[]> {
		const grouped: Record<string, ShortcutDefinition[]> = {
			Navigation: [],
			File: [],
			AI: [],
			Edit: [],
			Help: []
		};

		for (const shortcut of this.shortcuts.values()) {
			grouped[shortcut.category].push(shortcut);
		}

		return grouped;
	}

	/**
	 * Get all shortcuts as an array
	 */
	getShortcuts(): ShortcutDefinition[] {
		return Array.from(this.shortcuts.values());
	}

	/**
	 * Format shortcut for display
	 */
	formatShortcut(shortcut: ShortcutDefinition): string {
		const parts: string[] = [];

		if (shortcut.modifiers?.ctrl) parts.push('Ctrl');
		if (shortcut.modifiers?.shift) parts.push('Shift');
		if (shortcut.modifiers?.alt) parts.push('Alt');
		if (shortcut.modifiers?.meta) parts.push('Cmd');

		// Format key
		const keyName = shortcut.key === '/' ? '/' : shortcut.key.toUpperCase();
		parts.push(keyName);

		return parts.join('+');
	}
}

/**
 * Global shortcuts instance
 */
export const shortcuts = new KeyboardShortcuts();
