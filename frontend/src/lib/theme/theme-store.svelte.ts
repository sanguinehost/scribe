import { browser } from '$app/environment';
import type { ThemeType } from './themes';

const STORAGE_KEY = 'scribe-theme-preset';

class ThemeStore {
	// Current theme preset. Default is sanguine.
	activeTheme = $state<ThemeType>('theme-sanguine');

	constructor() {
		if (browser) {
			// Load preferred theme on startup
			const stored = localStorage.getItem(STORAGE_KEY) as ThemeType | null;
			if (stored) {
				this.activeTheme = stored;
			}

			// Wait for next tick so body exists, then apply it
			setTimeout(() => this.applyTheme(this.activeTheme), 0);
		}
	}

	setTheme(theme: ThemeType) {
		this.activeTheme = theme;
		if (browser) {
			localStorage.setItem(STORAGE_KEY, theme);
			this.applyTheme(theme);
		}
	}

	private applyTheme(theme: ThemeType) {
		if (!browser) return;
		const html = document.documentElement;

		// Remove all previous theme- classes
		const classList = Array.from(html.classList);
		for (const cls of classList) {
			if (cls.startsWith('theme-')) {
				html.classList.remove(cls);
			}
		}

		// Add new theme class
		html.classList.add(theme);
	}
}

// Export singleton instance
export const themeStore = new ThemeStore();
