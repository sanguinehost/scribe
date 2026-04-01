export type ThemeType =
	| 'theme-sanguine'
	| 'theme-obsidian'
	| 'theme-ocean'
	| 'theme-forest'
	| 'theme-amethyst'
	| 'theme-sunset';

export interface ThemeDefinition {
	id: ThemeType;
	name: string;
	description: string;
	colorHex: string; // Used for UI previews
}

export const THEMES: ThemeDefinition[] = [
	{
		id: 'theme-sanguine',
		name: 'Sanguine',
		description: 'The classic Scribe crimson aesthetic.',
		colorHex: '#dc2626'
	},
	{
		id: 'theme-obsidian',
		name: 'Obsidian',
		description: 'Sleek, minimalist monochrome graphite.',
		colorHex: '#3f3f46'
	},
	{
		id: 'theme-ocean',
		name: 'Ocean',
		description: 'Deep, calming blues and teal waters.',
		colorHex: '#0284c7'
	},
	{
		id: 'theme-forest',
		name: 'Forest',
		description: 'Natural earthy tones and moss greens.',
		colorHex: '#16a34a'
	},
	{
		id: 'theme-amethyst',
		name: 'Amethyst',
		description: 'Vibrant neon violet and soft purple glows.',
		colorHex: '#9333ea'
	},
	{
		id: 'theme-sunset',
		name: 'Sunset',
		description: 'Warm, harsh wasteland orange and rose.',
		colorHex: '#ea580c'
	}
];
