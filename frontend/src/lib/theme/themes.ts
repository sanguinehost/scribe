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
	colorHex: string; // Primary accent — used for UI previews
	secondaryHex: string; // Secondary accent for preview cards
	bgHex: string; // Dark mode background for preview cards
}

export const THEMES: ThemeDefinition[] = [
	{
		id: 'theme-sanguine',
		name: 'Sanguine',
		description: 'The classic Scribe crimson aesthetic.',
		colorHex: '#dc2626',
		secondaryHex: '#991b1b',
		bgHex: '#0c0a09'
	},
	{
		id: 'theme-obsidian',
		name: 'Obsidian',
		description: 'Sleek, minimalist monochrome graphite.',
		colorHex: '#3f3f46',
		secondaryHex: '#71717a',
		bgHex: '#09090b'
	},
	{
		id: 'theme-ocean',
		name: 'Ocean',
		description: 'Deep, calming blues and teal waters.',
		colorHex: '#0284c7',
		secondaryHex: '#0e7490',
		bgHex: '#0a1628'
	},
	{
		id: 'theme-forest',
		name: 'Forest',
		description: 'Natural earthy tones and moss greens.',
		colorHex: '#16a34a',
		secondaryHex: '#15803d',
		bgHex: '#0a1a0f'
	},
	{
		id: 'theme-amethyst',
		name: 'Amethyst',
		description: 'Vibrant neon violet and soft purple glows.',
		colorHex: '#9333ea',
		secondaryHex: '#7c3aed',
		bgHex: '#110e1a'
	},
	{
		id: 'theme-sunset',
		name: 'Sunset',
		description: 'Warm, harsh wasteland orange and rose.',
		colorHex: '#ea580c',
		secondaryHex: '#e11d48',
		bgHex: '#1a0f0a'
	}
];
