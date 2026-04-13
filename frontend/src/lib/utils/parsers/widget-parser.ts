/**
 * Utility to parse structured widgets out of raw markdown/LLM output.
 */

export type ContentSegment =
	| { type: 'markdown'; content: string }
	| { type: 'widget'; widgetType: string; rawData: string };

/**
 * Normalizes common AI formatting mistakes, such as wrapping XML tags in markdown code blocks.
 *
 * It looks for things like:
 * ```xml
 * <stats>
 * ...
 * </stats>
 * ```
 * And unwraps them into just the raw XML tags.
 */
export function normalizeAiOutput(text: string): string {
	if (!text) return '';

	// Matches ```[language] \n <tag>...</tag> \n ```
	// We use [\s\S]*? for non-greedy multiline matching.
	// Bounded to avoid ReDoS by not using overlapping catastrophic sequences.
	const regex = /```\w*\s*(<\w+>[\s\S]*?<\/\w+>)\s*```/g;
	return text.replace(regex, '$1');
}

/**
 * Searches the text for recognizable tags (e.g. <stats>...</stats>) and segments the text
 * into an array of markdown and widget segments.
 *
 * @param text The raw message text
 * @param supportedTags Array of tag names to intersect (default: ['stats'])
 */
export function segmentMessageContent(
	text: string,
	supportedTags: string[] = ['stats']
): ContentSegment[] {
	if (!text) return [];

	// First normalize the output to strip code blocks wrapping tags
	const normalizedText = normalizeAiOutput(text);

	const segments: ContentSegment[] = [];
	let currentIndex = 0;

	// Build a regex to match any of the supported tags
	// Example: <stats>...</stats>
	const tagPattern = supportedTags.join('|');
	// Case-insensitive, dotall using [\s\S]
	const tagRegex = new RegExp(`<(${tagPattern})>([\\s\\S]*?)</\\1>`, 'gi');

	let match;
	while ((match = tagRegex.exec(normalizedText)) !== null) {
		const matchStart = match.index;
		const matchEnd = tagRegex.lastIndex;

		const tagName = match[1].toLowerCase();
		const innerContent = match[2].trim();

		// Add markdown segment before the tag
		if (matchStart > currentIndex) {
			segments.push({
				type: 'markdown',
				content: normalizedText.slice(currentIndex, matchStart)
			});
		}

		// Add the widget segment
		segments.push({
			type: 'widget',
			widgetType: tagName,
			rawData: innerContent
		});

		currentIndex = matchEnd;
	}

	// Add any remaining text as a markdown segment
	if (currentIndex < normalizedText.length) {
		segments.push({
			type: 'markdown',
			content: normalizedText.slice(currentIndex)
		});
	}

	return segments;
}
