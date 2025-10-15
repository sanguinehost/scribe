/**
 * Text Formatter Utility
 *
 * Formats character descriptions with support for:
 * - Newlines and paragraphs
 * - Code blocks (triple backticks for status bars)
 * - Basic markdown-like formatting
 * - XSS protection via DOMPurify
 */

import DOMPurify from 'dompurify';

/**
 * Format character description text for display
 * Supports newlines, code blocks, and basic markdown
 */
export function formatDescription(text: string): string {
	if (!text) return '';

	// 1. Extract code blocks FIRST (before any HTML escaping)
	// This preserves literal characters like < > inside code blocks
	const codeBlocks: string[] = [];
	// Use placeholder that won't conflict with markdown syntax (no * or _)
	const codeBlockPlaceholder = '⦃⦃⦃CODEBLOCK:';

	let formatted = text.replace(/```([\s\S]*?)```/g, (_match, content) => {
		const index = codeBlocks.length;
		codeBlocks.push(content.trim()); // Store original content with newlines
		return `${codeBlockPlaceholder}${index}⦄⦄⦄`;
	});

	// 2. Process text OUTSIDE code blocks
	// Escape HTML entities to prevent XSS
	formatted = escapeHtml(formatted);

	// 3. Format basic markdown-like syntax
	formatted = formatMarkdown(formatted);

	// 4. Convert newlines to <br> tags (only for text outside code blocks)
	formatted = formatted.replace(/\n/g, '<br>');

	// 5. Restore code blocks with proper formatting
	// Now escape HTML inside code blocks for safe rendering
	formatted = formatted.replace(/⦃⦃⦃CODEBLOCK:(\d+)⦄⦄⦄/g, (match, index) => {
		const content = codeBlocks[parseInt(index)];
		if (!content) return match; // Safety check

		const isStatusBlock = isLikelyStatusBlock(content);
		const className = isStatusBlock ? 'code-block status-block' : 'code-block';

		// Escape HTML entities in code block content
		// This preserves < > as &lt; &gt; which displays correctly
		// Newlines are preserved as \n and rendered by CSS white-space: pre-wrap
		const escapedContent = escapeHtml(content);

		return `<pre class="${className}"><code>${escapedContent}</code></pre>`;
	});

	// 6. Sanitize HTML to prevent XSS attacks
	// Allow specific tags we generated
	const sanitized = DOMPurify.sanitize(formatted, {
		ALLOWED_TAGS: ['br', 'strong', 'em', 'code', 'pre', 'ul', 'ol', 'li', 'p', 'div'],
		ALLOWED_ATTR: ['class'],
		KEEP_CONTENT: true
	});

	return sanitized;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
	const htmlEscapeMap: Record<string, string> = {
		'&': '&amp;',
		'<': '&lt;',
		'>': '&gt;',
		'"': '&quot;',
		"'": '&#039;'
	};

	return text.replace(/[&<>"']/g, (char) => htmlEscapeMap[char] || char);
}

/**
 * Detect if code block content looks like a status block
 * Common patterns: HP:, Location:, Stats, Level, etc.
 */
function isLikelyStatusBlock(content: string): boolean {
	const statusPatterns = [
		/HP:|Health:|HP :/i,
		/Location:|Loc:|Position:/i,
		/Level:|LVL:|Lvl:/i,
		/Stats?:|Statistics:/i,
		/Status:|State:/i,
		/Inventory:|Items?:/i,
		/Mana:|MP:|Magic:/i,
		/Objective:|Goal:|Quest:/i
	];

	return statusPatterns.some((pattern) => pattern.test(content));
}

/**
 * Format basic markdown syntax
 * Supports: **bold**, *italic*, lists
 */
function formatMarkdown(text: string): string {
	let formatted = text;

	// Bold: **text** or __text__
	formatted = formatted.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
	formatted = formatted.replace(/__(.+?)__/g, '<strong>$1</strong>');

	// Italic: *text* or _text_ (but not inside URLs or filenames)
	formatted = formatted.replace(/(?<![\w/])\*(.+?)\*(?![\w/])/g, '<em>$1</em>');
	formatted = formatted.replace(/(?<![\w/])_(.+?)_(?![\w/])/g, '<em>$1</em>');

	// Unordered lists: lines starting with - or *
	formatted = formatted.replace(/^[-*] (.+)$/gm, '<li>$1</li>');

	// Wrap consecutive <li> elements in <ul>
	formatted = formatted.replace(/(<li>.*?<\/li>(?:<br>)?)+/g, (match) => {
		const items = match.replace(/<br>/g, '');
		return `<ul>${items}</ul>`;
	});

	return formatted;
}
