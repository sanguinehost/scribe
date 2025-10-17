/**
 * Research Workflows (Stub)
 *
 * Placeholder for future research workflow implementations.
 */

export function quickSearchWorkflow(
	_topic: string,
	_options?: Record<string, unknown>
): { goal: string; context: Record<string, unknown> } {
	return { goal: 'Quick search', context: {} };
}

export function deepResearchWorkflow(
	_url: string,
	_options?: Record<string, unknown>
): { goal: string; context: Record<string, unknown> } {
	return { goal: 'Deep research', context: {} };
}

export function topicResearchWorkflow(
	_topic: string,
	_sources?: string[],
	_options?: Record<string, unknown>
): { goal: string; context: Record<string, unknown> } {
	return { goal: 'Topic research', context: {} };
}

export function currentEventsWorkflow(
	_query: string,
	_options?: Record<string, unknown>
): { goal: string; context: Record<string, unknown> } {
	return { goal: 'Current events research', context: {} };
}

export function settingResearchWorkflow(
	_setting: string,
	_aspects?: string[],
	_options?: Record<string, unknown>
): { goal: string; context: Record<string, unknown> } {
	return { goal: 'Setting research', context: {} };
}
