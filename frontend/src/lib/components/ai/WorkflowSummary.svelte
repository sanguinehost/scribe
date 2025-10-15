<script lang="ts">
	import type { ToolExecution } from '$lib/utils/agentic';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import { Check, X, FileText, Image, Search, Plus, Edit, Trash2, Box } from 'lucide-svelte';

	interface Props {
		toolExecutions: ToolExecution[];
		showTiming?: boolean;
	}

	let { toolExecutions, showTiming = true }: Props = $props();

	/**
	 * Format a tool execution into a human-readable summary
	 */
	function formatExecution(execution: ToolExecution): {
		icon: typeof Check;
		label: string;
		details: string;
	} {
		// Guard against null/undefined execution or result (can happen during dialog transitions)
		if (!execution || !execution.result) {
			return {
				icon: X,
				label: 'Unknown',
				details: 'No result available'
			};
		}

		const { toolName } = execution;
		const result = execution.result as Record<string, unknown>;

		// Lorebook tools
		if (toolName === 'analyze_lorebook_gaps') {
			const gaps = result.gaps as unknown[] | undefined;
			const gapCategories = result.gapCategories as string[] | undefined;
			const gapCount = gaps?.length ?? 0;
			const categories = gapCategories?.join(', ') ?? 'various areas';
			return {
				icon: Search,
				label: 'Analyzed Lorebook',
				details: `Found ${gapCount} gaps in ${categories}`
			};
		}

		if (toolName === 'create_lorebook_entry') {
			const entryName = result.entryName as string | undefined;
			const entry = result.entry as { keys?: string[] } | undefined;
			const name = entryName ?? entry?.keys?.[0] ?? 'New Entry';
			const keyCount = entry?.keys?.length ?? 0;
			return {
				icon: Plus,
				label: 'Created Entry',
				details: `"${name}" (${keyCount} keys)`
			};
		}

		if (toolName === 'batch_create_lorebook_entries') {
			const createdCount = result.createdCount as number | undefined;
			const createdNames = result.createdNames as string[] | undefined;
			const count = createdCount ?? 0;
			const names = createdNames ?? [];
			const namesList =
				count > 3 ? `${names.slice(0, 3).join(', ')} and ${count - 3} more` : names.join(', ');
			return {
				icon: Box,
				label: 'Batch Created Entries',
				details: `${count} ${count === 1 ? 'entry' : 'entries'}${namesList ? ': ' + namesList : ''}`
			};
		}

		if (toolName === 'update_lorebook_entry') {
			const entryName = (result.entryName as string | undefined) ?? 'Entry';
			return {
				icon: Edit,
				label: 'Updated Entry',
				details: `"${entryName}"`
			};
		}

		if (toolName === 'delete_lorebook_entry') {
			const entryName = (result.entryName as string | undefined) ?? 'Entry';
			return {
				icon: Trash2,
				label: 'Deleted Entry',
				details: `"${entryName}"`
			};
		}

		if (toolName === 'read_lorebook_entries') {
			const entries = result.entries as unknown[] | undefined;
			const count = entries?.length ?? 0;
			return {
				icon: FileText,
				label: 'Read Lorebook',
				details: `${count} entries loaded`
			};
		}

		// Image generation tools
		if (toolName === 'analyze_character_for_image') {
			const characterName = (result.character_name as string | undefined) ?? 'Character';
			return {
				icon: Search,
				label: 'Analyzed Character',
				details: `Extracted visual details for ${characterName}`
			};
		}

		if (toolName === 'compose_image_prompt') {
			const style = (result.style as string | undefined) ?? 'unknown';
			const assetType = (result.asset_type as string | undefined) ?? 'image';
			return {
				icon: FileText,
				label: 'Composed Prompt',
				details: `${style} style ${assetType}`
			};
		}

		if (toolName === 'generate_image') {
			const assetType = (result.asset_type as string | undefined) ?? 'image';
			const metadata = result.metadata as Record<string, unknown> | undefined;
			const tokensUsed = metadata?.tokens_used as number | undefined;
			const timeMs = execution.executionTimeMs ?? 0;
			const timeSec = Math.round(timeMs / 1000);
			return {
				icon: Image,
				label: 'Generated Image',
				details: `${assetType} in ${timeSec}s${tokensUsed ? ` (${tokensUsed} tokens)` : ''}`
			};
		}

		// Generic fallback
		const message = (result.message as string | undefined) ?? '';
		const summary = (result.summary as string | undefined) ?? '';
		return {
			icon: Check,
			label: toolName.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase()),
			details: message || summary || 'Completed'
		};
	}
</script>

<div class="space-y-2">
	{#each toolExecutions as execution, i}
		{@const formatted = formatExecution(execution)}
		{@const IconComponent = formatted.icon}
		{@const timeSeconds = ((execution.executionTimeMs ?? 0) / 1000).toFixed(1)}

		<div
			class="flex items-start gap-3 rounded-lg border bg-card p-3 text-sm transition-colors hover:bg-muted/50"
		>
			<!-- Step number badge -->
			<Badge variant="secondary" class="shrink-0">
				{i + 1}
			</Badge>

			<!-- Status icon -->
			<div
				class="flex h-5 w-5 shrink-0 items-center justify-center rounded-full {execution.success
					? 'bg-green-100 text-green-600 dark:bg-green-900/20 dark:text-green-400'
					: 'bg-red-100 text-red-600 dark:bg-red-900/20 dark:text-red-400'}"
			>
				{#if execution.success}
					<Check class="h-3 w-3" />
				{:else}
					<X class="h-3 w-3" />
				{/if}
			</div>

			<!-- Tool icon -->
			<div class="flex h-5 w-5 shrink-0 items-center justify-center text-muted-foreground">
				<IconComponent class="h-4 w-4" />
			</div>

			<!-- Content -->
			<div class="min-w-0 flex-1">
				<div class="flex items-start justify-between gap-2">
					<div class="min-w-0 flex-1">
						<p class="break-words font-medium text-foreground">
							{formatted.label}
						</p>
						<p class="break-words text-muted-foreground">
							{formatted.details}
						</p>
					</div>

					<!-- Timing -->
					{#if showTiming}
						<span class="shrink-0 text-xs tabular-nums text-muted-foreground">
							{timeSeconds}s
						</span>
					{/if}
				</div>

				<!-- Error message -->
				{#if !execution.success && execution.error}
					<p class="mt-1 break-words text-xs text-destructive">
						Error: {execution.error}
					</p>
				{/if}
			</div>
		</div>
	{/each}
</div>
