<script lang="ts">
	import { Brain } from 'lucide-svelte';
	import { Button } from './ui/button';
	import {
		DropdownMenu,
		DropdownMenuContent,
		DropdownMenuItem,
		DropdownMenuTrigger,
		DropdownMenuLabel,
		DropdownMenuSeparator
	} from './ui/dropdown-menu';
	import { apiClient } from '$lib/api';
	import { cn } from '$lib/utils/shadcn';
	import type { ScribeChatSession } from '$lib/types';
	import { toast } from 'svelte-sonner';

	let {
		chat,
		disabled = false
	}: {
		chat: ScribeChatSession;
		disabled?: boolean;
	} = $props();

	let currentLevel = $state<string>('none');
	let isUpdating = $state(false);

	$effect(() => {
		if (chat.thinking_budget === -1) {
			currentLevel = 'dynamic';
		} else if (chat.thinking_level) {
			currentLevel = chat.thinking_level;
		} else {
			currentLevel = 'none';
		}
	});

	const levels = [
		{ id: 'none', name: 'None', description: 'Minimal or disabled reasoning' },
		{ id: 'dynamic', name: 'Dynamic', description: 'Auto-adjusts based on complexity' },
		{ id: 'low', name: 'Low', description: 'Brief reasoning budget' },
		{ id: 'medium', name: 'Medium', description: 'Balanced reasoning budget' },
		{ id: 'high', name: 'High', description: 'Maximum reasoning budget' }
	];

	async function updateLevel(levelId: string) {
		if (levelId === currentLevel || isUpdating) return;

		isUpdating = true;
		try {
			const modelId = chat.model_name?.toLowerCase() || '';
			const isPro = modelId.includes('pro');
			const isLite = modelId.includes('lite');

			let budget: number | null = null;
			let thinkingLevel: string | null = null;

			if (levelId === 'none') {
				// Pro cannot be disabled (min 128), Lite min is 512
				budget = isPro ? 128 : (isLite ? 512 : 0);
				thinkingLevel = null;
			} else if (levelId === 'dynamic') {
				budget = -1;
				thinkingLevel = null;
			} else {
				thinkingLevel = levelId; // "low", "medium", "high"
				if (levelId === 'low') {
					budget = isPro ? 4096 : 1024;
				} else if (levelId === 'medium') {
					budget = isPro ? 16384 : 8192;
				} else if (levelId === 'high') {
					budget = isPro ? 32768 : 24576;
				}
			}

			const result = await apiClient.updateChatSessionSettings(chat.id, {
				thinking_level: thinkingLevel,
				thinking_budget: budget
			});

			if (result.isOk()) {
				currentLevel = levelId;
				chat.thinking_level = thinkingLevel;
				chat.thinking_budget = budget;
				toast.success(`Thinking level set to ${levelId === 'dynamic' ? 'Dynamic' : levelId}`);
			} else {
				toast.error('Failed to update thinking settings');
				console.error(result.error);
			}
		} catch (error) {
			toast.error('Error updating thinking settings');
			console.error(error);
		} finally {
			isUpdating = false;
		}
	}

	const currentLevelLabel = $derived(levels.find((l) => l.id === currentLevel)?.name || 'None');
</script>

<DropdownMenu>
	<DropdownMenuTrigger>
		{#snippet child({ props })}
			<Button
				{...props}
				variant="outline"
				size="sm"
				class={cn(
					'gap-1.5 transition-colors',
					currentLevel !== 'none'
						? 'border-purple-200 bg-purple-50 text-purple-700 hover:bg-purple-100 hover:text-purple-800 dark:border-purple-800 dark:bg-purple-950/30 dark:text-purple-300 dark:hover:bg-purple-950/50'
						: '',
					disabled ? 'cursor-not-allowed opacity-50' : ''
				)}
				{disabled}
			>
				<Brain class={cn('h-4 w-4', currentLevel !== 'none' ? 'animate-pulse' : '')} />
				<span class="hidden sm:inline">{currentLevelLabel}</span>
			</Button>
		{/snippet}
	</DropdownMenuTrigger>
	<DropdownMenuContent align="end" class="w-56">
		<DropdownMenuLabel>AI Thinking Level</DropdownMenuLabel>
		<DropdownMenuSeparator />
		{#each levels as level, i (i)}
			<DropdownMenuItem
				onSelect={() => updateLevel(level.id)}
				class="flex flex-col items-start gap-0.5 py-2"
				data-active={currentLevel === level.id}
			>
				<span class="font-medium">{level.name}</span>
				<span class="text-xs text-muted-foreground">{level.description}</span>
			</DropdownMenuItem>
		{/each}
	</DropdownMenuContent>
</DropdownMenu>
