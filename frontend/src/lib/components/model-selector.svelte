<script lang="ts">
	import { Button } from './ui/button';
	import {
		DropdownMenu,
		DropdownMenuContent,
		DropdownMenuItem,
		DropdownMenuTrigger
	} from './ui/dropdown-menu';
	import CheckCircleFillIcon from './icons/check-circle-fill.svelte';
	import ChevronDownIcon from './icons/chevron-down.svelte';
	import { cn } from '$lib/utils/shadcn';
	import { chatModels, DEFAULT_CHAT_MODEL } from '$lib/ai/models';
	import type { ClassValue } from 'svelte/elements';
	import type { ScribeChatSession } from '$lib/types';
	import { SelectedModel } from '$lib/hooks/selected-model.svelte';
	import { apiClient } from '$lib/api';

	let {
		class: c,
		chat
	}: {
		class: ClassValue;
		chat?: ScribeChatSession | null;
	} = $props();

	let open = $state(false);
	const selectedChatModel = SelectedModel.fromContext();

	// When we have a chat, load and manage its model override
	let chatModelOverride = $state<string>('');
	let isLoadingChatSettings = $state(false);

	// Load chat settings when chat changes
	$effect(() => {
		if (chat?.id) {
			loadChatSettings();
		} else {
			chatModelOverride = '';
		}
	});

	async function loadChatSettings() {
		if (!chat?.id) return;

		isLoadingChatSettings = true;
		try {
			const result = await apiClient.getChatSessionSettings(chat.id);
			if (result.isOk()) {
				chatModelOverride = result.value.model_name || '';
			} else {
				console.error('Failed to load chat settings:', result.error);
			}
		} catch (error) {
			console.error('Failed to load chat settings:', error);
		} finally {
			isLoadingChatSettings = false;
		}
	}

	async function updateChatModelOverride(modelId: string) {
		if (!chat?.id) return;

		try {
			const result = await apiClient.updateChatSessionSettings(chat.id, {
				model_name: modelId || null
			});

			if (result.isOk()) {
				chatModelOverride = modelId;
			} else {
				console.error('Failed to update chat model override:', result.error);
			}
		} catch (error) {
			console.error('Failed to update chat model override:', error);
		}
	}

	// Determine which model to display
	const currentEffectiveModel = $derived(() => {
		if (chat && chatModelOverride) {
			return chatModelOverride;
		}
		return selectedChatModel.value;
	});

	const selectedChatModelDetails = $derived(
		chatModels.find((model) => model.id === currentEffectiveModel())
	);

	function handleModelSelect(modelId: string) {
		open = false;
		if (chat) {
			// Update chat model override
			updateChatModelOverride(modelId);
		} else {
			// Update global model
			selectedChatModel.value = modelId;
		}
	}
</script>

<DropdownMenu {open} onOpenChange={(val) => (open = val)}>
	<DropdownMenuTrigger>
		{#snippet child({ props })}
			<Button
				{...props}
				variant="outline"
				class={cn(
					'w-fit data-[state=open]:bg-accent data-[state=open]:text-accent-foreground md:h-[34px] md:px-2',
					c
				)}
			>
				{selectedChatModelDetails?.name}
				<ChevronDownIcon />
			</Button>
		{/snippet}
	</DropdownMenuTrigger>
	<DropdownMenuContent align="start" class="min-w-[300px]">
		{#if chat}
			<!-- Option to use global default when in chat context -->
			<DropdownMenuItem
				onSelect={() => handleModelSelect('')}
				class="group/item flex flex-row items-center justify-between gap-4"
				data-active={!chatModelOverride}
			>
				<div class="flex flex-col items-start gap-1">
					<div>Use Global Default</div>
					<div class="text-xs text-muted-foreground">
						{chatModels.find((m) => m.id === selectedChatModel.value)?.name || 'Default Model'}
					</div>
				</div>

				<div
					class="text-foreground opacity-0 group-data-[active=true]/item:opacity-100 dark:text-foreground"
				>
					<CheckCircleFillIcon />
				</div>
			</DropdownMenuItem>
		{/if}
		{#each chatModels as chatModel (chatModel.id)}
			<DropdownMenuItem
				onSelect={() => handleModelSelect(chatModel.id)}
				class="group/item flex flex-row items-center justify-between gap-4"
				data-active={chat
					? chatModelOverride === chatModel.id
					: chatModel.id === selectedChatModel.value}
			>
				<div class="flex flex-col items-start gap-1">
					<div>{chatModel.name}</div>
					<div class="text-xs text-muted-foreground">
						{chatModel.description}
					</div>
				</div>

				<div
					class="text-foreground opacity-0 group-data-[active=true]/item:opacity-100 dark:text-foreground"
				>
					<CheckCircleFillIcon />
				</div>
			</DropdownMenuItem>
		{/each}
	</DropdownMenuContent>
</DropdownMenu>
