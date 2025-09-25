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
	import { chatModels, getAllAvailableModels, DEFAULT_CHAT_MODEL } from '$lib/ai/models';
	import type { ClassValue } from 'svelte/elements';
	import type { ScribeChatSession } from '$lib/types';
	import { SelectedModel } from '$lib/hooks/selected-model.svelte';
	import { LLMStore } from '$lib/stores/llm.svelte';
	import { ModelLifecycleStore } from '$lib/stores/modelLifecycle.svelte';
	import { apiClient } from '$lib/api';
	import { creditStore } from '$lib/stores/credits';
	import { PAYMENT_FEATURES } from '$lib/utils/features';
	import { Coins } from 'lucide-svelte';

	let {
		class: c,
		chat
	}: {
		class: ClassValue;
		chat?: ScribeChatSession | null;
	} = $props();

	let open = $state(false);
	const selectedChatModel = SelectedModel.fromContext();
	const llmStore = LLMStore.fromContext();
	const modelLifecycleStore = ModelLifecycleStore.fromContext();

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

		// Determine the provider based on the model
		const selectedModel = availableModels().find((model) => model.id === modelId);
		const provider = selectedModel?.isLocal ? 'local' : 'gemini';

		try {
			const result = await apiClient.updateChatSessionSettings(chat.id, {
				model_name: modelId || null,
				model_provider: modelId ? provider : null
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

	// Dynamic model list that includes local models when available
	const availableModels = $derived(() => {
		// Get all local models that are actually downloaded (available)
		const localModels = llmStore.models.filter((m) => m.isLocal && m.downloaded);
		return getAllAvailableModels(localModels);
	});

	const selectedChatModelDetails = $derived(
		availableModels().find((model) => model.id === currentEffectiveModel())
	);

	// Get credit cost for a model (feature-gated)
	function getModelCreditCost(modelId: string): number {
		if (!PAYMENT_FEATURES.credits) return 0;
		return creditStore.getModelCreditCost(modelId);
	}

	// Check if user has sufficient credits for a model (feature-gated)
	function hasSufficientCredits(modelId: string): boolean {
		if (!PAYMENT_FEATURES.credits) return true;
		const cost = getModelCreditCost(modelId);
		return creditStore.hasSufficientCredits(cost);
	}

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
						{availableModels().find((m) => m.id === selectedChatModel.value)?.name ||
							'Default Model'}
						{#if PAYMENT_FEATURES.credits}
							{@const defaultModel = availableModels().find(
								(m) => m.id === selectedChatModel.value
							)}
							{#if defaultModel && !defaultModel.isLocal}
								{@const creditCost = getModelCreditCost(defaultModel.id)}
								{@const hasCredits = hasSufficientCredits(defaultModel.id)}
								<div class="mt-1 flex items-center gap-1">
									<Coins class="h-3 w-3" />
									<span class={hasCredits ? '' : 'text-red-500'}>
										{creditCost} credits per message
									</span>
								</div>
							{:else if defaultModel && defaultModel.isLocal}
								<div class="mt-1 flex items-center gap-1 text-green-600 dark:text-green-400">
									<Coins class="h-3 w-3" />
									<span>Free (local model)</span>
								</div>
							{/if}
						{/if}
					</div>
				</div>

				<div
					class="text-foreground opacity-0 group-data-[active=true]/item:opacity-100 dark:text-foreground"
				>
					<CheckCircleFillIcon />
				</div>
			</DropdownMenuItem>
		{/if}
		{#each availableModels() as chatModel (chatModel.id)}
			{@const hasCredits = hasSufficientCredits(chatModel.id)}
			<DropdownMenuItem
				onSelect={() => (hasCredits ? handleModelSelect(chatModel.id) : undefined)}
				class="group/item flex flex-row items-center justify-between gap-4 {!hasCredits
					? 'cursor-not-allowed opacity-50'
					: ''}"
				data-active={chat
					? chatModelOverride === chatModel.id
					: chatModel.id === selectedChatModel.value}
				disabled={!hasCredits}
			>
				<div class="flex flex-col items-start gap-1">
					<div class="flex items-center gap-2">
						<span>{chatModel.name}</span>
						{#if chatModel.isLocal}
							{@const isActive = modelLifecycleStore.isModelActive(chatModel.id)}
							{@const isActivating =
								modelLifecycleStore.isActivating &&
								modelLifecycleStore.activeModel === chatModel.id}
							<div class="flex items-center gap-1">
								<span
									class="rounded-full px-2 py-0.5 text-xs {isActive
										? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
										: 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400'}"
								>
									Local
								</span>
								{#if isActivating}
									<div
										class="inline-block h-3 w-3 animate-spin rounded-full border border-green-500 border-t-transparent"
									></div>
								{:else if isActive}
									<div class="h-2 w-2 rounded-full bg-green-500" title="Model is active"></div>
								{:else}
									<div class="h-2 w-2 rounded-full bg-gray-400" title="Model is inactive"></div>
								{/if}
							</div>
						{/if}
					</div>
					<div class="text-xs text-muted-foreground">
						{chatModel.description}
						{#if PAYMENT_FEATURES.credits && !chatModel.isLocal}
							{@const creditCost = getModelCreditCost(chatModel.id)}
							{@const hasCredits = hasSufficientCredits(chatModel.id)}
							<div class="mt-1 flex items-center gap-1">
								<Coins class="h-3 w-3" />
								<span class={hasCredits ? '' : 'text-red-500'}>
									{creditCost} credits per message
								</span>
								{#if !hasCredits}
									<span class="text-xs text-red-500">(insufficient credits)</span>
								{/if}
							</div>
						{:else if PAYMENT_FEATURES.credits && chatModel.isLocal}
							<div class="mt-1 flex items-center gap-1 text-green-600 dark:text-green-400">
								<Coins class="h-3 w-3" />
								<span>Free (local model)</span>
							</div>
						{/if}
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
