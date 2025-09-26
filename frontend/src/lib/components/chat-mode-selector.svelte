<script lang="ts">
	import { goto as _goto } from '$app/navigation';
	import { apiClient as _apiClient } from '$lib/api';
	import type { ChatMode } from '$lib/types';
	import { createChatModeStrategy } from '$lib/strategies/chat';
	import { toast } from 'svelte-sonner';
	import { Button as ButtonComponent } from './ui/button';
	import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogHeader,
		DialogTitle,
		DialogFooter,
		DialogTrigger
	} from './ui/dialog';
	import { Input } from './ui/input';
	import { Label } from './ui/label';

	type Props = {
		open?: boolean;
		onOpenChange?: (open: boolean) => void;
	};

	let { open = $bindable(false), onOpenChange }: Props = $props();

	// Available chat modes
	const chatModes: { mode: ChatMode; icon: string }[] = [
		{ mode: 'Character', icon: '👤' },
		{ mode: 'ScribeAssistant', icon: '✍️' },
		{ mode: 'Rpg', icon: '🎲' }
	];

	let selectedMode = $state<ChatMode | null>(null);
	let customTitle = $state('');
	let isCreating = $state(false);

	// Reset state when dialog opens/closes
	$effect(() => {
		if (!open) {
			selectedMode = null;
			customTitle = '';
			isCreating = false;
		}
	});

	function selectMode(mode: ChatMode) {
		selectedMode = mode;
		const strategy = createChatModeStrategy(mode);
		customTitle = strategy.generateChatTitle(null);
	}

	async function createChat() {
		if (!selectedMode) return;

		isCreating = true;
		try {
			const createChatResult = await _apiClient.createChat({
				chat_mode: selectedMode,
				character_id: null, // No character for non-character modes
				title: customTitle || createChatModeStrategy(selectedMode).generateChatTitle(null)
			});

			if (createChatResult.isOk()) {
				const chat = createChatResult.value;
				toast.success('Chat created successfully');
				await _goto(`/chat/${chat.id}`, { invalidateAll: true });
				open = false;
				onOpenChange?.(false);
			} else {
				toast.error('Failed to create chat', {
					description: createChatResult.error.message
				});
			}
		} catch (_error) {
			console.error('Error creating chat:', _error);
			toast.error('An unexpected error occurred');
		} finally {
			isCreating = false;
		}
	}
</script>

<Dialog bind:open {onOpenChange}>
	<DialogTrigger>
		{#snippet child({ props })}
			<ButtonComponent {...props} variant="outline" class="w-full">
				<span class="mr-2">💬</span>
				Start New Chat
			</ButtonComponent>
		{/snippet}
	</DialogTrigger>
	<DialogContent class="sm:max-w-md">
		<DialogHeader>
			<DialogTitle>Choose Chat Mode</DialogTitle>
			<DialogDescription>Select the type of conversation you'd like to start</DialogDescription>
		</DialogHeader>

		{#if !selectedMode}
			<!-- Mode Selection -->
			<div class="grid gap-3">
				{#each chatModes as { mode, icon }}
					{@const strategy = createChatModeStrategy(mode)}
					<Card
						class="cursor-pointer border-2 border-transparent transition-colors hover:border-primary/20 hover:bg-muted/50"
						onclick={() => selectMode(mode)}
					>
						<CardHeader class="pb-2">
							<CardTitle class="flex items-center gap-2 text-base">
								<span class="text-lg">{icon}</span>
								{strategy.getDisplayName()}
							</CardTitle>
						</CardHeader>
						<CardContent class="pt-0">
							<p class="text-sm text-muted-foreground">
								{strategy.getDescription()}
							</p>
						</CardContent>
					</Card>
				{/each}
			</div>
		{:else}
			<!-- Chat Configuration -->
			{@const strategy = createChatModeStrategy(selectedMode)}
			<div class="space-y-4">
				<div class="flex items-center gap-2 rounded-lg bg-muted/50 p-3">
					<span class="text-lg">
						{chatModes.find((m) => m.mode === selectedMode)?.icon}
					</span>
					<div>
						<h4 class="font-medium">{strategy.getDisplayName()}</h4>
						<p class="text-sm text-muted-foreground">{strategy.getDescription()}</p>
					</div>
				</div>

				<div class="space-y-2">
					<Label for="chat-title">Chat Title</Label>
					<Input
						id="chat-title"
						bind:value={customTitle}
						placeholder={strategy.generateChatTitle(null)}
					/>
				</div>
			</div>

			<DialogFooter class="gap-2">
				<ButtonComponent variant="outline" onclick={() => (selectedMode = null)}
					>Back</ButtonComponent
				>
				<ButtonComponent
					onclick={createChat}
					disabled={isCreating || !customTitle.trim()}
					class="min-w-[120px]"
				>
					{#if isCreating}
						Creating...
					{:else}
						Create Chat
					{/if}
				</ButtonComponent>
			</DialogFooter>
		{/if}
	</DialogContent>
</Dialog>
