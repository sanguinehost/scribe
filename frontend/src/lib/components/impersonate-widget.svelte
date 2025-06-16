<script lang="ts">
	import { Button } from './ui/button';
	import { toast } from 'svelte-sonner';
	import { User, Expand } from 'lucide-svelte';
	import { apiClient } from '$lib/api';

	type Props = {
		value: string;
		chatId?: string;
		onExpand: (expandedText: string) => void;
		onImpersonate: (response: string) => void;
		disabled?: boolean;
	};

	let { value, chatId, onExpand, onImpersonate, disabled = false }: Props = $props();

	let isExpanding = $state(false);
	let isImpersonating = $state(false);

	async function handleExpand() {
		if (!value.trim()) {
			toast.error('Please enter some text to expand');
			return;
		}

		if (!chatId) {
			toast.error('Chat session required for text expansion');
			return;
		}

		try {
			isExpanding = true;
			
			// Call the backend API to expand the text using the user's persona
			const result = await apiClient.expandText(chatId, value.trim());
			
			if (result.isOk()) {
				const expandedText = result.value.expanded_text;
				onExpand(expandedText);
				toast.success('Text expanded successfully');
			} else {
				console.error('Failed to expand text:', result.error);
				toast.error(result.error?.message || 'Failed to expand text');
			}
		} catch (error) {
			console.error('Error expanding text:', error);
			toast.error('An error occurred while expanding text');
		} finally {
			isExpanding = false;
		}
	}

	async function handleImpersonate() {
		if (!chatId) {
			toast.error('Chat session required for impersonation');
			return;
		}

		try {
			isImpersonating = true;
			
			// Call the backend API to generate a full user response based on chat context
			const result = await apiClient.impersonate(chatId);
			
			if (result.isOk()) {
				const response = result.value.generated_response;
				onImpersonate(response);
				toast.success('Generated persona response');
			} else {
				console.error('Failed to generate response:', result.error);
				toast.error(result.error?.message || 'Failed to generate response');
			}
		} catch (error) {
			console.error('Error generating response:', error);
			toast.error('An error occurred while generating response');
		} finally {
			isImpersonating = false;
		}
	}
</script>

<div class="flex items-center gap-1">
	<!-- Expand button - only show when there's text to expand -->
	{#if value.trim()}
		<Button
			variant="ghost"
			size="sm"
			class="h-7 w-7 p-1.5"
			onclick={handleExpand}
			disabled={disabled || isExpanding}
			title="Expand - Elaborate on your current text"
		>
			{#if isExpanding}
				<svg
					class="h-3.5 w-3.5 animate-spin"
					xmlns="http://www.w3.org/2000/svg"
					fill="none"
					viewBox="0 0 24 24"
				>
					<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
					<path
						class="opacity-75"
						fill="currentColor"
						d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
					></path>
				</svg>
			{:else}
				<Expand size={14} />
			{/if}
		</Button>
	{/if}

	<!-- Impersonate button - always available when chat exists -->
	{#if chatId}
		<Button
			variant="ghost"
			size="sm"
			class="h-7 w-7 p-1.5"
			onclick={handleImpersonate}
			disabled={disabled || isImpersonating}
			title="Impersonate - Generate a response as your persona"
		>
			{#if isImpersonating}
				<svg
					class="h-3.5 w-3.5 animate-spin"
					xmlns="http://www.w3.org/2000/svg"
					fill="none"
					viewBox="0 0 24 24"
				>
					<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
					<path
						class="opacity-75"
						fill="currentColor"
						d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
					></path>
				</svg>
			{:else}
				<User size={14} />
			{/if}
		</Button>
	{/if}
</div>