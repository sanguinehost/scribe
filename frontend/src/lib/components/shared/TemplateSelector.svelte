<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '../ui/button';
	import { Label } from '../ui/label';
	import { Skeleton } from '../ui/skeleton';
	import { Badge } from '../ui/badge';
	import ChevronDown from '../icons/chevron-down.svelte';
	import ChevronUp from '../icons/chevron-up.svelte';
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api';
	import type { PromptTemplateInfo } from '$lib/types';

	let {
		selectedTemplateId = $bindable('neutral_roleplay'),
		onTemplateChange,
		disabled = false,
		showCompatibility = true,
		currentChatMode = 'Character',
		hideLabel = false
	}: {
		selectedTemplateId?: string;
		onTemplateChange?: (templateId: string) => void;
		disabled?: boolean;
		showCompatibility?: boolean;
		currentChatMode?: string;
		hideLabel?: boolean;
	} = $props();

	let availableTemplates = $state<PromptTemplateInfo[]>([]);
	let isLoading = $state(true);
	let isDropdownOpen = $state(false);
	let selectedTemplate = $state<PromptTemplateInfo | null>(null);

	// Template descriptions for better UX
	const templateDescriptions = {
		neutral_roleplay: 'Balanced roleplay with narration and dialogue',
		chatbot_dialogue: 'Pure conversation, like texting with a friend',
		creative_writing: 'Rich narrative with detailed descriptions'
	};

	// Load available templates on mount
	onMount(async () => {
		await loadTemplates();
	});

	async function loadTemplates() {
		try {
			isLoading = true;
			const result = await apiClient.getPromptTemplates();

			if (result.isOk()) {
				availableTemplates = result.value.templates;
				// Find the currently selected template
				updateSelectedTemplate();
			} else {
				console.error('Failed to load prompt templates:', result.error);
				toast.error('Failed to load prompt templates');
			}
		} catch (error) {
			console.error('Error loading templates:', error);
			toast.error('Error loading templates');
		} finally {
			isLoading = false;
		}
	}

	function updateSelectedTemplate() {
		selectedTemplate = availableTemplates.find((t) => t.id === selectedTemplateId) || null;
	}

	// Update selected template when selectedTemplateId changes
	$effect(() => {
		if (selectedTemplateId && availableTemplates.length > 0) {
			updateSelectedTemplate();
		}
	});

	function handleTemplateSelect(template: PromptTemplateInfo) {
		// Check compatibility if needed
		if (showCompatibility && !isCompatible(template)) {
			toast.warning(
				`Template "${template.name}" may not be fully compatible with ${currentChatMode} mode`
			);
		}

		selectedTemplateId = template.id;
		selectedTemplate = template;
		isDropdownOpen = false;

		if (onTemplateChange) {
			onTemplateChange(template.id);
		}
	}

	function toggleDropdown() {
		if (!disabled) {
			isDropdownOpen = !isDropdownOpen;
		}
	}

	function isCompatible(template: PromptTemplateInfo): boolean {
		if (!showCompatibility) return true;

		// Check basic compatibility - for Character mode, prefer templates that require character
		if (currentChatMode === 'Character') {
			return template.compatibility.requires_character;
		}

		// For non-character modes, prefer templates that don't require character
		return !template.compatibility.requires_character;
	}

	function getCompatibilityBadge(template: PromptTemplateInfo): string | null {
		if (!showCompatibility) return null;

		const compatible = isCompatible(template);
		if (!compatible) return 'Limited';

		// Show recommended for perfect matches
		if (template.compatibility.requires_character === (currentChatMode === 'Character')) {
			return 'Recommended';
		}

		return null;
	}

	function closeDropdown() {
		isDropdownOpen = false;
	}

	// Close dropdown when clicking outside
	function handleClickOutside(event: Event) {
		const target = event.target as HTMLElement;
		const dropdown = document.querySelector('[data-template-selector]');
		if (dropdown && !dropdown.contains(target)) {
			closeDropdown();
		}
	}

	$effect(() => {
		if (isDropdownOpen) {
			document.addEventListener('click', handleClickOutside);
			return () => {
				document.removeEventListener('click', handleClickOutside);
			};
		}
	});
</script>

<div class="space-y-3">
	{#if !hideLabel}
		<Label class="text-sm font-medium">Prompt Style</Label>
	{/if}

	{#if isLoading}
		<div class="space-y-2">
			<Skeleton class="h-10 w-full" />
			<Skeleton class="h-4 w-3/4" />
		</div>
	{:else}
		<div class="relative" data-template-selector>
			<!-- Selected Template Display -->
			<Button
				variant="outline"
				class="h-auto w-full justify-between p-3 text-left overflow-hidden"
				{disabled}
				onclick={toggleDropdown}
			>
				<div class="flex flex-col items-start gap-1 min-w-0 flex-1 overflow-hidden">
					<span class="font-medium truncate w-full">
						{selectedTemplate?.name || 'Select Template'}
					</span>
					{#if selectedTemplate}
						<span class="text-xs text-muted-foreground truncate w-full">
							{selectedTemplate.description}
						</span>
					{/if}
				</div>
				{#if isDropdownOpen}
					<ChevronUp class="h-4 w-4 opacity-50 shrink-0" />
				{:else}
					<ChevronDown class="h-4 w-4 opacity-50 shrink-0" />
				{/if}
			</Button>

			<!-- Dropdown Menu -->
			{#if isDropdownOpen}
				<div
					class="absolute left-0 right-0 top-full z-50 mt-1 max-h-80 overflow-auto rounded-md border bg-popover p-1 shadow-md"
				>
					{#each availableTemplates as template (template.id)}
						<button
							type="button"
							class="flex w-full flex-col items-start gap-1 rounded-sm px-3 py-2 text-sm hover:bg-accent hover:text-accent-foreground focus:bg-accent focus:text-accent-foreground overflow-hidden {selectedTemplateId ===
							template.id
								? 'bg-accent text-accent-foreground'
								: ''}"
							onclick={() => handleTemplateSelect(template)}
						>
							<span class="font-medium truncate w-full text-left">{template.name}</span>
							<span class="text-left text-xs text-muted-foreground truncate w-full">
								{template.description}
							</span>
						</button>
					{/each}

					{#if availableTemplates.length === 0}
						<div class="px-3 py-2 text-sm text-muted-foreground">No templates available</div>
					{/if}
				</div>
			{/if}
		</div>
	{/if}
</div>
