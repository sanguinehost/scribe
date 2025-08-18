<script lang="ts">
	import { apiClient } from '$lib/api';
	import { SelectedChronicleStore } from '$lib/stores/selected-chronicle.svelte';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Textarea } from '$lib/components/ui/textarea';
	import { Label } from '$lib/components/ui/label';
	import {
		Card,
		CardContent,
		CardDescription,
		CardHeader,
		CardTitle
	} from '$lib/components/ui/card';
	import { ScrollText, ArrowLeft, Save } from 'lucide-svelte';
	import { toast } from 'svelte-sonner';
	import type { CreateChronicleRequest } from '$lib/types';

	const selectedChronicleStore = SelectedChronicleStore.fromContext();

	let name = $state('');
	let description = $state('');
	let isCreating = $state(false);

	function handleGoBack() {
		selectedChronicleStore.showList();
	}

	async function handleCreate() {
		if (!name.trim()) {
			toast.error('Chronicle name is required');
			return;
		}

		isCreating = true;
		try {
			const data: CreateChronicleRequest = {
				name: name.trim(),
				description: description.trim() || undefined
			};

			const result = await apiClient.createChronicle(data);
			if (result.isOk()) {
				toast.success('Chronicle created successfully');
				// Refresh the chronicles store
				await chronicleStore.loadChronicles();
				// Navigate to the new chronicle
				selectedChronicleStore.selectChronicle(result.value.id);
			} else {
				toast.error('Failed to create chronicle', {
					description: result.error.message
				});
			}
		} finally {
			isCreating = false;
		}
	}

	function handleKeyDown(event: KeyboardEvent) {
		if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
			event.preventDefault();
			handleCreate();
		}
	}
</script>

<div class="mx-auto max-w-2xl px-4">
	<div class="mb-8">
		<Button
			variant="ghost"
			onclick={handleGoBack}
			class="mb-4 gap-2 text-muted-foreground hover:text-foreground"
		>
			<ArrowLeft class="h-4 w-4" />
			Back to Chronicles
		</Button>

		<div class="flex items-center gap-3">
			<ScrollText class="h-8 w-8 text-muted-foreground" />
			<div>
				<h1 class="text-3xl font-bold">Create New Chronicle</h1>
				<p class="mt-1 text-muted-foreground">
					Start a new story chronicle to track events and memories
				</p>
			</div>
		</div>
	</div>

	<Card>
		<CardHeader>
			<CardTitle>Chronicle Details</CardTitle>
			<CardDescription>Enter the basic information for your new chronicle</CardDescription>
		</CardHeader>
		<CardContent class="space-y-6">
			<div class="space-y-2">
				<Label for="chronicle-name">Name *</Label>
				<Input
					id="chronicle-name"
					bind:value={name}
					placeholder="Enter chronicle name..."
					onkeydown={handleKeyDown}
					disabled={isCreating}
					class="text-base"
				/>
				<p class="text-xs text-muted-foreground">
					A descriptive name for your chronicle (e.g., "The Dragon's Quest", "Cyberpunk 2077
					Campaign")
				</p>
			</div>

			<div class="space-y-2">
				<Label for="chronicle-description">Description</Label>
				<Textarea
					id="chronicle-description"
					bind:value={description}
					placeholder="Enter a brief description of your chronicle..."
					rows={4}
					onkeydown={handleKeyDown}
					disabled={isCreating}
					class="text-base"
				/>
				<p class="text-xs text-muted-foreground">
					Optional description to help you remember what this chronicle is about
				</p>
			</div>

			<div class="flex gap-3 pt-4">
				<Button onclick={handleCreate} disabled={isCreating || !name.trim()} class="gap-2">
					{#if isCreating}
						Creating...
					{:else}
						<Save class="h-4 w-4" />
						Create Chronicle
					{/if}
				</Button>
				<Button variant="outline" onclick={handleGoBack} disabled={isCreating}>Cancel</Button>
			</div>

			<div class="rounded-md border border-muted bg-muted/20 p-4">
				<h4 class="font-medium">What happens next?</h4>
				<ul class="mt-2 space-y-1 text-sm text-muted-foreground">
					<li>• Your chronicle will be created and ready to use</li>
					<li>• You can link chat sessions to this chronicle</li>
					<li>• Events will be automatically extracted from conversations</li>
					<li>• You can manually add important events and memories</li>
				</ul>
			</div>
		</CardContent>
	</Card>
</div>
