<script lang="ts">
	import { onMount } from 'svelte';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import { SelectedChronicleStore } from '$lib/stores/selected-chronicle.svelte';
	import { Button } from '$lib/components/ui/button';
	import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { ScrollText, Plus, Calendar, MessageSquare, ArrowLeft } from 'lucide-svelte';
	import { toast } from 'svelte-sonner';
	import { slideAndFade } from '$lib/utils/transitions';

	const selectedChronicleStore = SelectedChronicleStore.fromContext();

	// Only load chronicles if not already loaded
	onMount(() => {
		if (chronicleStore.chronicles.length === 0 && !chronicleStore.isLoading) {
			chronicleStore.loadChronicles();
		}
	});

	function handleSelectChronicle(chronicleId: string) {
		selectedChronicleStore.selectChronicle(chronicleId);
	}

	function handleCreateNew() {
		selectedChronicleStore.showCreating();
	}

	function formatDate(dateString: string): string {
		const date = new Date(dateString);
		return date.toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		});
	}
</script>

<div class="mx-auto max-w-4xl px-4">
	<div class="mb-8">
		<div class="flex items-center justify-between">
			<div>
				<h1 class="text-3xl font-bold">Chronicles</h1>
				<p class="mt-2 text-muted-foreground">
					Manage your story chronicles and their events
				</p>
			</div>
			<Button onclick={handleCreateNew} class="gap-2">
				<Plus class="h-4 w-4" />
				New Chronicle
			</Button>
		</div>
	</div>

	{#if chronicleStore.isLoading}
		<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
			{#each Array(6) as _}
				<Card>
					<CardHeader>
						<div class="animate-pulse">
							<div class="h-6 w-3/4 rounded bg-muted"></div>
							<div class="mt-2 h-4 w-full rounded bg-muted"></div>
						</div>
					</CardHeader>
					<CardContent>
						<div class="animate-pulse">
							<div class="h-4 w-1/2 rounded bg-muted"></div>
						</div>
					</CardContent>
				</Card>
			{/each}
		</div>
	{:else if chronicleStore.error}
		<Card>
			<CardContent class="py-12 text-center">
				<div class="text-destructive">
					<h3 class="mb-2 text-lg font-semibold">Failed to load chronicles</h3>
					<p class="text-sm">{chronicleStore.error}</p>
				</div>
				<Button
					variant="outline"
					onclick={() => chronicleStore.loadChronicles()}
					class="mt-4"
				>
					Try Again
				</Button>
			</CardContent>
		</Card>
	{:else if chronicleStore.chronicles.length === 0}
		<Card>
			<CardContent class="py-12 text-center">
				<ScrollText class="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
				<h3 class="mb-2 text-lg font-semibold">No chronicles yet</h3>
				<p class="mb-6 text-sm text-muted-foreground">
					Create your first chronicle to start tracking story events
				</p>
				<Button onclick={handleCreateNew} class="gap-2">
					<Plus class="h-4 w-4" />
					Create First Chronicle
				</Button>
			</CardContent>
		</Card>
	{:else}
		<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
			{#each chronicleStore.chronicles as chronicle (chronicle.id)}
				{#key chronicle.id}
					<div
						in:slideAndFade={{ y: 20, duration: 300 }}
						out:slideAndFade={{ y: -20, duration: 200 }}
					>
						<Card class="cursor-pointer transition-colors hover:bg-muted/50">
							<button
								class="w-full text-left"
								onclick={() => handleSelectChronicle(chronicle.id)}
							>
								<CardHeader>
									<div class="flex items-start gap-3">
										<ScrollText class="mt-1 h-5 w-5 text-muted-foreground" />
										<div class="min-w-0 flex-1">
											<CardTitle class="text-lg">{chronicle.name}</CardTitle>
											{#if chronicle.description}
												<CardDescription class="mt-1 line-clamp-2">
													{chronicle.description}
												</CardDescription>
											{/if}
										</div>
									</div>
								</CardHeader>
								<CardContent>
									<div class="flex items-center gap-4 text-sm text-muted-foreground">
										<div class="flex items-center gap-1">
											<MessageSquare class="h-4 w-4" />
											{chronicle.event_count} events
										</div>
										<div class="flex items-center gap-1">
											<ScrollText class="h-4 w-4" />
											{chronicle.chat_session_count} chats
										</div>
									</div>
									<div class="mt-3 flex items-center gap-1 text-xs text-muted-foreground">
										<Calendar class="h-3 w-3" />
										Created {formatDate(chronicle.created_at)}
									</div>
								</CardContent>
							</button>
						</Card>
					</div>
				{/key}
			{/each}
		</div>
	{/if}
</div>