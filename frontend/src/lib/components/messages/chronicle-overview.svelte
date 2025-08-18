<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { apiClient } from '$lib/api';
	import { SelectedChronicleStore } from '$lib/stores/selected-chronicle.svelte';
	import { chronicleStore } from '$lib/stores/chronicle.svelte';
	import type {
		PlayerChronicle,
		ChronicleEvent,
		CreateEventRequest,
		UpdateChronicleRequest,
		EventFilter,
		EventSource
	} from '$lib/types';
	import { toast } from 'svelte-sonner';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Textarea } from '$lib/components/ui/textarea';
	import {
		Card,
		CardContent,
		CardDescription,
		CardFooter,
		CardHeader,
		CardTitle
	} from '$lib/components/ui/card';
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader,
		DialogTitle
	} from '$lib/components/ui/dialog';
	import {
		AlertDialog,
		AlertDialogAction,
		AlertDialogCancel,
		AlertDialogContent,
		AlertDialogDescription,
		AlertDialogFooter,
		AlertDialogHeader,
		AlertDialogTitle
	} from '$lib/components/ui/alert-dialog';
	import { Label } from '$lib/components/ui/label';
	import { Badge } from '$lib/components/ui/badge';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import {
		ScrollText,
		Plus,
		Calendar,
		MessageSquare,
		FileText,
		Trash2,
		Edit,
		ArrowLeft,
		Clock,
		User,
		Bot,
		Gamepad2,
		Settings
	} from 'lucide-svelte';

	let {
		chronicleId
	}: {
		chronicleId: string;
	} = $props();

	let chronicle = $state<PlayerChronicle | null>(null);
	let events = $state<ChronicleEvent[]>([]);
	let isLoadingChronicle = $state(true);
	let isLoadingEvents = $state(true);

	// Edit chronicle state
	let isEditingChronicle = $state(false);
	let editName = $state('');
	let editDescription = $state('');
	let isSavingChronicle = $state(false);

	// Create event state
	let createEventDialogOpen = $state(false);
	let eventType = $state('NARRATIVE.EVENT');
	let eventSummary = $state('');
	let eventSource = $state<EventSource>('USER_ADDED');
	let eventKeywords = $state('');
	let eventTimestamp = $state('');
	let isCreatingEvent = $state(false);

	// Delete confirmation state
	let deleteEventDialogOpen = $state(false);
	let eventToDelete = $state<ChronicleEvent | null>(null);
	let isDeletingEvent = $state(false);

	// Delete chronicle state
	let deleteChronicleDialogOpen = $state(false);
	let isDeletingChronicle = $state(false);

	// Store context
	const selectedChronicleStore = SelectedChronicleStore.fromContext();

	// Filter state
	let filterEventType = $state<string>('');
	let filterSource = $state<string>('');

	onMount(async () => {
		await loadChronicle();
		await loadEvents();
	});

	// Listen for chronicle event updates
	onMount(() => {
		const handleEventsUpdated = async (event: CustomEvent) => {
			const { chronicleId: eventChronicleId } = event.detail;
			if (eventChronicleId === chronicleId) {
				console.log('[Chronicle Overview] Events updated, refreshing');
				await loadEvents();
			}
		};

		window.addEventListener(
			'chronicle-events-updated',
			handleEventsUpdated as unknown as EventListener
		);

		return () => {
			window.removeEventListener(
				'chronicle-events-updated',
				handleEventsUpdated as unknown as EventListener
			);
		};
	});

	async function loadChronicle() {
		isLoadingChronicle = true;
		try {
			const result = await apiClient.getChronicle(chronicleId);
			if (result.isOk()) {
				chronicle = result.value;
			} else {
				toast.error('Failed to load chronicle', {
					description: result.error.message
				});
			}
		} finally {
			isLoadingChronicle = false;
		}
	}

	async function loadEvents() {
		isLoadingEvents = true;
		try {
			const filter: EventFilter = {};
			if (filterEventType) filter.event_type = filterEventType;
			if (filterSource) filter.source = filterSource as EventSource;
			filter.order_by = 'created_at_desc';

			const result = await apiClient.getChronicleEvents(chronicleId, filter);
			if (result.isOk()) {
				events = result.value;
			} else {
				toast.error('Failed to load events', {
					description: result.error.message
				});
			}
		} finally {
			isLoadingEvents = false;
		}
	}

	function startEditingChronicle() {
		if (!chronicle) return;
		editName = chronicle.name;
		editDescription = chronicle.description || '';
		isEditingChronicle = true;
	}

	async function saveChronicleChanges() {
		if (!chronicle) return;

		isSavingChronicle = true;
		try {
			const data: UpdateChronicleRequest = {
				name: editName.trim() || undefined,
				description: editDescription.trim() || undefined
			};

			const result = await apiClient.updateChronicle(chronicleId, data);
			if (result.isOk()) {
				chronicle = result.value;
				isEditingChronicle = false;
				toast.success('Chronicle updated successfully');
			} else {
				toast.error('Failed to update chronicle', {
					description: result.error.message
				});
			}
		} finally {
			isSavingChronicle = false;
		}
	}

	async function createEvent() {
		if (!eventType.trim() || !eventSummary.trim()) {
			toast.error('Event type and summary are required');
			return;
		}

		isCreatingEvent = true;
		try {
			// Parse keywords from comma-separated string
			const keywords = eventKeywords
				.split(',')
				.map((k) => k.trim())
				.filter((k) => k.length > 0);

			// Parse timestamp if provided
			let timestamp = undefined;
			if (eventTimestamp.trim()) {
				const date = new Date(eventTimestamp);
				if (!isNaN(date.getTime())) {
					timestamp = date.toISOString();
				}
			}

			const data: CreateEventRequest = {
				event_type: eventType.trim(),
				summary: eventSummary.trim(),
				source: eventSource,
				keywords: keywords.length > 0 ? keywords : undefined,
				timestamp_iso8601: timestamp
			};

			const result = await apiClient.createChronicleEvent(chronicleId, data);
			if (result.isOk()) {
				toast.success('Event created successfully');
				createEventDialogOpen = false;
				eventType = 'NARRATIVE.EVENT';
				eventSummary = '';
				eventSource = 'USER_ADDED';
				eventKeywords = '';
				eventTimestamp = '';
				await loadEvents();
			} else {
				toast.error('Failed to create event', {
					description: result.error.message
				});
			}
		} finally {
			isCreatingEvent = false;
		}
	}

	function handleDeleteEventClick(event: ChronicleEvent) {
		eventToDelete = event;
		deleteEventDialogOpen = true;
	}

	async function confirmDeleteEvent() {
		if (!eventToDelete) return;

		isDeletingEvent = true;
		try {
			const result = await apiClient.deleteChronicleEvent(chronicleId, eventToDelete.id);
			if (result.isOk()) {
				toast.success('Event deleted successfully');
				await loadEvents();
			} else {
				toast.error('Failed to delete event', {
					description: result.error.message
				});
			}
		} finally {
			isDeletingEvent = false;
			deleteEventDialogOpen = false;
			eventToDelete = null;
		}
	}

	function handleDeleteChronicleClick() {
		deleteChronicleDialogOpen = true;
	}

	async function confirmDeleteChronicle() {
		if (!chronicle) return;

		isDeletingChronicle = true;
		try {
			const result = await apiClient.deleteChronicle(chronicleId);
			if (result.isOk()) {
				toast.success('Chronicle deleted successfully');
				// Refresh the chronicle store to update all components
				await chronicleStore.refresh();

				// Notify other components that a chronicle was deleted
				window.dispatchEvent(
					new CustomEvent('chronicle-deleted', {
						detail: { chronicleId: chronicleId }
					})
				);

				// Navigate back to chronicles list by showing the list view
				selectedChronicleStore.showList();
				goto('/');
			} else {
				toast.error('Failed to delete chronicle', {
					description: result.error.message
				});
			}
		} finally {
			isDeletingChronicle = false;
			deleteChronicleDialogOpen = false;
		}
	}

	function formatDate(dateString: string): string {
		const date = new Date(dateString);
		return date.toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
	}

	function getSourceLabel(source: EventSource): string {
		switch (source) {
			case 'USER_ADDED':
				return 'User Added';
			case 'AI_EXTRACTED':
				return 'AI Extracted';
			case 'GAME_API':
				return 'Game API';
			case 'SYSTEM':
				return 'System';
			default:
				return source;
		}
	}

	// Get unique event types for filtering
	const uniqueEventTypes = $derived.by(() => {
		const types = new Set(events.map((e) => e.event_type));
		return Array.from(types).sort();
	});
</script>

<div class="mx-auto flex h-[90vh] max-w-7xl flex-col gap-6 px-4">
	<div class="flex min-h-0 flex-1 flex-col gap-6">
		{#if isLoadingChronicle}
			<Card class="border-0 shadow-sm">
				<CardHeader class="py-4">
					<div class="flex items-center gap-4">
						<div class="flex-1 space-y-2">
							<Skeleton class="h-7 w-1/2" />
							<Skeleton class="h-4 w-3/4" />
						</div>
					</div>
				</CardHeader>
			</Card>
		{:else if chronicle}
			<!-- Chronicle header -->
			<Card class="border-0 shadow-sm">
				<CardHeader class="py-4">
					{#if isEditingChronicle}
						<div class="space-y-4">
							<div>
								<Label for="edit-name">Name</Label>
								<Input
									id="edit-name"
									bind:value={editName}
									placeholder="Chronicle name"
									class="mt-1"
								/>
							</div>
							<div>
								<Label for="edit-description">Description</Label>
								<Textarea
									id="edit-description"
									bind:value={editDescription}
									placeholder="Chronicle description (optional)"
									rows={3}
									class="mt-1"
								/>
							</div>
							<div class="flex gap-2">
								<Button onclick={saveChronicleChanges} disabled={isSavingChronicle}>
									{isSavingChronicle ? 'Saving...' : 'Save Changes'}
								</Button>
								<Button variant="outline" onclick={() => (isEditingChronicle = false)}>
									Cancel
								</Button>
							</div>
						</div>
					{:else}
						<div class="flex items-start justify-between">
							<div class="min-w-0 flex-1">
								<div class="flex items-center gap-3">
									<ScrollText class="h-8 w-8 text-muted-foreground" />
									<div>
										<h1 class="text-2xl font-bold">{chronicle.name}</h1>
										{#if chronicle.description}
											<p class="mt-1 text-muted-foreground">{chronicle.description}</p>
										{/if}
									</div>
								</div>
								<div class="mt-4 flex items-center gap-4 text-sm text-muted-foreground">
									<div class="flex items-center gap-1">
										<Calendar class="h-4 w-4" />
										Created {formatDate(chronicle.created_at)}
									</div>
									<div class="flex items-center gap-1">
										<Clock class="h-4 w-4" />
										Updated {formatDate(chronicle.updated_at)}
									</div>
								</div>
							</div>
							<div class="flex gap-1">
								<Button
									variant="ghost"
									size="icon"
									onclick={startEditingChronicle}
									title="Edit chronicle"
								>
									<Edit class="h-4 w-4" />
								</Button>
								<Button
									variant="ghost"
									size="icon"
									onclick={handleDeleteChronicleClick}
									title="Delete chronicle"
								>
									<Trash2 class="h-4 w-4 text-destructive" />
								</Button>
							</div>
						</div>
					{/if}
				</CardHeader>
			</Card>

			<!-- Events section -->
			<div class="min-h-0 flex-1 space-y-6">
				<div class="flex items-center justify-between">
					<h2 class="text-xl font-semibold">Chronicle Events</h2>
					<div class="flex gap-2">
						{#if uniqueEventTypes.length > 0}
							<select
								class="w-40 rounded-md border border-input bg-background px-3 py-2 text-sm"
								bind:value={filterEventType}
								onchange={() => loadEvents()}
							>
								<option value="">All types</option>
								{#each uniqueEventTypes as type}
									<option value={type}>{type}</option>
								{/each}
							</select>
						{/if}
						<select
							class="w-40 rounded-md border border-input bg-background px-3 py-2 text-sm"
							bind:value={filterSource}
							onchange={() => loadEvents()}
						>
							<option value="">All sources</option>
							<option value="USER_ADDED">User Added</option>
							<option value="AI_EXTRACTED">AI Extracted</option>
							<option value="GAME_API">Game API</option>
							<option value="SYSTEM">System</option>
						</select>
						<Button onclick={() => (createEventDialogOpen = true)} class="gap-2">
							<Plus class="h-4 w-4" />
							Add Event
						</Button>
					</div>
				</div>

				<div class="min-h-0 flex-1 overflow-y-auto">
					{#if isLoadingEvents}
						<div class="space-y-4">
							{#each Array(3) as _}
								<Card>
									<CardHeader>
										<Skeleton class="h-6 w-1/4" />
										<Skeleton class="h-4 w-3/4" />
									</CardHeader>
								</Card>
							{/each}
						</div>
					{:else if events.length === 0}
						<Card>
							<CardContent class="py-12 text-center">
								<FileText class="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
								<h3 class="mb-2 text-lg font-semibold">No events yet</h3>
								<p class="mb-6 text-sm text-muted-foreground">
									Add events to track important moments in your chronicle
								</p>
								<Button onclick={() => (createEventDialogOpen = true)} class="gap-2">
									<Plus class="h-4 w-4" />
									Add First Event
								</Button>
							</CardContent>
						</Card>
					{:else}
						<div class="space-y-4">
							{#each events as event (event.id)}
								<Card>
									<CardHeader>
										<div class="flex items-start justify-between">
											<div class="min-w-0 flex-1">
												<div class="flex items-center gap-2">
													<Badge variant="outline" class="gap-1">
														{#if event.source === 'USER_ADDED'}
															<User class="h-3 w-3" />
														{:else if event.source === 'AI_EXTRACTED'}
															<Bot class="h-3 w-3" />
														{:else if event.source === 'GAME_API'}
															<Gamepad2 class="h-3 w-3" />
														{:else if event.source === 'SYSTEM'}
															<Settings class="h-3 w-3" />
														{:else}
															<FileText class="h-3 w-3" />
														{/if}
														{getSourceLabel(event.source)}
													</Badge>
													<Badge>{event.event_type}</Badge>
												</div>
												<CardDescription class="mt-2">{event.summary}</CardDescription>
												{#if event.keywords && event.keywords.length > 0}
													<div class="mt-2 flex flex-wrap gap-1">
														{#each event.keywords as keyword}
															<Badge variant="secondary" class="text-xs">{keyword}</Badge>
														{/each}
													</div>
												{/if}
												{#if event.timestamp_iso8601}
													<div class="mt-2 text-xs text-muted-foreground">
														<Clock class="mr-1 inline h-3 w-3" />
														Story time: {formatDate(event.timestamp_iso8601)}
													</div>
												{/if}
											</div>
											<Button
												variant="ghost"
												size="icon"
												onclick={() => handleDeleteEventClick(event)}
												title="Delete event"
											>
												<Trash2 class="h-4 w-4 text-destructive" />
											</Button>
										</div>
									</CardHeader>
									<CardFooter class="pt-0">
										<div class="text-xs text-muted-foreground">
											{formatDate(event.created_at)}
										</div>
									</CardFooter>
								</Card>
							{/each}
						</div>
					{/if}
				</div>
			</div>
		{/if}
	</div>
</div>

<!-- Create Event Dialog -->
<Dialog bind:open={createEventDialogOpen}>
	<DialogContent class="sm:max-w-lg">
		<DialogHeader>
			<DialogTitle>Add Chronicle Event</DialogTitle>
			<DialogDescription>Record an important moment or detail in your chronicle</DialogDescription>
		</DialogHeader>

		<div class="space-y-4 py-4">
			<div class="space-y-2">
				<Label for="event-summary">Summary</Label>
				<Textarea
					id="event-summary"
					bind:value={eventSummary}
					placeholder="Describe what happened in your story..."
					rows={3}
				/>
			</div>

			<div class="space-y-2">
				<Label for="event-keywords">
					Keywords <span class="text-muted-foreground">(comma-separated, optional)</span>
				</Label>
				<Input
					id="event-keywords"
					bind:value={eventKeywords}
					placeholder="e.g., dragon, battle, victory, castle"
				/>
				<p class="text-xs text-muted-foreground">
					Keywords help you find this event later when searching your chronicle
				</p>
			</div>

			<div class="space-y-2">
				<Label for="event-timestamp">
					Story Date/Time <span class="text-muted-foreground">(optional)</span>
				</Label>
				<Input id="event-timestamp" type="datetime-local" bind:value={eventTimestamp} />
				<p class="text-xs text-muted-foreground">
					When this event happened in your story world's timeline
				</p>
			</div>

			<div class="space-y-2">
				<Label for="event-source">Source</Label>
				<select
					id="event-source"
					class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
					bind:value={eventSource}
				>
					<option value="USER_ADDED">User Added</option>
					<option value="AI_EXTRACTED">AI Extracted</option>
					<option value="GAME_API">Game API</option>
					<option value="SYSTEM">System</option>
				</select>
			</div>

			<div class="space-y-2">
				<Label for="event-type">
					Event Type <span class="text-muted-foreground">(advanced)</span>
				</Label>
				<Input id="event-type" bind:value={eventType} placeholder="NARRATIVE.EVENT" />
			</div>
		</div>

		<DialogFooter>
			<Button
				variant="outline"
				onclick={() => (createEventDialogOpen = false)}
				disabled={isCreatingEvent}
			>
				Cancel
			</Button>
			<Button onclick={createEvent} disabled={isCreatingEvent || !eventSummary.trim()}>
				{isCreatingEvent ? 'Creating...' : 'Create Event'}
			</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>

<!-- Delete Event Confirmation Dialog -->
<AlertDialog bind:open={deleteEventDialogOpen}>
	<AlertDialogContent>
		<AlertDialogHeader>
			<AlertDialogTitle>Delete Event</AlertDialogTitle>
			<AlertDialogDescription>
				Are you sure you want to delete this event? This action cannot be undone.
				{#if eventToDelete}
					<div class="mt-4 rounded-md bg-muted p-3">
						<div class="font-medium">{eventToDelete.event_type}</div>
						<div class="text-sm text-muted-foreground">{eventToDelete.summary}</div>
					</div>
				{/if}
			</AlertDialogDescription>
		</AlertDialogHeader>
		<AlertDialogFooter>
			<AlertDialogCancel disabled={isDeletingEvent}>Cancel</AlertDialogCancel>
			<AlertDialogAction
				onclick={confirmDeleteEvent}
				disabled={isDeletingEvent}
				class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
			>
				{isDeletingEvent ? 'Deleting...' : 'Delete'}
			</AlertDialogAction>
		</AlertDialogFooter>
	</AlertDialogContent>
</AlertDialog>

<!-- Delete Chronicle Confirmation Dialog -->
<AlertDialog bind:open={deleteChronicleDialogOpen}>
	<AlertDialogContent>
		<AlertDialogHeader>
			<AlertDialogTitle>Delete Chronicle</AlertDialogTitle>
			<AlertDialogDescription>
				Are you sure you want to delete this chronicle? This action cannot be undone and will
				permanently delete all events associated with this chronicle.
				{#if chronicle}
					<div class="mt-4 rounded-md bg-muted p-3">
						<div class="font-medium">{chronicle.name}</div>
						{#if chronicle.description}
							<div class="text-sm text-muted-foreground">{chronicle.description}</div>
						{/if}
					</div>
				{/if}
			</AlertDialogDescription>
		</AlertDialogHeader>
		<AlertDialogFooter>
			<AlertDialogCancel disabled={isDeletingChronicle}>Cancel</AlertDialogCancel>
			<AlertDialogAction
				onclick={confirmDeleteChronicle}
				disabled={isDeletingChronicle}
				class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
			>
				{isDeletingChronicle ? 'Deleting...' : 'Delete Chronicle'}
			</AlertDialogAction>
		</AlertDialogFooter>
	</AlertDialogContent>
</AlertDialog>
