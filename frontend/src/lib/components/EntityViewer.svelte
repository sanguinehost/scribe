<script lang="ts">
	import { onMount } from 'svelte';
	import { apiClient } from '$lib/api';
	import { Card, CardContent, CardHeader, CardTitle } from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { Users, ChevronDown, ChevronRight, Clock, AlertCircle } from 'lucide-svelte';
	import type { EntityStateSnapshot } from '$lib/types';
	import { toast } from 'svelte-sonner';

	export let chronicleId: string;
	
	let entities: EntityStateSnapshot[] = [];
	let loading = true;
	let error: string | null = null;
	let expandedEntities = new Set<string>();
	let ecsEnhanced = false;
	let warnings: string[] = [];
	
	onMount(async () => {
		await loadEntities();
	});
	
	async function loadEntities() {
		loading = true;
		error = null;
		try {
			console.log('Loading entities for chronicle:', chronicleId);
			const result = await apiClient.getChronicleEntities(chronicleId, {
				include_current_state: true,
				include_relationships: false,
				limit: 50
			});
			
			console.log('API result:', result);
			
			if (result.isOk()) {
				entities = result.value.entities;
				ecsEnhanced = result.value.metadata.ecs_enhanced;
				warnings = result.value.metadata.warnings;
				
				console.log('Loaded entities:', entities);
				console.log('ECS Enhanced:', ecsEnhanced);
				console.log('Warnings:', warnings);
				
				if (warnings.length > 0) {
					console.warn('ECS Entity warnings:', warnings);
				}
			} else {
				error = result.error.message;
				console.error('API error:', result.error);
				toast.error('Failed to load entities', {
					description: result.error.message
				});
			}
		} catch (e) {
			error = 'Failed to load entities';
			console.error('Exception loading entities:', e);
			toast.error('Failed to load entities', {
				description: 'An unexpected error occurred'
			});
		} finally {
			loading = false;
		}
	}
	
	function toggleEntity(entityId: string) {
		if (expandedEntities.has(entityId)) {
			expandedEntities.delete(entityId);
		} else {
			expandedEntities.add(entityId);
		}
		expandedEntities = new Set(expandedEntities);
	}
	
	function getEntityDisplayName(entity: EntityStateSnapshot): string {
		// First try the standard "Name" component (capital N) that our backend creates
		if (entity.components.Name) {
			const nameComponent = entity.components.Name;
			// Handle different possible structures of the Name component
			if (typeof nameComponent === 'string') {
				return nameComponent;
			}
			if (nameComponent.name) {
				return nameComponent.name;
			}
			if (nameComponent.display_name) {
				return nameComponent.display_name;
			}
			if (nameComponent.value) {
				return nameComponent.value;
			}
		}
		
		// Try other common component names for backwards compatibility
		if (entity.components.character_name) {
			return entity.components.character_name.value || entity.components.character_name;
		}
		if (entity.components.name) {
			return entity.components.name.value || entity.components.name;
		}
		if (entity.components.location_name) {
			return entity.components.location_name.value || entity.components.location_name;
		}
		if (entity.components.item_name) {
			return entity.components.item_name.value || entity.components.item_name;
		}
		
		// Fallback to entity ID
		return entity.entity_id.substring(0, 8) + '...';
	}
	
	function getEntityType(entity: EntityStateSnapshot): string {
		// Determine entity type based on components
		if (entity.components.character_name || entity.components.personality || entity.components.dialogue) {
			return 'Character';
		}
		if (entity.components.location_name || entity.components.location || entity.components.spatial_containment) {
			return 'Location';
		}
		if (entity.components.item_name || entity.components.inventory || entity.components.equipment) {
			return 'Item';
		}
		if (entity.components.organization || entity.components.faction) {
			return 'Organization';
		}
		if (entity.components.concept || entity.components.abstract) {
			return 'Concept';
		}
		
		// Fallback to archetype or generic
		return entity.archetype_signature || 'Entity';
	}
	
	function getEntityTypeColor(entityType: string): string {
		switch (entityType.toLowerCase()) {
			case 'character':
				return 'bg-blue-100 text-blue-800 border-blue-200';
			case 'location':
				return 'bg-green-100 text-green-800 border-green-200';
			case 'item':
				return 'bg-purple-100 text-purple-800 border-purple-200';
			case 'organization':
				return 'bg-yellow-100 text-yellow-800 border-yellow-200';
			case 'concept':
				return 'bg-gray-100 text-gray-800 border-gray-200';
			default:
				return 'bg-slate-100 text-slate-800 border-slate-200';
		}
	}
	
	function formatComponentValue(value: any): string {
		if (typeof value === 'string') {
			return value;
		}
		if (typeof value === 'number') {
			return value.toString();
		}
		if (typeof value === 'boolean') {
			return value ? 'Yes' : 'No';
		}
		if (Array.isArray(value)) {
			return value.length > 0 ? value.join(', ') : 'Empty';
		}
		if (typeof value === 'object' && value !== null) {
			// Try to extract meaningful info from objects
			if (value.value !== undefined) {
				return formatComponentValue(value.value);
			}
			if (value.current !== undefined) {
				return formatComponentValue(value.current);
			}
			if (value.name !== undefined) {
				return formatComponentValue(value.name);
			}
			return JSON.stringify(value);
		}
		return String(value);
	}
	
	function shouldShowRawData(value: any): boolean {
		return typeof value === 'object' && value !== null && !Array.isArray(value);
	}
	
	function formatTimestamp(timestamp: string): string {
		const date = new Date(timestamp);
		const now = new Date();
		const diffMs = now.getTime() - date.getTime();
		const diffMins = Math.floor(diffMs / 60000);
		const diffHours = Math.floor(diffMins / 60);
		const diffDays = Math.floor(diffHours / 24);
		
		if (diffMins < 1) return 'Just now';
		if (diffMins < 60) return `${diffMins}m ago`;
		if (diffHours < 24) return `${diffHours}h ago`;
		if (diffDays < 7) return `${diffDays}d ago`;
		
		return date.toLocaleDateString();
	}
</script>

<div class="space-y-4">
	<!-- Header with ECS status -->
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-2">
			<h3 class="text-lg font-semibold">Chronicle Entities</h3>
			{#if !loading}
				<Badge variant="outline" class="gap-1">
					<Users class="h-3 w-3" />
					{entities.length}
				</Badge>
			{/if}
		</div>
		<div class="flex items-center gap-2">
			{#if !loading}
				{#if ecsEnhanced}
					<Badge variant="secondary" class="gap-1 text-xs">
						<div class="h-2 w-2 bg-green-500 rounded-full"></div>
						ECS Enhanced
					</Badge>
				{:else}
					<Badge variant="outline" class="gap-1 text-xs">
						<div class="h-2 w-2 bg-yellow-500 rounded-full"></div>
						Basic Mode
					</Badge>
				{/if}
			{/if}
			<Button
				variant="ghost"
				size="sm"
				onclick={loadEntities}
				disabled={loading}
				class="gap-1"
			>
				<svg class="h-4 w-4" class:animate-spin={loading} viewBox="0 0 24 24">
					<path fill="currentColor" d="M12 4V2A10 10 0 0 0 2 12h2a8 8 0 0 1 8-8Z"/>
				</svg>
				Refresh
			</Button>
		</div>
	</div>

	<!-- Warnings -->
	{#if warnings.length > 0}
		<div class="rounded-md border border-yellow-200 bg-yellow-50 p-3">
			<div class="flex items-start gap-2">
				<AlertCircle class="h-4 w-4 text-yellow-600 mt-0.5" />
				<div>
					<p class="text-sm font-medium text-yellow-800">System Warnings</p>
					<ul class="mt-1 text-sm text-yellow-700">
						{#each warnings as warning}
							<li>• {warning}</li>
						{/each}
					</ul>
				</div>
			</div>
		</div>
	{/if}

	<!-- Loading state -->
	{#if loading}
		<div class="space-y-3">
			{#each Array(3) as _}
				<Card>
					<CardHeader>
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<Skeleton class="h-4 w-4" />
								<Skeleton class="h-6 w-32" />
								<Skeleton class="h-5 w-16" />
							</div>
							<Skeleton class="h-4 w-20" />
						</div>
					</CardHeader>
				</Card>
			{/each}
		</div>
	{:else if error}
		<!-- Error state -->
		<Card>
			<CardContent class="py-8 text-center">
				<div class="text-destructive">
					<AlertCircle class="mx-auto h-12 w-12 mb-4" />
					<h3 class="mb-2 text-lg font-semibold">Failed to load entities</h3>
					<p class="text-sm mb-4">{error}</p>
					<Button variant="outline" onclick={loadEntities} class="gap-2">
						<svg class="h-4 w-4" viewBox="0 0 24 24">
							<path fill="currentColor" d="M12 4V2A10 10 0 0 0 2 12h2a8 8 0 0 1 8-8Z"/>
						</svg>
						Try Again
					</Button>
				</div>
			</CardContent>
		</Card>
	{:else if entities.length === 0}
		<!-- Empty state -->
		<Card>
			<CardContent class="py-12 text-center">
				<Users class="mx-auto h-12 w-12 text-muted-foreground mb-4" />
				<h3 class="text-lg font-semibold mb-2">No entities found</h3>
				<p class="text-sm text-muted-foreground mb-4">
					Entities will appear here as they are extracted from chronicle events.
				</p>
				{#if !ecsEnhanced}
					<p class="text-xs text-muted-foreground">
						ECS system may not be fully enabled for enhanced entity tracking.
					</p>
				{/if}
			</CardContent>
		</Card>
	{:else}
		<!-- Entity list -->
		<div class="space-y-3">
			{#each entities as entity (entity.entity_id)}
				{@const entityType = getEntityType(entity)}
				{@const displayName = getEntityDisplayName(entity)}
				{@const isExpanded = expandedEntities.has(entity.entity_id)}
				
				<Card>
					<CardHeader class="pb-3">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<button
									class="flex items-center gap-2 hover:text-primary transition-colors"
									onclick={() => toggleEntity(entity.entity_id)}
								>
									{#if isExpanded}
										<ChevronDown class="h-4 w-4" />
									{:else}
										<ChevronRight class="h-4 w-4" />
									{/if}
									<CardTitle class="text-lg">{displayName}</CardTitle>
								</button>
								<Badge variant="outline" class={getEntityTypeColor(entityType)}>
									{entityType}
								</Badge>
							</div>
							<div class="flex items-center gap-2 text-sm text-muted-foreground">
								<span>{Object.keys(entity.components).length} components</span>
								<Clock class="h-3 w-3" />
								<span>{formatTimestamp(entity.snapshot_time)}</span>
							</div>
						</div>
					</CardHeader>
					
					{#if isExpanded}
						<CardContent>
							<div class="space-y-4">
								<!-- Entity ID -->
								<div class="grid grid-cols-4 gap-2 text-sm">
									<span class="font-medium text-muted-foreground">Entity ID:</span>
									<span class="col-span-3 font-mono text-xs break-all">{entity.entity_id}</span>
								</div>
								
								<!-- Archetype -->
								<div class="grid grid-cols-4 gap-2 text-sm">
									<span class="font-medium text-muted-foreground">Archetype:</span>
									<span class="col-span-3">{entity.archetype_signature}</span>
								</div>
								
								<!-- Components -->
								<div>
									<p class="text-sm font-medium mb-3">Components:</p>
									<div class="grid gap-3">
										{#each Object.entries(entity.components) as [componentType, componentData]}
											<div class="border rounded-lg p-3 bg-muted/30">
												<div class="flex items-center justify-between mb-2">
													<span class="font-medium text-sm">{componentType}</span>
													<Badge variant="secondary" class="text-xs">
														{typeof componentData}
													</Badge>
												</div>
												<div class="text-sm text-muted-foreground">
													{#if shouldShowRawData(componentData)}
														<details class="mt-1">
															<summary class="cursor-pointer text-xs hover:text-foreground">
																{formatComponentValue(componentData)}
															</summary>
															<pre class="mt-2 text-xs bg-muted p-2 rounded overflow-auto border">
{JSON.stringify(componentData, null, 2)}</pre>
														</details>
													{:else}
														{formatComponentValue(componentData)}
													{/if}
												</div>
											</div>
										{/each}
									</div>
								</div>
								
								<!-- Status Indicators -->
								{#if entity.status_indicators.length > 0}
									<div>
										<p class="text-sm font-medium mb-2">Status Indicators:</p>
										<div class="flex flex-wrap gap-1">
											{#each entity.status_indicators as indicator}
												<Badge variant="outline" class="text-xs">{indicator}</Badge>
											{/each}
										</div>
									</div>
								{/if}
							</div>
						</CardContent>
					{/if}
				</Card>
			{/each}
		</div>
	{/if}
</div>