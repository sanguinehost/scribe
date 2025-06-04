<script lang="ts">
    import { createEventDispatcher } from 'svelte';
    import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '$lib/components/ui/dialog';
    import { Button } from '$lib/components/ui/button';
    import { Input } from '$lib/components/ui/input';
    import { Label } from '$lib/components/ui/label';
    import { Badge } from '$lib/components/ui/badge';
    import { Skeleton } from '$lib/components/ui/skeleton';
    import { toast } from 'svelte-sonner';
    import { apiClient } from '$lib/api';
    import type { Lorebook, ChatSessionLorebookAssociation } from '$lib/types';
    import type { ApiError } from '$lib/errors/api';

    let { 
        open = false,
        chatId,
        currentAssociations = []
    }: { 
        open: boolean;
        chatId: string | null;
        currentAssociations: ChatSessionLorebookAssociation[];
    } = $props();

    const dispatch = createEventDispatcher<{
        close: void;
        updated: { associations: ChatSessionLorebookAssociation[] };
    }>();

    let lorebooks: Lorebook[] = $state([]);
    let loading = $state(false);
    let searchQuery = $state('');
    let selectedLorebookIds = $state(new Set<string>());
    let originalAssociationIds = $state(new Set<string>());

    // Initialize selected lorebooks when associations change
    $effect(() => {
        const associatedIds = new Set(currentAssociations.map(a => a.lorebook_id));
        selectedLorebookIds = new Set(associatedIds);
        originalAssociationIds = new Set(associatedIds);
    });

    // Load lorebooks when dialog opens
    $effect(() => {
        if (open && lorebooks.length === 0) {
            loadLorebooks();
        }
    });

    async function loadLorebooks() {
        loading = true;
        try {
            const result = await apiClient.getLorebooks();
            if (result.isOk()) {
                lorebooks = result.value;
            } else {
                toast.error('Failed to load lorebooks');
                console.error('Failed to load lorebooks:', result.error);
            }
        } catch (error) {
            toast.error('An error occurred while loading lorebooks');
            console.error('Error loading lorebooks:', error);
        } finally {
            loading = false;
        }
    }

    // Filter lorebooks based on search query
    let filteredLorebooks = $derived(
        lorebooks.filter(lorebook =>
            lorebook.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            (lorebook.description?.toLowerCase().includes(searchQuery.toLowerCase()) ?? false)
        )
    );

    function toggleLorebook(lorebookId: string) {
        if (selectedLorebookIds.has(lorebookId)) {
            selectedLorebookIds.delete(lorebookId);
        } else {
            selectedLorebookIds.add(lorebookId);
        }
        // Trigger reactivity
        selectedLorebookIds = new Set(selectedLorebookIds);
    }

    async function saveChanges() {
        if (!chatId) {
            toast.error('No chat session selected');
            return;
        }

        loading = true;
        try {
            // Determine what needs to be added and removed
            const toAdd = [...selectedLorebookIds].filter(id => !originalAssociationIds.has(id));
            const toRemove = [...originalAssociationIds].filter(id => !selectedLorebookIds.has(id));

            // Process additions
            for (const lorebookId of toAdd) {
                const result = await apiClient.associateLorebookToChat(chatId, lorebookId);
                if (!result.isOk()) {
                    throw new Error(`Failed to associate lorebook: ${result.error.message}`);
                }
            }

            // Process removals
            for (const lorebookId of toRemove) {
                const result = await apiClient.disassociateLorebookFromChat(chatId, lorebookId);
                if (!result.isOk()) {
                    throw new Error(`Failed to disassociate lorebook: ${result.error.message}`);
                }
            }

            // Reload current associations
            const associationsResult = await apiClient.getChatLorebookAssociations(chatId);
            if (associationsResult.isOk()) {
                dispatch('updated', { associations: associationsResult.value });
                toast.success('Lorebook associations updated successfully');
            } else {
                throw new Error('Failed to reload associations');
            }

            handleClose();
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
            toast.error(`Failed to update associations: ${errorMessage}`);
            console.error('Error updating lorebook associations:', error);
        } finally {
            loading = false;
        }
    }

    function handleClose() {
        // Reset state
        searchQuery = '';
        dispatch('close');
    }

    let hasChanges = $derived(
        selectedLorebookIds.size !== originalAssociationIds.size ||
        [...selectedLorebookIds].some(id => !originalAssociationIds.has(id))
    );
</script>

<Dialog bind:open onOpenChange={handleClose}>
    <DialogContent class="sm:max-w-[600px] max-h-[80vh] flex flex-col">
        <DialogHeader>
            <DialogTitle>Manage Chat Lorebooks</DialogTitle>
            <DialogDescription>
                Select which lorebooks should be active for this chat. Associated lorebooks will provide context during conversations.
            </DialogDescription>
        </DialogHeader>

        <div class="flex-1 flex flex-col gap-4 min-h-0">
            <!-- Search -->
            <div class="grid gap-2">
                <Label for="lorebook-search">Search Lorebooks</Label>
                <Input 
                    id="lorebook-search" 
                    placeholder="Search by name or description..." 
                    bind:value={searchQuery}
                    disabled={loading}
                />
            </div>

            <!-- Selected count -->
            {#if selectedLorebookIds.size > 0}
                <div class="flex items-center gap-2">
                    <Badge variant="secondary">
                        {selectedLorebookIds.size} selected
                    </Badge>
                    {#if hasChanges}
                        <Badge variant="outline" class="text-orange-600 border-orange-600">
                            Changes pending
                        </Badge>
                    {/if}
                </div>
            {/if}

            <!-- Lorebook list -->
            <div class="flex-1 overflow-y-auto border rounded-md">
                {#if loading}
                    <div class="p-4 space-y-3">
                        {#each Array(3) as _}
                            <div class="flex items-center space-x-3">
                                <Skeleton class="h-4 w-4" />
                                <div class="space-y-2 flex-1">
                                    <Skeleton class="h-4 w-[250px]" />
                                    <Skeleton class="h-3 w-[400px]" />
                                </div>
                            </div>
                        {/each}
                    </div>
                {:else if filteredLorebooks.length === 0}
                    <div class="p-4 text-center text-muted-foreground">
                        {#if searchQuery}
                            No lorebooks found matching "{searchQuery}"
                        {:else if lorebooks.length === 0}
                            No lorebooks available. Create a lorebook first.
                        {:else}
                            No lorebooks found
                        {/if}
                    </div>
                {:else}
                    <div class="p-4 space-y-3">
                        {#each filteredLorebooks as lorebook (lorebook.id)}
                            <div class="flex items-start space-x-3 p-2 rounded-md hover:bg-muted/50 transition-colors">
                                <input
                                    type="checkbox"
                                    checked={selectedLorebookIds.has(lorebook.id)}
                                    onchange={() => toggleLorebook(lorebook.id)}
                                    disabled={loading}
                                    class="mt-1 h-4 w-4 text-primary border-gray-300 rounded focus:ring-primary focus:ring-2"
                                />
                                <div class="flex-1 min-w-0">
                                    <div class="font-medium truncate">{lorebook.name}</div>
                                    {#if lorebook.description}
                                        <div class="text-sm text-muted-foreground mt-1 line-clamp-2">
                                            {lorebook.description}
                                        </div>
                                    {/if}
                                    <div class="text-xs text-muted-foreground mt-1">
                                        Updated: {new Date(lorebook.updated_at).toLocaleDateString()}
                                    </div>
                                </div>
                            </div>
                        {/each}
                    </div>
                {/if}
            </div>
        </div>

        <DialogFooter>
            <Button variant="outline" onclick={handleClose} disabled={loading}>
                Cancel
            </Button>
            <Button onclick={saveChanges} disabled={loading || !hasChanges}>
                {#if loading}
                    Updating...
                {:else}
                    Save Changes
                {/if}
            </Button>
        </DialogFooter>
    </DialogContent>
</Dialog>

<style>
    .line-clamp-2 {
        display: -webkit-box;
        -webkit-line-clamp: 2;
        -webkit-box-orient: vertical;
        overflow: hidden;
    }
</style>