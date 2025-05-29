<script lang="ts">
	import { Button } from './ui/button';
	import {
		useSidebar,
		Sidebar,
		SidebarContent,
		SidebarFooter,
		SidebarHeader,
		SidebarMenu
	} from './ui/sidebar';
	import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';
	import { goto } from '$app/navigation';
	import PlusIcon from './icons/plus.svelte';
	import type { User } from '$lib/types'; // Assuming User type is defined elsewhere or remove if not used directly here
	import SidebarUserNav from './sidebar-user-nav.svelte';
	// import { SidebarHistory } from './sidebar-history'; // Remove SidebarHistory import
	import CharacterList from './CharacterList.svelte'; // Import the new CharacterList component
	import CharacterUploader from './CharacterUploader.svelte'; // Import the uploader component
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';

	let { user }: { user?: User } = $props();

	const context = useSidebar();
	const selectedCharacterStore = SelectedCharacterStore.fromContext();
	let isUploaderOpen = $state(false); // State for dialog visibility (Changed to $state)
	let characterListComp: CharacterList; // Reference to CharacterList component instance

	// Placeholder handlers for events from CharacterList
	async function handleSelectCharacter(event: CustomEvent<{ characterId: string }>) {
		const characterId = event.detail.characterId;
		console.log('Character selected:', characterId);
		
		// Set the selected character in the store
		selectedCharacterStore.select(characterId);
		
		// Navigate to home to show the character overview
		goto('/', { invalidateAll: true });
		context.setOpenMobile(false); // Close mobile sidebar on selection
	}

	function handleUploadCharacter() {
		console.log('Upload character triggered');
		isUploaderOpen = true; // Open the dialog
		context.setOpenMobile(false); // Close mobile sidebar
	}

	async function handleUploadSuccess() {
		console.log('Upload successful, refreshing list...');
		if (characterListComp) {
			await characterListComp.refresh(); // Call refresh on the CharacterList instance
		}
	}
</script>

<Sidebar class="group-data-[side=left]:border-r-0">
	<SidebarHeader>
		<SidebarMenu>
			<div class="flex h-10 flex-row items-center justify-between md:h-[34px]">
				<a
					href="/"
					onclick={() => {
						context.setOpenMobile(false);
						selectedCharacterStore.clear(); // Clear any selected character
					}}
					class="flex flex-row items-center gap-3"
				>
					<span class="cursor-pointer rounded-md px-2 text-lg font-semibold hover:bg-muted">
						Scribe
					</span>
				</a>
				<Tooltip>
					<TooltipTrigger
						class="ring-offset-background focus-visible:ring-ring inline-flex h-fit items-center justify-center whitespace-nowrap rounded-md p-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0"
						onclick={() => {
							context.setOpenMobile(false);
							selectedCharacterStore.clear(); // Clear any selected character
							goto('/', { invalidateAll: true });
						}}
					>
						<PlusIcon />
					</TooltipTrigger>
					<TooltipContent align="end">New Chat</TooltipContent>
				</Tooltip>
			</div>
		</SidebarMenu>
	</SidebarHeader>
	<SidebarContent class="p-0">
		<!-- Replace SidebarHistory with CharacterList -->
		<CharacterList
			bind:this={characterListComp}
			on:selectCharacter={handleSelectCharacter}
			on:uploadCharacter={handleUploadCharacter}
		/>
	</SidebarContent>
	<SidebarFooter>
		{#if user}
			<SidebarUserNav {user} />
		{/if}
	</SidebarFooter>
</Sidebar>

<!-- Add the CharacterUploader component (Dialog) -->
<CharacterUploader
	bind:open={isUploaderOpen}
	onOpenChange={(value) => { isUploaderOpen = value; }}
	on:uploadSuccess={handleUploadSuccess}
/>
