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
	import { apiClient } from '$lib/api'; // Import the API client
	import { toast } from 'svelte-sonner'; // Import toast for error handling

	let { user }: { user?: User } = $props();

	const context = useSidebar();
	let isUploaderOpen = $state(false); // State for dialog visibility (Changed to $state)
	let characterListComp: CharacterList; // Reference to CharacterList component instance

	// Placeholder handlers for events from CharacterList
	async function handleSelectCharacter(event: CustomEvent<{ characterId: string }>) {
		const characterId = event.detail.characterId;
		console.log('Character selected:', characterId);
		context.setOpenMobile(false); // Close mobile sidebar on selection

		try {
			// 1. Fetch full character details
			const characterResult = await apiClient.getCharacter(characterId);

			if (characterResult.isErr()) {
				console.error('Failed to fetch character details:', characterResult.error);
				toast.error('Failed to load character details', { description: characterResult.error.message });
				return; // Stop if character details can't be fetched
			}

			const character = characterResult.value;
			const characterName = character.name || 'Character'; // Use fetched name or default

			// 2. Call API to create chat session with character details
			const createChatResult = await apiClient.createChat({
				character_id: characterId,
				title: `Chat with ${characterName}`, // Use character name in title
				// Ensure null is passed if the properties are missing or null/undefined
				system_prompt: character.system_prompt ?? null,
				personality: character.personality ?? null,
				scenario: character.scenario ?? null
			});

			if (createChatResult.isOk()) { // Check using isOk()
				const chat = createChatResult.value; // Access value using .value
				console.log('Chat session created/fetched:', chat.id);
				goto(`/chat/${chat.id}`, { invalidateAll: true }); // Navigate to the chat page with the new chat ID
			} else { // Error case
				const apiError = createChatResult.error; // Access error using .error
				console.error('Failed to create chat session:', apiError);
				toast.error('Failed to start chat session', { description: apiError.message });
				// Handle error
			}
		} catch (error) {
			console.error('Error starting chat session:', error);
			toast.error('An unexpected error occurred while starting the chat.');
			// Handle unexpected errors
		}
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
