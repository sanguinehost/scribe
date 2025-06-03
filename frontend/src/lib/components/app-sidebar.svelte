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
	import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from './ui/tooltip';
	import { goto } from '$app/navigation';
	import PlusIcon from './icons/plus.svelte';
	import type { User } from '$lib/types'; // Assuming User type is defined elsewhere or remove if not used directly here
	import SidebarUserNav from './sidebar-user-nav.svelte';
	// import { SidebarHistory } from './sidebar-history'; // Remove SidebarHistory import
	import CharacterList from './CharacterList.svelte'; // Import the new CharacterList component
	import CharacterUploader from './CharacterUploader.svelte'; // Import the uploader component
	import PersonaList from './PersonaList.svelte'; // Import the PersonaList component
	import LorebooksSidebarList from './LorebooksSidebarList.svelte'; // Import the LorebooksSidebarList component
	import SettingsIcon from './icons/settings.svelte'; // Import the new SettingsIcon
	import { SettingsStore } from '$lib/stores/settings.svelte'; // Import SettingsStore
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';

	let { user }: { user?: User } = $props();

	const context = useSidebar();
	const settingsStore = SettingsStore.fromContext(); // Initialize SettingsStore
	const selectedCharacterStore = SelectedCharacterStore.fromContext();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();
	let isUploaderOpen = $state(false); // State for dialog visibility (Changed to $state)
	let activeTab = $state<'characters' | 'personas' | 'lorebooks'>('characters'); // Track active tab
	let characterListComp = $state<CharacterList | undefined>(undefined); // Reference to CharacterList component instance
	let personaListComp = $state<PersonaList | undefined>(undefined); // Reference to PersonaList component instance

	// Character handlers
	async function handleSelectCharacter(event: CustomEvent<{ characterId: string }>) {
		const characterId = event.detail.characterId;
		console.log('Character selected:', characterId);
		
		// Clear any selected persona and set the selected character
		selectedPersonaStore.clear();
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

	async function handlePersonaCreated() {
		console.log('Persona created, refreshing list...');
		if (personaListComp) {
			await personaListComp.refresh(); // Call refresh on the PersonaList instance
		}
	}

	// Persona handlers
	async function handleSelectPersona(event: CustomEvent<{ personaId: string }>) {
		const personaId = event.detail.personaId;
		console.log('Persona selected:', personaId);
		
		// Clear any selected character and set the selected persona
		selectedCharacterStore.clear();
		selectedPersonaStore.selectPersona(personaId);
		
		// Navigate to home to show the persona overview
		goto('/', { invalidateAll: true });
		context.setOpenMobile(false); // Close mobile sidebar on selection
	}

	function handleCreatePersona() {
		console.log('Create persona triggered');
		
		// Clear any selected character and set the persona store to creating mode
		selectedCharacterStore.clear();
		selectedPersonaStore.showCreating();
		
		// Navigate to home to show the persona editor
		goto('/', { invalidateAll: true });
		context.setOpenMobile(false); // Close mobile sidebar
	}

	function switchTab(tab: 'characters' | 'personas') {
		activeTab = tab;
		// Clear any selections when switching tabs
		if (tab === 'characters') {
			selectedPersonaStore.clear();
		} else {
			selectedCharacterStore.clear();
		}
	}

	function openSettings() {
		settingsStore.show();
		context.setOpenMobile(false); // Close mobile sidebar if open
	}

	// Lorebook handlers
	async function handleSelectLorebook(event: CustomEvent<{ lorebookId: string }>) {
		const lorebookId = event.detail.lorebookId;
		console.log('Lorebook selected:', lorebookId);
		
		// Navigate to the specific lorebook
		goto(`/lorebooks/${lorebookId}`);
		context.setOpenMobile(false); // Close mobile sidebar on selection
	}

	function handleViewAllLorebooks() {
		goto('/lorebooks');
		context.setOpenMobile(false); // Close mobile sidebar
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
						selectedPersonaStore.clear(); // Clear any selected persona
					}}
					class="flex flex-row items-center gap-3"
				>
					<span class="cursor-pointer rounded-md px-2 text-lg font-semibold hover:bg-muted">
						Scribe
					</span>
				</a>
				<TooltipProvider>
					<Tooltip>
						<TooltipTrigger
							class="ring-offset-background focus-visible:ring-ring inline-flex h-fit items-center justify-center whitespace-nowrap rounded-md p-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0"
							onclick={() => {
								context.setOpenMobile(false);
								selectedCharacterStore.clear(); // Clear any selected character
								selectedPersonaStore.clear(); // Clear any selected persona
								goto('/', { invalidateAll: true });
							}}
						>
							<PlusIcon />
						</TooltipTrigger>
						<TooltipContent align="end">New Chat</TooltipContent>
					</Tooltip>
				</TooltipProvider>
			</div>
		</SidebarMenu>
	</SidebarHeader>
	<SidebarContent class="p-0">
		<!-- Tab Navigation -->
		<div class="flex border-b">
			<button
				class="flex-1 px-3 py-2 text-xs font-medium transition-colors {activeTab === 'characters'
					? 'bg-background text-foreground border-b-2 border-primary'
					: 'text-muted-foreground hover:text-foreground'}"
				onclick={() => switchTab('characters')}
			>
				Characters
			</button>
			<button
				class="flex-1 px-3 py-2 text-xs font-medium transition-colors {activeTab === 'personas'
					? 'bg-background text-foreground border-b-2 border-primary'
					: 'text-muted-foreground hover:text-foreground'}"
				onclick={() => switchTab('personas')}
			>
				Personas
			</button>
			<button
				class="flex-1 px-3 py-2 text-xs font-medium transition-colors {activeTab === 'lorebooks'
					? 'bg-background text-foreground border-b-2 border-primary'
					: 'text-muted-foreground hover:text-foreground'}"
				onclick={() => switchTab('lorebooks')}
			>
				Lorebooks
			</button>
		</div>

		<!-- Tab Content -->
		{#if activeTab === 'characters'}
			<CharacterList
				bind:this={characterListComp}
				on:selectCharacter={handleSelectCharacter}
				on:uploadCharacter={handleUploadCharacter}
			/>
		{:else if activeTab === 'personas'}
			<PersonaList
				bind:this={personaListComp}
				on:selectPersona={handleSelectPersona}
				on:createPersona={handleCreatePersona}
			/>
		{:else if activeTab === 'lorebooks'}
			<LorebooksSidebarList
				on:selectLorebook={handleSelectLorebook}
				on:viewAllLorebooks={handleViewAllLorebooks}
			/>
		{/if}
	</SidebarContent>
	<SidebarFooter class="flex flex-col gap-2">
		<Button variant="ghost" class="w-full justify-start" onclick={openSettings}>
			<SettingsIcon size={16} class="mr-2" />
			Settings
		</Button>
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
