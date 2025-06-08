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
	import { page } from '$app/stores';
	import PlusIcon from './icons/plus.svelte';
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
	import { SidebarStore } from '$lib/stores/sidebar.svelte';
	import { getCurrentUser, getIsAuthenticated } from '$lib/auth.svelte';

	const context = useSidebar();
	const settingsStore = SettingsStore.fromContext(); // Initialize SettingsStore
	const selectedCharacterStore = SelectedCharacterStore.fromContext();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();
	const sidebarStore = SidebarStore.fromContext();
	let isUploaderOpen = $state(false); // State for dialog visibility (Changed to $state)
	let characterListComp = $state<CharacterList | undefined>(undefined); // Reference to CharacterList component instance
	let personaListComp = $state<PersonaList | undefined>(undefined); // Reference to PersonaList component instance

	// Character handlers
	async function handleSelectCharacter(event: CustomEvent<{ characterId: string }>) {
		const characterId = event.detail.characterId;
		console.log('Character selected:', characterId);

		// Clear any selected persona and set the selected character
		selectedPersonaStore.clear();
		selectedCharacterStore.select(characterId);

		// Hide settings if visible to show character overview immediately
		if (settingsStore.isVisible) {
			settingsStore.hide();
		}

		// Only navigate if we're not on the home page already
		// This prevents unnecessary page reloads that break transitions
		if ($page.url.pathname !== '/') {
			goto('/', { replaceState: true });
		}
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

		// Hide settings if visible to show persona overview immediately
		if (settingsStore.isVisible) {
			settingsStore.hide();
		}

		// Only navigate if we're not on the home page already
		// This prevents unnecessary page reloads that break transitions
		if ($page.url.pathname !== '/') {
			goto('/', { replaceState: true });
		}
		context.setOpenMobile(false); // Close mobile sidebar on selection
	}

	function handleCreatePersona() {
		console.log('Create persona triggered');

		// Clear any selected character and set the persona store to creating mode
		selectedCharacterStore.clear();
		selectedPersonaStore.showCreating();

		// Only navigate if we're not on the home page already
		// This prevents unnecessary page reloads that break transitions
		if ($page.url.pathname !== '/') {
			goto('/', { replaceState: true });
		}
		context.setOpenMobile(false); // Close mobile sidebar
	}

	function switchTab(tab: 'characters' | 'personas' | 'lorebooks') {
		sidebarStore.setActiveTab(tab);
		// Don't clear selections when switching tabs - let users browse sidebar
		// while maintaining their current view (character overview, chat, etc.)
		// This prevents unnecessary navigation and content flickering
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
							class="inline-flex h-fit items-center justify-center whitespace-nowrap rounded-md p-2 text-sm font-medium ring-offset-background transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0"
							onclick={() => {
								context.setOpenMobile(false);
								selectedCharacterStore.clear(); // Clear any selected character
								selectedPersonaStore.clear(); // Clear any selected persona
								// Only navigate if we're not on the home page already
								if ($page.url.pathname !== '/') {
									goto('/', { replaceState: true });
								}
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
				class="flex-1 px-3 py-2 text-xs font-medium transition-colors {sidebarStore.activeTab === 'characters'
					? 'border-b-2 border-primary bg-background text-foreground'
					: 'text-muted-foreground hover:text-foreground'}"
				onclick={() => switchTab('characters')}
			>
				Characters
			</button>
			<button
				class="flex-1 px-3 py-2 text-xs font-medium transition-colors {sidebarStore.activeTab === 'personas'
					? 'border-b-2 border-primary bg-background text-foreground'
					: 'text-muted-foreground hover:text-foreground'}"
				onclick={() => switchTab('personas')}
			>
				Personas
			</button>
			<button
				class="flex-1 px-3 py-2 text-xs font-medium transition-colors {sidebarStore.activeTab === 'lorebooks'
					? 'border-b-2 border-primary bg-background text-foreground'
					: 'text-muted-foreground hover:text-foreground'}"
				onclick={() => switchTab('lorebooks')}
			>
				Lorebooks
			</button>
		</div>

		<!-- Tab Content - Keep all components mounted but show/hide them to prevent re-initialization -->
		<div class="relative h-full">
			<div 
				class="tab-content" 
				class:active={sidebarStore.activeTab === 'characters'}
				class:inactive={sidebarStore.activeTab !== 'characters'}
			>
				<CharacterList
					bind:this={characterListComp}
					on:selectCharacter={handleSelectCharacter}
					on:uploadCharacter={handleUploadCharacter}
				/>
			</div>
			<div 
				class="tab-content" 
				class:active={sidebarStore.activeTab === 'personas'}
				class:inactive={sidebarStore.activeTab !== 'personas'}
			>
				<PersonaList
					bind:this={personaListComp}
					on:selectPersona={handleSelectPersona}
					on:createPersona={handleCreatePersona}
				/>
			</div>
			<div 
				class="tab-content" 
				class:active={sidebarStore.activeTab === 'lorebooks'}
				class:inactive={sidebarStore.activeTab !== 'lorebooks'}
			>
				<LorebooksSidebarList
					on:selectLorebook={handleSelectLorebook}
					on:viewAllLorebooks={handleViewAllLorebooks}
				/>
			</div>
		</div>
	</SidebarContent>
	<SidebarFooter class="flex flex-col gap-2">
		<Button variant="ghost" class="w-full justify-start" onclick={openSettings}>
			<SettingsIcon size={16} class="mr-2" />
			Settings
		</Button>
		{#if getIsAuthenticated() && getCurrentUser()}
			<SidebarUserNav />
		{/if}
	</SidebarFooter>
</Sidebar>

<!-- Add the CharacterUploader component (Dialog) -->
<CharacterUploader
	bind:open={isUploaderOpen}
	onOpenChange={(value) => {
		isUploaderOpen = value;
	}}
	on:uploadSuccess={handleUploadSuccess}
/>

<style>
	.tab-content {
		position: absolute;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		transition: opacity 200ms ease-in-out;
		pointer-events: none;
		opacity: 0;
	}

	.tab-content.active {
		pointer-events: auto;
		opacity: 1;
	}

	.tab-content.inactive {
		pointer-events: none;
		opacity: 0;
	}
</style>
