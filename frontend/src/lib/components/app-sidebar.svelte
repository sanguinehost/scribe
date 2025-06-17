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
	import ChevronLeft from './icons/chevron-left.svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import SidebarUserNav from './sidebar-user-nav.svelte';
	import CharacterList from './CharacterList.svelte'; // Import the new CharacterList component
	import CharacterUploader from './CharacterUploader.svelte'; // Import the uploader component
	import PersonaList from './PersonaList.svelte'; // Import the PersonaList component
	import LorebooksSidebarList from './LorebooksSidebarList.svelte'; // Import the LorebooksSidebarList component
	import SettingsIcon from './icons/settings.svelte'; // Import the new SettingsIcon
	import { SettingsStore } from '$lib/stores/settings.svelte'; // Import SettingsStore
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SelectedLorebookStore } from '$lib/stores/selected-lorebook.svelte';
	import { SidebarStore } from '$lib/stores/sidebar.svelte';
	import { getCurrentUser, getIsAuthenticated } from '$lib/auth.svelte';

	const context = useSidebar();
	const settingsStore = SettingsStore.fromContext(); // Initialize SettingsStore
	const selectedCharacterStore = SelectedCharacterStore.fromContext();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();
	const selectedLorebookStore = SelectedLorebookStore.fromContext();
	const sidebarStore = SidebarStore.fromContext();
	let isUploaderOpen = $state(false); // State for dialog visibility (Changed to $state)
	let characterListComp = $state<CharacterList | undefined>(undefined); // Reference to CharacterList component instance
	let personaListComp = $state<PersonaList | undefined>(undefined); // Reference to PersonaList component instance
	let lorebookListComp = $state<LorebooksSidebarList | undefined>(undefined); // Reference to LorebooksSidebarList component instance

	// Character handlers
	async function handleSelectCharacter(event: CustomEvent<{ characterId: string }>) {
		const characterId = event.detail.characterId;
		console.log('Character selected:', characterId);

		// Clear any selected persona, lorebook and set the selected character
		selectedPersonaStore.clear();
		selectedLorebookStore.clear();
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
		// Also refresh lorebooks since character upload can create embedded lorebooks
		if (lorebookListComp) {
			await lorebookListComp.refresh(); // Call refresh on the LorebooksSidebarList instance
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

		// Clear any selected character, lorebook and set the selected persona
		selectedCharacterStore.clear();
		selectedLorebookStore.clear();
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

		// Clear any selected character, lorebook and set the persona store to creating mode
		selectedCharacterStore.clear();
		selectedLorebookStore.clear();
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

	async function openSettings() {
		// Set transitioning state immediately to prevent Overview from showing
		settingsStore.isTransitioning = true;
		
		// Clear all selections when opening settings
		selectedCharacterStore.clear();
		selectedPersonaStore.clear();
		selectedLorebookStore.clear();
		
		// Only navigate if we're not on the home page already
		// This prevents unnecessary page reloads that break transitions
		if ($page.url.pathname !== '/') {
			await goto('/', { replaceState: true });
			// Small delay to ensure navigation completes smoothly
			await new Promise(resolve => setTimeout(resolve, 50));
		}
		
		settingsStore.show();
		context.setOpenMobile(false); // Close mobile sidebar if open
	}

	// Lorebook handlers
	async function handleSelectLorebook(event: CustomEvent<{ lorebookId: string }>) {
		const lorebookId = event.detail.lorebookId;
		console.log('Lorebook selected:', lorebookId);

		// Clear any selected character and persona, then set selected lorebook
		selectedCharacterStore.clear();
		selectedPersonaStore.clear();
		selectedLorebookStore.selectLorebook(lorebookId);

		// Hide settings if visible to show lorebook detail immediately
		if (settingsStore.isVisible) {
			settingsStore.hide();
		}

		context.setOpenMobile(false); // Close mobile sidebar on selection
	}

	function handleViewAllLorebooks() {
		console.log('View all lorebooks triggered');

		// Clear any selected character and persona, then show lorebook list
		selectedCharacterStore.clear();
		selectedPersonaStore.clear();
		selectedLorebookStore.showList();

		// Hide settings if visible to show lorebook list immediately
		if (settingsStore.isVisible) {
			settingsStore.hide();
		}

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
						selectedLorebookStore.clear(); // Clear any selected lorebook
					}}
					class="flex flex-row items-center gap-3"
				>
					<span class="cursor-pointer rounded-md px-2 text-lg font-semibold hover:bg-muted">
						Scribe
					</span>
				</a>
				<!-- Collapse button on desktop -->
				<Button
					variant="ghost"
					size="icon"
					class="hidden h-8 w-8 md:flex"
					onclick={() => context.toggle()}
				>
					<ChevronLeft class="h-4 w-4" />
				</Button>
			</div>
		</SidebarMenu>
	</SidebarHeader>
	<SidebarContent class="p-0">
		<!-- Tab Navigation -->
		<div class="flex border-b">
			<button
				class="flex-1 px-3 py-2 text-xs font-medium transition-colors {sidebarStore.activeTab ===
				'characters'
					? 'border-b-2 border-primary bg-background text-foreground'
					: 'text-muted-foreground hover:text-foreground'}"
				onclick={() => switchTab('characters')}
			>
				Characters
			</button>
			<button
				class="flex-1 px-3 py-2 text-xs font-medium transition-colors {sidebarStore.activeTab ===
				'personas'
					? 'border-b-2 border-primary bg-background text-foreground'
					: 'text-muted-foreground hover:text-foreground'}"
				onclick={() => switchTab('personas')}
			>
				Personas
			</button>
			<button
				class="flex-1 px-3 py-2 text-xs font-medium transition-colors {sidebarStore.activeTab ===
				'lorebooks'
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
					bind:this={lorebookListComp}
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
		transition: opacity 400ms cubic-bezier(0.25, 0.46, 0.45, 0.94);
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
