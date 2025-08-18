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
	import { Users, UserCircle, BookOpen, ScrollText } from 'lucide-svelte';
	import * as Tooltip from '$lib/components/ui/tooltip';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import SidebarUserNav from './sidebar-user-nav.svelte';
	import CharacterList from './CharacterList.svelte'; // Import the new CharacterList component
	import CharacterUploader from './CharacterUploader.svelte'; // Import the uploader component
	import PersonaList from './PersonaList.svelte'; // Import the PersonaList component
	import LorebooksSidebarList from './LorebooksSidebarList.svelte'; // Import the LorebooksSidebarList component
	import ChroniclesSidebarList from './ChroniclesSidebarList.svelte'; // Import the ChroniclesSidebarList component
	import SettingsIcon from './icons/settings.svelte'; // Import the new SettingsIcon
	import { SettingsStore } from '$lib/stores/settings.svelte'; // Import SettingsStore
	import { SelectedCharacterStore } from '$lib/stores/selected-character.svelte';
	import { SelectedPersonaStore } from '$lib/stores/selected-persona.svelte';
	import { SelectedLorebookStore } from '$lib/stores/selected-lorebook.svelte';
	import { SelectedChronicleStore } from '$lib/stores/selected-chronicle.svelte';
	import { SidebarStore } from '$lib/stores/sidebar.svelte';
	import { getCurrentUser, getIsAuthenticated } from '$lib/auth.svelte';

	const context = useSidebar();
	const settingsStore = SettingsStore.fromContext(); // Initialize SettingsStore
	const selectedCharacterStore = SelectedCharacterStore.fromContext();
	const selectedPersonaStore = SelectedPersonaStore.fromContext();
	const selectedLorebookStore = SelectedLorebookStore.fromContext();
	const selectedChronicleStore = SelectedChronicleStore.fromContext();
	const sidebarStore = SidebarStore.fromContext();
	let isUploaderOpen = $state(false); // State for dialog visibility (Changed to $state)
	let characterListComp = $state<CharacterList | undefined>(undefined); // Reference to CharacterList component instance
	let personaListComp = $state<PersonaList | undefined>(undefined); // Reference to PersonaList component instance
	let lorebookListComp = $state<LorebooksSidebarList | undefined>(undefined); // Reference to LorebooksSidebarList component instance
	let chronicleListComp = $state<ChroniclesSidebarList | undefined>(undefined); // Reference to ChroniclesSidebarList component instance

	// Character handlers
	async function handleSelectCharacter(event: CustomEvent<{ characterId: string }>) {
		const characterId = event.detail.characterId;
		console.log('Character selected:', characterId);

		// Clear any selected persona, lorebook, chronicle and set the selected character
		selectedPersonaStore.clear();
		selectedLorebookStore.clear();
		selectedChronicleStore.clear();
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

		// Clear any selected character, lorebook, chronicle and set the selected persona
		selectedCharacterStore.clear();
		selectedLorebookStore.clear();
		selectedChronicleStore.clear();
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

		// Clear any selected character, lorebook, chronicle and set the persona store to creating mode
		selectedCharacterStore.clear();
		selectedLorebookStore.clear();
		selectedChronicleStore.clear();
		selectedPersonaStore.showCreating();

		// Only navigate if we're not on the home page already
		// This prevents unnecessary page reloads that break transitions
		if ($page.url.pathname !== '/') {
			goto('/', { replaceState: true });
		}
		context.setOpenMobile(false); // Close mobile sidebar
	}

	function switchTab(tab: 'characters' | 'personas' | 'lorebooks' | 'chronicles') {
		sidebarStore.setActiveTab(tab);

		// Refresh chronicles when switching to that tab
		if (tab === 'chronicles' && chronicleListComp) {
			chronicleListComp.refresh();
		}

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
		selectedChronicleStore.clear();

		// Only navigate if we're not on the home page already
		// This prevents unnecessary page reloads that break transitions
		if ($page.url.pathname !== '/') {
			await goto('/', { replaceState: true });
			// Small delay to ensure navigation completes smoothly
			await new Promise((resolve) => setTimeout(resolve, 50));
		}

		settingsStore.show();
		context.setOpenMobile(false); // Close mobile sidebar if open
	}

	// Lorebook handlers
	async function handleSelectLorebook(event: CustomEvent<{ lorebookId: string }>) {
		const lorebookId = event.detail.lorebookId;
		console.log('Lorebook selected:', lorebookId);

		// Clear any selected character, persona, chronicle and set selected lorebook
		selectedCharacterStore.clear();
		selectedPersonaStore.clear();
		selectedChronicleStore.clear();
		selectedLorebookStore.selectLorebook(lorebookId);

		// Hide settings if visible to show lorebook detail immediately
		if (settingsStore.isVisible) {
			settingsStore.hide();
		}

		context.setOpenMobile(false); // Close mobile sidebar on selection
	}

	function handleViewAllLorebooks() {
		console.log('View all lorebooks triggered');

		// Clear any selected character, persona, chronicle and show lorebook list
		selectedCharacterStore.clear();
		selectedPersonaStore.clear();
		selectedChronicleStore.clear();
		selectedLorebookStore.showList();

		// Hide settings if visible to show lorebook list immediately
		if (settingsStore.isVisible) {
			settingsStore.hide();
		}

		context.setOpenMobile(false); // Close mobile sidebar
	}

	// Chronicle handlers
	async function handleSelectChronicle(event: CustomEvent<{ chronicleId: string }>) {
		const chronicleId = event.detail.chronicleId;
		console.log('Chronicle selected:', chronicleId);

		// Clear any selected character, persona, and lorebook, then set selected chronicle
		selectedCharacterStore.clear();
		selectedPersonaStore.clear();
		selectedLorebookStore.clear();
		selectedChronicleStore.selectChronicle(chronicleId);

		// Hide settings if visible to show chronicle detail immediately
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

	function handleViewAllChronicles() {
		console.log('View all chronicles triggered');

		// Clear any selected character, persona, and lorebook, then show chronicle list
		selectedCharacterStore.clear();
		selectedPersonaStore.clear();
		selectedLorebookStore.clear();
		selectedChronicleStore.showList();

		// Hide settings if visible to show chronicle list immediately
		if (settingsStore.isVisible) {
			settingsStore.hide();
		}

		// Only navigate if we're not on the home page already
		// This prevents unnecessary page reloads that break transitions
		if ($page.url.pathname !== '/') {
			goto('/', { replaceState: true });
		}
		context.setOpenMobile(false); // Close mobile sidebar
	}

	function handleCreateChronicle() {
		console.log('Create chronicle triggered');

		// Clear any selections and set chronicle store to creating mode
		selectedCharacterStore.clear();
		selectedPersonaStore.clear();
		selectedLorebookStore.clear();
		selectedChronicleStore.showCreating();

		// Only navigate if we're not on the home page already
		// This prevents unnecessary page reloads that break transitions
		if ($page.url.pathname !== '/') {
			goto('/', { replaceState: true });
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
						selectedChronicleStore.clear(); // Clear any selected chronicle
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
		<Tooltip.Provider>
			<div class="flex min-w-0 border-b">
				<Tooltip.Root>
					<Tooltip.Trigger
						class="flex flex-1 items-center justify-center px-2 py-3 transition-all duration-200 hover:bg-muted/50 {sidebarStore.activeTab ===
						'characters'
							? 'border-b-2 border-primary bg-background text-foreground'
							: 'text-muted-foreground hover:text-foreground'}"
						onclick={() => switchTab('characters')}
					>
						<Users class="h-4 w-4" />
					</Tooltip.Trigger>
					<Tooltip.Content side="bottom">
						<p>Characters</p>
					</Tooltip.Content>
				</Tooltip.Root>

				<Tooltip.Root>
					<Tooltip.Trigger
						class="flex flex-1 items-center justify-center px-2 py-3 transition-all duration-200 hover:bg-muted/50 {sidebarStore.activeTab ===
						'personas'
							? 'border-b-2 border-primary bg-background text-foreground'
							: 'text-muted-foreground hover:text-foreground'}"
						onclick={() => switchTab('personas')}
					>
						<UserCircle class="h-4 w-4" />
					</Tooltip.Trigger>
					<Tooltip.Content side="bottom">
						<p>Personas</p>
					</Tooltip.Content>
				</Tooltip.Root>

				<Tooltip.Root>
					<Tooltip.Trigger
						class="flex flex-1 items-center justify-center px-2 py-3 transition-all duration-200 hover:bg-muted/50 {sidebarStore.activeTab ===
						'lorebooks'
							? 'border-b-2 border-primary bg-background text-foreground'
							: 'text-muted-foreground hover:text-foreground'}"
						onclick={() => switchTab('lorebooks')}
					>
						<BookOpen class="h-4 w-4" />
					</Tooltip.Trigger>
					<Tooltip.Content side="bottom">
						<p>Lorebooks</p>
					</Tooltip.Content>
				</Tooltip.Root>

				<Tooltip.Root>
					<Tooltip.Trigger
						class="flex flex-1 items-center justify-center px-2 py-3 transition-all duration-200 hover:bg-muted/50 {sidebarStore.activeTab ===
						'chronicles'
							? 'border-b-2 border-primary bg-background text-foreground'
							: 'text-muted-foreground hover:text-foreground'}"
						onclick={() => switchTab('chronicles')}
					>
						<ScrollText class="h-4 w-4" />
					</Tooltip.Trigger>
					<Tooltip.Content side="bottom">
						<p>Chronicles</p>
					</Tooltip.Content>
				</Tooltip.Root>
			</div>
		</Tooltip.Provider>

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
			<div
				class="tab-content"
				class:active={sidebarStore.activeTab === 'chronicles'}
				class:inactive={sidebarStore.activeTab !== 'chronicles'}
			>
				<ChroniclesSidebarList
					bind:this={chronicleListComp}
					on:selectChronicle={handleSelectChronicle}
					on:viewAllChronicles={handleViewAllChronicles}
					on:createChronicle={handleCreateChronicle}
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
