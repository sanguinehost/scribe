<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { apiClient } from '$lib/api';
	import type { Character, ScribeChatSession, UserPersona } from '$lib/types';
	import { getCurrentUser } from '$lib/auth.svelte';
	import { toast } from 'svelte-sonner';
	import { scale } from 'svelte/transition';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Textarea } from '$lib/components/ui/textarea';
	import {
		Card,
		CardHeader,
		CardTitle,
		CardDescription,
		CardContent
	} from '$lib/components/ui/card';
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar';
	import { Skeleton } from '$lib/components/ui/skeleton';
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
	import PlusIcon from '../icons/plus.svelte';
	import MessageIcon from '../icons/message.svelte';
	import TrashIcon from '../icons/trash.svelte';
	import PencilEdit from '../icons/pencil-edit.svelte';
	import CheckCircleFill from '../icons/check-circle-fill.svelte';
	import MarkdownRenderer from '../markdown/renderer.svelte';

	let {
		characterId,
		onStartChat
	}: {
		characterId: string;
		onStartChat?: (chatId: string) => void;
	} = $props();

	let character = $state<Character | null>(null);
	let chats = $state<ScribeChatSession[]>([]);
	let allChats = $state<ScribeChatSession[]>([]);
	let showAllChats = $state(false);
	let isLoadingCharacter = $state(true);
	let isLoadingChats = $state(true);
	let deleteDialogOpen = $state(false);
	let chatToDelete = $state<ScribeChatSession | null>(null);
	let isDeletingChat = $state(false);

	// Edit mode state
	let isEditMode = $state(false);
	let isSaving = $state(false);
	let editedName = $state('');
	let editedDescription = $state('');
	let editedScenario = $state('');
	let editedPersonality = $state('');
	let editedGreeting = $state('');

	// User persona for template substitution
	let currentUserPersona = $state<UserPersona | null>(null);
	let userPersonaName = $state('User'); // Fallback to 'User'

	function getInitials(name: string): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Template substitution for frontend preview
	function substituteTemplateVariables(text: string, characterName: string): string {
		if (!text) return text;
		return text.replace(/\{\{char\}\}/g, characterName).replace(/\{\{user\}\}/g, userPersonaName);
	}

	// Basic HTML sanitization to prevent XSS while preserving formatting
	function sanitizeHtml(html: string | null | undefined): string {
		if (!html) return '';

		// Create a temporary div to parse HTML
		const temp = document.createElement('div');
		temp.innerHTML = html;

		// Remove script tags and event handlers
		const scripts = temp.querySelectorAll('script');
		scripts.forEach((script) => script.remove());

		// Remove all event handlers
		const allElements = temp.querySelectorAll('*');
		allElements.forEach((el) => {
			// Remove all attributes that start with 'on'
			Array.from(el.attributes).forEach((attr) => {
				if (attr.name.startsWith('on')) {
					el.removeAttribute(attr.name);
				}
			});

			// Remove javascript: hrefs
			if (el.tagName === 'A' && el.getAttribute('href')?.startsWith('javascript:')) {
				el.removeAttribute('href');
			}
		});

		return temp.innerHTML;
	}

	function formatDate(date: string | Date): string {
		const d = new Date(date);
		const now = new Date();
		const diffInHours = (now.getTime() - d.getTime()) / (1000 * 60 * 60);

		if (diffInHours < 24) {
			if (diffInHours < 1) {
				const diffInMinutes = Math.floor(diffInHours * 60);
				return diffInMinutes === 0 ? 'Just now' : `${diffInMinutes}m ago`;
			}
			return `${Math.floor(diffInHours)}h ago`;
		} else if (diffInHours < 168) {
			// Less than a week
			const diffInDays = Math.floor(diffInHours / 24);
			return diffInDays === 1 ? 'Yesterday' : `${diffInDays}d ago`;
		}

		return d.toLocaleDateString('en-US', {
			month: 'short',
			day: 'numeric',
			year: d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
		});
	}

	async function loadUserPersona() {
		try {
			const currentUser = getCurrentUser();
			if (currentUser?.default_persona_id) {
				const personaResult = await apiClient.getUserPersona(currentUser.default_persona_id);
				if (personaResult.isOk()) {
					currentUserPersona = personaResult.value;
					userPersonaName = currentUserPersona.name || 'User';
				} else {
					console.warn('Failed to load user persona:', personaResult.error);
					userPersonaName = currentUser.username || 'User';
				}
			} else if (currentUser?.username) {
				userPersonaName = currentUser.username;
			}
		} catch (error) {
			console.warn('Error loading user persona:', error);
			userPersonaName = 'User';
		}
	}

	async function loadCharacterData() {
		if (!characterId) return;

		isLoadingCharacter = true;
		isLoadingChats = true;

		// Load user persona first for template substitution
		await loadUserPersona();

		// Load character details
		const characterResult = await apiClient.getCharacter(characterId);
		if (characterResult.isOk()) {
			character = characterResult.value;
			// Initialize edit values
			editedName = character.name || '';
			editedDescription = character.description || '';
			editedScenario = character.scenario || '';
			editedPersonality = character.personality || '';
			editedGreeting = character.greeting || '';
		} else {
			toast.error('Failed to load character', {
				description: characterResult.error.message
			});
		}
		isLoadingCharacter = false;

		// Load chats for this character
		const chatsResult = await apiClient.getChatsByCharacter(characterId);
		if (chatsResult.isOk()) {
			allChats = chatsResult.value;
			// Show only first 5 chats initially
			chats = allChats.slice(0, 5);
		} else {
			toast.error('Failed to load chats', {
				description: chatsResult.error.message
			});
		}
		isLoadingChats = false;
	}

	function handleEdit() {
		if (!character) return;

		// Reset edit values to current character data
		editedName = character.name || '';
		editedDescription = character.description || '';
		editedScenario = character.scenario || '';
		editedPersonality = character.personality || '';
		editedGreeting = character.greeting || '';

		isEditMode = true;
	}

	function handleCancelEdit() {
		isEditMode = false;
		// Reset values back to original
		if (character) {
			editedName = character.name || '';
			editedDescription = character.description || '';
			editedScenario = character.scenario || '';
			editedPersonality = character.personality || '';
			editedGreeting = character.greeting || '';
		}
	}

	async function handleSave() {
		if (!character) return;

		isSaving = true;

		try {
			const updateData: any = {};

			// Only include changed fields
			if (editedName !== (character.name || '') && editedName.trim()) {
				updateData.name = editedName.trim();
			}
			if (editedDescription !== (character.description || '')) {
				updateData.description = editedDescription.trim();
			}
			if (editedScenario !== (character.scenario || '')) {
				updateData.scenario = editedScenario.trim();
			}
			if (editedPersonality !== (character.personality || '')) {
				updateData.personality = editedPersonality.trim();
			}
			if (editedGreeting !== (character.greeting || '')) {
				updateData.first_mes = editedGreeting.trim(); // Backend uses first_mes
			}

			// Only make API call if there are changes
			if (Object.keys(updateData).length > 0) {
				const result = await apiClient.updateCharacter(character.id, updateData);
				if (result.isOk()) {
					// Update local character data
					character.name = editedName.trim();
					character.description = editedDescription.trim() || null;
					character.scenario = editedScenario.trim() || null;
					character.personality = editedPersonality.trim() || null;
					character.greeting = editedGreeting.trim() || null;

					toast.success('Character updated successfully');
					isEditMode = false;
				} else {
					toast.error('Failed to update character: ' + result.error.message);
				}
			} else {
				// No changes, just exit edit mode
				isEditMode = false;
			}
		} catch (error) {
			toast.error('Error updating character');
			console.error('Error updating character:', error);
		} finally {
			isSaving = false;
		}
	}

	async function handleStartNewChat() {
		if (!character) return;

		try {
			const createChatResult = await apiClient.createChat({
				character_id: characterId,
				title: `Chat with ${character.name}`,
				system_prompt: character.system_prompt ?? null,
				personality: character.personality ?? null,
				scenario: character.scenario ?? null
			});

			if (createChatResult.isOk()) {
				const chat = createChatResult.value;
				if (onStartChat) {
					onStartChat(chat.id);
				}
				await goto(`/chat/${chat.id}`, { invalidateAll: true });
			} else {
				toast.error('Failed to start chat', {
					description: createChatResult.error.message
				});
			}
		} catch (error) {
			console.error('Error starting chat:', error);
			toast.error('An unexpected error occurred');
		}
	}

	function handleSelectChat(chatId: string) {
		goto(`/chat/${chatId}`);
	}

	function handleDeleteClick(e: MouseEvent, chat: ScribeChatSession) {
		e.stopPropagation(); // Prevent triggering the chat selection
		chatToDelete = chat;

		// If shift key is held, skip confirmation
		if (e.shiftKey) {
			confirmDelete();
		} else {
			deleteDialogOpen = true;
		}
	}

	async function confirmDelete() {
		if (!chatToDelete) return;

		isDeletingChat = true;
		try {
			const result = await apiClient.deleteChatById(chatToDelete.id);
			if (result.isOk()) {
				// Remove the chat from both lists
				chats = chats.filter((c) => c.id !== chatToDelete!.id);
				allChats = allChats.filter((c) => c.id !== chatToDelete!.id);
				toast.success('Chat deleted successfully');
			} else {
				toast.error('Failed to delete chat', {
					description: result.error.message
				});
			}
		} catch (error) {
			console.error('Error deleting chat:', error);
			toast.error('An unexpected error occurred');
		} finally {
			isDeletingChat = false;
			deleteDialogOpen = false;
			chatToDelete = null;
		}
	}

	function toggleAllChats() {
		showAllChats = !showAllChats;
		if (showAllChats) {
			chats = allChats;
		} else {
			chats = allChats.slice(0, 5);
		}
	}

	function getMostRecentChat(): ScribeChatSession | null {
		if (allChats.length === 0) return null;
		return allChats[0]; // Assuming chats are sorted by creation date descending
	}

	onMount(() => {
		loadCharacterData();
	});
</script>

<div class="mx-auto max-w-4xl px-4" transition:scale={{ opacity: 0, start: 0.98 }}>
	<div class="space-y-6">
		<!-- Character Header Card -->
		{#if isLoadingCharacter}
			<Card class="border-0 shadow-none">
				<CardHeader class="px-0">
					<div class="flex items-center space-x-6">
						<Skeleton class="h-24 w-24 rounded-full" />
						<div class="flex-1 space-y-3">
							<Skeleton class="h-8 w-2/3" />
							<Skeleton class="h-4 w-full" />
							<Skeleton class="h-4 w-5/6" />
						</div>
					</div>
				</CardHeader>
			</Card>
		{:else if character}
			<Card class="border-0 shadow-none">
				<CardHeader class="px-0">
					<div class="flex items-start space-x-6">
						<Avatar class="h-24 w-24 border-2 border-muted">
							{#if character.avatar}
								<AvatarImage src={character.avatar} alt={character.name} />
							{/if}
							<AvatarFallback class="text-3xl font-semibold">
								{getInitials(character.name)}
							</AvatarFallback>
						</Avatar>
						<div class="flex-1 space-y-4">
							<div class="relative">
								{#if !isEditMode}
									<div class="group relative">
										<h2 class="text-3xl font-bold">{character.name}</h2>
										<Button
											variant="ghost"
											size="sm"
											class="absolute -right-8 top-0 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
											onclick={handleEdit}
											aria-label="Edit character name"
										>
											<PencilEdit class="h-3 w-3" />
										</Button>
									</div>
									<div class="flex gap-3 mt-4">
										<Button onclick={handleStartNewChat} size="lg" class="gap-2">
											<PlusIcon class="h-4 w-4" />
											Start New Chat
										</Button>
										{#if getMostRecentChat()}
											<Button
												variant="outline"
												size="lg"
												class="gap-2"
												onclick={() => handleSelectChat(getMostRecentChat()!.id)}
											>
												<MessageIcon class="h-4 w-4" />
												Continue Last Chat
											</Button>
										{/if}
									</div>
									{#if character.description}
										<div class="group relative mt-2">
											<div class="text-muted-foreground prose prose-sm dark:prose-invert max-w-none [&_*]:!text-muted-foreground">
												<MarkdownRenderer md={substituteTemplateVariables(character.description, character.name)} />
											</div>
											<Button
												variant="ghost"
												size="sm"
												class="absolute -right-8 top-0 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
												onclick={handleEdit}
												aria-label="Edit character description"
											>
												<PencilEdit class="h-3 w-3" />
											</Button>
										</div>
									{/if}
								{:else}
									<div class="space-y-3">
										<div>
											<label for="edit-name" class="text-sm font-medium">Name</label>
											<Input
												id="edit-name"
												bind:value={editedName}
												class="mt-1"
												placeholder="Character name"
											/>
										</div>
										<div>
											<label for="edit-description" class="text-sm font-medium">Description</label>
											<Textarea
												id="edit-description"
												bind:value={editedDescription}
												class="mt-1"
												placeholder="Character description"
												rows={3}
											/>
										</div>
										<div class="flex gap-2">
											<Button onclick={handleSave} disabled={isSaving} size="sm" class="gap-2">
												{#if isSaving}
													<div
														class="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"
													></div>
													Saving...
												{:else}
													<CheckCircleFill class="h-3 w-3" />
													Save
												{/if}
											</Button>
											<Button onclick={handleCancelEdit} variant="outline" size="sm">Cancel</Button>
										</div>
									</div>
								{/if}
							</div>
						</div>
					</div>
				</CardHeader>
			</Card>
		{/if}

		<!-- Chat Sessions Section -->
		<div class="space-y-4">
			<div class="flex items-center justify-between">
				<h3 class="text-xl font-semibold">Recent Chats</h3>
			</div>

			{#if isLoadingChats}
				<div class="grid gap-3">
					{#each Array(3) as _}
						<Card class="cursor-pointer transition-colors hover:bg-muted/50">
							<CardHeader>
								<div class="space-y-2">
									<Skeleton class="h-5 w-3/4" />
									<Skeleton class="h-4 w-1/4" />
								</div>
							</CardHeader>
						</Card>
					{/each}
				</div>
			{:else if chats.length === 0}
				<Card class="border-dashed">
					<CardContent class="py-12 text-center">
						<MessageIcon class="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
						<p class="mb-4 text-muted-foreground">
							No conversations yet with {character?.name || 'this character'}
						</p>
						<Button onclick={handleStartNewChat} variant="outline" disabled={!character}>
							Start Your First Chat
						</Button>
					</CardContent>
				</Card>
			{:else}
				<div class="grid gap-3">
					{#each chats as chat}
						<Card
							class="group cursor-pointer transition-colors hover:bg-muted/50"
							onclick={() => handleSelectChat(chat.id)}
							onkeydown={(e) => e.key === 'Enter' && handleSelectChat(chat.id)}
							tabindex={0}
							role="button"
						>
							<CardHeader class="pb-6">
								<div class="flex items-start justify-between">
									<div class="min-w-0 flex-1 space-y-1">
										<CardTitle class="truncate text-base font-medium">
											{chat.title || `Chat with ${character?.name}`}
										</CardTitle>
										<CardDescription class="text-sm">
											{formatDate(chat.created_at)}
										</CardDescription>
									</div>
									<div class="ml-3 flex items-center gap-2">
										<Button
											variant="ghost"
											size="icon"
											class="h-8 w-8 opacity-0 transition-opacity group-hover:opacity-100"
											onclick={(e) => handleDeleteClick(e, chat)}
											aria-label="Delete chat"
											title="Delete chat (hold Shift to skip confirmation)"
										>
											<TrashIcon class="h-4 w-4 text-destructive" />
										</Button>
										<MessageIcon class="h-5 w-5 flex-shrink-0 text-muted-foreground" />
									</div>
								</div>
							</CardHeader>
						</Card>
					{/each}
				</div>
			{/if}

			<!-- Show All Chats Button -->
			{#if allChats.length > 5}
				<div class="pt-4 text-center">
					<Button variant="outline" onclick={toggleAllChats}>
						{showAllChats ? 'Show Recent Only' : `Show All ${allChats.length} Chats`}
					</Button>
				</div>
			{/if}
		</div>

		<!-- Character Details Section (moved below chats) -->
		{#if character && !isEditMode && (character.scenario || character.personality || character.greeting)}
			<Card class="border-0 shadow-none">
				<CardContent class="space-y-4 px-0">
					{#if character.scenario}
						<div class="group relative rounded-lg bg-muted/50 p-4">
							<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Scenario</h4>
							<div
								class="prose prose-sm prose-p:my-2 prose-p:leading-relaxed prose-strong:font-semibold prose-headings:font-bold dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
							>
								<MarkdownRenderer md={substituteTemplateVariables(character.scenario, character.name)} />
							</div>
							<Button
								variant="ghost"
								size="sm"
								class="absolute -right-2 top-2 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
								onclick={handleEdit}
								aria-label="Edit scenario"
							>
								<PencilEdit class="h-3 w-3" />
							</Button>
						</div>
					{/if}
					{#if character.personality}
						<div class="group relative rounded-lg bg-muted/50 p-4">
							<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Personality</h4>
							<div
								class="prose prose-sm prose-p:my-2 prose-p:leading-relaxed prose-strong:font-semibold prose-headings:font-bold dark:prose-invert max-w-none text-sm [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
							>
								<MarkdownRenderer md={substituteTemplateVariables(character.personality, character.name)} />
							</div>
							<Button
								variant="ghost"
								size="sm"
								class="absolute -right-2 top-2 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
								onclick={handleEdit}
								aria-label="Edit personality"
							>
								<PencilEdit class="h-3 w-3" />
							</Button>
						</div>
					{/if}
					{#if character.greeting}
						<div class="group relative rounded-lg bg-muted/50 p-4">
							<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Greeting</h4>
							<div
								class="prose prose-sm dark:prose-invert max-w-none text-sm italic [&_*[style*='color']]:!text-foreground [&_p]:!text-foreground [&_span]:!text-foreground [&_strong]:!text-foreground"
							>
								<MarkdownRenderer md={substituteTemplateVariables(character.greeting, character.name)} />
							</div>
							<Button
								variant="ghost"
								size="sm"
								class="absolute -right-2 top-2 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
								onclick={handleEdit}
								aria-label="Edit greeting"
							>
								<PencilEdit class="h-3 w-3" />
							</Button>
						</div>
					{/if}
				</CardContent>
			</Card>
		{:else if character && isEditMode}
			<!-- Edit mode for character details -->
			<Card class="border-0 shadow-none">
				<CardContent class="space-y-4 px-0">
					<div>
						<label for="edit-scenario" class="text-sm font-medium">Scenario</label>
						<Textarea
							id="edit-scenario"
							bind:value={editedScenario}
							class="mt-1"
							placeholder="Character scenario"
							rows={4}
						/>
					</div>
					<div>
						<label for="edit-personality" class="text-sm font-medium">Personality</label>
						<Textarea
							id="edit-personality"
							bind:value={editedPersonality}
							class="mt-1"
							placeholder="Character personality"
							rows={4}
						/>
					</div>
					<div>
						<label for="edit-greeting" class="text-sm font-medium">Greeting</label>
						<Textarea
							id="edit-greeting"
							bind:value={editedGreeting}
							class="mt-1"
							placeholder="Character greeting message"
							rows={3}
						/>
					</div>
					<div class="flex gap-2">
						<Button onclick={handleSave} disabled={isSaving} class="gap-2">
							{#if isSaving}
								<div
									class="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
								></div>
								Saving...
							{:else}
								<CheckCircleFill class="h-4 w-4" />
								Save Changes
							{/if}
						</Button>
						<Button onclick={handleCancelEdit} variant="outline">Cancel</Button>
					</div>
				</CardContent>
			</Card>
		{/if}
	</div>
</div>

<!-- Delete Confirmation Dialog -->
<AlertDialog bind:open={deleteDialogOpen}>
	<AlertDialogContent>
		<AlertDialogHeader>
			<AlertDialogTitle>Delete Chat</AlertDialogTitle>
			<AlertDialogDescription>
				Are you sure you want to delete this chat? This action cannot be undone.
				{#if chatToDelete}
					<br />
					<strong class="mt-2 block"
						>"{chatToDelete.title || `Chat with ${character?.name}`}"</strong
					>
				{/if}
			</AlertDialogDescription>
		</AlertDialogHeader>
		<AlertDialogFooter>
			<AlertDialogCancel disabled={isDeletingChat}>Cancel</AlertDialogCancel>
			<AlertDialogAction
				onclick={confirmDelete}
				disabled={isDeletingChat}
				class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
			>
				{isDeletingChat ? 'Deleting...' : 'Delete'}
			</AlertDialogAction>
		</AlertDialogFooter>
	</AlertDialogContent>
</AlertDialog>

<style>
	/* Override inline styles from HTML content to respect theme */
	:global(.prose *[style*='color: #000000']),
	:global(.prose *[style*='color: rgb(0, 0, 0)']),
	:global(.prose *[style*='color:#000000']),
	:global(.prose *[style*='color:rgb(0,0,0)']) {
		color: hsl(var(--foreground)) !important;
	}

	/* Ensure text remains visible in both themes */
	:global(.prose p),
	:global(.prose span),
	:global(.prose strong) {
		color: hsl(var(--foreground)) !important;
	}

	/* Properly style centered text */
	:global(.prose p[style*='text-align: center']) {
		margin-top: 1rem;
		margin-bottom: 1rem;
	}
</style>
