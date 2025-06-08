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
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogHeader,
		DialogTitle,
		DialogFooter
	} from '$lib/components/ui/dialog';
	import PlusIcon from '../icons/plus.svelte';
	import MessageIcon from '../icons/message.svelte';
	import TrashIcon from '../icons/trash.svelte';
	import PencilEdit from '../icons/pencil-edit.svelte';
	import CheckCircleFill from '../icons/check-circle-fill.svelte';
	import SettingsIcon from '../icons/settings.svelte';
	import MarkdownRenderer from '../markdown/renderer.svelte';
	import CharacterEditor from '../CharacterEditor.svelte';

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

	// Individual field editing states
	let editingField = $state<string | null>(null);
	let isSaving = $state(false);
	let editValue = $state('');

	// Character editor dialog state
	let characterEditorOpen = $state(false);

	// Pop-out editor state for inline editing
	let popoutEditorOpen = $state(false);
	let popoutFieldName = $state('');
	let popoutFieldLabel = $state('');
	let popoutContent = $state('');

	// User persona for template substitution
	let currentUserPersona = $state<UserPersona | null>(null);
	let userPersonaName = $state('User'); // Fallback to 'User'

	function getInitials(name: string): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Calculate appropriate textarea rows based on content
	function calculateTextareaRows(content: string | null | undefined, minRows = 3): number {
		if (!content) return minRows;
		
		// Count actual line breaks in the content
		const lineBreaks = (content.match(/\n/g) || []).length + 1;
		
		// Estimate additional lines based on text length (assuming ~80 characters per line)
		const estimatedWrappedLines = Math.ceil(content.length / 80);
		
		// Use the larger of actual lines or estimated wrapped lines, with a minimum
		const calculatedRows = Math.max(lineBreaks, estimatedWrappedLines, minRows);
		
		// Cap at a reasonable maximum to prevent huge textareas
		return Math.min(calculatedRows, 15);
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
			// Character loaded successfully
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

	function handleEditField(fieldName: string, currentValue: string) {
		if (!character) return;
		editingField = fieldName;
		editValue = currentValue || '';
	}

	function handleCancelEdit() {
		editingField = null;
		editValue = '';
	}

	async function handleSaveField() {
		if (!character || !editingField) return;

		isSaving = true;

		try {
			const updateData: any = {};
			const trimmedValue = editValue.trim();
			let currentValue: string | null = null;

			// Get current value and set update data based on field
			switch (editingField) {
				case 'name':
					currentValue = character.name || '';
					if (trimmedValue !== currentValue && trimmedValue) {
						updateData.name = trimmedValue;
					}
					break;
				case 'description':
					currentValue = character.description || '';
					if (trimmedValue !== currentValue) {
						updateData.description = trimmedValue;
					}
					break;
				case 'scenario':
					currentValue = character.scenario || '';
					if (trimmedValue !== currentValue) {
						updateData.scenario = trimmedValue;
					}
					break;
				case 'personality':
					currentValue = character.personality || '';
					if (trimmedValue !== currentValue) {
						updateData.personality = trimmedValue;
					}
					break;
			}

			// Only make API call if there are changes
			if (Object.keys(updateData).length > 0) {
				const result = await apiClient.updateCharacter(character.id, updateData);
				if (result.isOk()) {
					// Update local character data
					switch (editingField) {
						case 'name':
							character.name = trimmedValue;
							break;
						case 'description':
							character.description = trimmedValue || null;
							break;
						case 'scenario':
							character.scenario = trimmedValue || null;
							break;
						case 'personality':
							character.personality = trimmedValue || null;
							break;
					}

					toast.success('Character updated successfully');
					editingField = null;
					editValue = '';
				} else {
					toast.error('Failed to update character: ' + result.error.message);
				}
			} else {
				// No changes, just exit edit mode
				editingField = null;
				editValue = '';
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

	function openPopoutEditor(fieldName: string, fieldLabel: string, currentValue: string) {
		popoutFieldName = fieldName;
		popoutFieldLabel = fieldLabel;
		popoutContent = currentValue || '';
		popoutEditorOpen = true;
	}

	function savePopoutEditor() {
		editValue = popoutContent;
		popoutEditorOpen = false;
		popoutFieldName = '';
		popoutFieldLabel = '';
		popoutContent = '';
	}

	function cancelPopoutEditor() {
		popoutEditorOpen = false;
		popoutFieldName = '';
		popoutFieldLabel = '';
		popoutContent = '';
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
								{#if editingField !== 'name'}
									<div class="group relative">
										<h2 class="text-3xl font-bold">{character.name}</h2>
										<Button
											variant="ghost"
											size="sm"
											class="absolute -right-8 top-0 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
											onclick={() => handleEditField('name', character.name)}
											aria-label="Edit character name"
										>
											<PencilEdit class="h-3 w-3" />
										</Button>
									</div>
								{:else}
									<div class="space-y-2">
										<Input
											bind:value={editValue}
											class="text-3xl font-bold h-auto py-2"
											placeholder="Character name"
											onfocus={(e) => e.target.select()}
											onkeydown={(e) => {
												if (e.key === 'Enter') handleSaveField();
												if (e.key === 'Escape') handleCancelEdit();
											}}
										/>
										<div class="flex gap-2">
											<Button onclick={handleSaveField} disabled={isSaving} size="sm" class="gap-2">
												{#if isSaving}
													<div class="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"></div>
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
										<Button
											variant="outline"
											size="lg"
											class="gap-2"
											onclick={() => { characterEditorOpen = true; }}
										>
											<SettingsIcon class="h-4 w-4" />
											Edit Character
										</Button>
									</div>
									{#if character.description && editingField !== 'description'}
										<div class="group relative mt-2">
											<div class="text-muted-foreground prose prose-sm dark:prose-invert max-w-none [&_*]:!text-muted-foreground">
												<MarkdownRenderer md={substituteTemplateVariables(character.description, character.name)} />
											</div>
											<Button
												variant="ghost"
												size="sm"
												class="absolute -right-8 top-0 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
												onclick={() => handleEditField('description', character.description)}
												aria-label="Edit character description"
											>
												<PencilEdit class="h-3 w-3" />
											</Button>
										</div>
									{:else if !character.description && editingField !== 'description'}
										<div class="group relative mt-2">
											<div class="text-muted-foreground italic text-sm">No description</div>
											<Button
												variant="ghost"
												size="sm"
												class="absolute -right-8 top-0 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
												onclick={() => handleEditField('description', '')}
												aria-label="Add character description"
											>
												<PencilEdit class="h-3 w-3" />
											</Button>
										</div>
									{:else if editingField === 'description'}
										<div class="space-y-2 mt-2">
											<div class="flex gap-2">
												<Textarea
													bind:value={editValue}
													placeholder="Character description"
													rows={calculateTextareaRows(character.description, 3)}
													onfocus={(e) => e.target.select()}
													onkeydown={(e) => {
														if (e.key === 'Escape') handleCancelEdit();
														if (e.key === 'Enter' && e.ctrlKey) handleSaveField();
													}}
													class="flex-1"
												/>
												<Button
													variant="outline"
													size="sm"
													onclick={() => openPopoutEditor('description', 'Description', editValue)}
													class="self-start mt-1"
												>
													Expand
												</Button>
											</div>
											<div class="flex gap-2">
												<Button onclick={handleSaveField} disabled={isSaving} size="sm" class="gap-2">
													{#if isSaving}
														<div class="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"></div>
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

		<!-- Character Details Section ---->
		{#if character}
			<Card class="border-0 shadow-none">
				<CardContent class="space-y-4 px-0">
					<!-- Scenario Field -->
					{#if editingField === 'scenario'}
						<div class="rounded-lg bg-muted/50 p-4 space-y-2">
							<h4 class="text-sm font-semibold text-muted-foreground">Scenario</h4>
							<div class="flex gap-2">
								<Textarea
									bind:value={editValue}
									placeholder="Character scenario"
									rows={calculateTextareaRows(character.scenario, 4)}
									onfocus={(e) => e.target.select()}
									onkeydown={(e) => {
										if (e.key === 'Escape') handleCancelEdit();
										if (e.key === 'Enter' && e.ctrlKey) handleSaveField();
									}}
									class="flex-1"
								/>
								<Button
									variant="outline"
									size="sm"
									onclick={() => openPopoutEditor('scenario', 'Scenario', editValue)}
									class="self-start mt-1"
								>
									Expand
								</Button>
							</div>
							<div class="flex gap-2">
								<Button onclick={handleSaveField} disabled={isSaving} size="sm" class="gap-2">
									{#if isSaving}
										<div class="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"></div>
										Saving...
									{:else}
										<CheckCircleFill class="h-3 w-3" />
										Save
									{/if}
								</Button>
								<Button onclick={handleCancelEdit} variant="outline" size="sm">Cancel</Button>
							</div>
						</div>
					{:else if character.scenario}
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
								onclick={() => handleEditField('scenario', character.scenario)}
								aria-label="Edit scenario"
							>
								<PencilEdit class="h-3 w-3" />
							</Button>
						</div>
					{:else}
						<div class="group relative rounded-lg bg-muted/50 p-4">
							<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Scenario</h4>
							<div class="text-muted-foreground italic text-sm">No scenario defined</div>
							<Button
								variant="ghost"
								size="sm"
								class="absolute -right-2 top-2 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
								onclick={() => handleEditField('scenario', '')}
								aria-label="Add scenario"
							>
								<PencilEdit class="h-3 w-3" />
							</Button>
						</div>
					{/if}

					<!-- Personality Field -->
					{#if editingField === 'personality'}
						<div class="rounded-lg bg-muted/50 p-4 space-y-2">
							<h4 class="text-sm font-semibold text-muted-foreground">Personality</h4>
							<div class="flex gap-2">
								<Textarea
									bind:value={editValue}
									placeholder="Character personality"
									rows={calculateTextareaRows(character.personality, 4)}
									onfocus={(e) => e.target.select()}
									onkeydown={(e) => {
										if (e.key === 'Escape') handleCancelEdit();
										if (e.key === 'Enter' && e.ctrlKey) handleSaveField();
									}}
									class="flex-1"
								/>
								<Button
									variant="outline"
									size="sm"
									onclick={() => openPopoutEditor('personality', 'Personality', editValue)}
									class="self-start mt-1"
								>
									Expand
								</Button>
							</div>
							<div class="flex gap-2">
								<Button onclick={handleSaveField} disabled={isSaving} size="sm" class="gap-2">
									{#if isSaving}
										<div class="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"></div>
										Saving...
									{:else}
										<CheckCircleFill class="h-3 w-3" />
										Save
									{/if}
								</Button>
								<Button onclick={handleCancelEdit} variant="outline" size="sm">Cancel</Button>
							</div>
						</div>
					{:else if character.personality}
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
								onclick={() => handleEditField('personality', character.personality)}
								aria-label="Edit personality"
							>
								<PencilEdit class="h-3 w-3" />
							</Button>
						</div>
					{:else}
						<div class="group relative rounded-lg bg-muted/50 p-4">
							<h4 class="mb-2 text-sm font-semibold text-muted-foreground">Personality</h4>
							<div class="text-muted-foreground italic text-sm">No personality defined</div>
							<Button
								variant="ghost"
								size="sm"
								class="absolute -right-2 top-2 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
								onclick={() => handleEditField('personality', '')}
								aria-label="Add personality"
							>
								<PencilEdit class="h-3 w-3" />
							</Button>
						</div>
					{/if}

				</CardContent>
			</Card>
		{/if}
	</div>
</div>

<!-- Character Editor Dialog -->
{#if character}
	<CharacterEditor characterId={character.id} bind:open={characterEditorOpen} />
{/if}

<!-- Pop-out Editor Dialog for inline editing -->
<Dialog bind:open={popoutEditorOpen}>
	<DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-6xl">
		<DialogHeader>
			<DialogTitle>Edit {popoutFieldLabel}</DialogTitle>
			<DialogDescription>
				Edit the {popoutFieldLabel.toLowerCase()} content in a larger editor for better readability.
			</DialogDescription>
		</DialogHeader>

		<div class="py-4">
			<Textarea
				bind:value={popoutContent}
				placeholder={`Enter ${popoutFieldLabel.toLowerCase()} content...`}
				rows={20}
				class="min-h-[400px] resize-none font-mono text-sm"
			/>
		</div>

		<DialogFooter>
			<Button variant="outline" onclick={cancelPopoutEditor}>Cancel</Button>
			<Button onclick={savePopoutEditor}>Save Changes</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>

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
