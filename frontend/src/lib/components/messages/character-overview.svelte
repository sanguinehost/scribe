<script lang="ts">
	import { goto } from '$app/navigation';
	import { apiClient } from '$lib/api';
	import { env } from '$env/dynamic/public';
	import type { Character, ScribeChatSession, UserPersona } from '$lib/types';
	import { getCurrentUser } from '$lib/auth.svelte';
	import { toast } from 'svelte-sonner';
	import DOMPurify from 'dompurify';
	// Removed transitions - handled at container level in messages.svelte
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Textarea } from '$lib/components/ui/textarea';
	import {
		Card,
		CardHeader,
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
	let popoutFieldLabel = $state('');
	let popoutContent = $state('');


	// Full-screen states
	let descriptionFullScreen = $state(false);
	let scenarioFullScreen = $state(false);
	let personalityFullScreen = $state(false);


	// User persona for template substitution
	let currentUserPersona = $state<UserPersona | null>(null);
	let userPersonaName = $state('User'); // Fallback to 'User'

	function getInitials(name: string): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Create properly formatted avatar URL
	const characterAvatarSrc = $derived.by(() => {
		if (!character?.avatar) return null;

		// If avatar already has a full URL, use it as-is
		if (character.avatar.startsWith('http://') || character.avatar.startsWith('https://')) {
			return character.avatar;
		}

		// Otherwise, prepend the API URL
		const apiBaseUrl = (env.PUBLIC_API_URL || '').trim();
		return `${apiBaseUrl}${character.avatar}`;
	});

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

	// Check if content contains HTML tags
	function containsHtml(text: string | null | undefined): boolean {
		if (!text) return false;
		return /<[^>]*>/g.test(text);
	}

	// Text truncation utilities

	// Secure HTML sanitization using DOMPurify
	function sanitizeHtml(html: string | null | undefined): string {
		if (!html) return '';

		// Configure DOMPurify to allow safe formatting tags while removing dangerous content
		return DOMPurify.sanitize(html, {
			ALLOWED_TAGS: [
				'p',
				'br',
				'strong',
				'em',
				'i',
				'b',
				'span',
				'div',
				'h1',
				'h2',
				'h3',
				'h4',
				'h5',
				'h6'
			],
			ALLOWED_ATTR: ['style'],
			ALLOW_DATA_ATTR: false,
			// Remove any remaining black/white color styles that don't work with themes
			SANITIZE_DOM: true,
			KEEP_CONTENT: true
		});
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
				chat_mode: 'Character', // Character mode for character-based chats
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


	function getMostRecentChat(): ScribeChatSession | null {
		if (allChats.length === 0) return null;
		return allChats[0]; // Assuming chats are sorted by creation date descending
	}

	function openPopoutEditor(_fieldName: string, fieldLabel: string, currentValue: string) {
		popoutFieldLabel = fieldLabel;
		popoutContent = currentValue || '';
		popoutEditorOpen = true;
	}

	function savePopoutEditor() {
		editValue = popoutContent;
		popoutEditorOpen = false;
		popoutFieldLabel = '';
		popoutContent = '';
	}

	function cancelPopoutEditor() {
		popoutEditorOpen = false;
		popoutFieldLabel = '';
		popoutContent = '';
	}

	// Track the last loaded character ID to prevent unnecessary reloads
	let lastLoadedCharacterId = $state<string | null>(null);
	let isTransitioning = $state(false);

	// Only reload data when characterId actually changes
	$effect(() => {
		if (characterId && characterId !== lastLoadedCharacterId) {
			if (lastLoadedCharacterId !== null) {
				// This is a character change, trigger transition
				isTransitioning = true;
				setTimeout(() => {
					loadCharacterData();
					setTimeout(() => {
						isTransitioning = false;
					}, 100);
				}, 200);
			} else {
				// Initial load
				loadCharacterData();
			}
			lastLoadedCharacterId = characterId;
		}
	});
</script>

<div class="mx-auto max-w-7xl px-4 h-[90vh] flex flex-col gap-6">
	<div
		class="flex-1 min-h-0 flex flex-col gap-6"
		style="opacity: {isTransitioning ? 0.3 : 1}; transition: opacity 300ms ease-in-out;"
	>
		<!-- Compact Character Header -->
		{#if isLoadingCharacter}
			<Card class="border-0 shadow-sm">
				<CardHeader class="py-4">
					<div class="flex items-center gap-4">
						<Skeleton class="h-16 w-16 rounded-full" />
						<div class="flex-1 space-y-2">
							<Skeleton class="h-7 w-1/2" />
							<Skeleton class="h-4 w-3/4" />
						</div>
						<div class="flex gap-2">
							<Skeleton class="h-10 w-32" />
							<Skeleton class="h-10 w-24" />
						</div>
					</div>
				</CardHeader>
			</Card>
		{:else if character}
			<!-- Compact Character Header -->
			<Card class="border-0 shadow-sm">
				<CardHeader class="py-4">
					<div class="flex items-center gap-4">
						<!-- Compact Avatar -->
						<Avatar class="h-16 w-16 border-2 border-muted">
							{#if characterAvatarSrc}
								<AvatarImage src={characterAvatarSrc} alt={character.name} />
							{/if}
							<AvatarFallback class="text-xl font-semibold">
								{getInitials(character.name)}
							</AvatarFallback>
						</Avatar>

						<!-- Character Name and Inline Edit -->
						<div class="min-w-0 flex-1">
							{#if editingField !== 'name'}
								<div class="group relative">
									<h1 class="truncate text-2xl font-bold">{character.name}</h1>
									<Button
										variant="ghost"
										size="sm"
										class="absolute -right-2 top-0 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
										onclick={() => handleEditField('name', character?.name || '')}
										aria-label="Edit character name"
									>
										<PencilEdit class="h-3 w-3" />
									</Button>
								</div>
							{:else}
								<div class="space-y-2">
									<Input
										bind:value={editValue}
										class="h-auto py-1 text-2xl font-bold"
										placeholder="Character name"
										onfocus={(e) => (e.target as HTMLInputElement)?.select()}
										onkeydown={(e) => {
											if (e.key === 'Enter') handleSaveField();
											if (e.key === 'Escape') handleCancelEdit();
										}}
									/>
									<div class="flex gap-2">
										<Button onclick={handleSaveField} disabled={isSaving} size="sm" class="gap-2">
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
							<p class="mt-1 text-sm text-muted-foreground">
								{allChats.length} conversation{allChats.length !== 1 ? 's' : ''}
							</p>
						</div>

						<!-- Primary Actions -->
						<div class="flex flex-shrink-0 gap-2">
							<Button onclick={handleStartNewChat} size="default" class="gap-2">
								<PlusIcon class="h-4 w-4" />
								New Chat
							</Button>
							{#if getMostRecentChat()}
								<Button
									variant="outline"
									size="default"
									class="gap-2"
									onclick={() => handleSelectChat(getMostRecentChat()!.id)}
								>
									<MessageIcon class="h-4 w-4" />
									Continue
								</Button>
							{/if}
							<Button
								variant="outline"
								size="default"
								class="gap-1"
								onclick={() => {
									characterEditorOpen = true;
								}}
							>
								<SettingsIcon class="h-4 w-4" />
								Edit
							</Button>
						</div>
					</div>
				</CardHeader>
			</Card>

			<!-- Two-Column Layout -->
			<div class="grid grid-cols-1 gap-6 md:grid-cols-5 flex-1 min-h-0">
				<!-- Left Column: Recent Chats & Character Details (2/5 width) -->
				<div class="flex flex-col gap-4 md:col-span-2 md:min-h-0">
					<!-- Recent Chats -->
					<Card class="shadow-sm flex flex-col md:flex-1 md:min-h-0">
						<CardHeader class="pb-3">
							<h3 class="text-lg font-semibold">Recent Chats</h3>
						</CardHeader>
						<CardContent class="pt-0 flex-1 overflow-y-auto">
							{#if isLoadingChats}
								<div class="space-y-2">
									{#each Array(3) as _}
										<div class="flex items-center gap-3 p-2">
											<Skeleton class="h-2 w-2 rounded-full" />
											<div class="flex-1 space-y-1">
												<Skeleton class="h-4 w-3/4" />
												<Skeleton class="h-3 w-1/4" />
											</div>
										</div>
									{/each}
								</div>
							{:else if chats.length === 0}
								<div class="py-8 text-center">
									<MessageIcon class="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
									<p class="text-sm text-muted-foreground">No conversations yet</p>
								</div>
							{:else}
								<div class="space-y-1">
									{#each chats as chat}
										<div
											class="group cursor-pointer rounded-md p-2 transition-colors hover:bg-muted/50"
											onclick={() => handleSelectChat(chat.id)}
											onkeydown={(e) => e.key === 'Enter' && handleSelectChat(chat.id)}
											tabindex={0}
											role="button"
										>
											<div class="flex items-center gap-2">
												<div class="h-2 w-2 rounded-full bg-muted-foreground/50"></div>
												<div class="min-w-0 flex-1">
													<p class="truncate text-sm font-medium">
														{chat.title || `Chat with ${character?.name}`}
													</p>
													<p class="text-xs text-muted-foreground">
														{formatDate(chat.created_at)}
													</p>
												</div>
												<Button
													variant="ghost"
													size="sm"
													class="h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
													onclick={(e) => handleDeleteClick(e, chat)}
													aria-label="Delete chat"
												>
													<TrashIcon class="h-3 w-3 text-destructive" />
												</Button>
											</div>
										</div>
									{/each}
								</div>
							{/if}
						</CardContent>
					</Card>

					{#if character}
						<!-- Scenario Section -->
						<Card class="shadow-sm flex flex-col md:flex-1 md:min-h-0">
							<CardHeader class="pb-3">
								<div class="flex items-center justify-between">
									<h3 class="text-lg font-semibold">Scenario</h3>
									<div class="flex items-center gap-2">
										{#if character.scenario && editingField !== 'scenario'}
											<Button
												variant="ghost"
												size="sm"
												class="h-6 w-6 p-0"
												onclick={() => (scenarioFullScreen = true)}
												title="View full screen"
											>
												<svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
													<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
												</svg>
											</Button>
										{/if}
										<Button
											variant="ghost"
											size="sm"
											class="h-6 w-6 p-0"
											onclick={() => handleEditField('scenario', character?.scenario || '')}
											aria-label="Edit scenario"
										>
											<PencilEdit class="h-3 w-3" />
										</Button>
									</div>
								</div>
							</CardHeader>
							<CardContent class="pt-0 flex-1 overflow-y-auto">
								{#if editingField === 'scenario'}
									<div class="space-y-3">
										<div class="flex gap-2">
											<Textarea
												bind:value={editValue}
												placeholder="Character scenario"
												rows={calculateTextareaRows(character.scenario, 4)}
												onfocus={(e) => (e.target as HTMLTextAreaElement)?.select()}
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
												class="mt-1 self-start"
											>
												Expand
											</Button>
										</div>
										<div class="flex gap-2">
											<Button onclick={handleSaveField} disabled={isSaving} size="sm" class="gap-2">
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
								{:else if character.scenario}
									<div class="prose prose-sm dark:prose-invert max-w-none [&_*]:!text-foreground">
										{#if containsHtml(character.scenario)}
											<!-- eslint-disable-next-line svelte/no-at-html-tags -->
											{@html sanitizeHtml(
												substituteTemplateVariables(
													character.scenario,
													character.name
												)
											)}
										{:else}
											<MarkdownRenderer
												md={substituteTemplateVariables(
													character.scenario,
													character.name
												)}
											/>
										{/if}
									</div>
								{:else}
									<div class="py-8 text-center">
										<p class="mb-3 text-sm text-muted-foreground">No scenario defined</p>
										<Button
											variant="outline"
											size="sm"
											onclick={() => handleEditField('scenario', '')}
											class="gap-2"
										>
											<PencilEdit class="h-3 w-3" />
											Add Scenario
										</Button>
									</div>
								{/if}
							</CardContent>
						</Card>

						<!-- Personality Section -->
						<Card class="shadow-sm flex flex-col md:flex-1 md:min-h-0">
							<CardHeader class="pb-3">
								<div class="flex items-center justify-between">
									<h3 class="text-lg font-semibold">Personality</h3>
									<div class="flex items-center gap-2">
										{#if character.personality && editingField !== 'personality'}
											<Button
												variant="ghost"
												size="sm"
												class="h-6 w-6 p-0"
												onclick={() => (personalityFullScreen = true)}
												title="View full screen"
											>
												<svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
													<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
												</svg>
											</Button>
										{/if}
										<Button
											variant="ghost"
											size="sm"
											class="h-6 w-6 p-0"
											onclick={() => handleEditField('personality', character?.personality || '')}
											aria-label="Edit personality"
										>
											<PencilEdit class="h-3 w-3" />
										</Button>
									</div>
								</div>
							</CardHeader>
							<CardContent class="pt-0 flex-1 overflow-y-auto">
								{#if editingField === 'personality'}
									<div class="space-y-3">
										<div class="flex gap-2">
											<Textarea
												bind:value={editValue}
												placeholder="Character personality"
												rows={calculateTextareaRows(character.personality, 4)}
												onfocus={(e) => (e.target as HTMLTextAreaElement)?.select()}
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
												class="mt-1 self-start"
											>
												Expand
											</Button>
										</div>
										<div class="flex gap-2">
											<Button onclick={handleSaveField} disabled={isSaving} size="sm" class="gap-2">
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
								{:else if character.personality}
									<div class="prose prose-sm dark:prose-invert max-w-none [&_*]:!text-foreground">
										{#if containsHtml(character.personality)}
											<!-- eslint-disable-next-line svelte/no-at-html-tags -->
											{@html sanitizeHtml(
												substituteTemplateVariables(
													character.personality,
													character.name
												)
											)}
										{:else}
											<MarkdownRenderer
												md={substituteTemplateVariables(
													character.personality,
													character.name
												)}
											/>
										{/if}
									</div>
								{:else}
									<div class="py-8 text-center">
										<p class="mb-3 text-sm text-muted-foreground">No personality defined</p>
										<Button
											variant="outline"
											size="sm"
											onclick={() => handleEditField('personality', '')}
											class="gap-2"
										>
											<PencilEdit class="h-3 w-3" />
											Add Personality
										</Button>
									</div>
								{/if}
							</CardContent>
						</Card>
					{/if}
				</div>

				<!-- Right Column: Character Description (3/5 width) -->
				<div class="flex flex-col gap-4 md:col-span-3 md:min-h-0">
					{#if character.description || editingField === 'description'}
						<Card class="shadow-sm flex flex-col md:flex-1 md:min-h-0">
							<CardHeader class="pb-3">
								<div class="flex items-center justify-between">
									<h3 class="text-lg font-semibold">Description</h3>
									<div class="flex items-center gap-2">
										{#if character.description && editingField !== 'description'}
											<Button
												variant="ghost"
												size="sm"
												class="h-6 w-6 p-0"
												onclick={() => (descriptionFullScreen = true)}
												title="View full screen"
											>
												<svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
													<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
												</svg>
											</Button>
										{/if}
										<Button
											variant="ghost"
											size="sm"
											class="h-6 w-6 p-0"
											onclick={() => handleEditField('description', character?.description || '')}
											aria-label="Edit character description"
										>
											<PencilEdit class="h-3 w-3" />
										</Button>
									</div>
								</div>
							</CardHeader>
							<CardContent class="pt-0 flex-1 overflow-y-auto">
								{#if editingField !== 'description'}
									<div class="prose prose-sm dark:prose-invert max-w-none [&_*]:!text-foreground pb-6">
										{#if containsHtml(character.description)}
											<!-- eslint-disable-next-line svelte/no-at-html-tags -->
											{@html sanitizeHtml(
												substituteTemplateVariables(
													character.description || '',
													character.name
												)
											)}
										{:else}
											<MarkdownRenderer
												md={substituteTemplateVariables(
													character.description || '',
													character.name
												)}
											/>
										{/if}
									</div>
								{:else}
									<div class="space-y-3">
										<div class="flex gap-2">
											<Textarea
												bind:value={editValue}
												placeholder="Character description"
												rows={calculateTextareaRows(character.description, 8)}
												onfocus={(e) => (e.target as HTMLTextAreaElement)?.select()}
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
												class="mt-1 self-start"
											>
												Expand
											</Button>
										</div>
										<div class="flex gap-2">
											<Button onclick={handleSaveField} disabled={isSaving} size="sm" class="gap-2">
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
							</CardContent>
						</Card>
					{:else}
						<Card class="border-dashed shadow-sm">
							<CardContent class="py-8 text-center">
								<p class="mb-3 text-muted-foreground">No description available</p>
								<Button
									variant="outline"
									size="sm"
									onclick={() => handleEditField('description', '')}
									class="gap-2"
								>
									<PencilEdit class="h-3 w-3" />
									Add Description
								</Button>
							</CardContent>
						</Card>
					{/if}
				</div>
			</div>
{/if}
	</div>
</div>

<!-- Full-Screen Description Modal -->
{#if descriptionFullScreen && character?.description}
	<div
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4"
		onclick={(e) => {
			if (e.target === e.currentTarget) descriptionFullScreen = false;
		}}
		onkeydown={(e) => {
			if (e.key === 'Escape') descriptionFullScreen = false;
		}}
		tabindex="0"
		role="dialog"
		aria-modal="true"
		aria-labelledby="description-title"
	>
		<div class="w-full max-w-4xl max-h-[90vh] overflow-auto bg-background rounded-lg shadow-lg">
			<div class="sticky top-0 bg-background border-b p-4 flex items-center justify-between">
				<h2 id="description-title" class="text-xl font-semibold">
					{character.name} - Description
				</h2>
				<Button
					variant="ghost"
					size="sm"
					onclick={() => (descriptionFullScreen = false)}
					class="h-8 w-8 p-0"
				>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
					</svg>
				</Button>
			</div>
			<div class="p-6">
				<div class="prose prose-sm dark:prose-invert max-w-none [&_*]:!text-foreground">
					{#if containsHtml(character.description)}
						<!-- eslint-disable-next-line svelte/no-at-html-tags -->
						{@html sanitizeHtml(
							substituteTemplateVariables(character.description, character.name)
						)}
					{:else}
						<MarkdownRenderer
							md={substituteTemplateVariables(character.description || '', character.name)}
						/>
					{/if}
				</div>
			</div>
		</div>
	</div>
{/if}

<!-- Full-Screen Scenario Modal -->
{#if scenarioFullScreen && character?.scenario}
	<div
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4"
		onclick={(e) => {
			if (e.target === e.currentTarget) scenarioFullScreen = false;
		}}
		onkeydown={(e) => {
			if (e.key === 'Escape') scenarioFullScreen = false;
		}}
		tabindex="0"
		role="dialog"
		aria-modal="true"
		aria-labelledby="scenario-title"
	>
		<div class="w-full max-w-4xl max-h-[90vh] overflow-auto bg-background rounded-lg shadow-lg">
			<div class="sticky top-0 bg-background border-b p-4 flex items-center justify-between">
				<h2 id="scenario-title" class="text-xl font-semibold">
					{character.name} - Scenario
				</h2>
				<Button
					variant="ghost"
					size="sm"
					onclick={() => (scenarioFullScreen = false)}
					class="h-8 w-8 p-0"
				>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
					</svg>
				</Button>
			</div>
			<div class="p-6">
				<div class="prose prose-sm dark:prose-invert max-w-none [&_*]:!text-foreground">
					{#if containsHtml(character.scenario)}
						<!-- eslint-disable-next-line svelte/no-at-html-tags -->
						{@html sanitizeHtml(
							substituteTemplateVariables(character.scenario, character.name)
						)}
					{:else}
						<MarkdownRenderer
							md={substituteTemplateVariables(character.scenario || '', character.name)}
						/>
					{/if}
				</div>
			</div>
		</div>
	</div>
{/if}

<!-- Full-Screen Personality Modal -->
{#if personalityFullScreen && character?.personality}
	<div
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4"
		onclick={(e) => {
			if (e.target === e.currentTarget) personalityFullScreen = false;
		}}
		onkeydown={(e) => {
			if (e.key === 'Escape') personalityFullScreen = false;
		}}
		tabindex="0"
		role="dialog"
		aria-modal="true"
		aria-labelledby="personality-title"
	>
		<div class="w-full max-w-4xl max-h-[90vh] overflow-auto bg-background rounded-lg shadow-lg">
			<div class="sticky top-0 bg-background border-b p-4 flex items-center justify-between">
				<h2 id="personality-title" class="text-xl font-semibold">
					{character.name} - Personality
				</h2>
				<Button
					variant="ghost"
					size="sm"
					onclick={() => (personalityFullScreen = false)}
					class="h-8 w-8 p-0"
				>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
					</svg>
				</Button>
			</div>
			<div class="p-6">
				<div class="prose prose-sm dark:prose-invert max-w-none [&_*]:!text-foreground">
					{#if containsHtml(character.personality)}
						<!-- eslint-disable-next-line svelte/no-at-html-tags -->
						{@html sanitizeHtml(
							substituteTemplateVariables(character.personality, character.name)
						)}
					{:else}
						<MarkdownRenderer
							md={substituteTemplateVariables(character.personality || '', character.name)}
						/>
					{/if}
				</div>
			</div>
		</div>
	</div>
{/if}

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

	:global(.prose p),
	:global(.prose span),
	:global(.prose strong) {
		color: hsl(var(--foreground)) !important;
	}

	:global(.prose p[style*='text-align: center']) {
		margin-top: 1rem;
		margin-bottom: 1rem;
	}
</style>
