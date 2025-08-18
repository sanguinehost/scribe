<script lang="ts">
	import { goto } from '$app/navigation';
	import { apiClient } from '$lib/api';
	import { env } from '$env/dynamic/public';
	import type {
		Character,
		ScribeChatSession,
		UserPersona,
		ChronicleAction,
		ChatDeletionAnalysisResponse
	} from '$lib/types';
	import { getCurrentUser } from '$lib/auth.svelte';
	import { toast } from 'svelte-sonner';
	import DOMPurify from 'dompurify';
	// Removed transitions - handled at container level in messages.svelte
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Textarea } from '$lib/components/ui/textarea';
	import { Card, CardHeader, CardContent } from '$lib/components/ui/card';
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
	let deletionAnalysis = $state<ChatDeletionAnalysisResponse | null>(null);
	let selectedAction = $state<ChronicleAction>('delete_events');
	let analysisLoading = $state(false);

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

	async function handleDeleteClick(e: MouseEvent, chat: ScribeChatSession) {
		e.stopPropagation(); // Prevent triggering the chat selection
		chatToDelete = chat;

		// Reset previous state
		deletionAnalysis = null;
		selectedAction = 'delete_events';

		// If shift key is held, skip confirmation
		if (e.shiftKey) {
			confirmDelete();
		} else {
			// Fetch deletion analysis first
			analysisLoading = true;
			deleteDialogOpen = true;

			try {
				const result = await apiClient.getChatDeletionAnalysis(chat.id);
				if (result.isOk()) {
					deletionAnalysis = result.value;
					if (deletionAnalysis.has_chronicle && deletionAnalysis.chronicle?.can_delete_chronicle) {
						selectedAction = 'delete_events'; // Conservative default
					} else {
						selectedAction = 'delete_events';
					}
				} else {
					// If analysis fails, fall back to simple deletion
					deletionAnalysis = { has_chronicle: false };
				}
			} catch (error) {
				console.error('Error fetching deletion analysis:', error);
				deletionAnalysis = { has_chronicle: false };
			} finally {
				analysisLoading = false;
			}
		}
	}

	async function confirmDelete() {
		if (!chatToDelete) return;

		isDeletingChat = true;
		try {
			const action = deletionAnalysis?.has_chronicle ? selectedAction : undefined;
			const result = await apiClient.deleteChatById(chatToDelete.id, action);
			if (result.isOk()) {
				// Remove the chat from both lists
				chats = chats.filter((c) => c.id !== chatToDelete!.id);
				allChats = allChats.filter((c) => c.id !== chatToDelete!.id);

				// Show appropriate success message based on action
				if (action === 'delete_chronicle') {
					toast.success('Chat and chronicle deleted successfully');
					// Notify other components that a chronicle was deleted
					if (deletionAnalysis?.chronicle?.id) {
						window.dispatchEvent(
							new CustomEvent('chronicle-deleted', {
								detail: { chronicleId: deletionAnalysis.chronicle.id }
							})
						);
					}
				} else if (action === 'disassociate') {
					toast.success('Chat deleted, chronicle preserved');
				} else {
					toast.success('Chat deleted successfully');
				}
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
			deletionAnalysis = null;
			selectedAction = 'delete_events';
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

<div class="mx-auto flex h-[90vh] max-w-7xl flex-col gap-6 px-4">
	<div
		class="flex min-h-0 flex-1 flex-col gap-6"
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
								class="gap-2"
								onclick={() => goto('/chronicles?character=' + characterId)}
								title="View character's chronicles"
							>
								<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path
										stroke-linecap="round"
										stroke-linejoin="round"
										stroke-width="2"
										d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"
									/>
								</svg>
								Chronicles
							</Button>
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
			<div class="grid min-h-0 flex-1 grid-cols-1 gap-6 md:grid-cols-5">
				<!-- Left Column: Recent Chats & Character Details (2/5 width) -->
				<div class="flex flex-col gap-4 md:col-span-2 md:min-h-0">
					<!-- Recent Chats -->
					<Card class="flex flex-col shadow-sm md:min-h-0 md:flex-1">
						<CardHeader class="pb-3">
							<h3 class="text-lg font-semibold">Recent Chats</h3>
						</CardHeader>
						<CardContent class="flex-1 overflow-y-auto pt-0">
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
						<Card class="flex flex-col shadow-sm md:min-h-0 md:flex-1">
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
													<path
														stroke-linecap="round"
														stroke-linejoin="round"
														stroke-width="2"
														d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"
													/>
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
							<CardContent class="flex-1 overflow-y-auto pt-0">
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
												substituteTemplateVariables(character.scenario, character.name)
											)}
										{:else}
											<MarkdownRenderer
												md={substituteTemplateVariables(character.scenario, character.name)}
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
						<Card class="flex flex-col shadow-sm md:min-h-0 md:flex-1">
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
													<path
														stroke-linecap="round"
														stroke-linejoin="round"
														stroke-width="2"
														d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"
													/>
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
							<CardContent class="flex-1 overflow-y-auto pt-0">
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
												substituteTemplateVariables(character.personality, character.name)
											)}
										{:else}
											<MarkdownRenderer
												md={substituteTemplateVariables(character.personality, character.name)}
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
						<Card class="flex flex-col shadow-sm md:min-h-0 md:flex-1">
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
													<path
														stroke-linecap="round"
														stroke-linejoin="round"
														stroke-width="2"
														d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"
													/>
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
							<CardContent class="flex-1 overflow-y-auto pt-0">
								{#if editingField !== 'description'}
									<div
										class="prose prose-sm dark:prose-invert max-w-none pb-6 [&_*]:!text-foreground"
									>
										{#if containsHtml(character.description)}
											<!-- eslint-disable-next-line svelte/no-at-html-tags -->
											{@html sanitizeHtml(
												substituteTemplateVariables(character.description || '', character.name)
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
		<div class="max-h-[90vh] w-full max-w-4xl overflow-auto rounded-lg bg-background shadow-lg">
			<div class="sticky top-0 flex items-center justify-between border-b bg-background p-4">
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
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="2"
							d="M6 18L18 6M6 6l12 12"
						/>
					</svg>
				</Button>
			</div>
			<div class="p-6">
				<div class="prose prose-sm dark:prose-invert max-w-none [&_*]:!text-foreground">
					{#if containsHtml(character.description)}
						<!-- eslint-disable-next-line svelte/no-at-html-tags -->
						{@html sanitizeHtml(substituteTemplateVariables(character.description, character.name))}
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
		<div class="max-h-[90vh] w-full max-w-4xl overflow-auto rounded-lg bg-background shadow-lg">
			<div class="sticky top-0 flex items-center justify-between border-b bg-background p-4">
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
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="2"
							d="M6 18L18 6M6 6l12 12"
						/>
					</svg>
				</Button>
			</div>
			<div class="p-6">
				<div class="prose prose-sm dark:prose-invert max-w-none [&_*]:!text-foreground">
					{#if containsHtml(character.scenario)}
						<!-- eslint-disable-next-line svelte/no-at-html-tags -->
						{@html sanitizeHtml(substituteTemplateVariables(character.scenario, character.name))}
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
		<div class="max-h-[90vh] w-full max-w-4xl overflow-auto rounded-lg bg-background shadow-lg">
			<div class="sticky top-0 flex items-center justify-between border-b bg-background p-4">
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
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="2"
							d="M6 18L18 6M6 6l12 12"
						/>
					</svg>
				</Button>
			</div>
			<div class="p-6">
				<div class="prose prose-sm dark:prose-invert max-w-none [&_*]:!text-foreground">
					{#if containsHtml(character.personality)}
						<!-- eslint-disable-next-line svelte/no-at-html-tags -->
						{@html sanitizeHtml(substituteTemplateVariables(character.personality, character.name))}
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
	<AlertDialogContent class="max-w-lg">
		<AlertDialogHeader>
			<AlertDialogTitle>Delete Chat</AlertDialogTitle>
			<AlertDialogDescription class="text-left">
				{#if chatToDelete}
					<strong class="mb-3 block"
						>"{chatToDelete.title || `Chat with ${character?.name}`}"</strong
					>
				{/if}

				{#if analysisLoading}
					<div class="flex items-center space-x-2 py-4">
						<div class="h-4 w-4 animate-spin rounded-full border-b-2 border-blue-600"></div>
						<span>Analyzing chronicle relationships...</span>
					</div>
				{:else if deletionAnalysis?.has_chronicle && deletionAnalysis?.chronicle}
					<div
						class="mb-4 rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/30"
					>
						<div class="mb-2 flex items-center space-x-2">
							<span class="text-amber-600 dark:text-amber-400">📚</span>
							<span class="font-medium text-amber-800 dark:text-amber-200">
								Chronicle: "{deletionAnalysis.chronicle.name}"
							</span>
						</div>
						<div class="space-y-1 text-sm text-amber-700 dark:text-amber-300">
							<p>• {deletionAnalysis.chronicle.total_events} total events</p>
							<p>• {deletionAnalysis.chronicle.events_from_this_chat} events from this chat</p>
							{#if deletionAnalysis.chronicle.other_chats_using_chronicle > 0}
								<p>
									• {deletionAnalysis.chronicle.other_chats_using_chronicle} other chats use this chronicle
								</p>
							{/if}
						</div>
					</div>

					<div class="space-y-3">
						<p class="text-sm font-medium">What would you like to do?</p>

						<div class="space-y-2">
							<label class="flex cursor-pointer items-start space-x-3">
								<input
									type="radio"
									bind:group={selectedAction}
									value="delete_events"
									class="mt-1"
								/>
								<div class="flex-1">
									<div class="font-medium">Delete chat & its events</div>
									<div class="text-xs text-gray-600 dark:text-gray-400">
										Keep chronicle, remove {deletionAnalysis.chronicle.events_from_this_chat} events
										from this chat
									</div>
								</div>
							</label>

							<label class="flex cursor-pointer items-start space-x-3">
								<input type="radio" bind:group={selectedAction} value="disassociate" class="mt-1" />
								<div class="flex-1">
									<div class="font-medium">Keep chronicle & all events</div>
									<div class="text-xs text-gray-600 dark:text-gray-400">
										Only delete the chat, preserve all narrative history
									</div>
								</div>
							</label>

							{#if deletionAnalysis.chronicle.can_delete_chronicle}
								<label class="flex cursor-pointer items-start space-x-3">
									<input
										type="radio"
										bind:group={selectedAction}
										value="delete_chronicle"
										class="mt-1"
									/>
									<div class="flex-1">
										<div class="font-medium text-red-700 dark:text-red-400">
											Delete entire chronicle
										</div>
										<div class="text-xs text-red-600 dark:text-red-500">
											⚠️ Permanently delete all {deletionAnalysis.chronicle.total_events} events
										</div>
									</div>
								</label>
							{:else}
								<div class="flex items-start space-x-3 opacity-50">
									<input type="radio" disabled class="mt-1" />
									<div class="flex-1">
										<div class="font-medium text-gray-500">Delete entire chronicle</div>
										<div class="text-xs text-gray-500">
											Cannot delete - other chats use this chronicle
										</div>
									</div>
								</div>
							{/if}
						</div>
					</div>
				{:else}
					This action cannot be undone. This will permanently delete your chat and remove it from
					our servers.
				{/if}
			</AlertDialogDescription>
		</AlertDialogHeader>
		<AlertDialogFooter>
			<AlertDialogCancel disabled={isDeletingChat || analysisLoading}>Cancel</AlertDialogCancel>
			<AlertDialogAction
				onclick={confirmDelete}
				disabled={isDeletingChat || analysisLoading}
				class={selectedAction === 'delete_chronicle'
					? 'bg-red-600 hover:bg-red-700 focus:ring-red-600'
					: 'bg-destructive text-destructive-foreground hover:bg-destructive/90'}
			>
				{#if isDeletingChat}
					Deleting...
				{:else if analysisLoading}
					Please wait...
				{:else if selectedAction === 'delete_chronicle'}
					Delete Chronicle
				{:else if selectedAction === 'disassociate'}
					Keep Chronicle
				{:else if selectedAction === 'delete_events'}
					Delete Chat & Events
				{:else}
					Delete Chat
				{/if}
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
