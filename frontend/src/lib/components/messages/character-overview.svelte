<script lang="ts">
	import { resolve } from '$app/paths';
	import { goto as _goto } from '$app/navigation';
	import { apiClient as _apiClient } from '$lib/api';
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
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Textarea as TextareaComponent } from '$lib/components/ui/textarea';
	import { Card, CardHeader, CardContent } from '$lib/components/ui/card';
	import { Avatar, AvatarFallback, AvatarImage } from '$lib/components/ui/avatar';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import ImageLightbox from '$lib/components/ui/image-lightbox.svelte';
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

	// Appearance Editor state
	let appearanceEditorOpen = $state(false);
	let editBannerUrl = $state('');
	let editPrimaryColor = $state('');
	let editCardStyle = $state<'default' | 'dossier' | 'minimal' | 'terminal'>('dossier');

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

	// Image lightbox state
	let avatarLightboxOpen = $state(false);

	// User persona for template substitution
	let currentUserPersona = $state<UserPersona | null>(null);
	let userPersonaName = $derived(currentUserPersona?.name || 'User');

	function getInitials(name: string): string {
		return name ? name.charAt(0).toUpperCase() : '?';
	}

	// Extract visual metadata safely
	const visualMetadata = $derived.by(() => {
		if (!character?.extensions?.visual_metadata) return null;
		return character.extensions.visual_metadata as any;
	});

	const customPrimaryColor = $derived(visualMetadata?.primary_color);
	const heroBannerUrl = $derived(visualMetadata?.banner_url);
	const cssVars = $derived(customPrimaryColor ? `--char-primary: ${customPrimaryColor};` : '');
	const cardStyle = $derived(visualMetadata?.card_style || 'dossier');

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
				const personaResult = await _apiClient.getUserPersona(currentUser.default_persona_id);
				if (personaResult.isOk()) {
					currentUserPersona = personaResult.value;
				} else {
					console.warn('Failed to load user persona:', personaResult.error);
					// Create a fallback persona with username
					if (currentUser.username) {
						currentUserPersona = { name: currentUser.username } as UserPersona;
					}
				}
			} else if (currentUser?.username) {
				// Create a fallback persona with username
				currentUserPersona = { name: currentUser.username } as UserPersona;
			}
		} catch (_error) {
			console.warn('Error loading user persona:', _error);
			// currentUserPersona remains null, so userPersonaName will be 'User'
		}
	}

	async function loadCharacterData() {
		if (!characterId) return;

		isLoadingCharacter = true;
		isLoadingChats = true;

		// Load user persona first for template substitution
		await loadUserPersona();

		// Load character details
		const characterResult = await _apiClient.getCharacter(characterId);
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
		const chatsResult = await _apiClient.getChatsByCharacter(characterId);
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
			const updateData: Record<string, string> = {};
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
				const result = await _apiClient.updateCharacter(character.id, updateData);
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
		} catch (_error) {
			toast.error('Error updating character');
			console.error('Error updating character:', _error);
		} finally {
			isSaving = false;
		}
	}

	async function handleStartNewChat() {
		if (!character) return;

		try {
			const createChatResult = await _apiClient.createChat({
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
				await _goto(`/chat/${chat.id}`, { invalidateAll: true });
			} else {
				toast.error('Failed to start chat', {
					description: createChatResult.error.message
				});
			}
		} catch (_error) {
			console.error('Error starting chat:', _error);
			toast.error('An unexpected error occurred');
		}
	}

	function handleSelectChat(chatId: string) {
		_goto(resolve(`/chat/${chatId}`));
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
				const result = await _apiClient.getChatDeletionAnalysis(chat.id);
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
			} catch (_error) {
				console.error('Error fetching deletion analysis:', _error);
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
			const result = await _apiClient.deleteChatById(chatToDelete.id, action);
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
		} catch (_error) {
			console.error('Error deleting chat:', _error);
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

	function handleOpenAppearance() {
		editBannerUrl = visualMetadata?.banner_url || '';
		editPrimaryColor = visualMetadata?.primary_color || '';
		editCardStyle = visualMetadata?.card_style || 'dossier';
		appearanceEditorOpen = true;
	}

	async function handleSaveAppearance() {
		if (!character) return;
		
		isSaving = true;
		try {
			// Construct new extensions object safely
			const currentExtensions = character.extensions || {};
			const updatedVisualMetadata = {
				...(currentExtensions.visual_metadata || {}),
				banner_url: editBannerUrl || undefined,
				primary_color: editPrimaryColor || undefined,
				card_style: editCardStyle !== 'dossier' ? editCardStyle : undefined // dossier is default
			};
			
			const updatedExtensions = {
				...currentExtensions,
				visual_metadata: Object.keys(updatedVisualMetadata).filter(k => (updatedVisualMetadata as any)[k] !== undefined).length > 0 
					? updatedVisualMetadata 
					: undefined
			};
			
			const result = await _apiClient.updateCharacter(character.id, {
				extensions: updatedExtensions
			});
			
			if (result.isOk()) {
				character.extensions = updatedExtensions;
				toast.success('Appearance updated successfully');
				appearanceEditorOpen = false;
			} else {
				toast.error('Failed to update appearance: ' + result.error.message);
			}
		} catch (_error) {
			toast.error('Error updating appearance');
			console.error('Error updating appearance:', _error);
		} finally {
			isSaving = false;
		}
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

<div class="mx-auto flex h-[90vh] max-w-7xl flex-col gap-6 px-4 pt-6 pb-4">
	<div
		class="flex min-h-0 flex-1 flex-col gap-6"
		style="opacity: {isTransitioning ? 0.3 : 1}; transition: opacity 300ms ease-in-out;"
	>
		<!-- Compact Character Header -->
		{#if isLoadingCharacter}
			<Card class="border-border/10 shadow-sm bg-background/50 backdrop-blur-sm rounded-xl overflow-hidden mt-4">
				<CardHeader class="py-5 px-6">
					<div class="flex flex-col sm:flex-row sm:items-center gap-5">
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
			<!-- Dossier Character Header -->
			<Card 
				class="border-border/10 shadow-sm bg-background/50 backdrop-blur-sm rounded-xl overflow-hidden mt-4 transition-all duration-300 relative border-0 sm:border"
				style={cssVars}
			>
				<!-- Hero Banner Image or blurred background placeholder -->
				<div class="h-32 sm:h-48 w-full relative overflow-hidden bg-muted/30">
					{#if heroBannerUrl}
						<img src={heroBannerUrl} alt="Banner" class="w-full h-full object-cover" />
						<div class="absolute inset-0 bg-gradient-to-t from-background via-background/20 to-transparent"></div>
					{:else if characterAvatarSrc}
						<!-- Fallback to blurred avatar -->
						<img src={characterAvatarSrc} alt="" class="w-full h-full object-cover blur-[32px] scale-125 opacity-40 dark:opacity-30" />
						<div class="absolute inset-0 bg-gradient-to-t from-background via-background/50 to-background/10"></div>
					{:else}
						<div class="absolute inset-0 bg-gradient-to-br from-primary/10 to-primary/5"></div>
						<div class="absolute inset-0 bg-gradient-to-t from-background to-transparent"></div>
					{/if}
					
					<!-- Top Right Appearance Buttons -->
					<div class="absolute top-4 right-4 z-10 flex gap-2">
						<ButtonComponent variant="outline" size="sm" class="bg-background/40 backdrop-blur-md border-border/20 text-foreground hover:bg-background/80" onclick={handleOpenAppearance}>
							<SettingsIcon class="h-4 w-4 sm:mr-2" />
							<span class="hidden sm:inline">Appearance</span>
						</ButtonComponent>
					</div>
				</div>

				<div class="px-4 sm:px-6 pb-6 relative">
					<div class="flex flex-col sm:flex-row gap-4 sm:gap-6 -mt-12 sm:-mt-16">
						<!-- Dossier Avatar -->
						<Avatar
							class="h-24 w-24 sm:h-32 sm:w-32 border-4 border-background shadow-lg transition-transform hover:scale-105 {characterAvatarSrc ? 'cursor-pointer' : ''} bg-background z-10 shrink-0"
							onclick={() => characterAvatarSrc && (avatarLightboxOpen = true)}
							style={customPrimaryColor ? `box-shadow: 0 4px 20px -5px ${customPrimaryColor}` : ''}
						>
							{#if characterAvatarSrc}
								<AvatarImage src={characterAvatarSrc} alt={character.name} class="object-cover" />
							{/if}
							<AvatarFallback class="text-3xl sm:text-4xl font-bold bg-muted text-muted-foreground">
								{getInitials(character.name)}
							</AvatarFallback>
						</Avatar>

						<!-- Character Name and Actions -->
						<div class="min-w-0 flex-1 pt-2 sm:pt-16 flex flex-col justify-between gap-4">
							<div class="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
								<!-- Name Section -->
								<div class="min-w-0 flex-1 space-y-1">
									{#if editingField !== 'name'}
										<div class="group relative flex items-center max-w-full">
											<h1 class="text-2xl sm:text-4xl font-extrabold tracking-tight text-balance leading-tight pr-8 drop-shadow-sm" style={customPrimaryColor ? `color: ${customPrimaryColor}` : ''}>{character.name}</h1>
											<ButtonComponent
												variant="ghost"
												size="sm"
												class="absolute right-0 top-1 h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100 text-muted-foreground flex-shrink-0"
												onclick={() => handleEditField('name', character?.name || '')}
												aria-label="Edit character name"
											>
												<PencilEdit class="h-3 w-3" />
											</ButtonComponent>
										</div>
									{:else}
										<div class="space-y-2 max-w-sm">
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
												<ButtonComponent onclick={handleSaveField} disabled={isSaving} size="sm" class="gap-2">
													{#if isSaving}
														<div class="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"></div>
													{:else}
														<CheckCircleFill class="h-3 w-3" />
													{/if}
												</ButtonComponent>
												<ButtonComponent onclick={handleCancelEdit} variant="outline" size="sm">Cancel</ButtonComponent>
											</div>
										</div>
									{/if}
									
									{#if character.creator || character.character_version}
										<div class="flex flex-wrap items-center gap-2 text-sm text-muted-foreground font-medium mt-1">
											{#if character.creator}<span>By <span class="text-foreground/80">{character.creator}</span></span>{/if}
											{#if character.creator && character.character_version}<span class="text-border text-xs">•</span>{/if}
											{#if character.character_version}<span>v{character.character_version}</span>{/if}
										</div>
									{/if}
								</div>

								<!-- Primary Actions -->
								<div class="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0 w-full sm:w-auto mt-2 sm:mt-0">
									<ButtonComponent
										onclick={handleStartNewChat}
										class="gap-2 shadow-sm text-primary-foreground relative overflow-hidden group flex-1 sm:flex-none justify-center"
										style={customPrimaryColor ? `background-color: var(--char-primary); border-color: var(--char-primary);` : ''}
									>
										{#if customPrimaryColor}
											<div class="absolute inset-0 opacity-10 group-hover:opacity-20 transition-opacity bg-black dark:bg-white"></div>
										{/if}
										<PlusIcon class="h-4 w-4 relative z-10" />
										<span class="relative z-10">Chat</span>
									</ButtonComponent>
									{#if getMostRecentChat()}
										<ButtonComponent
											variant="outline"
											class="gap-2 shadow-sm bg-background/50 flex-1 sm:flex-none justify-center border-border/40"
											onclick={() => handleSelectChat(getMostRecentChat()!.id)}
										>
											<MessageIcon class="h-4 w-4" />
											Continue
										</ButtonComponent>
									{/if}
									<ButtonComponent
										variant="outline"
										class="gap-2 shadow-sm bg-background/50 flex-none justify-center border-border/40 px-3 hidden sm:flex"
										onclick={() => _goto('/chronicles?character=' + characterId)}
										title="View chronicles"
									>
										<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
											<path
												stroke-linecap="round"
												stroke-linejoin="round"
												stroke-width="2"
												d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"
											/>
										</svg>
									</ButtonComponent>
								</div>
							</div>

							<!-- Stat Grid (Tags, Context, etc) -->
							<div class="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs sm:text-sm mt-1 border-t sm:border-t-0 border-border/10 pt-3 sm:pt-0">
								<div class="flex items-center gap-1.5 text-muted-foreground bg-muted/30 px-2 py-1 rounded-md border border-border/5">
									<MessageIcon class="h-3.5 w-3.5 opacity-70" />
									<span class="font-medium text-foreground/80">{allChats.length}</span> entries
								</div>
								{#if character.token_budget}
									<div class="flex items-center gap-1.5 text-muted-foreground bg-muted/30 px-2 py-1 rounded-md border border-border/5">
										<div class="h-3.5 w-3.5 rounded-full border border-current flex items-center justify-center opacity-70"><span class="text-[8px] font-bold">C</span></div>
										<span class="font-medium text-foreground/80">{character.token_budget}</span> tokens
									</div>
								{/if}
								{#if character.tags && character.tags.length > 0}
									<div class="w-px h-4 bg-border/40 hidden sm:block"></div>
									<div class="flex items-center gap-1.5 flex-wrap">
										{#each character.tags.slice(0, 4) as tag}
											<span class="px-2 py-0.5 rounded-full bg-secondary/40 text-secondary-foreground font-medium border border-border/40">{tag}</span>
										{/each}
										{#if character.tags.length > 4}
											<span class="text-muted-foreground font-medium ml-1">+{character.tags.length - 4}</span>
										{/if}
									</div>
								{/if}
							</div>
						</div>
					</div>
				</div>
			</Card>

			<!-- Two-Column Layout -->
			<div class="grid min-h-0 flex-1 grid-cols-1 gap-6 md:grid-cols-5 mt-2">
				<!-- Left Column: Recent Chats & Character Details (2/5 width) -->
				<div class="flex flex-col gap-6 md:col-span-2 md:min-h-0">
					<!-- Recent Chats -->
					<Card class="flex flex-col shadow-sm border-border/10 bg-background/50 backdrop-blur-sm rounded-xl md:min-h-0 md:flex-1">
						<CardHeader class="pb-3 border-b border-border/5">
							<h3 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80">Recent Chats</h3>
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
												<ButtonComponent
													variant="ghost"
													size="sm"
													class="h-6 w-6 p-0 opacity-0 transition-opacity group-hover:opacity-100"
													onclick={(e) => handleDeleteClick(e, chat)}
													aria-label="Delete chat"
												>
													<TrashIcon class="h-3 w-3 text-destructive" />
												</ButtonComponent>
											</div>
										</div>
									{/each}
								</div>
							{/if}
						</CardContent>
					</Card>

					{#if character}
						<!-- Scenario Section -->
						{#if character.scenario || editingField === 'scenario'}
						<Card class="flex flex-col shadow-sm border-border/10 bg-background/50 backdrop-blur-sm rounded-xl md:min-h-0 md:flex-1">
							<CardHeader class="pb-3 border-b border-border/5">
								<div class="flex items-center justify-between">
									<h3 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80">Scenario</h3>
									<div class="flex items-center gap-2">
										{#if character.scenario && editingField !== 'scenario'}
											<ButtonComponent
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
											</ButtonComponent>
										{/if}
										<ButtonComponent
											variant="ghost"
											size="sm"
											class="h-6 w-6 p-0"
											onclick={() => handleEditField('scenario', character?.scenario || '')}
											aria-label="Edit scenario"
										>
											<PencilEdit class="h-3 w-3" />
										</ButtonComponent>
									</div>
								</div>
							</CardHeader>
							<CardContent class="flex-1 overflow-y-auto pt-0">
								{#if editingField === 'scenario'}
									<div class="space-y-3">
										<div class="flex gap-2">
											<TextareaComponent
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
											<ButtonComponent
												variant="outline"
												size="sm"
												onclick={() => openPopoutEditor('scenario', 'Scenario', editValue)}
												class="mt-1 self-start"
											>
												Expand
											</ButtonComponent>
										</div>
										<div class="flex gap-2">
											<ButtonComponent
												onclick={handleSaveField}
												disabled={isSaving}
												size="sm"
												class="gap-2"
											>
												{#if isSaving}
													<div
														class="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"
													></div>
													Saving...
												{:else}
													<CheckCircleFill class="h-3 w-3" />
													Save
												{/if}
											</ButtonComponent>
											<ButtonComponent onclick={handleCancelEdit} variant="outline" size="sm"
												>Cancel</ButtonComponent
											>
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
										<ButtonComponent
											variant="outline"
											size="sm"
											onclick={() => handleEditField('scenario', '')}
											class="gap-2"
										>
											<PencilEdit class="h-3 w-3" />
											Add Scenario
										</ButtonComponent>
									</div>
								{/if}
							</CardContent>
						</Card>
						{/if}

						<!-- Personality Section -->
						{#if character.personality || editingField === 'personality'}
						<Card class="flex flex-col shadow-sm border-border/10 bg-background/50 backdrop-blur-sm rounded-xl md:min-h-0 md:flex-1">
							<CardHeader class="pb-3 border-b border-border/5">
								<div class="flex items-center justify-between">
									<h3 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80">Personality</h3>
									<div class="flex items-center gap-2">
										{#if character.personality && editingField !== 'personality'}
											<ButtonComponent
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
											</ButtonComponent>
										{/if}
										<ButtonComponent
											variant="ghost"
											size="sm"
											class="h-6 w-6 p-0"
											onclick={() => handleEditField('personality', character?.personality || '')}
											aria-label="Edit personality"
										>
											<PencilEdit class="h-3 w-3" />
										</ButtonComponent>
									</div>
								</div>
							</CardHeader>
							<CardContent class="flex-1 overflow-y-auto pt-0">
								{#if editingField === 'personality'}
									<div class="space-y-3">
										<div class="flex gap-2">
											<TextareaComponent
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
											<ButtonComponent
												variant="outline"
												size="sm"
												onclick={() => openPopoutEditor('personality', 'Personality', editValue)}
												class="mt-1 self-start"
											>
												Expand
											</ButtonComponent>
										</div>
										<div class="flex gap-2">
											<ButtonComponent
												onclick={handleSaveField}
												disabled={isSaving}
												size="sm"
												class="gap-2"
											>
												{#if isSaving}
													<div
														class="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"
													></div>
													Saving...
												{:else}
													<CheckCircleFill class="h-3 w-3" />
													Save
												{/if}
											</ButtonComponent>
											<ButtonComponent onclick={handleCancelEdit} variant="outline" size="sm"
												>Cancel</ButtonComponent
											>
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
										<ButtonComponent
											variant="outline"
											size="sm"
											onclick={() => handleEditField('personality', '')}
											class="gap-2"
										>
											<PencilEdit class="h-3 w-3" />
											Add Personality
										</ButtonComponent>
									</div>
								{/if}
							</CardContent>
						</Card>
						{/if}
					{/if}
				</div>

				<!-- Right Column: Character Description (3/5 width) -->
				<div class="flex flex-col gap-6 md:col-span-3 md:min-h-0">
					{#if character.description || editingField === 'description'}
						<Card class="flex flex-col shadow-sm border-border/10 bg-background/50 backdrop-blur-sm rounded-xl md:min-h-0 md:flex-1">
							<CardHeader class="pb-3 border-b border-border/5">
								<div class="flex items-center justify-between">
									<h3 class="text-sm font-bold tracking-wider uppercase text-muted-foreground/80">Description</h3>
									<div class="flex items-center gap-2">
										{#if character.description && editingField !== 'description'}
											<ButtonComponent
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
											</ButtonComponent>
										{/if}
										<ButtonComponent
											variant="ghost"
											size="sm"
											class="h-6 w-6 p-0"
											onclick={() => handleEditField('description', character?.description || '')}
											aria-label="Edit character description"
										>
											<PencilEdit class="h-3 w-3" />
										</ButtonComponent>
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
											<TextareaComponent
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
											<ButtonComponent
												variant="outline"
												size="sm"
												onclick={() => openPopoutEditor('description', 'Description', editValue)}
												class="mt-1 self-start"
											>
												Expand
											</ButtonComponent>
										</div>
										<div class="flex gap-2">
											<ButtonComponent
												onclick={handleSaveField}
												disabled={isSaving}
												size="sm"
												class="gap-2"
											>
												{#if isSaving}
													<div
														class="h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"
													></div>
													Saving...
												{:else}
													<CheckCircleFill class="h-3 w-3" />
													Save
												{/if}
											</ButtonComponent>
											<ButtonComponent onclick={handleCancelEdit} variant="outline" size="sm"
												>Cancel</ButtonComponent
											>
										</div>
									</div>
								{/if}
							</CardContent>
						</Card>
					{:else}
						<Card class="border-dashed shadow-sm">
							<CardContent class="py-8 text-center">
								<p class="mb-3 text-muted-foreground">No description available</p>
								<ButtonComponent
									variant="outline"
									size="sm"
									onclick={() => handleEditField('description', '')}
									class="gap-2"
								>
									<PencilEdit class="h-3 w-3" />
									Add Description
								</ButtonComponent>
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
				<ButtonComponent
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
				</ButtonComponent>
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
				<ButtonComponent
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
				</ButtonComponent>
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
				<ButtonComponent
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
				</ButtonComponent>
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
	<CharacterEditor {character} bind:open={characterEditorOpen} />
{/if}

<!-- Avatar Image Lightbox -->
{#if character && characterAvatarSrc}
	<ImageLightbox src={characterAvatarSrc} alt={character.name} bind:open={avatarLightboxOpen} />
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
			<TextareaComponent
				bind:value={popoutContent}
				placeholder={`Enter ${popoutFieldLabel.toLowerCase()} content...`}
				rows={20}
				class="min-h-[400px] resize-none font-mono text-sm"
			/>
		</div>

		<DialogFooter>
			<ButtonComponent variant="outline" onclick={cancelPopoutEditor}>Cancel</ButtonComponent>
			<ButtonComponent onclick={savePopoutEditor}>Save Changes</ButtonComponent>
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

<!-- Appearance Settings Dialog -->
<Dialog bind:open={appearanceEditorOpen}>
	<DialogContent class="sm:max-w-md">
		<DialogHeader>
			<DialogTitle>Appearance Settings</DialogTitle>
			<DialogDescription>
				Customize the visual presentation of this character.
			</DialogDescription>
		</DialogHeader>

		<div class="grid gap-4 py-4">
			<div class="grid gap-2">
				<label for="banner_url" class="text-sm font-medium leading-none">Banner Image URL</label>
				<Input
					id="banner_url"
					bind:value={editBannerUrl}
					placeholder="https://example.com/image.png"
				/>
				<p class="text-[0.8rem] text-muted-foreground">URL to a wide image to use as the hero banner.</p>
			</div>
			
			<div class="grid gap-2">
				<label for="primary_color" class="text-sm font-medium leading-none">Primary Color</label>
				<div class="flex gap-2 items-center">
					<Input
						id="primary_color"
						type="color"
						bind:value={editPrimaryColor}
						class="w-12 h-10 p-1 bg-background"
					/>
					<Input
						bind:value={editPrimaryColor}
						placeholder="#ff0000 or hsl(0, 100%, 50%)"
						class="flex-1"
					/>
				</div>
				<p class="text-[0.8rem] text-muted-foreground">Custom accent color for buttons and typography.</p>
			</div>

			<div class="grid gap-2">
				<label for="card_style" class="text-sm font-medium leading-none">Layout Style</label>
				<select
					id="card_style"
					bind:value={editCardStyle}
					class="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background disabled:cursor-not-allowed disabled:opacity-50"
				>
					<option value="dossier">Dossier (Immersive)</option>
					<option value="default">Default</option>
					<option value="minimal">Minimal</option>
					<option value="terminal">Terminal</option>
				</select>
			</div>
		</div>

		<DialogFooter>
			<ButtonComponent variant="outline" onclick={() => (appearanceEditorOpen = false)}>Cancel</ButtonComponent>
			<ButtonComponent onclick={handleSaveAppearance} disabled={isSaving}>
				{#if isSaving}
					<div class="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"></div>
				{/if}
				Save Changes
			</ButtonComponent>
		</DialogFooter>
	</DialogContent>
</Dialog>
