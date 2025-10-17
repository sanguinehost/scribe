<script lang="ts">
	import { characterStore } from '$lib/stores/character.svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import Button from '$lib/components/ui/button/button.svelte';
	import TagInput from '$lib/components/shared/TagInput.svelte';
	import FieldHelp from '$lib/components/shared/FieldHelp.svelte';
	import AiAssistantWidget from '$lib/components/ai/AiAssistantWidget.svelte';
	import AiAssistantDialog from '$lib/components/ai/AiAssistantDialog.svelte';
	import ImageGenerationDialog from '$lib/components/ai/ImageGenerationDialog.svelte';
	import { Upload, X, Sparkles } from '@lucide/svelte';
	import { buildCharacterContext } from '$lib/utils/character-context';
	import { aiSettings } from '$lib/stores/ai-settings.svelte';
	import type { CharacterCardV3 } from '$lib/types/character';

	const { character, baseImage } = $derived(characterStore);

	// AI dialog state
	let aiDialogOpen = $state(false);
	let aiFieldName = $state<string>('');

	// Image generation dialog state
	let imageGenerationDialogOpen = $state(false);

	// Image upload state
	let uploadError = $state<string | null>(null);
	let isUploadingImage = $state(false);

	// Constants for image validation
	const MAX_IMAGE_SIZE = 20 * 1024 * 1024; // 20MB
	const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];

	function updateField<K extends keyof CharacterCardV3['data']>(
		field: K,
		value: CharacterCardV3['data'][K]
	) {
		characterStore.updateField(field, value);
	}

	async function handleAvatarUpload(e: Event) {
		const input = e.currentTarget as HTMLInputElement;
		const file = input.files?.[0];

		uploadError = null;

		if (!file) return;

		// Validate file type
		if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
			uploadError = 'Invalid file type. Please upload JPEG, PNG, WebP, or GIF images.';
			return;
		}

		// Validate file size
		if (file.size > MAX_IMAGE_SIZE) {
			const sizeMB = (file.size / 1024 / 1024).toFixed(2);
			uploadError = `File size (${sizeMB}MB) exceeds maximum allowed size of 20MB.`;
			return;
		}

		isUploadingImage = true;

		try {
			const reader = new FileReader();
			reader.onload = (e) => {
				const result = e.target?.result as string;
				characterStore.setBaseImage(result);
				isUploadingImage = false;
			};
			reader.onerror = () => {
				uploadError = 'Failed to read image file';
				isUploadingImage = false;
			};
			reader.readAsDataURL(file);
		} catch (_err) {
			uploadError = 'Failed to upload image';
			isUploadingImage = false;
		}
	}

	function removeAvatar() {
		characterStore.setBaseImage(null);
		uploadError = null;
	}

	// Handle AI-generated avatar
	function handleAvatarGenerated(imageDataUrl: string) {
		characterStore.setBaseImage(imageDataUrl);
	}

	// Open AI assistant for specific field
	function openAiAssistant(fieldName: string) {
		aiFieldName = fieldName;
		aiDialogOpen = true;
	}

	// Handle AI-generated content
	function handleAiGenerated(content: string) {
		if (aiFieldName) {
			characterStore.updateField(
				aiFieldName as keyof CharacterCardV3['data'],
				content as CharacterCardV3['data'][keyof CharacterCardV3['data']]
			);
		}
	}

	// Build character context (exclude the field being generated)
	const characterContext = $derived(buildCharacterContext(character, aiFieldName));
	const currentFieldValue = $derived(
		character ? character.data[aiFieldName as keyof CharacterCardV3['data']] : undefined
	);
</script>

<div class="space-y-4">
	<!-- Name -->
	<div class="space-y-2">
		<div class="flex items-center gap-2">
			<Label for="name">
				Name <span class="text-destructive">*</span>
			</Label>
			<FieldHelp
				title="Character Name"
				description="The name of your character. This is a required field and will be used throughout the app."
				examples={['Aria Nightshade', 'Captain James Reynolds', '小林 (Kobayashi)']}
			/>
		</div>
		<Input
			id="name"
			type="text"
			placeholder="Character name"
			value={character?.data.name || ''}
			oninput={(e) => updateField('name', e.currentTarget.value)}
		/>
	</div>

	<!-- Avatar -->
	<div class="space-y-2">
		<div class="flex items-center gap-2">
			<Label>Character Avatar</Label>
			<FieldHelp
				title="Character Avatar"
				description="Upload or generate an image representing your character. This will be embedded in PNG exports and shown in the preview."
				aiTip="Use 'Generate with AI' to create custom character portraits based on your description"
			/>
		</div>
		{#if baseImage}
			<div class="flex items-start gap-4">
				<img
					src={baseImage}
					alt="Character avatar"
					class="h-32 w-32 rounded-lg border-2 border-border object-cover"
				/>
				<div class="flex flex-col gap-2">
					<p class="text-sm text-muted-foreground">Avatar uploaded successfully</p>
					<div class="flex gap-2">
						<Button
							size="sm"
							variant="outline"
							onclick={() => (imageGenerationDialogOpen = true)}
							disabled={isUploadingImage || !aiSettings.hasApiKey}
						>
							<Sparkles class="mr-1 h-4 w-4" />
							Generate New
						</Button>
						<Button size="sm" variant="outline" onclick={removeAvatar} disabled={isUploadingImage}>
							<X class="mr-1 h-4 w-4" />
							Remove
						</Button>
					</div>
				</div>
			</div>
		{:else}
			<div class="space-y-2">
				<label
					class="flex h-32 w-full cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-border bg-muted/20 transition-colors hover:border-primary/50 {isUploadingImage
						? 'cursor-wait opacity-50'
						: ''}"
				>
					<input
						type="file"
						accept="image/jpeg,image/jpg,image/png,image/webp,image/gif"
						onchange={handleAvatarUpload}
						class="hidden"
						disabled={isUploadingImage}
					/>
					{#if isUploadingImage}
						<div class="flex flex-col items-center gap-2">
							<div
								class="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"
							></div>
							<p class="text-sm text-muted-foreground">Uploading...</p>
						</div>
					{:else}
						<Upload class="h-8 w-8 text-muted-foreground" />
						<p class="mt-2 text-sm text-muted-foreground">Click to upload avatar</p>
						<p class="mt-1 text-xs text-muted-foreground/70">JPEG, PNG, WebP, GIF (max 20MB)</p>
					{/if}
				</label>
				<Button
					variant="outline"
					class="w-full"
					onclick={() => (imageGenerationDialogOpen = true)}
					disabled={!aiSettings.hasApiKey}
				>
					<Sparkles class="mr-2 h-4 w-4" />
					Generate with AI
				</Button>
			</div>
		{/if}
		{#if uploadError}
			<p class="text-sm text-destructive">{uploadError}</p>
		{/if}
		<p class="text-xs text-muted-foreground">
			Upload or generate a character avatar image (used for PNG exports and preview)
		</p>
	</div>

	<!-- Nickname -->
	<div class="space-y-2">
		<div class="flex items-center gap-2">
			<Label for="nickname">Nickname (V3)</Label>
			<FieldHelp
				title="Nickname"
				description="An optional nickname or alternate name for the character. This is a Character Card V3 feature."
				examples={['Ace', 'The Doctor', 'Red']}
			/>
		</div>
		<Input
			id="nickname"
			type="text"
			placeholder="Optional nickname"
			value={character?.data.nickname || ''}
			oninput={(e) => updateField('nickname', e.currentTarget.value)}
		/>
	</div>

	<!-- Description -->
	<div class="space-y-2">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<Label for="description">
					Description <span class="text-destructive">*</span>
				</Label>
				<FieldHelp
					title="Character Description"
					description="The main description of your character including personality traits, physical appearance, demeanor, and background."
					examples={[
						'Traits: Curious, brave, analytical, witty',
						'A tall woman with piercing blue eyes and silver hair, known for her sharp wit and mysterious past',
						'Appearance: Athletic build, 6\'2", scar across left eye | Demeanor: Confident, commanding'
					]}
					aiTip="AI can generate in various styles: traits (comma-separated), narrative (prose), or profile (structured)"
				/>
			</div>
			<AiAssistantWidget onclick={() => openAiAssistant('description')} />
		</div>
		<Textarea
			id="description"
			placeholder="Character description (personality traits, appearance, etc.)"
			value={character?.data.description || ''}
			oninput={(e) => updateField('description', e.currentTarget.value)}
			rows={6}
			class="resize-y"
		/>
		<p class="text-xs text-muted-foreground">
			The main character description. Can be formatted as traits, narrative, or profile style.
		</p>
	</div>

	<!-- Creator -->
	<div class="space-y-2">
		<div class="flex items-center gap-2">
			<Label for="creator">Creator</Label>
			<FieldHelp
				title="Creator Name"
				description="Your name, username, or handle. This will be included in exported character cards to attribute the work."
				examples={['@username', 'YourName', 'Studio/Team Name']}
			/>
		</div>
		<Input
			id="creator"
			type="text"
			placeholder="Your name or handle"
			value={character?.data.creator || ''}
			oninput={(e) => updateField('creator', e.currentTarget.value)}
		/>
	</div>

	<!-- Character Version -->
	<div class="space-y-2">
		<div class="flex items-center gap-2">
			<Label for="character_version">Character Version</Label>
			<FieldHelp
				title="Character Version"
				description="Version number for tracking iterations and updates to your character."
				examples={['1.0', '2.5.1', 'v3-beta', '2024.10.06']}
			/>
		</div>
		<Input
			id="character_version"
			type="text"
			placeholder="e.g., 1.0, 2.3, etc."
			value={character?.data.character_version || ''}
			oninput={(e) => updateField('character_version', e.currentTarget.value)}
		/>
	</div>

	<!-- Tags -->
	<div class="space-y-2">
		<div class="flex items-center gap-2">
			<Label for="tags">Tags</Label>
			<FieldHelp
				title="Character Tags"
				description="Keywords and categories to help organize and search for your character. Press Enter to add each tag."
				examples={[
					'fantasy, wizard, mentor',
					'sci-fi, android, detective',
					'modern, CEO, dominant, female'
				]}
			/>
		</div>
		<TagInput tags={character?.data.tags || []} on:update={(e) => updateField('tags', e.detail)} />
		<p class="text-xs text-muted-foreground">
			Add tags to help categorize and search for this character
		</p>
	</div>
</div>

<!-- AI Assistant Dialog -->
<AiAssistantDialog
	bind:open={aiDialogOpen}
	fieldName={aiFieldName}
	fieldValue={typeof currentFieldValue === 'string'
		? currentFieldValue
		: String(currentFieldValue ?? '')}
	{characterContext}
	onGenerate={handleAiGenerated}
	onOpenChange={(open) => (aiDialogOpen = open)}
/>

<!-- AI Image Generation Dialog -->
<ImageGenerationDialog
	bind:open={imageGenerationDialogOpen}
	onImageGenerated={handleAvatarGenerated}
/>
