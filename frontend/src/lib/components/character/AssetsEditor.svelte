<script lang="ts">
	import { characterStore } from '$lib/stores/character.svelte';
	import Badge from '$lib/components/ui/badge/badge.svelte';
	import Button from '$lib/components/ui/button/button.svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import * as Card from '$lib/components/ui/card';
	import FieldHelp from '$lib/components/shared/FieldHelp.svelte';
	import { Info, Upload, Trash2, Image, Sparkles, UserCircle } from '@lucide/svelte';
	import type { Asset } from '$lib/types/character';
	import ImageGenerationDialog from '$lib/components/ai/ImageGenerationDialog.svelte';
	import { aiSettings } from '$lib/stores/ai-settings.svelte';

	const { character } = $derived(characterStore);

	let assetType = $state<string>('icon');
	let assetName = $state<string>('');
	let assetFile = $state<File | null>(null);
	let assetPreview = $state<string | null>(null);

	// AI Image Generation Dialog
	let imageGenerationDialogOpen = $state(false);

	const assetTypes = [
		{ value: 'icon', label: 'Icon' },
		{ value: 'background', label: 'Background' },
		{ value: 'emotion', label: 'Emotion' },
		{ value: 'sprite', label: 'Sprite' },
		{ value: 'other', label: 'Other' }
	];

	function handleAssetSelect(e: Event) {
		const input = e.currentTarget as HTMLInputElement;
		const file = input.files?.[0];

		if (file && file.type.startsWith('image/')) {
			assetFile = file;

			const reader = new FileReader();
			reader.onload = (e) => {
				assetPreview = e.target?.result as string;
			};
			reader.readAsDataURL(file);

			// Auto-set name from filename if empty
			if (!assetName) {
				assetName = file.name.replace(/\.[^/.]+$/, ''); // Remove extension
			}
		}
	}

	async function addAsset() {
		if (!assetFile || !assetName) return;

		const ext = assetFile.name.split('.').pop() || 'png';
		const reader = new FileReader();

		reader.onload = (e) => {
			const dataUrl = e.target?.result as string;

			const newAsset: Asset = {
				type: assetType,
				uri: dataUrl, // Store as data URL
				name: assetName,
				ext: ext
			};

			const currentAssets = character?.data.assets || [];
			characterStore.updateField('assets', [...currentAssets, newAsset]);

			// Reset form
			assetFile = null;
			assetPreview = null;
			assetName = '';
		};

		reader.readAsDataURL(assetFile);
	}

	function removeAsset(index: number) {
		const currentAssets = character?.data.assets || [];
		const updated = currentAssets.filter((_, i) => i !== index);
		characterStore.updateField('assets', updated);
	}

	function setAsAvatar(index: number) {
		const asset = character?.data.assets?.[index];
		if (asset?.uri) {
			characterStore.setBaseImage(asset.uri);
		}
	}
</script>

<div class="space-y-4">
	<Alert.Root>
		<Info class="h-4 w-4" />
		<Alert.Title>Character Card V3 Feature</Alert.Title>
		<Alert.Description>
			Assets allow embedding character images, backgrounds, emotion sprites, and other visual
			resources in the character card.
		</Alert.Description>
	</Alert.Root>

	<!-- Add Asset Form -->
	<Card.Root>
		<Card.Header>
			<Card.Title>Add Asset</Card.Title>
			<Card.Description>Upload images or generate them with AI</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-4">
			<!-- AI Generation Button -->
			<div class="flex items-center justify-center py-2">
				<Button
					variant="outline"
					onclick={() => (imageGenerationDialogOpen = true)}
					class="w-full"
					disabled={!aiSettings.hasApiKey}
				>
					<Sparkles class="mr-2 h-4 w-4" />
					Generate with AI
				</Button>
			</div>

			<div class="relative">
				<div class="absolute inset-0 flex items-center">
					<span class="w-full border-t"></span>
				</div>
				<div class="relative flex justify-center text-xs uppercase">
					<span class="bg-background px-2 text-muted-foreground">Or upload manually</span>
				</div>
			</div>
			<!-- Asset Type -->
			<div class="space-y-2">
				<div class="flex items-center gap-2">
					<Label>Asset Type</Label>
					<FieldHelp
						title="Asset Type"
						description="Determines how the asset is used. 'icon' for character portraits, 'background' for backdrops, 'emotion' for expressions, 'sprite' for visual effects."
						examples={[
							'icon (name: main) - Main character portrait',
							'emotion (name: happy) - Happy expression',
							'background - Scene backdrop'
						]}
					/>
				</div>
				<div class="grid grid-cols-5 gap-2">
					{#each assetTypes as type, i (i)}
						<Button
							size="sm"
							variant={assetType === type.value ? 'default' : 'outline'}
							onclick={() => (assetType = type.value)}
						>
							{type.label}
						</Button>
					{/each}
				</div>
			</div>

			<!-- Asset Name -->
			<div class="space-y-2">
				<div class="flex items-center gap-2">
					<Label for="asset-name">Asset Name</Label>
					<FieldHelp
						title="Asset Name"
						description="Identifies the asset. For 'icon' type with name 'main', this becomes the default portrait. For 'emotion' type, name identifies the emotion (happy, sad, angry)."
						examples={[
							'main - Default icon (required for multi-icon cards)',
							'happy - Happy emotion sprite',
							'forest - Forest background'
						]}
					/>
				</div>
				<Input id="asset-name" type="text" placeholder="my-asset" bind:value={assetName} />
			</div>

			<!-- File Upload -->
			<div class="space-y-2">
				<Label>Asset File</Label>
				{#if assetPreview}
					<div class="flex items-start gap-4">
						<img src={assetPreview} alt="Asset preview" class="h-24 w-24 rounded-lg object-cover" />
						<div class="flex flex-col gap-2">
							<p class="text-sm text-muted-foreground">
								{assetFile?.name}
							</p>
							<Button
								size="sm"
								variant="outline"
								onclick={() => {
									assetFile = null;
									assetPreview = null;
								}}
							>
								Change File
							</Button>
						</div>
					</div>
				{:else}
					<label
						class="flex h-24 w-full cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-border bg-muted/20 transition-colors hover:border-primary/50"
					>
						<input type="file" accept="image/*" onchange={handleAssetSelect} class="hidden" />
						<Upload class="h-6 w-6 text-muted-foreground" />
						<p class="mt-1 text-sm text-muted-foreground">Click to select file</p>
					</label>
				{/if}
			</div>

			<Button onclick={addAsset} disabled={!assetFile || !assetName} class="w-full">
				<Upload class="mr-2 h-4 w-4" />
				Add Asset
			</Button>
		</Card.Content>
	</Card.Root>

	<!-- Current Assets -->
	{#if character?.data.assets && character.data.assets.length > 0}
		<div class="space-y-2">
			<Label>Current Assets ({character.data.assets.length})</Label>
			<div class="space-y-2">
				{#each character.data.assets as asset, index (index)}
					<Card.Root>
						<Card.Content class="flex items-center gap-4 p-4">
							{#if asset.uri.startsWith('data:') || asset.uri.startsWith('http://') || asset.uri.startsWith('https://') || asset.uri.startsWith('/')}
								<img src={asset.uri} alt={asset.name} class="h-16 w-16 rounded-lg object-cover" />
							{:else}
								<div class="flex h-16 w-16 items-center justify-center rounded-lg bg-muted">
									<Image class="h-8 w-8 text-muted-foreground" />
								</div>
							{/if}
							<div class="flex-1">
								<p class="font-medium">
									{asset.name}.{asset.ext}
								</p>
								<Badge variant="secondary" class="mt-1">{asset.type}</Badge>
							</div>
							<Button
								size="sm"
								variant="outline"
								onclick={() => setAsAvatar(index)}
								title="Set as character avatar"
							>
								<UserCircle class="mr-1 h-4 w-4" />
								Set as Avatar
							</Button>
							<Button size="icon" variant="ghost" onclick={() => removeAsset(index)}>
								<Trash2 class="h-4 w-4" />
							</Button>
						</Card.Content>
					</Card.Root>
				{/each}
			</div>
		</div>
	{:else}
		<p class="text-sm text-muted-foreground">
			No assets yet. Add images, backgrounds, emotions, and other visual resources.
		</p>
	{/if}
</div>

<!-- AI Image Generation Dialog -->
<ImageGenerationDialog
	bind:open={imageGenerationDialogOpen}
	onImageGenerated={(imageUrl, assetType) => {
		console.log('[AssetsEditor] Image generated:', { assetType, urlLength: imageUrl.length });
	}}
/>
