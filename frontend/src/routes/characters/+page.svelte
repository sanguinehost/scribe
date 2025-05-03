<script lang="ts">
	import CharacterList from '$lib/components/characters/CharacterList.svelte';
	import CharacterUploader from '$lib/components/characters/CharacterUploader.svelte';
	import { Separator } from '$lib/components/ui/separator';

	// State to force CharacterList refresh
	let listVersion = $state(0);

	const handleUploadSuccess = () => {
		console.log('Upload successful, incrementing list version.');
		listVersion += 1;
	};
</script>

<div class="container mx-auto py-6 px-4 md:px-6">
	<h1 class="text-3xl font-bold mb-4">Your Characters</h1>
	<p class="text-muted-foreground mb-6">
		Select a character to start chatting or upload a new character card (.png).
	</p>

	<div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
		<div class="lg:col-span-2">
			<h2 class="text-xl font-semibold mb-4">Character List</h2>
			{#key listVersion}
				<CharacterList />
			{/key}
		</div>

		<div class="lg:col-span-1">
			<h2 class="text-xl font-semibold mb-4">Upload New Character</h2>
			<CharacterUploader onUploadSuccess={handleUploadSuccess} />
		</div>
	</div>

</div>