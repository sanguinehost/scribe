<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Slider } from '$lib/components/ui/slider';
	import { Textarea } from '$lib/components/ui/textarea';
	// Removed: createEventDispatcher, get, chatStore, Dialog imports
	import { getChatSettings, updateChatSettings, type ChatSettings } from '$lib/services/apiClient';
	import * as Alert from '$lib/components/ui/alert'; // For error/loading display

	// --- Props ---
	let { sessionId }: { sessionId: string } = $props();

	// --- Component State ---
	let isLoading = $state(false); // Use $state for reactivity if needed within component logic
	let error: string | null = $state(null);
	let successMessage: string | null = $state(null); // Optional success feedback

	// --- Reactive variables for settings (defaults) ---
	let systemPrompt: string = $state('');
	let temperature: number[] = $state([1]);
	let maxOutputTokens: number | undefined = $state(undefined);
	let frequencyPenalty: number[] = $state([0]);
	let presencePenalty: number[] = $state([0]);
	let topK: number | undefined = $state(undefined);
	let topP: number[] = $state([1]);
	let repetitionPenalty: number[] = $state([1]);
	let minP: number[] = $state([0]);
	let topA: number[] = $state([0]);
	let seed: number | undefined = $state(undefined);
	let logitBias: string = $state(''); // Store as JSON string for textarea binding

	// --- Fetch settings when sessionId is available ---
	$effect(() => {
		if (sessionId) {
			fetchSettings();
		}
	});


	async function fetchSettings() {
		// Use the sessionId prop directly
		if (!sessionId) {
			error = 'Session ID is missing.'; // Should not happen if rendered correctly
			return;
		}

		isLoading = true;
		error = null;
		successMessage = null; // Clear previous messages

		try {
			const fetchedSettings = await getChatSettings(sessionId);
			// Map fetched settings (snake_case) to local variables (camelCase)
			systemPrompt = fetchedSettings.system_prompt ?? '';
			temperature = [fetchedSettings.temperature ?? 1];
			maxOutputTokens = fetchedSettings.max_output_tokens ?? undefined;
			frequencyPenalty = [fetchedSettings.frequency_penalty ?? 0];
			presencePenalty = [fetchedSettings.presence_penalty ?? 0];
			topK = fetchedSettings.top_k ?? undefined;
			topP = [fetchedSettings.top_p ?? 1];
			repetitionPenalty = [fetchedSettings.repetition_penalty ?? 1];
			minP = [fetchedSettings.min_p ?? 0];
			topA = [fetchedSettings.top_a ?? 0];
			seed = fetchedSettings.seed ?? undefined;
			// Convert logit_bias object back to string for textarea, handle null
			logitBias = fetchedSettings.logit_bias ? JSON.stringify(fetchedSettings.logit_bias, null, 2) : '';

		} catch (err) {
			console.error('Failed to fetch settings:', err);
			error = err instanceof Error ? err.message : 'Failed to load settings.';
		} finally {
			isLoading = false;
		}
	}


	// Removed handleOpenChange function

	async function handleSave() {
		// Use the sessionId prop directly
		if (!sessionId) {
			error = 'Session ID is missing. Cannot save settings.';
			return;
		}

		isLoading = true;
		error = null;
		successMessage = null;

		let parsedLogitBias: Record<string, number> | undefined | null = undefined;
		if (logitBias.trim()) {
			try {
				parsedLogitBias = JSON.parse(logitBias);
				if (typeof parsedLogitBias !== 'object' || parsedLogitBias === null || Array.isArray(parsedLogitBias)) {
					throw new Error('Logit Bias must be a JSON object.');
				}
				// Optional: Further validation that values are numbers
				for (const key in parsedLogitBias) {
					if (typeof parsedLogitBias[key] !== 'number') {
						throw new Error(`Invalid value for key "${key}" in Logit Bias. Must be a number.`);
					}
				}
			} catch (err) {
				error = `Invalid Logit Bias JSON: ${err instanceof Error ? err.message : 'Parsing error'}`;
				isLoading = false;
				return;
			}
		} else {
			// Treat empty string as null or undefined depending on API expectation
			// Assuming API accepts null to clear the setting
			parsedLogitBias = null;
		}


		// Construct the payload with snake_case keys
		const settingsToSave: Partial<ChatSettings> = {
			system_prompt: systemPrompt,
			temperature: temperature[0],
			max_output_tokens: maxOutputTokens === undefined || isNaN(Number(maxOutputTokens)) ? null : Number(maxOutputTokens), // Ensure number or null
			frequency_penalty: frequencyPenalty[0],
			presence_penalty: presencePenalty[0],
			top_k: topK === undefined || isNaN(Number(topK)) ? null : Number(topK),
			top_p: topP[0],
			repetition_penalty: repetitionPenalty[0],
			min_p: minP[0],
			top_a: topA[0],
			seed: seed === undefined || isNaN(Number(seed)) ? null : Number(seed),
			logit_bias: parsedLogitBias, // Use the parsed object (or null)
		};

		// Remove undefined values if API doesn't handle them well (optional)
		// Object.keys(settingsToSave).forEach(key => settingsToSave[key] === undefined && delete settingsToSave[key]);

		try {
			await updateChatSettings(sessionId, settingsToSave);
			successMessage = 'Settings saved successfully!';
			// Removed dialog closing logic - parent handles closing
			// Optionally clear success message after a delay if desired
			setTimeout(() => {
				successMessage = null;
			}, 3000);
		} catch (err) {
			console.error('Failed to save settings for session', sessionId, ':', err);
			error = err instanceof Error ? err.message : 'Failed to save settings.';
		} finally {
			isLoading = false;
		}
	}

	// Removed handleCancel function
</script>

<!-- Removed Dialog.Root, Dialog.Content, Dialog.Header, Dialog.Footer -->
<!-- The parent component (+page.svelte) now provides the Dialog structure -->

{#if isLoading && !error && !successMessage} <!-- Adjusted condition -->
	<div class="flex items-center justify-center p-4">
		<p>Loading settings...</p>
		<!-- Add a spinner here if desired -->
	</div>
{/if}

{#if error}
	<Alert.Root variant="destructive" class="my-4">
		<Alert.Title>Error</Alert.Title>
		<Alert.Description>{error}</Alert.Description>
	</Alert.Root>
{/if}
{#if successMessage}
	<Alert.Root variant="default" class="my-4 bg-green-100 dark:bg-green-900 border-green-300 dark:border-green-700">
		<Alert.Title>Success</Alert.Title>
		<Alert.Description>{successMessage}</Alert.Description>
	</Alert.Root>
{/if}

<!-- Disable form fields while loading/saving -->
<fieldset disabled={isLoading} class="grid gap-6 py-4">
	<!-- System Prompt -->
	<div class="grid gap-2">
		<Label for="system-prompt">System Prompt</Label>
		<Textarea
			id="system-prompt"
			bind:value={systemPrompt}
			placeholder="Define the AI's persona or instructions..."
			class="min-h-[100px]"
		/>
	</div>

	<!-- Numerical/Slider Settings Grid -->
	<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
		<!-- Temperature -->
		<div class="grid gap-2">
			<!-- Added nullish coalescing for safety during initial load -->
			<Label for="temperature">Temperature ({(temperature?.[0] ?? 1).toFixed(1)})</Label>
			<Slider
				id="temperature"
				bind:value={temperature}
				max={2}
				step={0.1}
				class="[&>span]:h-4 [&>span]:w-4"
			/>
		</div>

		<!-- Max Output Tokens -->
		<div class="grid gap-2">
			<Label for="max-output-tokens">Max Output Tokens</Label>
			<Input
				id="max-output-tokens"
				type="number"
				bind:value={maxOutputTokens}
				placeholder="e.g., 1024"
				min="1"
			/>
		</div>

		<!-- Frequency Penalty -->
		<div class="grid gap-2">
			<Label for="frequency-penalty">Frequency Penalty ({(frequencyPenalty?.[0] ?? 0).toFixed(1)})</Label>
			<Slider
				id="frequency-penalty"
				bind:value={frequencyPenalty}
				max={2}
				step={0.1}
				class="[&>span]:h-4 [&>span]:w-4"
			/>
		</div>

		<!-- Presence Penalty -->
		<div class="grid gap-2">
			<Label for="presence-penalty">Presence Penalty ({(presencePenalty?.[0] ?? 0).toFixed(1)})</Label>
			<Slider
				id="presence-penalty"
				bind:value={presencePenalty}
				max={2}
				step={0.1}
				class="[&>span]:h-4 [&>span]:w-4"
			/>
		</div>

		<!-- Top K -->
		<div class="grid gap-2">
			<Label for="top-k">Top K</Label>
			<Input id="top-k" type="number" bind:value={topK} placeholder="e.g., 40" min="0" />
		</div>

		<!-- Top P -->
		<div class="grid gap-2">
			<Label for="top-p">Top P ({(topP?.[0] ?? 1).toFixed(2)})</Label>
			<Slider
				id="top-p"
				bind:value={topP}
				max={1}
				step={0.01}
				class="[&>span]:h-4 [&>span]:w-4"
			/>
		</div>

		<!-- Repetition Penalty -->
		<div class="grid gap-2">
			<Label for="repetition-penalty">Repetition Penalty ({(repetitionPenalty?.[0] ?? 1).toFixed(1)})</Label>
			<Slider
				id="repetition-penalty"
				bind:value={repetitionPenalty}
				max={2}
				step={0.1}
				class="[&>span]:h-4 [&>span]:w-4"
			/>
		</div>

		<!-- Min P -->
		<div class="grid gap-2">
			<Label for="min-p">Min P ({(minP?.[0] ?? 0).toFixed(2)})</Label>
			<Slider
				id="min-p"
				bind:value={minP}
				max={1}
				step={0.01}
				class="[&>span]:h-4 [&>span]:w-4"
			/>
		</div>

		<!-- Top A -->
		<div class="grid gap-2">
			<Label for="top-a">Top A ({(topA?.[0] ?? 0).toFixed(2)})</Label>
			<Slider
				id="top-a"
				bind:value={topA}
				max={1}
				step={0.01}
				class="[&>span]:h-4 [&>span]:w-4"
			/>
		</div>

		<!-- Seed -->
		<div class="grid gap-2">
			<Label for="seed">Seed</Label>
			<Input id="seed" type="number" bind:value={seed} placeholder="e.g., 42" />
		</div>
	</div>

	<!-- Logit Bias -->
	<div class="grid gap-2">
		<Label for="logit-bias">Logit Bias (JSON)</Label>
		<Textarea
			id="logit-bias"
			bind:value={logitBias}
			placeholder='e.g., &lbrace;"123": -1.0, "456": 2.0&rbrace;'
			class="min-h-[80px] font-mono"
			aria-invalid={error?.includes('Logit Bias')}
		/>
		<p class="text-sm text-muted-foreground">
			Enter as a JSON object mapping token IDs (strings) to bias values (numbers).
		</p>
	</div>
</fieldset>

<!-- Save button remains, Cancel button removed (handled by Dialog close) -->
<div class="flex justify-end pt-4">
	<Button on:click={handleSave} disabled={isLoading}>
		{#if isLoading}Saving...{:else}Save Changes{/if}
	</Button>
</div>