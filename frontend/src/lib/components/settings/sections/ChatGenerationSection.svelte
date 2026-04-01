<script lang="ts">
	import { Card, CardHeader, CardTitle, CardContent } from '../../ui/card';
	import { Input } from '../../ui/input';
	import { Label } from '../../ui/label';
	import { Button } from '../../ui/button';
	import ChevronDown from '../../icons/chevron-down.svelte';
	import ChevronUp from '../../icons/chevron-up.svelte';
	import { chatModels, DEFAULT_CHAT_MODEL } from '$lib/ai/models';

	let {
		localSettings = $bindable(),
		expanded = $bindable(false),
		clearOverride
	}: {
		localSettings: any;
		expanded: boolean;
		clearOverride: (field: any) => void;
	} = $props();
</script>

<Card>
	<CardHeader
		onclick={() => (expanded = !expanded)}
		class="cursor-pointer {expanded ? '' : 'pb-6'}"
	>
		<div class="flex items-center justify-between">
			<CardTitle class="text-base">Generation Settings</CardTitle>
			{#if expanded}
				<ChevronUp />
			{:else}
				<ChevronDown />
			{/if}
		</div>
	</CardHeader>
	{#if expanded}
		<CardContent class="space-y-4">
			<div class="space-y-2">
				<Label for="model">Model Override</Label>
				<select
					id="model"
					class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
					bind:value={localSettings.model_name}
				>
					<option value="">
						Use global default ({chatModels.find((m) => m.id === DEFAULT_CHAT_MODEL)?.name ||
							DEFAULT_CHAT_MODEL})
					</option>
					{#each chatModels as model}
						<option value={model.id}>{model.name}</option>
					{/each}
				</select>
				<p class="text-xs text-muted-foreground">
					Override the global model setting for this specific chat
				</p>
			</div>

			<div class="space-y-2">
				<Label for="agent-mode">Context Enhancement Agent</Label>
				<select
					id="agent-mode"
					class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
					bind:value={localSettings.agent_mode}
				>
					<option value="disabled">Disabled</option>
					<option value="pre_processing">Pre-process (before AI response)</option>
					<option value="post_processing">Post-process (after AI response)</option>
				</select>
				<p class="text-xs text-muted-foreground">
					{#if localSettings.agent_mode === 'pre_processing'}
						Agent searches for context before generating response (slight delay)
					{:else if localSettings.agent_mode === 'post_processing'}
						Agent enriches context after response (no delay)
					{:else}
						No automatic context enrichment
					{/if}
				</p>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label for="temperature">Temperature</Label>
						{#if localSettings.temperature !== 1.0}
							<Button
								variant="ghost"
								size="sm"
								onclick={() => clearOverride('temperature')}
							>
								Clear
							</Button>
						{/if}
					</div>
					<Input
						id="temperature"
						type="number"
						min="0"
						max="2"
						step="0.1"
						bind:value={localSettings.temperature}
					/>
				</div>
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label for="max-tokens">Max Tokens</Label>
						{#if localSettings.max_output_tokens !== 1000}
							<Button
								variant="ghost"
								size="sm"
								onclick={() => clearOverride('max_output_tokens')}
							>
								Clear
							</Button>
						{/if}
					</div>
					<Input
						id="max-tokens"
						type="number"
						min="1"
						max="8192"
						bind:value={localSettings.max_output_tokens}
					/>
				</div>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label for="top-p">Top P</Label>
						{#if localSettings.top_p !== 0.95}
							<Button variant="ghost" size="sm" onclick={() => clearOverride('top_p')}>
								Clear
							</Button>
						{/if}
					</div>
					<Input
						id="top-p"
						type="number"
						min="0"
						max="1"
						step="0.05"
						bind:value={localSettings.top_p}
					/>
				</div>
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label for="top-k">Top K</Label>
						{#if localSettings.top_k !== 40}
							<Button variant="ghost" size="sm" onclick={() => clearOverride('top_k')}>
								Clear
							</Button>
						{/if}
					</div>
					<Input
						id="top-k"
						type="number"
						min="0"
						max="100"
						step="1"
						bind:value={localSettings.top_k}
					/>
				</div>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label for="freq-penalty">Frequency Penalty</Label>
						{#if localSettings.frequency_penalty !== 0.0}
							<Button
								variant="ghost"
								size="sm"
								onclick={() => clearOverride('frequency_penalty')}
							>
								Clear
							</Button>
						{/if}
					</div>
					<Input
						id="freq-penalty"
						type="number"
						min="-2"
						max="2"
						step="0.1"
						bind:value={localSettings.frequency_penalty}
					/>
				</div>
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label for="presence-penalty">Presence Penalty</Label>
						{#if localSettings.presence_penalty !== 0.0}
							<Button
								variant="ghost"
								size="sm"
								onclick={() => clearOverride('presence_penalty')}
							>
								Clear
							</Button>
						{/if}
					</div>
					<Input
						id="presence-penalty"
						type="number"
						min="-2"
						max="2"
						step="0.1"
						bind:value={localSettings.presence_penalty}
					/>
				</div>
			</div>

			<div class="space-y-2">
				<div class="flex items-center justify-between">
					<Label for="seed">Seed (optional)</Label>
					{#if localSettings.seed !== null}
						<Button variant="ghost" size="sm" onclick={() => clearOverride('seed')}>
							Clear
						</Button>
					{/if}
				</div>
				<Input
					id="seed"
					type="number"
					placeholder="Leave empty for random"
					bind:value={localSettings.seed}
				/>
			</div>
		</CardContent>
	{/if}
</Card>
