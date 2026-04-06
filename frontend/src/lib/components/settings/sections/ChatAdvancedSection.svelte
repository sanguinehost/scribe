<script lang="ts">
	import { Card, CardHeader, CardTitle, CardContent } from '../../ui/card';
	import { Input } from '../../ui/input';
	import { Label } from '../../ui/label';
	import { Button } from '../../ui/button';
	import ChevronDown from '../../icons/chevron-down.svelte';
	import ChevronUp from '../../icons/chevron-up.svelte';
	import ContextConfigurator from '$lib/components/shared/ContextConfigurator.svelte';
	import ContextConfiguratorCompact from '$lib/components/shared/ContextConfiguratorCompact.svelte';

	let {
		localSettings = $bindable(),
		expanded = $bindable(false),
		clearOverride,
		compact = false,
		typingSpeed = $bindable(),
		saveTypingSpeed
	}: {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		localSettings: any;
		expanded: boolean;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		clearOverride: (field: any) => void;
		compact: boolean;
		typingSpeed: number;
		saveTypingSpeed: () => void;
	} = $props();
</script>

<Card>
	<CardHeader
		onclick={() => (expanded = !expanded)}
		class="cursor-pointer {expanded ? '' : 'pb-6'}"
	>
		<div class="flex items-center justify-between">
			<CardTitle class="text-base">Advanced Settings</CardTitle>
			{#if expanded}
				<ChevronUp />
			{:else}
				<ChevronDown />
			{/if}
		</div>
	</CardHeader>
	{#if expanded}
		<CardContent class="space-y-4">
			<!-- Context Configuration Override -->
			{#if compact}
				<ContextConfiguratorCompact
					bind:total_token_limit={localSettings.context_total_token_limit}
					bind:recent_history_budget={localSettings.context_recent_history_budget}
					bind:rag_budget={localSettings.context_rag_budget}
					bind:rag_chronicles_limit={localSettings.rag_chronicles_limit}
					bind:rag_lorebooks_limit={localSettings.rag_lorebooks_limit}
					bind:rag_older_chat_limit={localSettings.rag_older_chat_limit}
					title="Context Override"
					description="Override default context allocation for this chat."
				/>
			{:else}
				<ContextConfigurator
					bind:total_token_limit={localSettings.context_total_token_limit}
					bind:recent_history_budget={localSettings.context_recent_history_budget}
					bind:rag_budget={localSettings.context_rag_budget}
					bind:rag_chronicles_limit={localSettings.rag_chronicles_limit}
					bind:rag_lorebooks_limit={localSettings.rag_lorebooks_limit}
					bind:rag_older_chat_limit={localSettings.rag_older_chat_limit}
					title="Context Override"
					description="Override default context allocation for this chat."
				/>
			{/if}

			<!-- Gemini-specific Options -->
			<div class="grid grid-cols-2 gap-3">
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label for="thinking-budget">Thinking Budget</Label>
						{#if localSettings.thinking_budget !== null}
							<Button
								variant="ghost"
								size="sm"
								onclick={() => clearOverride('thinking_budget')}
							>
								Clear
							</Button>
						{/if}
					</div>
					<Input
						id="thinking-budget"
						type="number"
						min="0"
						placeholder="Default"
						bind:value={localSettings.thinking_budget}
					/>
				</div>
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label for="thinking-level">Thinking Level</Label>
						{#if localSettings.thinking_level !== null}
							<Button
								variant="ghost"
								size="sm"
								onclick={() => clearOverride('thinking_level')}
							>
								Clear
							</Button>
						{/if}
					</div>
					<select
						id="thinking-level"
						class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
						bind:value={localSettings.thinking_level}
					>
						<option value={null}>Default</option>
						<option value="Low">Low</option>
						<option value="Medium">Medium</option>
						<option value="High">High</option>
					</select>
				</div>
				<div class="col-span-2 space-y-2">
					<div class="flex items-center justify-between">
						<Label for="code-execution">Code Execution</Label>
						{#if localSettings.enable_code_execution !== false}
							<Button
								variant="ghost"
								size="sm"
								onclick={() => clearOverride('enable_code_execution')}
							>
								Clear
							</Button>
						{/if}
					</div>
					<select
						id="code-execution"
						class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
						bind:value={localSettings.enable_code_execution}
					>
						<option value={false}>Disabled</option>
						<option value={true}>Enabled</option>
					</select>
				</div>
			</div>

			<!-- Streaming Animation Speed -->
			<div class="space-y-2">
				<div class="flex items-center justify-between">
					<Label for="typing-speed">Typing Animation Speed</Label>
					<span class="text-xs text-muted-foreground">{typingSpeed}ms</span>
				</div>
				<input
					id="typing-speed"
					type="range"
					min="1"
					max="100"
					step="1"
					bind:value={typingSpeed}
					onchange={() => saveTypingSpeed()}
					class="h-2 w-full cursor-pointer appearance-none rounded-lg bg-muted accent-primary"
				/>
				<p class="text-xs text-muted-foreground">
					Lower = faster (1ms), Higher = slower (100ms). Default: 30ms
				</p>
			</div>
		</CardContent>
	{/if}
</Card>
