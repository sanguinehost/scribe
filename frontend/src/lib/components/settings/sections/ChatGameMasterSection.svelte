<script lang="ts">
	import { Card, CardHeader, CardTitle, CardContent } from '../../ui/card';
	import { Label } from '../../ui/label';
	import { Button } from '../../ui/button';
	import { Badge } from '../../ui/badge';
	import { Checkbox } from '../../ui/checkbox';
	import ChevronDown from '../../icons/chevron-down.svelte';
	import ChevronUp from '../../icons/chevron-up.svelte';

	let {
		localSettings = $bindable(),
		expanded = $bindable(false),
		clearOverride,
		saveSettings
	}: {
		localSettings: any;
		expanded: boolean;
		clearOverride: (field: any) => void;
		saveSettings: () => void;
	} = $props();
</script>

<Card>
	<CardHeader
		onclick={() => (expanded = !expanded)}
		class="cursor-pointer {expanded ? '' : 'pb-6'}"
	>
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<CardTitle class="text-lg">Game Master Mode</CardTitle>
				{#if localSettings.game_master_mode_enabled}
					<Badge variant="default" class="bg-purple-600 hover:bg-purple-700">Active</Badge>
				{/if}
			</div>
			<Button variant="ghost" size="sm" class="pointer-events-none">
				{#if expanded}
					<ChevronUp />
				{:else}
					<ChevronDown />
				{/if}
			</Button>
		</div>
	</CardHeader>
	{#if expanded}
		<CardContent class="space-y-4">
			<div class="flex items-center justify-between space-x-2">
				<div class="space-y-0.5">
					<Label for="gm-mode">Enable Game Master</Label>
					<p class="text-xs text-muted-foreground">Tracks inventory, quests, and vitals.</p>
				</div>
				<div class="flex items-center gap-2">
					{#if localSettings.game_master_mode_enabled !== false}
						<Button
							variant="ghost"
							size="icon"
							class="h-6 w-6 text-muted-foreground hover:text-foreground"
							onclick={() => clearOverride('game_master_mode_enabled')}
							title="Reset to default"
						>
							<span class="sr-only">Reset</span>
							<svg
								xmlns="http://www.w3.org/2000/svg"
								width="12"
								height="12"
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="2"
								stroke-linecap="round"
								stroke-linejoin="round"
							>
								<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74-2.74L3 12" />
							</svg>
						</Button>
					{/if}
					<Checkbox
						id="gm-mode"
						checked={localSettings.game_master_mode_enabled}
						on:change={(e) => {
							localSettings.game_master_mode_enabled = e.detail;
							saveSettings();
						}}
					/>
				</div>
			</div>
		</CardContent>
	{/if}
</Card>
