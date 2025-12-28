<script lang="ts">
	import type { Location, EnvironmentState, GameTime, GameState } from '$lib/types';
	import { MapPin, Edit2, Save, X, Plus, Trash2 } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';
	import { Button } from '../ui/button';
	import { Input } from '../ui/input';
	import { Label } from '../ui/label';
	import { Textarea } from '../ui/textarea';

	interface Props {
		location?: Location | null;
		environment?: EnvironmentState | null;
		gameTime?: GameTime | null;
		onUpdate?: (updates: Partial<GameState>) => void;
	}

	const defaultEnvironment: EnvironmentState = {
		weather: null,
		lighting: null,
		temperature: null,
		hazards: [],
		tags: []
	};

	let { location = null, environment = null, gameTime = null, onUpdate }: Props = $props();

	// Use provided environment or default
	const env = $derived(environment ?? defaultEnvironment);

	let isEditing = $state(false);

	// Local edit state
	let editLocation = $state<Location>({
		id: crypto.randomUUID(),
		name: '',
		description: '',
		region: '',
		tags: []
	});
	let editEnv = $state<EnvironmentState>({ ...defaultEnvironment });
	let editTime = $state<GameTime>({
		day: 1,
		hour: 12,
		minute: 0,
		period: 'day',
		date: '',
		calendar_system: '',
		season: null,
		weekday: null,
		total_seconds_elapsed: 0
	});

	function startEditing() {
		editLocation = location
			? { ...location }
			: {
					id: crypto.randomUUID(),
					name: '',
					description: '',
					region: '',
					tags: []
				};
		editEnv = environment ? { ...environment } : { ...defaultEnvironment };
		editTime = gameTime
			? { ...gameTime }
			: {
					day: 1,
					hour: 12,
					minute: 0,
					period: 'day',
					date: '',
					calendar_system: '',
					season: null,
					weekday: null,
					total_seconds_elapsed: 0
				};
		isEditing = true;
	}

	function save() {
		if (onUpdate) {
			onUpdate({
				location: editLocation,
				environment: editEnv,
				game_time: editTime
			});
		}
		isEditing = false;
	}

	function cancel() {
		isEditing = false;
	}

	// Helper to manage array fields (tags, hazards)
	function addTag() {
		if (!editLocation.tags) editLocation.tags = [];
		editLocation.tags.push('New Tag');
	}

	function removeTag(index: number) {
		if (editLocation.tags) {
			editLocation.tags = editLocation.tags.filter((_, i) => i !== index);
		}
	}

	function addHazard() {
		if (!editEnv.hazards) editEnv.hazards = [];
		editEnv.hazards.push('New Hazard');
	}

	function removeHazard(index: number) {
		if (editEnv.hazards) {
			editEnv.hazards = editEnv.hazards.filter((_, i) => i !== index);
		}
	}

	// Get weather icon
	function getWeatherIcon(weather: string | null): string {
		if (!weather) return '🌤️';
		const icons: Record<string, string> = {
			clear: '☀️',
			sunny: '☀️',
			cloudy: '☁️',
			overcast: '🌥️',
			rain: '🌧️',
			rainy: '🌧️',
			storm: '⛈️',
			thunderstorm: '⛈️',
			snow: '❄️',
			snowy: '❄️',
			fog: '🌫️',
			foggy: '🌫️',
			windy: '💨',
			hot: '🔥',
			cold: '🥶'
		};
		return icons[weather.toLowerCase()] || '🌤️';
	}

	// Get time period icon
	function getTimeIcon(period: string | null): string {
		if (!period) return '🕐';
		const icons: Record<string, string> = {
			dawn: '🌅',
			morning: '🌄',
			midday: '☀️',
			afternoon: '🌤️',
			dusk: '🌇',
			evening: '🌆',
			night: '🌙',
			midnight: '🌑'
		};
		return icons[period.toLowerCase()] || '🕐';
	}

	// Get lighting level color
	function getLightingColor(lighting: string | null): string {
		if (!lighting) return 'text-muted-foreground';
		const light = lighting.toLowerCase();
		if (light.includes('bright') || light.includes('day')) return 'text-yellow-400';
		if (light.includes('dim') || light.includes('dusk')) return 'text-orange-400';
		if (light.includes('dark') || light.includes('night')) return 'text-indigo-400';
		return 'text-muted-foreground';
	}
</script>

{#snippet iconSnippet()}
	<MapPin class="h-4 w-4" />
{/snippet}

{#snippet headerAction()}
	{#if onUpdate}
		{#if isEditing}
			<div class="flex gap-1">
				<Button variant="ghost" size="icon" class="h-6 w-6" onclick={save} title="Save">
					<Save class="text-primary h-3.5 w-3.5" />
				</Button>
				<Button variant="ghost" size="icon" class="h-6 w-6" onclick={cancel} title="Cancel">
					<X class="text-muted-foreground h-3.5 w-3.5" />
				</Button>
			</div>
		{:else}
			<Button
				variant="ghost"
				size="icon"
				class="h-6 w-6"
				onclick={startEditing}
				title="Edit Location"
			>
				<Edit2 class="text-muted-foreground hover:text-primary h-3.5 w-3.5" />
			</Button>
		{/if}
	{/if}
{/snippet}

<WidgetBase title="Location" icon={iconSnippet} action={headerAction}>
	<div class="space-y-3">
		{#if isEditing}
			<!-- EDIT MODE -->
			<div class="space-y-4">
				<!-- Location Details -->
				<div class="bg-muted/30 space-y-2 rounded-lg p-2">
					<Label class="text-primary text-xs font-semibold">Place</Label>
					<div class="grid gap-2">
						<div>
							<Label class="text-muted-foreground text-[10px]">Name</Label>
							<Input bind:value={editLocation.name} class="h-7 text-xs" />
						</div>
						<div>
							<Label class="text-muted-foreground text-[10px]">Region</Label>
							<Input bind:value={editLocation.region} class="h-7 text-xs" />
						</div>
						<div>
							<Label class="text-muted-foreground text-[10px]">Description</Label>
							<Textarea bind:value={editLocation.description} class="min-h-[60px] text-xs" />
						</div>
					</div>
				</div>

				<!-- Time -->
				<div class="bg-muted/30 space-y-2 rounded-lg p-2">
					<Label class="text-primary text-xs font-semibold">Time</Label>
					<div class="grid grid-cols-2 gap-2">
						<div>
							<Label class="text-muted-foreground text-[10px]">Day</Label>
							<Input type="number" bind:value={editTime.day} class="h-7 text-xs" />
						</div>
						<div>
							<Label class="text-muted-foreground text-[10px]">Weekday</Label>
							<Input bind:value={editTime.weekday} class="h-7 text-xs" placeholder="Monday" />
						</div>
						<div>
							<Label class="text-muted-foreground text-[10px]">Period</Label>
							<Input bind:value={editTime.period} class="h-7 text-xs" />
						</div>
						<div>
							<Label class="text-muted-foreground text-[10px]">Season</Label>
							<Input bind:value={editTime.season} class="h-7 text-xs" />
						</div>
						<div>
							<Label class="text-muted-foreground text-[10px]">Hour</Label>
							<Input
								type="number"
								bind:value={editTime.hour}
								min="0"
								max="23"
								class="h-7 text-xs"
							/>
						</div>
						<div>
							<Label class="text-muted-foreground text-[10px]">Minute</Label>
							<Input
								type="number"
								bind:value={editTime.minute}
								min="0"
								max="59"
								class="h-7 text-xs"
							/>
						</div>
						<div class="col-span-2">
							<Label class="text-muted-foreground text-[10px]">Date String</Label>
							<Input bind:value={editTime.date} class="h-7 text-xs" />
						</div>
					</div>
				</div>

				<!-- Environment -->
				<div class="bg-muted/30 space-y-2 rounded-lg p-2">
					<Label class="text-primary text-xs font-semibold">Environment</Label>
					<div class="grid grid-cols-2 gap-2">
						<div>
							<Label class="text-muted-foreground text-[10px]">Weather</Label>
							<Input bind:value={editEnv.weather} class="h-7 text-xs" />
						</div>
						<div>
							<Label class="text-muted-foreground text-[10px]">Lighting</Label>
							<Input bind:value={editEnv.lighting} class="h-7 text-xs" />
						</div>
						<div class="col-span-2">
							<Label class="text-muted-foreground text-[10px]">Temperature</Label>
							<Input bind:value={editEnv.temperature} class="h-7 text-xs" />
						</div>
					</div>

					<!-- Hazards -->
					<div class="pt-2">
						<div class="flex items-center justify-between">
							<Label class="text-muted-foreground text-[10px]">Hazards</Label>
							<Button variant="ghost" size="icon" class="h-5 w-5" onclick={addHazard}>
								<Plus class="h-3 w-3" />
							</Button>
						</div>
						<div class="mt-1 space-y-1">
							{#each editEnv.hazards || [] as hazard, i}
								<div class="flex gap-1">
									<Input bind:value={editEnv.hazards![i]} class="h-6 text-xs" />
									<Button
										variant="ghost"
										size="icon"
										class="text-destructive h-6 w-6"
										onclick={() => removeHazard(i)}
									>
										<Trash2 class="h-3 w-3" />
									</Button>
								</div>
							{/each}
						</div>
					</div>
				</div>
			</div>
		{:else}
			<!-- VIEW MODE -->
			<!-- Current Location -->
			{#if location}
				<div class="bg-muted/50 rounded-lg p-3">
					<h4 class="text-foreground font-medium">{location.name}</h4>
					{#if location.region}
						<p class="text-muted-foreground text-xs">{location.region}</p>
					{/if}
					{#if location.description}
						<p class="text-muted-foreground mt-2 text-sm">{location.description}</p>
					{/if}
					{#if location.tags && location.tags.length > 0}
						<div class="mt-2 flex flex-wrap gap-1">
							{#each location.tags as tag}
								<span class="bg-primary/20 text-primary rounded px-1.5 py-0.5 text-[10px]">
									{tag}
								</span>
							{/each}
						</div>
					{/if}
				</div>
			{:else}
				<p class="text-muted-foreground py-2 text-center text-sm italic">Location unknown</p>
			{/if}

			<!-- Game Time -->
			{#if gameTime}
				<div class="bg-muted/50 flex flex-col gap-1 rounded-lg px-3 py-2">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<span>{getTimeIcon(gameTime.period)}</span>
							<span class="text-foreground text-sm">
								Day {gameTime.day}, {gameTime.hour}:{String(gameTime.minute ?? 0).padStart(2, '0')}
							</span>
						</div>
						<div class="flex flex-col items-end">
							<span class="text-muted-foreground text-xs capitalize">{gameTime.period}</span>
							{#if gameTime.weekday}
								<span class="text-muted-foreground text-[10px]">{gameTime.weekday}</span>
							{/if}
						</div>
					</div>
					{#if gameTime.date}
						<div class="border-border/50 text-muted-foreground border-t pt-1 text-[10px]">
							{gameTime.date}
							{#if gameTime.calendar_system}
								<span class="ml-1 opacity-70">({gameTime.calendar_system})</span>
							{/if}
						</div>
					{/if}
				</div>
			{/if}

			<!-- Environment -->
			<div class="grid grid-cols-3 gap-2">
				<!-- Weather -->
				<div class="bg-muted/50 flex flex-col items-center rounded-lg p-2">
					<span class="text-lg">{getWeatherIcon(env.weather)}</span>
					<span class="text-muted-foreground mt-1 text-xs capitalize"
						>{env.weather || 'Unknown'}</span
					>
				</div>

				<!-- Lighting -->
				<div class="bg-muted/50 flex flex-col items-center rounded-lg p-2">
					<span class="text-lg {getLightingColor(env.lighting)}">💡</span>
					<span class="text-muted-foreground mt-1 text-xs capitalize"
						>{env.lighting || 'Unknown'}</span
					>
				</div>

				<!-- Temperature -->
				<div class="bg-muted/50 flex flex-col items-center rounded-lg p-2">
					<span class="text-lg">🌡️</span>
					<span class="text-muted-foreground mt-1 text-xs capitalize"
						>{env.temperature || 'Unknown'}</span
					>
				</div>
			</div>

			<!-- Hazards -->
			{#if env.hazards && env.hazards.length > 0}
				<div class="border-destructive/30 bg-destructive/10 rounded-lg border p-2">
					<div class="text-destructive flex items-center gap-1 text-xs">
						<span>⚠️</span>
						<span class="font-medium">Hazards</span>
					</div>
					<div class="mt-1.5 flex flex-wrap gap-1">
						{#each env.hazards as hazard}
							<span class="bg-destructive/20 text-destructive rounded px-1.5 py-0.5 text-[10px]"
								>{hazard}</span
							>
						{/each}
					</div>
				</div>
			{/if}
		{/if}
	</div>
</WidgetBase>
