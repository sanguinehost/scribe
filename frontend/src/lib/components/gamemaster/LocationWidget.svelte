<script lang="ts">
	import type { Location, EnvironmentState, GameTime } from '$lib/types';
	import { MapPin } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		location?: Location | null;
		environment?: EnvironmentState | null;
		gameTime?: GameTime | null;
	}

	const defaultEnvironment: EnvironmentState = {
		weather: null,
		lighting: null,
		temperature: null,
		hazards: [],
		tags: []
	};

	let { location = null, environment = null, gameTime = null }: Props = $props();

	// Use provided environment or default
	const env = environment ?? defaultEnvironment;

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

<WidgetBase title="Location" icon={iconSnippet}>
	<div class="space-y-3">
		<!-- Current Location -->
		{#if location}
			<div class="rounded-lg bg-muted/50 p-3">
				<h4 class="font-medium text-foreground">{location.name}</h4>
				{#if location.region}
					<p class="text-xs text-muted-foreground">{location.region}</p>
				{/if}
				{#if location.description}
					<p class="mt-2 text-sm text-muted-foreground">{location.description}</p>
				{/if}
				{#if location.tags && location.tags.length > 0}
					<div class="mt-2 flex flex-wrap gap-1">
						{#each location.tags as tag}
							<span class="rounded bg-primary/20 px-1.5 py-0.5 text-[10px] text-primary">
								{tag}
							</span>
						{/each}
					</div>
				{/if}
			</div>
		{:else}
			<p class="py-2 text-center text-sm italic text-muted-foreground">Location unknown</p>
		{/if}

		<!-- Game Time -->
		{#if gameTime}
			<div class="flex flex-col gap-1 rounded-lg bg-muted/50 px-3 py-2">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<span>{getTimeIcon(gameTime.period)}</span>
						<span class="text-sm text-foreground">
							Day {gameTime.day}, {gameTime.hour}:{String(gameTime.minute ?? 0).padStart(2, '0')}
						</span>
					</div>
					<span class="text-xs capitalize text-muted-foreground">{gameTime.period}</span>
				</div>
				{#if gameTime.date}
					<div class="border-t border-border/50 pt-1 text-[10px] text-muted-foreground">
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
			<div class="flex flex-col items-center rounded-lg bg-muted/50 p-2">
				<span class="text-lg">{getWeatherIcon(env.weather)}</span>
				<span class="mt-1 text-xs capitalize text-muted-foreground">{env.weather || 'Unknown'}</span
				>
			</div>

			<!-- Lighting -->
			<div class="flex flex-col items-center rounded-lg bg-muted/50 p-2">
				<span class="text-lg {getLightingColor(env.lighting)}">💡</span>
				<span class="mt-1 text-xs capitalize text-muted-foreground"
					>{env.lighting || 'Unknown'}</span
				>
			</div>

			<!-- Temperature -->
			<div class="flex flex-col items-center rounded-lg bg-muted/50 p-2">
				<span class="text-lg">🌡️</span>
				<span class="mt-1 text-xs capitalize text-muted-foreground"
					>{env.temperature || 'Unknown'}</span
				>
			</div>
		</div>

		<!-- Hazards -->
		{#if env.hazards && env.hazards.length > 0}
			<div class="rounded-lg border border-destructive/30 bg-destructive/10 p-2">
				<div class="flex items-center gap-1 text-xs text-destructive">
					<span>⚠️</span>
					<span class="font-medium">Hazards</span>
				</div>
				<div class="mt-1.5 flex flex-wrap gap-1">
					{#each env.hazards as hazard}
						<span class="rounded bg-destructive/20 px-1.5 py-0.5 text-[10px] text-destructive"
							>{hazard}</span
						>
					{/each}
				</div>
			</div>
		{/if}
	</div>
</WidgetBase>
