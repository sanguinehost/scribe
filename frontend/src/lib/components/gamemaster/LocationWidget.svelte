<script lang="ts">
	import type { Location, EnvironmentState, GameTime } from '$lib/types';
	import { MapPin } from 'lucide-svelte';
	import WidgetBase from './WidgetBase.svelte';

	interface Props {
		location: Location | null;
		environment: EnvironmentState;
		gameTime: GameTime | null;
	}

	let {
		location,
		environment = {
			weather: null,
			lighting: null,
			temperature: null,
			hazards: [],
			tags: []
		},
		gameTime
	}: Props = $props();

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
			<div class="bg-muted/50 flex items-center justify-between rounded-lg px-3 py-2">
				<div class="flex items-center gap-2">
					<span>{getTimeIcon(gameTime.period)}</span>
					<span class="text-foreground text-sm">
						Day {gameTime.day}, {gameTime.hour}:00
					</span>
				</div>
				<span class="text-muted-foreground text-xs capitalize">{gameTime.period}</span>
			</div>
		{/if}

		<!-- Environment -->
		<div class="grid grid-cols-3 gap-2">
			<!-- Weather -->
			<div class="bg-muted/50 flex flex-col items-center rounded-lg p-2">
				<span class="text-lg">{getWeatherIcon(environment.weather)}</span>
				<span class="text-muted-foreground mt-1 text-xs capitalize"
					>{environment.weather || 'Unknown'}</span
				>
			</div>

			<!-- Lighting -->
			<div class="bg-muted/50 flex flex-col items-center rounded-lg p-2">
				<span class="text-lg {getLightingColor(environment.lighting)}">💡</span>
				<span class="text-muted-foreground mt-1 text-xs capitalize"
					>{environment.lighting || 'Unknown'}</span
				>
			</div>

			<!-- Temperature -->
			<div class="bg-muted/50 flex flex-col items-center rounded-lg p-2">
				<span class="text-lg">🌡️</span>
				<span class="text-muted-foreground mt-1 text-xs capitalize"
					>{environment.temperature || 'Unknown'}</span
				>
			</div>
		</div>

		<!-- Hazards -->
		{#if environment.hazards && environment.hazards.length > 0}
			<div class="border-destructive/30 bg-destructive/10 rounded-lg border p-2">
				<div class="text-destructive flex items-center gap-1 text-xs">
					<span>⚠️</span>
					<span class="font-medium">Hazards</span>
				</div>
				<div class="mt-1.5 flex flex-wrap gap-1">
					{#each environment.hazards as hazard}
						<span class="bg-destructive/20 text-destructive rounded px-1.5 py-0.5 text-[10px]"
							>{hazard}</span
						>
					{/each}
				</div>
			</div>
		{/if}
	</div>
</WidgetBase>
