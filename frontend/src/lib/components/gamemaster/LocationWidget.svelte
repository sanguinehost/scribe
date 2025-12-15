<script lang="ts">
	import type { Location, EnvironmentState, GameTime } from '$lib/types';
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
		if (!lighting) return 'text-gray-400';
		const light = lighting.toLowerCase();
		if (light.includes('bright') || light.includes('day')) return 'text-yellow-300';
		if (light.includes('dim') || light.includes('dusk')) return 'text-orange-400';
		if (light.includes('dark') || light.includes('night')) return 'text-indigo-400';
		return 'text-gray-400';
	}
</script>

{#snippet iconSnippet()}
	<svg
		xmlns="http://www.w3.org/2000/svg"
		class="h-4 w-4"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="2"
	>
		<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path>
		<circle cx="12" cy="10" r="3"></circle>
	</svg>
{/snippet}

<WidgetBase title="Location" icon={iconSnippet}>
	<div class="space-y-3">
		<!-- Current Location -->
		{#if location}
			<div class="rounded-lg bg-gray-800/50 p-3">
				<h4 class="font-medium text-gray-200">{location.name}</h4>
				{#if location.region}
					<p class="text-xs text-gray-500">{location.region}</p>
				{/if}
				{#if location.description}
					<p class="mt-2 text-sm text-gray-400">{location.description}</p>
				{/if}
				{#if location.tags && location.tags.length > 0}
					<div class="mt-2 flex flex-wrap gap-1">
						{#each location.tags as tag}
							<span class="rounded bg-purple-500/20 px-1.5 py-0.5 text-[10px] text-purple-300">
								{tag}
							</span>
						{/each}
					</div>
				{/if}
			</div>
		{:else}
			<p class="py-2 text-center text-sm italic text-gray-500">Location unknown</p>
		{/if}

		<!-- Game Time -->
		{#if gameTime}
			<div class="flex items-center justify-between rounded-lg bg-gray-800/50 px-3 py-2">
				<div class="flex items-center gap-2">
					<span>{getTimeIcon(gameTime.period)}</span>
					<span class="text-sm text-gray-300">
						Day {gameTime.day}, {gameTime.hour}:00
					</span>
				</div>
				<span class="text-xs capitalize text-gray-500">{gameTime.period}</span>
			</div>
		{/if}

		<!-- Environment -->
		<div class="grid grid-cols-3 gap-2">
			<!-- Weather -->
			<div class="flex flex-col items-center rounded-lg bg-gray-800/50 p-2">
				<span class="text-lg">{getWeatherIcon(environment.weather)}</span>
				<span class="mt-1 text-xs capitalize text-gray-400">{environment.weather || 'Unknown'}</span
				>
			</div>

			<!-- Lighting -->
			<div class="flex flex-col items-center rounded-lg bg-gray-800/50 p-2">
				<span class="text-lg {getLightingColor(environment.lighting)}">💡</span>
				<span class="mt-1 text-xs capitalize text-gray-400"
					>{environment.lighting || 'Unknown'}</span
				>
			</div>

			<!-- Temperature -->
			<div class="flex flex-col items-center rounded-lg bg-gray-800/50 p-2">
				<span class="text-lg">🌡️</span>
				<span class="mt-1 text-xs capitalize text-gray-400"
					>{environment.temperature || 'Unknown'}</span
				>
			</div>
		</div>

		<!-- Hazards -->
		{#if environment.hazards && environment.hazards.length > 0}
			<div class="rounded-lg border border-red-500/30 bg-red-500/10 p-2">
				<div class="flex items-center gap-1 text-xs text-red-400">
					<span>⚠️</span>
					<span class="font-medium">Hazards</span>
				</div>
				<div class="mt-1.5 flex flex-wrap gap-1">
					{#each environment.hazards as hazard}
						<span class="rounded bg-red-500/20 px-1.5 py-0.5 text-[10px] text-red-300"
							>{hazard}</span
						>
					{/each}
				</div>
			</div>
		{/if}
	</div>
</WidgetBase>
