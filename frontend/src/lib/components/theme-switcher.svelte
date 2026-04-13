<script lang="ts">
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { Button } from '$lib/components/ui/button';
	import { Palette, Check } from 'lucide-svelte';
	import { THEMES } from '$lib/theme/themes';
	import { themeStore } from '$lib/theme/theme-store.svelte';
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger>
		<Button
			variant="ghost"
			size="icon"
			class="w-7 h-7 rounded-full text-muted-foreground hover:text-foreground hover:bg-background transition-all"
		>
			<Palette class="h-3.5 w-3.5" />
			<span class="sr-only">Switch Theme</span>
		</Button>
	</DropdownMenu.Trigger>
	<DropdownMenu.Content
		align="end"
		side="top"
		class="w-[280px] rounded-xl border border-border/50 bg-background/95 p-3 backdrop-blur-xl shadow-xl"
	>
		<div class="mb-2 px-0.5">
			<p class="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Theme</p>
		</div>

		<div class="grid grid-cols-3 gap-2">
			{#each THEMES as theme (theme.id)}
				{@const isActive = themeStore.activeTheme === theme.id}
				<DropdownMenu.Item class="p-0 focus:bg-transparent">
					<button
						class="group relative flex w-full flex-col items-center gap-1.5 rounded-lg border p-1.5 transition-all duration-200 {isActive
							? 'border-primary bg-primary/5 shadow-sm ring-1 ring-primary/30'
							: 'border-border/30 hover:border-border hover:bg-muted/30'}"
						onclick={() => themeStore.setTheme(theme.id)}
					>
						<!-- Mini preview card -->
						<div
							class="relative w-full aspect-[4/3] rounded-md overflow-hidden"
							style="background-color: {theme.bgHex};"
						>
							<!-- Simulated sidebar -->
							<div
								class="absolute left-0 top-0 bottom-0 w-[30%] opacity-30"
								style="background-color: {theme.secondaryHex};"
							></div>
							<!-- Header bar -->
							<div
								class="absolute top-0 left-[30%] right-0 h-[15%] opacity-20"
								style="background-color: {theme.colorHex};"
							></div>
							<!-- Simulated message bubbles -->
							<div class="absolute left-[35%] top-[28%] right-[15%] space-y-[3px]">
								<div
									class="h-[3px] rounded-full opacity-30"
									style="background-color: {theme.colorHex}; width: 70%;"
								></div>
								<div
									class="h-[3px] rounded-full opacity-20"
									style="background-color: {theme.secondaryHex}; width: 90%;"
								></div>
								<div
									class="h-[3px] rounded-full opacity-15"
									style="background-color: {theme.colorHex}; width: 55%;"
								></div>
							</div>
							<!-- Input bar -->
							<div
								class="absolute bottom-[8%] left-[33%] right-[10%] h-[10%] rounded-sm opacity-25"
								style="background-color: {theme.secondaryHex};"
							></div>

							<!-- Active checkmark -->
							{#if isActive}
								<div class="absolute top-0.5 right-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full shadow-sm" style="background-color: {theme.colorHex};">
									<Check class="h-2 w-2 text-white" />
								</div>
							{/if}
						</div>

						<!-- Theme name -->
						<div class="flex items-center gap-1">
							<div
								class="h-2 w-2 rounded-full shadow-sm"
								style="background-color: {theme.colorHex};"
							></div>
							<span class="text-[10px] font-medium {isActive ? 'text-foreground' : 'text-muted-foreground group-hover:text-foreground'}">{theme.name}</span>
						</div>
					</button>
				</DropdownMenu.Item>
			{/each}
		</div>
	</DropdownMenu.Content>
</DropdownMenu.Root>
