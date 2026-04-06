<script lang="ts">
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { Button } from '$lib/components/ui/button';
	import { Palette } from 'lucide-svelte';
	import { THEMES } from '$lib/theme/themes';
	import { themeStore } from '$lib/theme/theme-store.svelte';
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger>
		<Button variant="outline" size="icon" class="w-10 h-10 rounded-full border border-border/40 bg-background/50 backdrop-blur-sm shadow-sm hover:bg-accent hover:text-accent-foreground transition-all">
			<!-- Show icon, indicate a palette/theme switch -->
			<Palette class="h-4 w-4" />
			<span class="sr-only">Switch Theme</span>
		</Button>
	</DropdownMenu.Trigger>
	<DropdownMenu.Content align="end" class="w-48 p-2 rounded-xl border border-border/50 bg-background/90 backdrop-blur-md shadow-lg">
		<DropdownMenu.Label class="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 px-2">
			Theme Preset
		</DropdownMenu.Label>
		<DropdownMenu.Separator class="bg-border/50" />

		{#each THEMES as theme, i (i)}
			<DropdownMenu.Item
				class="flex items-center justify-between gap-0 p-0 cursor-pointer transition-colors duration-200 rounded-md hover:bg-accent"
			>
				<div
					class="flex items-center justify-between gap-3 px-2 py-2 w-full h-full rounded-md {themeStore.activeTheme === theme.id ? 'bg-primary/10 text-primary font-medium' : ''}"
					role="button"
					tabindex="0"
					onclick={() => themeStore.setTheme(theme.id)}
					onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') themeStore.setTheme(theme.id); }}
				>
					<div class="flex items-center gap-3">
						<div
							class="w-4 h-4 rounded-full border border-border/50 shadow-sm"
							style="background-color: {theme.colorHex}"
							aria-hidden="true"
						></div>
						<span>{theme.name}</span>
					</div>

					{#if themeStore.activeTheme === theme.id}
						<div class="w-1.5 h-1.5 rounded-full bg-primary" aria-label="Active"></div>
					{/if}
				</div>
			</DropdownMenu.Item>
		{/each}
	</DropdownMenu.Content>
</DropdownMenu.Root>
