<script lang="ts">
	import '../app.css';
	import { ThemeProvider } from '@sejohnson/svelte-themes';
	import { Toaster } from '$lib/components/ui/sonner';
import { SettingsStore } from '$lib/stores/settings.svelte';

	const settingsStore = new SettingsStore();
	SettingsStore.toContext(settingsStore);

	let { children } = $props();
</script>

<ThemeProvider attribute="class" disableTransitionOnChange>
	<Toaster position="top-center" />
	{@render children()}
</ThemeProvider>
