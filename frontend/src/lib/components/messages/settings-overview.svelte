<script lang="ts">
	import { scale } from 'svelte/transition';
	import { Button } from '../ui/button';
	import { SettingsStore } from '$lib/stores/settings.svelte';

	const settingsStore = SettingsStore.fromContext();

	function showDefaultSettings() {
		settingsStore.setViewMode('defaults');
	}

	function showAdvancedSettings() {
		settingsStore.setViewMode('advanced');
	}

	function closeSettings() {
		settingsStore.hide();
	}
</script>

<div class="mx-auto max-w-3xl md:mt-20" transition:scale={{ opacity: 0, start: 0.98 }}>
	<div class="flex max-w-xl flex-col gap-8 rounded-xl p-6 text-center leading-relaxed">
		<p class="flex flex-row items-center justify-center gap-4">
			<!-- Settings icon -->
			<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-settings">
				<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.38a2 2 0 0 0-.73-2.73l-.15-.1a2 2 0 0 1-1-1.72v-.51a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/>
				<circle cx="12" cy="12" r="3"/>
			</svg>
		</p>
		<h1 class="text-2xl font-bold">Settings</h1>
		<p>
			Configure your default preferences for <strong>Scribe</strong>. These settings will apply to new chats and can be overridden per-chat.
		</p>
		
		<div class="flex flex-col gap-4">
			<Button onclick={showDefaultSettings} class="w-full">
				<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-sliders mr-2">
					<line x1="4" x2="4" y1="21" y2="14"/>
					<line x1="4" x2="4" y1="10" y2="3"/>
					<line x1="12" x2="12" y1="21" y2="12"/>
					<line x1="12" x2="12" y1="8" y2="3"/>
					<line x1="20" x2="20" y1="21" y2="16"/>
					<line x1="20" x2="20" y1="12" y2="3"/>
					<line x1="1" x2="7" y1="14" y2="14"/>
					<line x1="9" x2="15" y1="8" y2="8"/>
					<line x1="17" x2="23" y1="16" y2="16"/>
				</svg>
				Default Settings
			</Button>
			
			<Button onclick={showAdvancedSettings} variant="outline" class="w-full">
				<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-wrench mr-2">
					<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
				</svg>
				Advanced Settings
			</Button>

			<Button onclick={closeSettings} variant="link" class="w-full text-muted-foreground">
				Close Settings
			</Button>
		</div>

		<div class="text-sm text-muted-foreground mt-4">
			<p>Settings are saved automatically and synced across your devices.</p>
		</div>
	</div>
</div>