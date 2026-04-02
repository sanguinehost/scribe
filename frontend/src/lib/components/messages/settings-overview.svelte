<script lang="ts">
	import { fly as _fly } from 'svelte/transition';
	import { quintOut as _quintOut } from 'svelte/easing';
	import { Button as ButtonComponent } from '../ui/button';
	import { SettingsStore } from '$lib/stores/settings.svelte';
	import { MembershipSettings } from '$lib/components/membership';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { Settings, Sliders } from 'lucide-svelte';

	const settingsStore = SettingsStore.fromContext();

	function showConsolidatedSettings() {
		settingsStore.setViewMode('consolidated');
	}

	function closeSettings() {
		settingsStore.hide();
	}
</script>

<div class="mx-auto max-w-3xl">
	<div class="mx-auto flex max-w-xl flex-col gap-8 rounded-xl p-6 text-center leading-relaxed">
		<p class="flex flex-row items-center justify-center gap-4">
			<!-- Settings icon -->
			<Settings class="h-8 w-8" />
		</p>
		<h1 class="text-2xl font-bold">Settings</h1>
		<p>
			Configure your default preferences for <strong>Scribe</strong>. These settings will apply to
			new chats and can be overridden per-chat.
		</p>

		<!-- Membership Settings Card - Make it prominent -->
		{#if ENABLE_PAYMENTS}
			<div class="w-full">
				<MembershipSettings />
			</div>
			<div class="mt-4">
				<ButtonComponent onclick={showConsolidatedSettings} class="w-full" variant="outline">
					<Sliders class="mr-2 h-4 w-4" />
					Advanced Settings
				</ButtonComponent>
			</div>
		{:else}
			<div class="flex flex-col gap-4">
				<ButtonComponent onclick={showConsolidatedSettings} class="w-full">
					<Sliders class="mr-2 h-4 w-4" />
					Configure Settings
				</ButtonComponent>
			</div>
		{/if}

		<div class="mt-4">
			<ButtonComponent onclick={closeSettings} variant="link" class="w-full text-muted-foreground">
				Close Settings
			</ButtonComponent>
		</div>

		<div class="mt-4 text-sm text-muted-foreground">
			<p>Settings are saved automatically and synced across your devices.</p>
		</div>
	</div>
</div>
