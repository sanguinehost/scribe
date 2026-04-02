<script lang="ts">
	import { Card, CardHeader, CardTitle, CardContent } from '$lib/components/ui/card';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { AlertCircle, Lock, Key, Eye, EyeOff } from 'lucide-svelte';

	// Placeholder state (will be replaced with actual backend integration)
	let isLoading = $state(false);

	function handleSaveKeys() {
		isLoading = true;
		// TODO: Implement backend API call to save encrypted keys
		console.log('Saving API keys (not implemented yet)');
		setTimeout(() => {
			isLoading = false;
		}, 1000);
	}
</script>

<div class="space-y-6">
	<!-- Info Banner -->
	<Card class="border-blue-200 bg-blue-50 dark:border-blue-900 dark:bg-blue-950">
		<CardContent class="pt-6">
			<div class="flex gap-3">
				<AlertCircle class="h-5 w-5 text-blue-600 dark:text-blue-400" />
				<div class="space-y-2">
					<h3 class="font-semibold text-blue-900 dark:text-blue-100">
						API Keys Management - Coming Soon
					</h3>
					<p class="text-sm text-blue-800 dark:text-blue-200">
						This feature is currently in development. When implemented, all API keys will be:
					</p>
					<ul class="list-inside list-disc space-y-1 text-sm text-blue-800 dark:text-blue-200">
						<li>Encrypted server-side using AES-256</li>
						<li>Never transmitted to the frontend</li>
						<li>Used only for backend-initiated agentic workflows</li>
						<li>Scoped to your user account with no cross-user access</li>
					</ul>
				</div>
			</div>
		</CardContent>
	</Card>



	<!-- Save Button (disabled for now) -->
	<div class="flex justify-end gap-4 border-t pt-6">
		<ButtonComponent variant="outline" disabled={true}>Clear All Keys</ButtonComponent>
		<ButtonComponent onclick={handleSaveKeys} disabled={true}>
			{#if isLoading}
				<svg
					class="-ml-1 mr-2 h-4 w-4 animate-spin"
					xmlns="http://www.w3.org/2000/svg"
					fill="none"
					viewBox="0 0 24 24"
				>
					<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"
					></circle>
					<path
						class="opacity-75"
						fill="currentColor"
						d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
					></path>
				</svg>
				Saving...
			{:else}
				Save API Keys (Coming Soon)
			{/if}
		</ButtonComponent>
	</div>

	<!-- Security Notice -->
	<Card class="border-amber-200 bg-amber-50 dark:border-amber-900 dark:bg-amber-950">
		<CardContent class="pt-6">
			<div class="flex gap-3">
				<Lock class="h-5 w-5 text-amber-600 dark:text-amber-400" />
				<div class="space-y-2">
					<h3 class="font-semibold text-amber-900 dark:text-amber-100">
						Security & Privacy Notice
					</h3>
					<p class="text-sm text-amber-800 dark:text-amber-200">
						Once implemented, your API keys will be encrypted using industry-standard AES-256
						encryption and stored securely on our servers. They will only be used by backend
						services for features you explicitly activate (research, image generation, etc.). We
						will never log or expose your keys, and you can delete them at any time.
					</p>
				</div>
			</div>
		</CardContent>
	</Card>
</div>
