<script lang="ts">
	import { authStore } from '$lib/stores/authStore';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { AlertCircle } from 'lucide-svelte';
	import { Alert, AlertDescription, AlertTitle } from '$lib/components/ui/alert';
	import { goto } from '$app/navigation'; // Import goto

	let username = '';
	let password = '';

	$: ({ isLoading, error } = $authStore);

	const handleSubmit = async () => {
		// Remove basic client-side validation, rely on store/API errors
		// if (!username || !password) { ... }

		const success = await authStore.login(username, password);

		if (success) {
			// Navigate on successful login
			console.log('Login successful, navigating to /characters');
			goto('/characters', { replaceState: true });
		}
		// If not successful, the error will be displayed via the reactive $authStore.error
	};
</script>

<form on:submit|preventDefault={handleSubmit} class="space-y-4">
	{#if error}
		<Alert variant="destructive">
			<AlertCircle class="h-4 w-4" />
			<AlertTitle>Error</AlertTitle>
			<AlertDescription>{error}</AlertDescription>
		</Alert>
	{/if}

	<div class="space-y-2">
		<Label for="username">Username</Label>
		<Input id="username" type="text" bind:value={username} placeholder="Enter your username" required disabled={isLoading} />
	</div>

	<div class="space-y-2">
		<Label for="password">Password</Label>
		<Input id="password" type="password" bind:value={password} placeholder="Enter your password" required disabled={isLoading} />
	</div>

	<Button type="submit" class="w-full" disabled={isLoading}>
		{#if isLoading}
			<svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
				<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
				<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
			</svg>
			Logging in...
		{:else}
			Login
		{/if}
	</Button>
</form>