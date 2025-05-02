<script lang="ts">
	// Removed authStore import
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { AlertCircle } from 'lucide-svelte';
	import { Alert, AlertDescription, AlertTitle } from '$lib/components/ui/alert';
	import { goto } from '$app/navigation'; // Import goto
	import { apiClient } from '$lib/services/apiClient'; // Import apiClient

	let username = '';
	// Removed email state
	let password = '';
	let confirmPassword = '';
	let error: string | null = null; // Local error state
	let isLoading = false; // Local loading state

	// Removed reactive authStore dependency

	const handleRegister = async () => {
		error = null; // Clear previous errors

		// Basic client-side check for password match
		if (password !== confirmPassword) {
			error = 'Passwords do not match.';
			return;
		}

		isLoading = true;
		try {
			// Call apiClient.register without email
			await apiClient.register(username, password);
			// On successful registration, redirect to login page
			console.log('Registration successful, navigating to /login');
			goto('/login', { replaceState: true });
			// No need to set isLoading = false here as we are navigating away
		} catch (err: any) {
			console.error('Registration failed:', err);
			// Display error from API or a generic message
			error = err?.message || 'Registration failed. Please try again.';
			isLoading = false; // Stop loading indicator on error
		}
	};
</script>

<form on:submit|preventDefault={handleRegister} class="space-y-4">
	{#if error}
		<Alert variant="destructive">
			<AlertCircle class="h-4 w-4" />
			<AlertTitle>Error</AlertTitle>
			<AlertDescription>{error}</AlertDescription>
		</Alert>
	{/if}

	<div class="space-y-2">
		<Label for="username">Username</Label>
		<Input id="username" type="text" bind:value={username} placeholder="Choose a username" required disabled={isLoading} />
	</div>

	<div class="space-y-2">
		<Label for="password">Password</Label>
		<Input id="password" type="password" bind:value={password} placeholder="Create a password" required disabled={isLoading} />
	</div>

	<div class="space-y-2">
		<Label for="confirmPassword">Confirm Password</Label>
		<Input id="confirmPassword" type="password" bind:value={confirmPassword} placeholder="Confirm your password" required disabled={isLoading} />
	</div>

	<Button type="submit" class="w-full" disabled={isLoading}>
		{#if isLoading}
			<svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
				<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
				<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
			</svg>
			Registering...
		{:else}
			Register
		{/if}
	</Button>
</form>