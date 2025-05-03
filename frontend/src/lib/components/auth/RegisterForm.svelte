<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { authStore } from '$lib/stores/authStore';
	import { AlertCircle } from 'lucide-svelte'; // For error icon
	import * as Alert from '$lib/components/ui/alert';

	let username = $state('');
	let email = $state('');
	let password = $state('');
	let isLoading = $state(false);
	let errorMessage = $state<string | null>(null);

	const handleSubmit = async (event: SubmitEvent) => {
		event.preventDefault(); // Prevent default form submission
		errorMessage = null; // Clear previous errors
		if (!username || !email || !password) {
			errorMessage = 'Username, email, and password are required.';
			return;
		}
		// Add more validation later (e.g., password complexity)

		isLoading = true;
		try {
			// authStore.register handles success (redirect) and sets its own error state
			await authStore.register(username, email, password);
			// Success is handled by the store/layout redirecting
		} catch (error: any) {
			console.error('Registration failed:', error);
			// Use the error message from the store if available, otherwise a generic one
			errorMessage = $authStore.error || 'Registration failed. Please try again.';
		} finally {
			isLoading = false;
		}
	};
</script>

<Card.Root class="w-full max-w-sm">
	<Card.Header>
		<Card.Title class="text-2xl">Register</Card.Title>
		<Card.Description>Enter your details below to create an account.</Card.Description>
	</Card.Header>
	<Card.Content class="grid gap-4">
		{#if errorMessage}
			<Alert.Root variant="destructive">
				<AlertCircle class="h-4 w-4" />
				<Alert.Title>Error</Alert.Title>
				<Alert.Description>{errorMessage}</Alert.Description>
			</Alert.Root>
		{/if}
		<form onsubmit={handleSubmit} class="grid gap-4">
		  <div class="grid gap-2">
		    <Label for="username">Username</Label>
				<Input id="username" type="text" placeholder="your_username" required bind:value={username} disabled={isLoading} />
			</div>
			<div class="grid gap-2">
				<Label for="email">Email</Label>
				<Input id="email" type="email" placeholder="m@example.com" required bind:value={email} disabled={isLoading} />
			</div>
			<div class="grid gap-2">
				<Label for="password">Password</Label>
				<Input id="password" type="password" required bind:value={password} disabled={isLoading} />
			</div>
			<Button type="submit" class="w-full" disabled={isLoading}>
				{#if isLoading}
					<svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
					</svg>
					Processing...
				{:else}
					Register
				{/if}
			</Button>
		</form>
	</Card.Content>
	<Card.Footer>
		<p class="text-sm text-muted-foreground">
			Already have an account? <a href="/login" class="underline">Login</a>
		</p>
	</Card.Footer>
</Card.Root>