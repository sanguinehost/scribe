<script lang="ts">
	import { goto } from '$app/navigation';
	import { apiClient } from '$lib/api';
	import { ApiResponseError, ApiNetworkError, ApiClientError } from '$lib/errors/api';
	import Button from '$lib/components/ui/button/button.svelte';
	import Input from '$lib/components/ui/input/input.svelte';
	import Label from '$lib/components/ui/label/label.svelte';
	import * as Card from '$lib/components/ui/card';
	import { toast } from 'svelte-sonner'; // Added toast import

	let email = '';
	let username = '';
	let password = '';
	let confirmPassword = '';
	let loading = false;
	let errorMessage = '';

	async function handleSubmit() {
		// Basic client-side validation (optional, enhance as needed)
		if (!email || !username || !password || password !== confirmPassword) {
			errorMessage = 'Please fill all fields correctly. Passwords must match.';
			return;
		}
		if (password.length < 8) {
			errorMessage = 'Password must be at least 8 characters long.';
			return;
		}
		// TODO: Add email format check if desired

		loading = true;
		errorMessage = '';

		try {
			// 1. Register the user
			const registerResult = await apiClient.createUser({ email, username, password });

			if (registerResult.isOk()) {
				const authUser = registerResult.value;
				console.log('User registered successfully via apiClient:', authUser);

				// Registration successful, redirect to signin page
				toast.success('Registration successful! Please sign in.');
				goto('/signin'); 
			} else {
				// Handle registration error
				console.error('Registration failed:', registerResult.error);
				errorMessage = registerResult.error.message;
				// Check for specific errors like 'UsernameTaken' or 'EmailTaken' by checking the error type and status
				if (registerResult.error instanceof ApiResponseError && registerResult.error.statusCode === 409) { 
					errorMessage = `Registration failed: ${registerResult.error.message}`;
				}
			}
		} catch (error: unknown) {
			console.error('Error during signup process:', error);
			// Check if it's an ApiError we know how to handle
			if (error instanceof ApiResponseError || error instanceof ApiNetworkError || error instanceof ApiClientError) {
				errorMessage = `An unexpected error occurred: ${error.message}`;
			} else if (error instanceof Error) { // Handle generic Error objects
				errorMessage = `An unexpected error occurred: ${error.message}`;
			} else { // Fallback for unknown error types
				errorMessage = 'An unexpected error occurred.';
			}
		} finally {
			loading = false;
		}
	}
</script>

<div class="flex min-h-screen items-center justify-center bg-gray-100 dark:bg-gray-900">
	<Card.Root class="w-full max-w-md">
		<Card.Header class="space-y-1 text-center">
			<Card.Title class="text-2xl font-bold">Sign Up</Card.Title>
			<Card.Description>Enter your details to create an account</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-4">
			<form on:submit|preventDefault={handleSubmit} class="space-y-4">
				<div class="space-y-2">
					<Label for="email">Email</Label>
					<Input id="email" type="email" placeholder="m@example.com" required bind:value={email} />
				</div>
				<div class="space-y-2">
					<Label for="username">Username</Label>
					<Input id="username" type="text" placeholder="Your username" required bind:value={username} />
				</div>
				<div class="space-y-2">
					<Label for="password">Password</Label>
					<Input id="password" type="password" required bind:value={password} />
				</div>
				<div class="space-y-2">
					<Label for="confirm-password">Confirm Password</Label>
					<Input id="confirm-password" type="password" required bind:value={confirmPassword} />
				</div>
				{#if errorMessage}
					<p class="text-sm text-red-600 dark:text-red-400">{errorMessage}</p>
				{/if}
				<Button type="submit" class="w-full" disabled={loading}>
					{#if loading} Creating Account... {:else} Create Account {/if}
				</Button>
			</form>
		</Card.Content>
		<Card.Footer class="text-center text-sm">
			Already have an account? <a href="/signin" class="underline">Sign In</a>
		</Card.Footer>
	</Card.Root>
</div>