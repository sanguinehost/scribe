<script module lang="ts">
	import { resolve } from '$app/paths';
	// Snippet is imported in the main script block below

	export type FormSuccessData = {
		success: true;
	};
	export type FormFailureData = {
		success: false;
		message: string;
		email?: string;
		username?: string; // Add username for potential error feedback
	};
	export type FormData = FormSuccessData | FormFailureData;

	export type AuthFormProps = {
		authType: 'login' | 'register'; // Add authType prop
		form?: FormData;
		submitButton: Snippet<[{ pending: boolean; success: boolean }]>;
		children: Snippet;
	};
</script>

<script lang="ts">
	import { Input } from '$lib/components/ui/input';
	import type { Snippet } from 'svelte'; // Keep this import
	import { toast } from 'svelte-sonner';
	import { isDesktopMode } from '$lib/utils/features';
	import { apiClient } from '$lib/api';
	import { goto } from '$app/navigation';
	import { setAuthenticated, initializeAuth } from '$lib/auth.svelte';

	// Correctly destructure props using Svelte 5 syntax
	let { authType, submitButton, children }: AuthFormProps = $props();

	// Correctly declare state using Svelte 5 syntax
	let pending = $state(false);
	let success = $state(false);
	let errorMessage = $state<string | null>(null);

	// Form field values
	let identifier = $state('');
	let email = $state('');
	let username = $state('');
	let password = $state('');

	// Check if running in desktop mode
	const inDesktopMode = isDesktopMode();

	async function handleSubmit(event: Event) {
		event.preventDefault();
		event.stopPropagation();

		pending = true;
		errorMessage = null;

		try {
			if (authType === 'login') {
				const result = await apiClient.authenticateUser({
					identifier,
					password
				});

				if (result.isOk()) {
					success = true;
					const loginData = result.value;

					// Update auth store
					setAuthenticated(loginData.user);

					// Force initialize auth to ensure all state is synced
					await initializeAuth(true);

					toast.success('Successfully signed in');
					goto(resolve('/')); // Redirect to home/chat on success
				} else {
					errorMessage = result.error.message;
					toast.error(errorMessage);
				}
			} else {
				// In desktop mode, we hide the email field but the API still requires it.
				// Provide a safe default for local-only registration.
				const registrationEmail = inDesktopMode ? (email || `${username}@local.scribe`) : email;

				const result = await apiClient.createUser({
					email: registrationEmail,
					username,
					password
				});

				if (result.isOk()) {
					success = true;
					toast.success('Registration successful!', {
						description: 'Please check your email to verify your account before signing in.',
						duration: 8000
					});

					// Redirect to signin with success message
					goto(resolve('/signin?registration=success'));
				} else {
					errorMessage = result.error.message;
					toast.error(errorMessage);
				}
			}
		} catch (error) {
			console.error('Auth submission error:', error);
			errorMessage = 'An unexpected error occurred. Please try again.';
			toast.error(errorMessage);
		} finally {
			pending = false;
		}
	}

	// Determine identifier field properties based on authType
	const identifierLabel = $derived(authType === 'login' ? 'Email or Username' : 'Email Address');
	const identifierName = $derived(authType === 'login' ? 'identifier' : 'email');
	const identifierPlaceholder = $derived(
		authType === 'login' ? 'user@acme.com or username' : 'user@acme.com'
	);
</script>

<form onsubmit={handleSubmit} class="flex flex-col gap-4 px-4 sm:px-16" novalidate>
	<!-- Email/Identifier field: Hidden in desktop mode for registration -->
	{#if !inDesktopMode || authType === 'login'}
		<div class="flex flex-col gap-2">
			<label
				for={identifierName}
				class="text-sm font-medium leading-none text-zinc-600 peer-disabled:cursor-not-allowed peer-disabled:opacity-70 dark:text-zinc-400"
				>{identifierLabel}</label
			>

			{#if authType === 'login'}
				<Input
					id="identifier"
					name="identifier"
					class="text-md bg-muted md:text-sm"
					type="text"
					placeholder={identifierPlaceholder}
					autocomplete="username"
					required
					autofocus={!inDesktopMode}
					bind:value={identifier}
				/>
			{:else}
				<Input
					id="email"
					name="email"
					class="text-md bg-muted md:text-sm"
					type="email"
					placeholder={identifierPlaceholder}
					autocomplete="email"
					required
					autofocus={!inDesktopMode}
					bind:value={email}
				/>
			{/if}
		</div>
	{/if}

	{#if authType === 'register'}
		<div class="flex flex-col gap-2">
			<label
				for="username"
				class="text-sm font-medium leading-none text-zinc-600 peer-disabled:cursor-not-allowed peer-disabled:opacity-70 dark:text-zinc-400"
				>Username</label
			>
			<Input
				id="username"
				name="username"
				class="text-md bg-muted md:text-sm"
				type="text"
				placeholder="your_username"
				autocomplete="username"
				required
				autofocus={inDesktopMode}
				bind:value={username}
			/>
		</div>
	{/if}

	<div class="flex flex-col gap-2">
		<label
			for="password"
			class="text-sm font-medium leading-none text-zinc-600 peer-disabled:cursor-not-allowed peer-disabled:opacity-70 dark:text-zinc-400"
			>Password</label
		>

		<Input
			id="password"
			name="password"
			class="text-md bg-muted md:text-sm"
			type="password"
			required
			bind:value={password}
		/>
	</div>

	{#if errorMessage}
		<div
			class="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive"
			role="alert"
		>
			<p class="font-semibold">{errorMessage}</p>
			{#if errorMessage.toLowerCase().includes('pending email verification')}
				<p class="mt-1 opacity-90">
					Please check your inbox and spam folder for the verification link before trying to sign in.
				</p>
			{/if}
		</div>
	{/if}

	{@render submitButton({ pending, success })}
	{@render children()}
</form>
