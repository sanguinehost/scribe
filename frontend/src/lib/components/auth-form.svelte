<script module lang="ts">
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
	import { enhance } from '$app/forms';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import type { SubmitFunction } from '@sveltejs/kit';
	import type { Snippet } from 'svelte'; // Keep this import
	import { toast } from 'svelte-sonner';

	// Correctly destructure props using Svelte 5 syntax
	let { authType, form, submitButton, children }: AuthFormProps = $props();

	// Correctly declare state using Svelte 5 syntax
	let pending = $state(false);

	const enhanceCallback: SubmitFunction<FormSuccessData, FormFailureData> = () => {
		pending = true;
		return async ({ result, update }) => {
			if (result.type === 'failure' && result.data?.message) {
				toast.error(result.data.message, { duration: 5000 });
			}
			pending = false;
			// Don't call update() on success for auth forms, rely on redirect/navigation
			if (result.type !== 'success') {
				await update();
			}
		};
	};

	// Determine identifier field properties based on authType
	const identifierLabel = $derived(authType === 'login' ? 'Email or Username' : 'Email Address');
	const identifierName = $derived(authType === 'login' ? 'identifier' : 'email');
	const identifierType = $derived(authType === 'login' ? 'text' : 'email');
	const identifierPlaceholder = $derived(
		authType === 'login' ? 'user@acme.com or username' : 'user@acme.com'
	);
	const identifierAutocomplete = $derived(authType === 'login' ? 'username' : 'email'); // Use 'username' as it's a valid value and common hint

	const identifierDefaultValue = $derived.by(() => {
		// Repopulate identifier field on error
		if (!form?.success) {
			// For login, the backend might send back the attempted identifier in the 'email' field (if it was an email)
			// or potentially a different field if it was a username. Assuming 'email' for now.
			// For register, it's definitely the email.
			return form?.email; // Use optional chaining
		}
		return undefined;
	});

	const usernameDefaultValue = $derived.by(() => {
		// Repopulate username field on registration error
		if (authType === 'register' && !form?.success) {
			return form?.username; // Use optional chaining
		}
		return undefined;
	});
</script>

<form method="POST" class="flex flex-col gap-4 px-4 sm:px-16" use:enhance={enhanceCallback}>
	<div class="flex flex-col gap-2">
		<Label for={identifierName} class=" text-zinc-600 dark:text-zinc-400">{identifierLabel}</Label>

		<Input
			id={identifierName}
			name={identifierName}
			class="text-md bg-muted md:text-sm"
			type={identifierType}
			placeholder={identifierPlaceholder}
			autocomplete={identifierAutocomplete}
			required
			autofocus
			value={identifierDefaultValue}
		/>
	</div>

	{#if authType === 'register'}
		<div class="flex flex-col gap-2">
			<Label for="username" class="text-zinc-600 dark:text-zinc-400">Username</Label>
			<Input
				id="username"
				name="username"
				class="text-md bg-muted md:text-sm"
				type="text"
				placeholder="your_username"
				autocomplete="username"
				required
				value={usernameDefaultValue}
			/>
		</div>
	{/if}

	<div class="flex flex-col gap-2">
		<Label for="password" class="text-zinc-600 dark:text-zinc-400">Password</Label>

		<Input
			id="password"
			name="password"
			class="text-md bg-muted md:text-sm"
			type="password"
			required
		/>
	</div>

	{@render submitButton({ pending, success: !!form?.success })}
	{@render children()}
</form>
