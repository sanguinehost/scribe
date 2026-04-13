<script lang="ts">
	import AuthForm from '$lib/components/auth-form.svelte';
	import type { FormData as AuthFormData } from '$lib/components/auth-form.svelte'; // Import FormData type
	import SubmitButton from '$lib/components/submit-button.svelte';
	import { page } from '$app/stores'; // Use $app/stores for page store
	import { onMount } from 'svelte';
	import { toast } from 'svelte-sonner';
	import { isDesktopMode } from '$lib/utils/features';
	import { resolve } from '$app/paths';

	// Desktop mode: form data from server actions is not available with ssr:false
	let { form }: { form?: unknown } = $props();

	// Use $page store for route parameters
	const currentAuthTypeParam = $derived($page.params.authType);
	const signInSignUp = $derived(currentAuthTypeParam === 'signup' ? 'Sign up' : 'Sign in');
	// Map route param to AuthForm prop value using correct $derived syntax
	const authType = $derived<'login' | 'register'>(
		currentAuthTypeParam === 'signup' ? 'register' : 'login'
	);

	// Check if running in desktop mode
	const inDesktopMode = isDesktopMode();

	// Update description based on authType and desktop mode using correct $derived syntax
	const _description = $derived(
		authType === 'register'
			? inDesktopMode
				? 'Choose a username and password for your local account'
				: 'Use your email, username and password to sign up'
			: inDesktopMode
				? 'Sign in with your username and password'
				: 'Use your email or username and password to sign in'
	);

	// Explicitly cast form to the type expected by AuthForm
	const authFormProp = $derived(form as AuthFormData | undefined);

	// Handle FIDO2 errors by suppressing them
	onMount(() => {
		// Check if this is a redirect from successful registration
		const urlParams = new URLSearchParams(window.location.search);
		if (urlParams.get('registration') === 'success') {
			toast.success('Registration successful!', {
				description: 'Please check your email to verify your account before signing in.',
				duration: 8000
			});
		}
		// Create a custom error handler for the page
		window.addEventListener(
			'error',
			(event) => {
				// Check if the error is the FIDO2 duplicate script ID error
				if (
					event.message &&
					event.message.includes('Duplicate script ID') &&
					event.message.includes('fido2-page-script')
				) {
					// Prevent the error from propagating
					event.preventDefault();
					event.stopPropagation();
					console.log('Suppressed FIDO2 script error');
					return true;
				}
				return false;
			},
			true
		); // Use capture phase to intercept early
	});
</script>

<div
	class="bg-ambient flex min-h-dvh w-screen items-start justify-center pt-12 md:items-center md:pt-0"
>
	<div class="flex w-full max-w-lg flex-col gap-8 p-4">
		<!-- Pass authType prop and the explicitly cast form data -->
		<AuthForm {authType} form={authFormProp}>
			{#snippet submitButton({ pending, success })}
				<SubmitButton {pending} {success}>{signInSignUp}</SubmitButton>
			{/snippet}

			{#if authType === 'register'}
				{@render switchAuthType({
					question: 'Already have an account? ',
					href: '/signin',
					cta: 'Sign in',
					postscript: ' instead.'
				})}
			{:else}
				{@render switchAuthType({
					question: "Don't have an account? ",
					href: '/signup',
					cta: 'Sign up',
					postscript: ' for free.'
				})}
			{/if}
		</AuthForm>

		{#if inDesktopMode && authType === 'register'}
			<p class="text-center text-xs text-muted-foreground/60">
				No email required — your data stays on your device
			</p>
		{/if}
	</div>
</div>

{#snippet switchAuthType({
	question,
	href,
	cta,
	postscript
}: {
	question: string;
	href: string;
	cta: string;
	postscript: string;
})}
	<p class="mt-4 text-center text-sm text-muted-foreground">
		{question}
		<a href={resolve(href as unknown as "/")} class="font-semibold text-foreground/80 hover:text-foreground hover:underline">
			{cta}
		</a>
		{postscript}
	</p>
{/snippet}
