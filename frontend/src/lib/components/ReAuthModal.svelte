<script lang="ts">
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogHeader,
		DialogTitle
	} from '$lib/components/ui/dialog';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { apiClient } from '$lib/api';
	import { setAuthenticated } from '$lib/auth.svelte';
	import { clearDekMissing } from '$lib/stores/authState';
	import { AlertCircle } from 'lucide-svelte';
	import { onMount } from 'svelte';

	// Svelte 5 runes mode: Use $props() instead of export let
	let {
		open = $bindable(false),
		reason = 'dek_missing',
		onSuccess
	}: {
		open?: boolean;
		reason?: 'dek_missing' | 'session_expired';
		onSuccess?: () => void;
	} = $props();

	// CRITICAL: Internal state must use $state() for reactivity
	let password = $state('');
	let loading = $state(false);
	let error = $state<string | null>(null);
	let identifier = $state('');

	// Load current user email/username from localStorage or session
	onMount(async () => {
		const storedUser = localStorage.getItem('user_email') || '';
		identifier = storedUser;
	});

	const messages = {
		dek_missing: {
			title: 'Re-authentication Required',
			description: 'Please sign in to continue',
			explanation:
				'Required after session expiry, server restarts/updates, or for security verification.',
			note: '',
			icon: '🔐'
		},
		session_expired: {
			title: 'Session Expired',
			description: 'Please sign in to continue',
			explanation:
				'Required after session expiry, server restarts/updates, or for security verification.',
			note: '',
			icon: '🔐'
		}
	};

	async function handleReAuth() {
		if (!password) {
			error = 'Please enter your password';
			return;
		}

		loading = true;
		error = null;

		try {
			const result = await apiClient.authenticateUser({ identifier, password });

			if (result.isOk()) {
				const authData = result.value;
				setAuthenticated(authData.user);

				// Clear form
				password = '';

				// Close modal
				open = false;

				// Clear DEK missing flag in global state
				clearDekMissing();

				// Dispatch event to trigger queued request retries
				window.dispatchEvent(
					new CustomEvent('auth:reauth-complete', {
						detail: { success: true }
					})
				);

				// Call success callback if provided
				if (onSuccess) {
					onSuccess();
				}

				// Show success message
				console.log('[ReAuthModal] Re-authentication successful');
			} else {
				error = result.error.message || 'Authentication failed. Please check your password.';
			}
		} catch (e) {
			error = 'An unexpected error occurred. Please try again.';
			console.error('[ReAuthModal] Re-authentication error:', e);
		} finally {
			loading = false;
		}
	}

	function handleKeyPress(event: KeyboardEvent) {
		if (event.key === 'Enter' && !loading) {
			handleReAuth();
		}
	}

	// Prevent modal from closing when reason is 'dek_missing'
	function handleOpenChange(newOpen: boolean) {
		// If trying to close (newOpen = false) and reason is dek_missing, prevent it
		if (!newOpen && reason === 'dek_missing') {
			// Keep modal open
			return;
		}
		// Otherwise allow the state change
		open = newOpen;
	}
</script>

<Dialog bind:open onOpenChange={handleOpenChange}>
	<DialogContent class="sm:max-w-[500px] {reason === 'dek_missing' ? '[&>button]:hidden' : ''}">
		<DialogHeader>
			<div class="flex items-center gap-3">
				<div class="text-3xl">{messages[reason].icon}</div>
				<div>
					<DialogTitle class="text-xl">{messages[reason].title}</DialogTitle>
					<DialogDescription class="text-base">
						{messages[reason].description}
					</DialogDescription>
				</div>
			</div>
		</DialogHeader>

		<div class="space-y-4 py-4">
			<!-- Explanation -->
			<div
				class="rounded-lg border border-blue-200 bg-blue-50 p-4 dark:border-blue-800 dark:bg-blue-950"
			>
				<p class="text-sm text-blue-900 dark:text-blue-100">
					{messages[reason].explanation}
				</p>
			</div>

			<!-- Re-authentication form -->
			<div class="space-y-4">
				<div class="space-y-2">
					<Label for="reauth-identifier">Email or Username</Label>
					<Input
						id="reauth-identifier"
						type="text"
						bind:value={identifier}
						placeholder="your@email.com"
						disabled={loading}
					/>
				</div>

				<div class="space-y-2">
					<Label for="reauth-password">Password</Label>
					<Input
						id="reauth-password"
						type="password"
						bind:value={password}
						placeholder="Enter your password"
						disabled={loading}
						onkeypress={handleKeyPress}
						autofocus
					/>
				</div>

				{#if error}
					<div
						class="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 dark:border-red-800 dark:bg-red-950"
					>
						<AlertCircle class="mt-0.5 h-5 w-5 flex-shrink-0 text-red-600 dark:text-red-400" />
						<p class="text-sm text-red-900 dark:text-red-100">{error}</p>
					</div>
				{/if}
			</div>

			<!-- Note -->
			{#if messages[reason].note}
				<div class="rounded-lg bg-muted p-3">
					<p class="text-xs text-muted-foreground">{messages[reason].note}</p>
				</div>
			{/if}

			<!-- Actions -->
			<div class="flex justify-end gap-2 pt-2">
				<!-- Only show Cancel button for session_expired, not for dek_missing (which requires re-auth) -->
				{#if reason === 'session_expired'}
					<Button variant="outline" onclick={() => (open = false)} disabled={loading}>Cancel</Button
					>
				{/if}
				<Button onclick={handleReAuth} disabled={loading || !password}>
					{#if loading}
						<span class="flex items-center gap-2">
							<span class="animate-spin">⟳</span>
							Verifying...
						</span>
					{:else}
						Sign In
					{/if}
				</Button>
			</div>
		</div>
	</DialogContent>
</Dialog>
