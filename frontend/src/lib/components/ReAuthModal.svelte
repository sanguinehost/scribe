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
	import { AlertCircle } from 'lucide-svelte';
	import { onMount } from 'svelte';

	export let open = false;
	export let reason: 'dek_missing' | 'session_expired' = 'dek_missing';
	export let onSuccess: (() => void) | undefined = undefined;

	let password = '';
	let loading = false;
	let error: string | null = null;
	let identifier = '';

	// Load current user email/username from localStorage or session
	onMount(async () => {
		const storedUser = localStorage.getItem('user_email') || '';
		identifier = storedUser;
	});

	const messages = {
		dek_missing: {
			title: 'Security Key Required',
			description: 'System Update Detected',
			explanation:
				'Our servers were recently updated for security and performance improvements. For your security, your encryption key was not persisted during the update and must be re-derived from your password.',
			note: 'Your session is still valid - we just need to verify your password to unlock your encrypted data. None of your data has been lost.',
			icon: '🔄'
		},
		session_expired: {
			title: 'Session Expired',
			description: 'Your session has expired',
			explanation:
				'For security reasons, sessions expire after a period of inactivity. Please sign in again to continue.',
			note: '',
			icon: '⏱️'
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
