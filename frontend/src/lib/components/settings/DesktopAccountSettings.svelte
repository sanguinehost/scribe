<script lang="ts">
	import { Button } from '../ui/button';
	import { Input } from '../ui/input';
	import { Label } from '../ui/label';
	import { Separator } from '../ui/separator';
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api';
	import { onMount } from 'svelte';
	import type { DesktopConfigResponse } from '$lib/types';

	// Desktop config state
	let desktopConfig = $state<DesktopConfigResponse | null>(null);
	let configLoading = $state(true);

	// Upgrade form state
	let showUpgradeForm = $state(false);
	let username = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let isUpgrading = $state(false);

	// Validation errors
	let usernameError = $state('');
	let passwordError = $state('');
	let confirmPasswordError = $state('');

	// Load desktop config on mount
	onMount(async () => {
		const result = await apiClient.getDesktopConfig();
		if (result.isOk()) {
			desktopConfig = result.value;
		} else {
			toast.error('Failed to load settings', {
				description: 'Could not retrieve desktop configuration'
			});
		}
		configLoading = false;
	});

	// Show upgrade form
	function startUpgrade() {
		showUpgradeForm = true;
		// Reset form
		username = '';
		password = '';
		confirmPassword = '';
		usernameError = '';
		passwordError = '';
		confirmPasswordError = '';
	}

	// Cancel upgrade
	function cancelUpgrade() {
		showUpgradeForm = false;
		username = '';
		password = '';
		confirmPassword = '';
		usernameError = '';
		passwordError = '';
		confirmPasswordError = '';
	}

	// Validate upgrade form
	function validateUpgradeForm(): boolean {
		usernameError = '';
		passwordError = '';
		confirmPasswordError = '';

		if (!username || username.trim().length < 3) {
			usernameError = 'Username must be at least 3 characters';
			return false;
		}

		if (!password || password.length < 8) {
			passwordError = 'Password must be at least 8 characters';
			return false;
		}

		if (password !== confirmPassword) {
			confirmPasswordError = 'Passwords do not match';
			return false;
		}

		return true;
	}

	// Handle account upgrade
	async function handleUpgrade() {
		if (!validateUpgradeForm()) {
			return;
		}

		isUpgrading = true;

		const result = await apiClient.desktopUpgradeAccount({
			username: username.trim(),
			password: password
		});

		if (result.isOk()) {
			toast.success('Account upgraded!', {
				description: 'Your Quick Start account has been upgraded to a protected account.'
			});

			// Reload config to reflect new auth mode
			const configResult = await apiClient.getDesktopConfig();
			if (configResult.isOk()) {
				desktopConfig = configResult.value;
			}

			// Hide form and reset
			showUpgradeForm = false;
			username = '';
			password = '';
			confirmPassword = '';
		} else {
			toast.error('Upgrade failed', {
				description: result.error.message || 'Failed to upgrade account'
			});
		}

		isUpgrading = false;
	}

	// Computed display values
	const authModeDisplay = $derived(
		desktopConfig?.auth_mode === 'quick_start'
			? 'Quick Start (No Password)'
			: desktopConfig?.auth_mode === 'account'
				? 'Password Protected Account'
				: 'Unknown'
	);

	const canUpgrade = $derived(desktopConfig?.auth_mode === 'quick_start' && !showUpgradeForm);
</script>

{#if configLoading}
	<div class="flex items-center justify-center py-8">
		<p class="text-sm text-muted-foreground">Loading settings...</p>
	</div>
{:else if desktopConfig}
	<div class="space-y-6">
		<!-- Current Auth Mode -->
		<div class="space-y-4">
			<div class="space-y-2">
				<Label>Account Type</Label>
				<div class="flex items-center justify-between rounded-lg border bg-muted/50 p-4">
					<div class="space-y-1">
						<p class="font-medium">{authModeDisplay}</p>
						{#if desktopConfig.auth_mode === 'quick_start'}
							<p class="text-xs text-muted-foreground">
								No credentials required to access your data
							</p>
						{:else}
							<p class="text-xs text-muted-foreground">Password protection enabled</p>
						{/if}
					</div>
					{#if desktopConfig.auth_mode === 'quick_start'}
						<span
							class="rounded-full bg-blue-100 px-3 py-1 text-xs font-medium text-blue-700 dark:bg-blue-950 dark:text-blue-300"
						>
							Quick Start
						</span>
					{:else}
						<span
							class="rounded-full bg-green-100 px-3 py-1 text-xs font-medium text-green-700 dark:bg-green-950 dark:text-green-300"
						>
							Protected
						</span>
					{/if}
				</div>
			</div>

			<!-- Upgrade Section -->
			{#if canUpgrade}
				<Separator />
				<div class="space-y-3">
					<h3 class="text-sm font-semibold">Upgrade to Protected Account</h3>
					<p class="text-sm text-muted-foreground">
						Add username and password protection to secure your data. This is recommended for shared
						computers.
					</p>
					<ul class="space-y-1 text-sm text-muted-foreground">
						<li class="flex items-start gap-2">
							<span class="text-green-600 dark:text-green-400">✓</span>
							<span>Password protection on app launch</span>
						</li>
						<li class="flex items-start gap-2">
							<span class="text-green-600 dark:text-green-400">✓</span>
							<span>Keep all your existing data and conversations</span>
						</li>
						<li class="flex items-start gap-2">
							<span class="text-green-600 dark:text-green-400">✓</span>
							<span>Better security for shared devices</span>
						</li>
					</ul>
					<Button onclick={startUpgrade}>Upgrade to Protected Account</Button>
				</div>
			{/if}

			<!-- Upgrade Form -->
			{#if showUpgradeForm}
				<Separator />
				<div class="space-y-4">
					<h3 class="text-sm font-semibold">Create Account Credentials</h3>

					<div class="space-y-2">
						<Label for="upgrade-username">Username</Label>
						<Input
							id="upgrade-username"
							bind:value={username}
							placeholder="Enter username"
							autocomplete="username"
							class={usernameError ? 'border-red-500' : ''}
							disabled={isUpgrading}
						/>
						{#if usernameError}
							<p class="text-sm text-red-500">{usernameError}</p>
						{/if}
					</div>

					<div class="space-y-2">
						<Label for="upgrade-password">Password</Label>
						<Input
							id="upgrade-password"
							type="password"
							bind:value={password}
							placeholder="Enter password"
							autocomplete="new-password"
							class={passwordError ? 'border-red-500' : ''}
							disabled={isUpgrading}
						/>
						{#if passwordError}
							<p class="text-sm text-red-500">{passwordError}</p>
						{:else}
							<p class="text-xs text-muted-foreground">At least 8 characters</p>
						{/if}
					</div>

					<div class="space-y-2">
						<Label for="upgrade-confirm-password">Confirm Password</Label>
						<Input
							id="upgrade-confirm-password"
							type="password"
							bind:value={confirmPassword}
							placeholder="Confirm password"
							autocomplete="new-password"
							class={confirmPasswordError ? 'border-red-500' : ''}
							disabled={isUpgrading}
						/>
						{#if confirmPasswordError}
							<p class="text-sm text-red-500">{confirmPasswordError}</p>
						{/if}
					</div>

					<div class="flex justify-end gap-2">
						<Button variant="outline" onclick={cancelUpgrade} disabled={isUpgrading}>Cancel</Button>
						<Button onclick={handleUpgrade} disabled={isUpgrading}>
							{#if isUpgrading}
								Upgrading...
							{:else}
								Upgrade Account
							{/if}
						</Button>
					</div>
				</div>
			{/if}
		</div>
	</div>
{:else}
	<div class="flex items-center justify-center py-8">
		<p class="text-sm text-red-500">Failed to load desktop configuration</p>
	</div>
{/if}
