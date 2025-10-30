<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { Separator } from '$lib/components/ui/separator';
	import { goto } from '$app/navigation';
	import { toast } from 'svelte-sonner';
	import { apiClient } from '$lib/api';
	import { setAuthenticated } from '$lib/auth.svelte';
	import type { DesktopAuthMode } from '$lib/types';

	// Wizard state
	let currentStep = $state<1 | 2 | 3>(1);
	let selectedAuthMode = $state<DesktopAuthMode | null>(null);
	let isLoading = $state(false);

	// Form fields for Account mode
	let username = $state('');
	let password = $state('');
	let confirmPassword = $state('');

	// Validation errors
	let usernameError = $state('');
	let passwordError = $state('');
	let confirmPasswordError = $state('');

	// Step navigation
	function nextStep() {
		if (currentStep === 1) {
			currentStep = 2;
		} else if (currentStep === 2) {
			if (selectedAuthMode === 'quick_start') {
				handleQuickStart();
			} else if (selectedAuthMode === 'account') {
				currentStep = 3;
			}
		}
	}

	function previousStep() {
		if (currentStep === 3) {
			currentStep = 2;
		} else if (currentStep === 2) {
			currentStep = 1;
		}
	}

	function selectAuthMode(mode: DesktopAuthMode) {
		selectedAuthMode = mode;
	}

	// Validation
	function validateAccountForm(): boolean {
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

	// Handle Quick Start
	async function handleQuickStart() {
		isLoading = true;

		const result = await apiClient.desktopSetup({
			auth_mode: 'quick_start'
		});

		if (result.isOk()) {
			const data = result.value;
			setAuthenticated(data.user);
			toast.success('Welcome to Sanguine Scribe!', {
				description: 'Quick Start setup complete. You can start chatting right away.'
			});
			goto('/chat');
		} else {
			toast.error('Setup failed', {
				description: result.error.message || 'Failed to complete Quick Start setup'
			});
		}

		isLoading = false;
	}

	// Handle Account Setup
	async function handleAccountSetup() {
		if (!validateAccountForm()) {
			return;
		}

		isLoading = true;

		const result = await apiClient.desktopSetup({
			auth_mode: 'account',
			username: username.trim(),
			password: password
		});

		if (result.isOk()) {
			const data = result.value;
			setAuthenticated(data.user);
			toast.success('Account created!', {
				description: `Welcome, ${data.user.username}! Your account has been created.`
			});
			goto('/chat');
		} else {
			toast.error('Setup failed', {
				description: result.error.message || 'Failed to create account'
			});
		}

		isLoading = false;
	}
</script>

<div
	class="flex h-dvh w-screen items-start justify-center bg-background pt-12 md:items-center md:pt-0"
>
	<div class="flex w-full max-w-md flex-col gap-8 overflow-hidden rounded-2xl px-4">
		<!-- Logo and Title -->
		<div class="flex flex-col items-center justify-center gap-4 text-center">
			<div class="flex flex-col items-center gap-3">
				<div class="h-16 w-16 overflow-hidden rounded-xl">
					<img
						src="/logo_mini.png"
						alt="Sanguine Scribe Logo"
						class="h-full w-full object-contain"
					/>
				</div>
				<h1
					class="bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-2xl font-bold text-transparent dark:text-zinc-50"
				>
					Welcome to Sanguine Scribe
				</h1>
			</div>
		</div>

		<!-- Step Indicator -->
		<div class="flex items-center justify-center gap-2">
			<div class="h-2 w-2 rounded-full {currentStep >= 1 ? 'bg-purple-600' : 'bg-gray-300'}"></div>
			<div class="h-2 w-2 rounded-full {currentStep >= 2 ? 'bg-purple-600' : 'bg-gray-300'}"></div>
			<div class="h-2 w-2 rounded-full {currentStep >= 3 ? 'bg-purple-600' : 'bg-gray-300'}"></div>
		</div>

		<!-- Step 1: Welcome Message -->
		{#if currentStep === 1}
			<Card.Root>
				<Card.Header>
					<Card.Title>Getting Started</Card.Title>
					<Card.Description>
						Let's set up your desktop experience in just a few steps
					</Card.Description>
				</Card.Header>
				<Card.Content class="space-y-4">
					<p class="text-sm text-muted-foreground">
						Sanguine Scribe Desktop gives you a powerful AI character chat experience right on your
						computer. Your data stays local and private.
					</p>
					<div class="space-y-2 text-sm">
						<div class="flex items-start gap-2">
							<span class="text-green-600 dark:text-green-400">✓</span>
							<span>No internet required for core features</span>
						</div>
						<div class="flex items-start gap-2">
							<span class="text-green-600 dark:text-green-400">✓</span>
							<span>Your conversations stay on your device</span>
						</div>
						<div class="flex items-start gap-2">
							<span class="text-green-600 dark:text-green-400">✓</span>
							<span>Fast and responsive local experience</span>
						</div>
					</div>
				</Card.Content>
				<Card.Footer>
					<Button onclick={nextStep} class="w-full">Get Started</Button>
				</Card.Footer>
			</Card.Root>
		{/if}

		<!-- Step 2: Choose Auth Mode -->
		{#if currentStep === 2}
			<Card.Root>
				<Card.Header>
					<Card.Title>Choose Your Experience</Card.Title>
					<Card.Description>Select how you'd like to use Sanguine Scribe</Card.Description>
				</Card.Header>
				<Card.Content class="space-y-4">
					<!-- Quick Start Option -->
					<button
						onclick={() => selectAuthMode('quick_start')}
						class="w-full rounded-lg border-2 p-4 text-left transition-colors {selectedAuthMode ===
						'quick_start'
							? 'border-purple-600 bg-purple-50 dark:bg-purple-950'
							: 'border-gray-200 hover:border-gray-300 dark:border-gray-700 dark:hover:border-gray-600'}"
					>
						<div class="flex items-start justify-between">
							<div class="space-y-1">
								<h3 class="font-semibold">Quick Start</h3>
								<p class="text-sm text-muted-foreground">Jump right in with no account needed</p>
							</div>
							{#if selectedAuthMode === 'quick_start'}
								<div class="h-5 w-5 rounded-full bg-purple-600 flex items-center justify-center">
									<span class="text-xs text-white">✓</span>
								</div>
							{/if}
						</div>
						<ul class="mt-3 space-y-1 text-xs text-muted-foreground">
							<li>• No username or password</li>
							<li>• Start chatting immediately</li>
							<li>• Upgrade to account anytime</li>
						</ul>
					</button>

					<Separator />

					<!-- Account Option -->
					<button
						onclick={() => selectAuthMode('account')}
						class="w-full rounded-lg border-2 p-4 text-left transition-colors {selectedAuthMode ===
						'account'
							? 'border-purple-600 bg-purple-50 dark:bg-purple-950'
							: 'border-gray-200 hover:border-gray-300 dark:border-gray-700 dark:hover:border-gray-600'}"
					>
						<div class="flex items-start justify-between">
							<div class="space-y-1">
								<h3 class="font-semibold">Create Account</h3>
								<p class="text-sm text-muted-foreground">
									Secure your data with username and password
								</p>
							</div>
							{#if selectedAuthMode === 'account'}
								<div class="h-5 w-5 rounded-full bg-purple-600 flex items-center justify-center">
									<span class="text-xs text-white">✓</span>
								</div>
							{/if}
						</div>
						<ul class="mt-3 space-y-1 text-xs text-muted-foreground">
							<li>• Password protection</li>
							<li>• Multiple user profiles</li>
							<li>• Recommended for shared computers</li>
						</ul>
					</button>
				</Card.Content>
				<Card.Footer class="flex justify-between">
					<Button onclick={previousStep} variant="outline">Back</Button>
					<Button onclick={nextStep} disabled={!selectedAuthMode || isLoading}>
						{#if isLoading}
							Setting up...
						{:else if selectedAuthMode === 'quick_start'}
							Start Chatting
						{:else}
							Continue
						{/if}
					</Button>
				</Card.Footer>
			</Card.Root>
		{/if}

		<!-- Step 3: Account Setup Form -->
		{#if currentStep === 3}
			<Card.Root>
				<Card.Header>
					<Card.Title>Create Your Account</Card.Title>
					<Card.Description>Choose a username and password for your account</Card.Description>
				</Card.Header>
				<Card.Content class="space-y-4">
					<div class="space-y-2">
						<Label for="username">Username</Label>
						<Input
							id="username"
							bind:value={username}
							placeholder="Enter username"
							autocomplete="username"
							class={usernameError ? 'border-red-500' : ''}
						/>
						{#if usernameError}
							<p class="text-sm text-red-500">{usernameError}</p>
						{/if}
					</div>

					<div class="space-y-2">
						<Label for="password">Password</Label>
						<Input
							id="password"
							type="password"
							bind:value={password}
							placeholder="Enter password"
							autocomplete="new-password"
							class={passwordError ? 'border-red-500' : ''}
						/>
						{#if passwordError}
							<p class="text-sm text-red-500">{passwordError}</p>
						{:else}
							<p class="text-xs text-muted-foreground">At least 8 characters</p>
						{/if}
					</div>

					<div class="space-y-2">
						<Label for="confirm-password">Confirm Password</Label>
						<Input
							id="confirm-password"
							type="password"
							bind:value={confirmPassword}
							placeholder="Confirm password"
							autocomplete="new-password"
							class={confirmPasswordError ? 'border-red-500' : ''}
						/>
						{#if confirmPasswordError}
							<p class="text-sm text-red-500">{confirmPasswordError}</p>
						{/if}
					</div>
				</Card.Content>
				<Card.Footer class="flex justify-between">
					<Button onclick={previousStep} variant="outline" disabled={isLoading}>Back</Button>
					<Button onclick={handleAccountSetup} disabled={isLoading}>
						{#if isLoading}
							Creating Account...
						{:else}
							Create Account
						{/if}
					</Button>
				</Card.Footer>
			</Card.Root>
		{/if}
	</div>
</div>
