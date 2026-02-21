<script lang="ts">
	import { cn as _cn } from '$lib/utils/shadcn';
	import ChevronUp from './icons/chevron-up.svelte';
	import {
		DropdownMenu,
		DropdownMenuContent,
		DropdownMenuItem,
		DropdownMenuSeparator,
		DropdownMenuTrigger
	} from './ui/dropdown-menu';
	import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from './ui/sidebar';
	import { getCurrentUser, getIsAuthenticated, getHasConnectionError } from '$lib/auth.svelte';
	import { apiClient as _apiClient } from '$lib/api';
	import { performLogout } from '$lib/auth.svelte';
	import { goto as _goto } from '$app/navigation';
	import { PlanBadge, subscriptionStore, DailyMessageUsage } from './membership';
	import { CheckoutButton } from './payment';
	import { ENABLE_PAYMENTS } from '$lib/utils/features';
	import { SettingsStore } from '$lib/stores/settings.svelte';

	const settingsStore = SettingsStore.fromContext();

	async function handleSignOut() {
		// Use comprehensive logout that clears both state and cookies immediately
		await performLogout('manual', false);
		// Redirect to signin page - backend cleanup is now handled inside performLogout
		_goto('/signin');
	}

	function openMembershipSettings() {
		// Show settings overview which prominently displays membership when payments are enabled
		settingsStore.setViewMode('overview');
		settingsStore.show();
	}
</script>

<SidebarMenu>
	<SidebarMenuItem>
		<DropdownMenu>
			<DropdownMenuTrigger>
				{#snippet child({ props })}
					<SidebarMenuButton
						{...props}
						class="h-10 bg-background data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground {getHasConnectionError()
							? 'border-l-2 border-orange-500'
							: ''}"
					>
						{#if getIsAuthenticated() && getCurrentUser()}
							<div class="flex h-6 w-6 items-center justify-center rounded-full bg-muted">
								<span class="text-xs font-semibold">
									{getCurrentUser()?.username?.charAt(0).toUpperCase() ?? 'U'}
								</span>
							</div>
							<span class="truncate">{getCurrentUser()?.email}</span>
							{#if getHasConnectionError()}
								<span class="ml-auto text-xs text-orange-500">⚠</span>
							{:else}
								<ChevronUp class="ml-auto" />
							{/if}
						{:else if getHasConnectionError()}
							<!-- Show connection error state even when user data is not available -->
							<div class="flex h-6 w-6 items-center justify-center rounded-full bg-muted">
								<span class="text-xs">?</span>
							</div>
							<span class="truncate">Connection issues</span>
							<span class="ml-auto text-xs text-orange-500">⚠</span>
						{:else}
							<span class="truncate">Not signed in</span>
						{/if}
					</SidebarMenuButton>
				{/snippet}
			</DropdownMenuTrigger>
			<DropdownMenuContent side="top" class="w-[--bits-floating-anchor-width]">
				{#if getHasConnectionError()}
					<DropdownMenuItem class="cursor-default text-orange-600">
						⚠ Connection issues detected
					</DropdownMenuItem>
					<DropdownMenuSeparator />
				{/if}

				<!-- Membership information when payments are enabled and user is authenticated -->
				{#if ENABLE_PAYMENTS && getCurrentUser() && !getHasConnectionError()}
					<div class="px-2 py-2">
						<div class="mb-2 flex items-center gap-2">
							<PlanBadge
								planType={subscriptionStore.currentPlan}
								status={subscriptionStore.subscription?.status}
								_size="sm"
								showStatus={true}
							/>
							<span class="text-xs text-slate-600 dark:text-slate-300">
								{subscriptionStore.getPlanDisplayName()}
							</span>
						</div>

						<!-- Daily Activity Display -->
						<div class="mb-2">
							<DailyMessageUsage
								messageCount={subscriptionStore.dailyMessageCount}
								planType={subscriptionStore.currentPlan}
								isThrottled={subscriptionStore.isThrottled}
								throttleDelay={subscriptionStore.throttleDelay}
								_size="sm"
							/>
						</div>

						<!-- Debug logging for sidebar user nav -->
						{#if typeof window !== 'undefined'}
							{@const _ = console.log('🔍 Sidebar User Nav Debug:', {
								currentPlan: subscriptionStore.currentPlan,
								planDisplayName: subscriptionStore.getPlanDisplayName(),
								dailyMessageCount: subscriptionStore.dailyMessageCount,
								subscription: subscriptionStore.subscription,
								planFeatures: subscriptionStore.planFeatures
							})}
						{/if}

						<!-- Upgrade button for free users or when at daily limit -->
						{#if (subscriptionStore.currentPlan as unknown) === 'free' || (subscriptionStore.usageLimits?.daily_message_count && subscriptionStore.usageLimits.daily_message_count >= 20 && (subscriptionStore.currentPlan as unknown) === 'free')}
							<div class="mt-2">
								<CheckoutButton
									planType="basic"
									buttonText="Upgrade Plan"
									buttonClass="w-full text-xs py-1 px-2 bg-blue-600 hover:bg-blue-700 text-white rounded border-none cursor-pointer"
								/>
							</div>
						{/if}
					</div>
					<DropdownMenuItem class="cursor-pointer" onSelect={openMembershipSettings}>
						<svg
							xmlns="http://www.w3.org/2000/svg"
							width="16"
							height="16"
							viewBox="0 0 24 24"
							fill="none"
							stroke="currentColor"
							stroke-width="2"
							stroke-linecap="round"
							stroke-linejoin="round"
							class="mr-2"
						>
							<path
								d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.38a2 2 0 0 0-.73-2.73l-.15-.1a2 2 0 0 1-1-1.72v-.51a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"
							/>
							<circle cx="12" cy="12" r="3" />
						</svg>
						Manage Membership
					</DropdownMenuItem>
					<DropdownMenuSeparator />
				{/if}

				<!-- Show controls if we have user data OR connection issues (user might want to clear session) -->
				{#if getCurrentUser() || getHasConnectionError()}
					<DropdownMenuItem class="cursor-pointer" onSelect={handleSignOut}>
						{#if getHasConnectionError()}
							Clear session & sign out
						{:else}
							Sign out
						{/if}
					</DropdownMenuItem>
				{/if}
			</DropdownMenuContent>
		</DropdownMenu>
	</SidebarMenuItem>
</SidebarMenu>
