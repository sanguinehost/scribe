<script lang="ts">
	import { cn } from '$lib/utils/shadcn';
	import ChevronUp from './icons/chevron-up.svelte';
	import {
		DropdownMenu,
		DropdownMenuContent,
		DropdownMenuItem,
		DropdownMenuSeparator,
		DropdownMenuTrigger
	} from './ui/dropdown-menu';
	import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from './ui/sidebar';
	import { getTheme } from '@sejohnson/svelte-themes';
	import { getCurrentUser, getIsAuthenticated, getHasConnectionError } from '$lib/auth.svelte';
	import { apiClient } from '$lib/api';
	import { performLogout } from '$lib/auth.svelte';
	import { goto } from '$app/navigation';
	const theme = getTheme();

	async function handleSignOut() {
		// Use comprehensive logout that clears both state and cookies immediately
		await performLogout('manual', false);
		// Then navigate to logout route for backend cleanup and final redirect
		goto('/logout');
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
				<!-- Show controls if we have user data OR connection issues (user might want to clear session) -->
				{#if getCurrentUser() || getHasConnectionError()}
					<DropdownMenuItem
						class="cursor-pointer"
						onSelect={() =>
							(theme.selectedTheme = theme.resolvedTheme === 'light' ? 'dark' : 'light')}
					>
						Toggle {theme.resolvedTheme === 'light' ? 'dark' : 'light'} mode
					</DropdownMenuItem>
					<DropdownMenuSeparator />
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
