<script lang="ts">
	import type { User } from '$lib/types';
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
	import { apiClient } from '$lib/api';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';

	let { user }: { user: User } = $props();
	const theme = getTheme();

	async function handleSignOut() {
		const result = await apiClient.logout();
		if (result.isOk()) {
			// For SvelteKit, navigating to a page that requires auth
			// (or simply reloading) after logout should trigger the hooks
			// to redirect to login if the current page is protected.
			// A full reload is often the most robust way to clear all client state.
			if (typeof window !== 'undefined') {
				window.location.href = '/signin'; // Or simply window.location.reload();
			} else {
				// Fallback for server-side context if needed, though less likely for a click handler
				await goto('/signin');
			}
		} else {
			console.error('Logout failed:', result.error);
			// Optionally, show an error message to the user
		}
	}
</script>

<SidebarMenu>
	<SidebarMenuItem>
		<DropdownMenu>
			<DropdownMenuTrigger>
				{#snippet child({ props })}
					<SidebarMenuButton
						{...props}
						class="h-10 bg-background data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
					>
						<img
							src={`https://avatar.vercel.sh/${user.email}`}
							alt={user.email ?? 'User Avatar'}
							width={24}
							height={24}
							class="rounded-full"
						/>
						<span class="truncate">{user?.email}</span>
						<ChevronUp class="ml-auto" />
					</SidebarMenuButton>
				{/snippet}
			</DropdownMenuTrigger>
			<DropdownMenuContent side="top" class="w-[--bits-floating-anchor-width]">
				<DropdownMenuItem
					class="cursor-pointer"
					onSelect={() =>
						(theme.selectedTheme = theme.resolvedTheme === 'light' ? 'dark' : 'light')}
				>
					Toggle {theme.resolvedTheme === 'light' ? 'dark' : 'light'} mode
				</DropdownMenuItem>
				<DropdownMenuSeparator />
				<DropdownMenuItem class="cursor-pointer" onSelect={handleSignOut}>
					Sign out
				</DropdownMenuItem>
			</DropdownMenuContent>
		</DropdownMenu>
	</SidebarMenuItem>
</SidebarMenu>
