<script lang="ts">
	import type { Chat } from '$lib/types';
	import {
		DropdownMenu,
		DropdownMenuContent,
		DropdownMenuItem,
		DropdownMenuTrigger
	} from '../ui/dropdown-menu';
	import { useSidebar, SidebarMenuAction, SidebarMenuButton, SidebarMenuItem } from '../ui/sidebar';
	import TrashIcon from '../icons/trash.svelte';
	import MoreHorizontalIcon from '../icons/more-horizontal.svelte';
	import { goto } from '$app/navigation';

	let {
		chat,
		active,
		ondelete
	}: {
		chat: Chat;
		active: boolean;
		ondelete: (chatId: string) => void;
	} = $props();

	const context = useSidebar();
</script>

<SidebarMenuItem>
	<SidebarMenuButton isActive={active}>
		{#snippet child({ props })}
			<button
				{...props}
				onclick={() => {
					goto(`/chat/${chat.id}`);
					context.setOpenMobile(false);
				}}
			>
				<span>{chat.title}</span>
			</button>
		{/snippet}
	</SidebarMenuButton>

	<DropdownMenu>
		<DropdownMenuTrigger>
			{#snippet child({ props })}
				<SidebarMenuAction
					{...props}
					class="mr-0.5 data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
					showOnHover={!active}
				>
					<MoreHorizontalIcon />
					<span class="sr-only">More</span>
				</SidebarMenuAction>
			{/snippet}
		</DropdownMenuTrigger>

		<DropdownMenuContent side="bottom" align="end">
			<DropdownMenuItem
				class="cursor-pointer text-destructive focus:bg-destructive/15 focus:text-destructive dark:text-red-500"
				onclick={() => ondelete(chat.id)}
			>
				<TrashIcon />
				<span>Delete</span>
			</DropdownMenuItem>
		</DropdownMenuContent>
	</DropdownMenu>
</SidebarMenuItem>
