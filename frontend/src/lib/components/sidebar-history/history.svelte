<script lang="ts">
	import ChatItem from './item.svelte';
	import type {
		ScribeChatSession,
		User,
		ChatDeletionAnalysisResponse,
		ChronicleAction
	} from '$lib/types';
	import { SidebarGroup, SidebarGroupContent, SidebarMenu } from '../ui/sidebar';
	import { page } from '$app/state';
	import { subWeeks, subMonths, isToday, isYesterday } from 'date-fns';
	import {
		AlertDialog,
		AlertDialogAction,
		AlertDialogCancel,
		AlertDialogContent,
		AlertDialogDescription,
		AlertDialogFooter,
		AlertDialogHeader,
		AlertDialogTitle
	} from '../ui/alert-dialog';
	import { ChatHistory } from '$lib/hooks/chat-history.svelte';
	import { toast } from 'svelte-sonner';
	import { goto } from '$app/navigation';
	import { Skeleton } from '../ui/skeleton';
	import { apiClient } from '$lib/api';

	let { user }: { user?: User } = $props();
	const chatHistory = ChatHistory.fromContext();
	let alertDialogOpen = $state(false);
	let analysisLoading = $state(false);
	const groupedChats = $derived(groupChatsByDate(chatHistory.chats));
	let chatIdToDelete = $state<string | undefined>(undefined);
	let deletionAnalysis = $state<ChatDeletionAnalysisResponse | null>(null);
	let selectedAction = $state<ChronicleAction>('delete_events');

	// Get the chat to be deleted and check if it has chronicles
	const chatToDelete = $derived(() => {
		if (!chatIdToDelete) return null;
		return chatHistory.chats.find((chat) => chat.id === chatIdToDelete);
	});
	const chatHasChronicle = $derived(() => deletionAnalysis?.has_chronicle ?? false);

	type GroupedChats = {
		today: ScribeChatSession[];
		yesterday: ScribeChatSession[];
		lastWeek: ScribeChatSession[];
		lastMonth: ScribeChatSession[];
		older: ScribeChatSession[];
	};
	const chatGroupTitles = {
		today: 'Today',
		yesterday: 'Yesterday',
		lastWeek: 'Last 7 days',
		lastMonth: 'Last 30 days',
		older: 'Older'
	} as const;

	function groupChatsByDate(chats: ScribeChatSession[]): GroupedChats {
		const now = new Date();
		const oneWeekAgo = subWeeks(now, 1);
		const oneMonthAgo = subMonths(now, 1);

		return chats.reduce(
			(groups, chat) => {
				const chatDate = new Date(chat.created_at);

				if (isToday(chatDate)) {
					groups.today.push(chat);
				} else if (isYesterday(chatDate)) {
					groups.yesterday.push(chat);
				} else if (chatDate > oneWeekAgo) {
					groups.lastWeek.push(chat);
				} else if (chatDate > oneMonthAgo) {
					groups.lastMonth.push(chat);
				} else {
					groups.older.push(chat);
				}

				return groups;
			},
			{
				today: [],
				yesterday: [],
				lastWeek: [],
				lastMonth: [],
				older: []
			} as GroupedChats
		);
	}

	async function handleDeleteRequest(chatId: string) {
		chatIdToDelete = chatId;
		deletionAnalysis = null;
		selectedAction = 'delete_events';
		analysisLoading = true;
		alertDialogOpen = true;

		// Fetch deletion analysis
		const result = await apiClient.getChatDeletionAnalysis(chatId);
		analysisLoading = false;

		if (result.isErr()) {
			toast.error('Failed to analyze chat for deletion');
			console.error('Deletion analysis error:', result.error);
			// Still show dialog but without chronicle info
			deletionAnalysis = { has_chronicle: false };
		} else {
			deletionAnalysis = result.value;
			// Set default action based on analysis
			if (deletionAnalysis.has_chronicle && deletionAnalysis.chronicle?.can_delete_chronicle) {
				selectedAction = 'delete_events'; // Conservative default
			} else {
				selectedAction = 'delete_events';
			}
		}
	}

	async function handleDeleteChat() {
		if (!chatIdToDelete) return;

		const action = chatHasChronicle() ? selectedAction : undefined;

		const deletePromise = (async () => {
			// Use Scribe endpoint for deleting a chat with chronicle action
			const result = await apiClient.deleteChatById(chatIdToDelete!, action);
			if (result.isErr()) {
				throw new Error(result.error.message);
			}
		})();

		toast.promise(deletePromise, {
			loading: 'Deleting chat...',
			success: () => {
				chatHistory.chats = chatHistory.chats.filter((chat) => chat.id !== chatIdToDelete);
				chatHistory.refetch();

				// If we deleted a chronicle along with the chat, notify other components
				if (action === 'delete_chronicle') {
					window.dispatchEvent(
						new CustomEvent('chronicle-deleted', {
							detail: { chronicleId: deletionAnalysis?.chronicle?.id }
						})
					);
				}

				return getSuccessMessage(action);
			},
			error: 'Failed to delete chat'
		});

		alertDialogOpen = false;

		if (chatIdToDelete === page.params.chatId) {
			await goto('/');
		}
	}

	function getSuccessMessage(action?: ChronicleAction): string {
		if (!action || !chatHasChronicle()) return 'Chat deleted successfully';

		switch (action) {
			case 'delete_chronicle':
				return 'Chat and chronicle deleted successfully';
			case 'disassociate':
				return 'Chat deleted, chronicle preserved';
			case 'delete_events':
			default:
				return 'Chat deleted successfully';
		}
	}
</script>

{#if !user}
	<SidebarGroup>
		<SidebarGroupContent>
			<div
				class="flex w-full flex-row items-center justify-center gap-2 px-2 text-sm text-zinc-500"
			>
				Login to save and revisit previous chats!
			</div>
		</SidebarGroupContent>
	</SidebarGroup>
{:else if chatHistory.loading}
	<SidebarGroup>
		<div class="px-2 py-1 text-xs text-sidebar-foreground/50">Today</div>
		<SidebarGroupContent>
			<div class="flex flex-col">
				{#each [44, 32, 28, 64, 52] as width (width)}
					<div class="flex h-8 items-center gap-2 rounded-md px-2">
						<Skeleton
							class="h-4 max-w-[--skeleton-width] flex-1 bg-sidebar-accent-foreground/10"
							style="--skeleton-width: {width}%"
						/>
					</div>
				{/each}
			</div>
		</SidebarGroupContent>
	</SidebarGroup>
{:else if chatHistory.chats.length === 0}
	<SidebarGroup>
		<SidebarGroupContent>
			<div
				class="flex w-full flex-row items-center justify-center gap-2 px-2 text-sm text-zinc-500"
			>
				Your conversations will appear here once you start chatting!
			</div>
		</SidebarGroupContent>
	</SidebarGroup>
{:else}
	<SidebarGroup>
		<SidebarGroupContent>
			<SidebarMenu>
				{#each Object.entries(groupedChats) as [group, chats] (group)}
					{#if chats.length > 0}
						<div class="px-2 py-1 text-xs text-sidebar-foreground/50">
							{chatGroupTitles[group as keyof typeof chatGroupTitles]}
						</div>
						{#each chats as chat (chat.id)}
							<ChatItem
								{chat}
								active={chat.id === page.params.chatId}
								ondelete={handleDeleteRequest}
							/>
						{/each}
					{/if}
				{/each}
			</SidebarMenu>
		</SidebarGroupContent>
	</SidebarGroup>
	<AlertDialog bind:open={alertDialogOpen}>
		<AlertDialogContent class="max-w-md">
			<AlertDialogHeader>
				<AlertDialogTitle>
					{#if analysisLoading}
						Analyzing chat...
					{:else if chatHasChronicle()}
						Delete chat with chronicle?
					{:else}
						Delete chat?
					{/if}
				</AlertDialogTitle>
				<AlertDialogDescription>
					{#if analysisLoading}
						<div class="flex items-center space-x-2">
							<div
								class="h-4 w-4 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600"
							></div>
							<span>Checking for associated chronicles...</span>
						</div>
					{:else if chatHasChronicle() && deletionAnalysis?.chronicle}
						<div class="space-y-4">
							<div class="rounded-md bg-amber-50 p-3 dark:bg-amber-950">
								<div class="mb-2 font-medium text-amber-800 dark:text-amber-200">
									📚 Chronicle: "{deletionAnalysis.chronicle.name}"
								</div>
								<div class="space-y-1 text-sm text-amber-700 dark:text-amber-300">
									<p>• {deletionAnalysis.chronicle.total_events} total events</p>
									<p>• {deletionAnalysis.chronicle.events_from_this_chat} events from this chat</p>
									{#if deletionAnalysis.chronicle.other_chats_using_chronicle > 0}
										<p>
											• {deletionAnalysis.chronicle.other_chats_using_chronicle} other chats use this
											chronicle
										</p>
									{/if}
								</div>
							</div>

							<div class="space-y-3">
								<p class="text-sm font-medium">What would you like to do?</p>

								<div class="space-y-2">
									<label class="flex cursor-pointer items-start space-x-3">
										<input
											type="radio"
											bind:group={selectedAction}
											value="delete_events"
											class="mt-1"
										/>
										<div class="flex-1">
											<div class="font-medium">Delete chat & its events</div>
											<div class="text-xs text-gray-600 dark:text-gray-400">
												Keep chronicle, remove {deletionAnalysis.chronicle.events_from_this_chat} events
												from this chat
											</div>
										</div>
									</label>

									<label class="flex cursor-pointer items-start space-x-3">
										<input
											type="radio"
											bind:group={selectedAction}
											value="disassociate"
											class="mt-1"
										/>
										<div class="flex-1">
											<div class="font-medium">Keep chronicle & all events</div>
											<div class="text-xs text-gray-600 dark:text-gray-400">
												Only delete the chat, preserve all narrative history
											</div>
										</div>
									</label>

									{#if deletionAnalysis.chronicle.can_delete_chronicle}
										<label class="flex cursor-pointer items-start space-x-3">
											<input
												type="radio"
												bind:group={selectedAction}
												value="delete_chronicle"
												class="mt-1"
											/>
											<div class="flex-1">
												<div class="font-medium text-red-700 dark:text-red-400">
													Delete entire chronicle
												</div>
												<div class="text-xs text-red-600 dark:text-red-500">
													⚠️ Permanently delete all {deletionAnalysis.chronicle.total_events} events
												</div>
											</div>
										</label>
									{:else}
										<div class="flex items-start space-x-3 opacity-50">
											<input type="radio" disabled class="mt-1" />
											<div class="flex-1">
												<div class="font-medium text-gray-500">Delete entire chronicle</div>
												<div class="text-xs text-gray-500">
													Cannot delete - other chats use this chronicle
												</div>
											</div>
										</div>
									{/if}
								</div>
							</div>
						</div>
					{:else}
						This action cannot be undone. This will permanently delete your chat and remove it from
						our servers.
					{/if}
				</AlertDialogDescription>
			</AlertDialogHeader>
			<AlertDialogFooter>
				<AlertDialogCancel>Cancel</AlertDialogCancel>
				<AlertDialogAction
					onclick={handleDeleteChat}
					disabled={analysisLoading}
					class={selectedAction === 'delete_chronicle'
						? 'bg-red-600 hover:bg-red-700 focus:ring-red-600'
						: ''}
				>
					{#if analysisLoading}
						Please wait...
					{:else if selectedAction === 'delete_chronicle'}
						Delete Chronicle
					{:else if selectedAction === 'disassociate'}
						Keep Chronicle
					{:else if selectedAction === 'delete_events'}
						Delete Chat & Events
					{:else}
						Delete Chat
					{/if}
				</AlertDialogAction>
			</AlertDialogFooter>
		</AlertDialogContent>
	</AlertDialog>
{/if}
