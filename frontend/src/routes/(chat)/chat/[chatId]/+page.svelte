<script lang="ts">
	import ChatContainer from '$lib/components/ChatContainer.svelte';
	import type {
		ScribeChatSession,
		ScribeChatMessage,
		ScribeCharacter,
		BackendAuthResponse,
		User as _User
	} from '$lib/types.ts';

	// Define the type for the data prop received from the loader
	interface PageData {
		chat: ScribeChatSession;
		messages: ScribeChatMessage[];
		character: ScribeCharacter | null;
		user?: BackendAuthResponse; // User is optional as it might not be logged in
		initialCursor: string | null;
	}

	let { data }: { data: PageData } = $props();

	// Debug logging for user ID mismatch issue
	const isReadonly = data.user?.user_id !== data.chat?.user_id;
	console.log('[chat/[chatId]/+page.svelte] Readonly check:', {
		readonly: isReadonly,
		userUserId: data.user?.user_id,
		chatUserId: data.chat?.user_id,
		chatId: data.chat?.id,
		characterId: data.character?.id,
		chatMode: data.chat?.chat_mode
	});
</script>

<ChatContainer
	chat={data.chat}
	user={data.user
		? { ...data.user, id: data.user.user_id, username: data.user.username, email: data.user.email }
		: undefined}
	character={data.character}
	initialMessages={data.messages}
	readonly={isReadonly}
	initialCursor={data.initialCursor}
/>
