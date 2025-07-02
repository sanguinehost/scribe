<script lang="ts">
	import Chat from '$lib/components/chat.svelte';
	import type {
		ScribeChatSession,
		ScribeChatMessage,
		ScribeCharacter,
		BackendAuthResponse,
		User
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
</script>

<Chat
	chat={data.chat}
	initialMessages={data.messages}
	initialCursor={data.initialCursor}
	readonly={data.user?.user_id !== data.chat.user_id}
	user={data.user
		? { ...data.user, id: data.user.user_id, username: data.user.username, email: data.user.email }
		: undefined}
	character={data.character}
/>
