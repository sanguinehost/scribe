<script lang="ts">
	import Chat from '$lib/components/chat.svelte';
	// import { convertToUIMessages } from '$lib/utils/chat'; // Removed unused import

	let { data } = $props();
</script>

<Chat
		chat={data.chat}
		initialMessages={data.messages}
		readonly={data.user?.id !== data.chat.user_id}
		user={data.user}
/>
