<script lang="ts">
	import ChatContainer from '$lib/components/ChatContainer.svelte';

	let { data } = $props();
</script>

<ChatContainer
	chat={undefined}
	user={data.user}
	character={null}
	initialMessages={[]}
	readonly={false}
/>
<!-- TODO <DataStreamHandler {id} /> -->
