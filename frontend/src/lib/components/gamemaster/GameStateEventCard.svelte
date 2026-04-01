<script lang="ts">
	import { History } from 'lucide-svelte';
	import { Markdown } from '../markdown';
	import type { ScribeChatMessage } from '$lib/types';
	import { fly } from 'svelte/transition';

	let {
		message
	}: {
		message: ScribeChatMessage;
	} = $props();
</script>

<div
	class="mx-auto w-full max-w-3xl px-4 py-2"
	in:fly|global={{ opacity: 0, y: 10, duration: 400 }}
>
	<div
		class="relative flex w-full flex-col items-center justify-center gap-2 overflow-hidden rounded-2xl border border-purple-500/20 bg-muted/40 px-6 py-4 shadow-sm backdrop-blur-xl transition-colors hover:bg-muted/50 dark:border-purple-500/10 dark:bg-purple-950/20"
	>
		<!-- Ambient glow effect -->
		<div
			class="pointer-events-none absolute -inset-1 blur-xl"
			style="background: radial-gradient(circle at top, rgba(168, 85, 247, 0.05), transparent 70%);"
		></div>

		<div class="relative flex items-center gap-2 text-purple-600 dark:text-purple-400">
			<History size={16} class="shrink-0" />
			<span class="text-xs font-semibold uppercase leading-none tracking-widest text-muted-foreground">
				Game Master Event
			</span>
		</div>

		<div
			class="prose prose-sm dark:prose-invert prose-p:leading-relaxed relative w-full text-center text-foreground/90 max-w-2xl pt-1"
		>
			<Markdown md={message.content} />
		</div>
	</div>
</div>
