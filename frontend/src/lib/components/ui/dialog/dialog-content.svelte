<script lang="ts">
	import { Dialog as DialogPrimitive } from 'bits-ui';
	import X from 'lucide-svelte/icons/x';
	import * as Dialog from './index.js';
	import { cn as _cn } from '$lib/utils/shadcn.js';
	import { isDesktopMode } from '$lib/utils/features';

	type $$Props = DialogPrimitive.ContentProps;

	let className: $$Props['class'] = undefined;
	export { className as class };

	// CRITICAL: Disable Portal in Tauri desktop mode to fix reactivity
	// Portal teleports content to document.body, breaking Svelte's reactivity in Tauri WebView
	// Initialize synchronously to avoid rendering with Portal first
	const inDesktopMode = typeof window !== 'undefined' ? isDesktopMode() : false;
	console.log('[DialogContent] Desktop mode check (sync):', inDesktopMode);
</script>

{#if inDesktopMode}
	<!-- Desktop mode: Render without Portal to enable Svelte reactivity in Tauri WebView -->
	<Dialog.Overlay />
	<DialogPrimitive.Content
		class={_cn(
			'fixed left-[50%] top-[50%] z-50 grid w-full max-w-lg translate-x-[-50%] translate-y-[-50%] gap-4 border border-border/50 bg-background/80 backdrop-blur-2xl p-6 shadow-2xl sm:rounded-xl ring-1 ring-black/5 dark:ring-white/10 duration-200 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[state=closed]:slide-out-to-left-1/2 data-[state=closed]:slide-out-to-top-[48%] data-[state=open]:slide-in-from-left-1/2 data-[state=open]:slide-in-from-top-[48%] md:w-full',
			className
		)}
		{...$$restProps}
	>
		<slot />
		<DialogPrimitive.Close
			class="absolute right-4 top-4 rounded-full p-1 opacity-70 ring-offset-background transition-all hover:bg-muted/80 hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:pointer-events-none"
		>
			<X class="h-4 w-4" />
			<span class="sr-only">Close</span>
		</DialogPrimitive.Close>
	</DialogPrimitive.Content>
{:else}
	<!-- Cloud mode: Use Portal for proper z-index layering across the DOM -->
	<Dialog.Portal>
		<Dialog.Overlay />
		<DialogPrimitive.Content
			class={_cn(
				'fixed left-[50%] top-[50%] z-50 grid w-full max-w-lg translate-x-[-50%] translate-y-[-50%] gap-4 border border-border/50 bg-background/80 backdrop-blur-2xl p-6 shadow-2xl sm:rounded-xl ring-1 ring-black/5 dark:ring-white/10 duration-200 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[state=closed]:slide-out-to-left-1/2 data-[state=closed]:slide-out-to-top-[48%] data-[state=open]:slide-in-from-left-1/2 data-[state=open]:slide-in-from-top-[48%] md:w-full',
				className
			)}
			{...$$restProps}
		>
			<slot />
			<DialogPrimitive.Close
				class="absolute right-4 top-4 rounded-full p-1 opacity-70 ring-offset-background transition-all hover:bg-muted/80 hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:pointer-events-none"
			>
				<X class="h-4 w-4" />
				<span class="sr-only">Close</span>
			</DialogPrimitive.Close>
		</DialogPrimitive.Content>
	</Dialog.Portal>
{/if}
