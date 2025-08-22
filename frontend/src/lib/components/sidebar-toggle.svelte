<script>
	import ChevronRightIcon from './icons/chevron-right.svelte';
	import { Button } from './ui/button';
	import { useSidebar } from './ui/sidebar';
	import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from './ui/tooltip';

	const sidebar = useSidebar();
</script>

<!-- Show on mobile always, and on desktop only when sidebar is closed -->
<div class={sidebar.state === 'collapsed' ? '' : 'md:hidden'}>
	<TooltipProvider>
		<Tooltip>
			<TooltipTrigger>
				{#snippet child({ props })}
					<Button
						{...props}
						onclick={() => {
							sidebar.toggle();
						}}
						variant="ghost"
						size="icon"
						class="h-8 w-8"
					>
						<ChevronRightIcon size={16} />
					</Button>
				{/snippet}
			</TooltipTrigger>
			<TooltipContent align="start">Toggle Sidebar</TooltipContent>
		</Tooltip>
	</TooltipProvider>
</div>
