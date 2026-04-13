<!-- eslint-disable svelte/no-navigation-without-resolve -->
<script lang="ts" module>
	import type { WithElementRef } from 'bits-ui';
	import type { HTMLAnchorAttributes, HTMLButtonAttributes } from 'svelte/elements';
	import { type VariantProps, tv } from 'tailwind-variants';

	export const buttonVariants = tv({
		base: 'ring-offset-background focus-visible:ring-ring inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-lg text-sm font-medium transition-all duration-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 active:scale-[0.98]',
		variants: {
			variant: {
				default: 'bg-primary text-primary-foreground shadow hover:bg-primary/90 hover:shadow-md',
				destructive: 'bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90 hover:shadow-md',
				outline: 'border-border bg-background/50 backdrop-blur-sm shadow-sm hover:bg-accent hover:text-accent-foreground border',
				secondary: 'bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80',
				ghost: 'hover:bg-accent/50 hover:text-accent-foreground',
				link: 'text-primary underline-offset-4 hover:underline'
			},
			size: {
				default: 'h-10 px-4 py-2',
				sm: 'h-9 rounded-md px-3',
				lg: 'h-11 rounded-lg px-8',
				icon: 'h-10 w-10'
			}
		},
		defaultVariants: {
			variant: 'default',
			size: 'default'
		}
	});

	export type ButtonVariant = VariantProps<typeof buttonVariants>['variant'];
	export type ButtonSize = VariantProps<typeof buttonVariants>['size'];

	export type ButtonProps = WithElementRef<HTMLButtonAttributes> &
		WithElementRef<HTMLAnchorAttributes> & {
			variant?: ButtonVariant;
			size?: ButtonSize;
		};
</script>
<script lang="ts">
	import { resolve } from '$app/paths';
	// Disable custom elements to avoid props inference issues
	import { cn as _cn } from '$lib/utils/shadcn.js';

	interface _$$Events {
		click: MouseEvent;
	}
	let {
		class: className,
		variant = 'default',
		size = 'default',
		ref = $bindable(null),
		href = undefined,
		type = 'button',
		children,
		...restProps
	}: ButtonProps = $props();
</script>

{#if href}
	{#if href.startsWith('http') || href.startsWith('mailto:')}
		<a
			bind:this={ref}
			class={_cn(buttonVariants({ variant, size }), className)}
			{...{ href: href }}
			{...restProps}
		>
			{@render children?.()}
		</a>
	{:else}
		<a
			bind:this={ref}
			class={_cn(buttonVariants({ variant, size }), className)}
			href={resolve(href as unknown as "/")}
			{...restProps}
		>
			{@render children?.()}
		</a>
	{/if}
{:else}
	<button
		bind:this={ref}
		class={_cn(buttonVariants({ variant, size }), className)}
		{type}
		{...restProps}
	>
		{@render children?.()}
	</button>
{/if}
