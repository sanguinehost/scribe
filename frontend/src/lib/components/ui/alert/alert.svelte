<script lang="ts">
	import { cn } from '$lib/utils/shadcn.js';
	import { type VariantProps, tv } from 'tailwind-variants';

	const alertVariants = tv({
		base: 'relative w-full rounded-lg border p-4 [&>svg~*]:pl-7 [&>svg+div]:translate-y-[-3px] [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-foreground',
		variants: {
			variant: {
				default: 'bg-background text-foreground',
				destructive:
					'border-destructive/50 text-destructive dark:border-destructive [&>svg]:text-destructive',
				warning:
					'border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-800 dark:bg-orange-900/20 dark:text-orange-400 [&>svg]:text-orange-600 dark:[&>svg]:text-orange-400',
				info: 'border-blue-200 bg-blue-50 text-blue-800 dark:border-blue-800 dark:bg-blue-900/20 dark:text-blue-400 [&>svg]:text-blue-600 dark:[&>svg]:text-blue-400'
			}
		},
		defaultVariants: {
			variant: 'default'
		}
	});

	export let variant: VariantProps<typeof alertVariants>['variant'] = 'default';

	let className: string | undefined = undefined;
	export { className as class };
</script>

<div role="alert" class={cn(alertVariants({ variant }), className)} {...$$restProps}>
	<slot />
</div>
