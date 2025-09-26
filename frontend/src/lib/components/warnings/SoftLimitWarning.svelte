<script lang="ts">
	import { AlertTriangle, Clock, Zap } from 'lucide-svelte';
	import { Button as ButtonComponent } from '$lib/components/ui/button';
	import { Alert, AlertDescription } from '$lib/components/ui/alert';
	import { PAYMENT_FEATURES } from '$lib/utils/features';
	import type { SoftLimitStatus } from '$lib/types/payment';

	interface Props {
		softLimitStatus?: SoftLimitStatus | null;
		onUpgrade?: () => void;
		showUpgradeButton?: boolean;
		compact?: boolean;
	}

	let {
		softLimitStatus = null,
		onUpgrade = () => {},
		showUpgradeButton = true,
		compact = false
	}: Props = $props();

	// Don't show anything if soft limits feature is disabled
	const showWarning = $derived(PAYMENT_FEATURES.softLimits && softLimitStatus?.active);

	function formatDelay(delayMs: number): string {
		if (delayMs < 1000) {
			return `${delayMs}ms`;
		} else if (delayMs < 60000) {
			return `${Math.round(delayMs / 1000)}s`;
		} else {
			return `${Math.round(delayMs / 60000)}m`;
		}
	}

	function getWarningVariant(delayMs: number): 'default' | 'destructive' {
		return delayMs > 5000 ? 'destructive' : 'default';
	}

	// Safe access helpers
	const safeDelayMs = $derived(softLimitStatus?.current_delay_ms ?? 0);
	const safeWarningMessage = $derived(softLimitStatus?.warning_message);
	const safeNextThreshold = $derived(softLimitStatus?.next_threshold);
</script>

{#if showWarning}
	{#if compact}
		<!-- Compact warning for header/sidebar -->
		<div
			class="flex items-center gap-2 rounded-md border border-orange-200 bg-orange-50 px-2 py-1 dark:border-orange-800 dark:bg-orange-950"
		>
			<Clock class="h-4 w-4 text-orange-600 dark:text-orange-400" />
			<span class="text-sm font-medium text-orange-800 dark:text-orange-200">
				Rate limited (+{formatDelay(safeDelayMs)} delay)
			</span>
			{#if showUpgradeButton}
				<ButtonComponent variant="outline" size="sm" onclick={onUpgrade} class="ml-2">
					<Zap class="mr-1 h-3 w-3" />
					Upgrade
				</ButtonComponent>
			{/if}
		</div>
	{:else}
		<!-- Full warning card -->
		<Alert variant={getWarningVariant(safeDelayMs)}>
			<AlertTriangle class="h-4 w-4" />
			<h4 class="font-medium">Rate Limit Active</h4>
			<AlertDescription class="mt-2 space-y-3">
				<div>
					Your messages are being delayed by <strong>{formatDelay(safeDelayMs)}</strong>
					due to rate limiting.
				</div>

				{#if safeWarningMessage}
					<div class="text-sm">
						{safeWarningMessage}
					</div>
				{/if}

				{#if safeNextThreshold}
					<div class="rounded border bg-background/50 p-3 text-sm">
						<div class="mb-1 font-medium">Next threshold:</div>
						<div>
							After <strong>{safeNextThreshold.after_messages} more messages</strong>, delays will
							increase to <strong>{formatDelay(safeNextThreshold.delay_ms)}</strong>
						</div>
						{#if safeNextThreshold.fallback_model}
							<div class="mt-1">
								Requests will use fallback model: <strong>{safeNextThreshold.fallback_model}</strong
								>
							</div>
						{/if}
						{#if safeNextThreshold.warning_message}
							<div class="mt-1 text-muted-foreground">
								{safeNextThreshold.warning_message}
							</div>
						{/if}
					</div>
				{/if}

				{#if showUpgradeButton}
					<div class="flex gap-2 pt-2">
						<ButtonComponent onclick={onUpgrade} size="sm">
							<Zap class="mr-1.5 h-4 w-4" />
							Upgrade Plan
						</ButtonComponent>
						<ButtonComponent
							variant="outline"
							size="sm"
							onclick={() => window.open('/docs/rate-limits', '_blank')}
						>
							Learn More
						</ButtonComponent>
					</div>
				{/if}
			</AlertDescription>
		</Alert>
	{/if}
{/if}
