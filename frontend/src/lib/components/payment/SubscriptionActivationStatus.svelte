<script lang="ts">
	/**
	 * Visual feedback component for subscription activation progress
	 * Shows staged progress during payment verification and webhook processing
	 */

	interface Props {
		/** Current stage of activation process */
		stage: 'verifying' | 'activating' | 'completed' | 'checking';
		/** Current attempt number */
		attempt?: number;
		/** Maximum number of attempts */
		maxAttempts?: number;
		/** Optional custom message */
		message?: string;
	}

	let { stage = 'verifying', attempt = 1, maxAttempts = 8, message }: Props = $props();

	// Compute stage details
	const stageDetails = $derived(() => {
		switch (stage) {
			case 'verifying':
				return {
					title: 'Verifying Payment',
					description: 'Confirming your payment with Paddle...',
					icon: '💳',
					color: 'blue'
				};
			case 'activating':
				return {
					title: 'Activating Subscription',
					description: 'Setting up your subscription benefits...',
					icon: '⚡',
					color: 'purple'
				};
			case 'checking':
				return {
					title: 'Checking Subscription',
					description: 'Verifying your subscription status...',
					icon: '🔍',
					color: 'blue'
				};
			case 'completed':
				return {
					title: 'Subscription Activated!',
					description: 'Your subscription is now active',
					icon: '✅',
					color: 'green'
				};
			default:
				return {
					title: 'Processing...',
					description: 'Please wait...',
					icon: '⏳',
					color: 'gray'
				};
		}
	});

	const progress = $derived(() => {
		if (stage === 'completed') return 100;
		if (maxAttempts && attempt) {
			return Math.min(90, (attempt / maxAttempts) * 100);
		}
		return 30;
	});
</script>

<div
	class="w-full rounded-lg border border-slate-200 bg-white p-6 shadow-lg dark:border-slate-700 dark:bg-slate-800"
>
	<!-- Header with icon and title -->
	<div class="mb-4 flex items-center gap-3">
		<div
			class="flex h-12 w-12 items-center justify-center rounded-full text-2xl {stageDetails()
				.color === 'blue'
				? 'bg-blue-100 dark:bg-blue-900/30'
				: stageDetails().color === 'purple'
					? 'bg-purple-100 dark:bg-purple-900/30'
					: stageDetails().color === 'green'
						? 'bg-green-100 dark:bg-green-900/30'
						: 'bg-slate-100 dark:bg-slate-700'}"
		>
			{#if stage !== 'completed'}
				<div class="animate-pulse">
					{stageDetails().icon}
				</div>
			{:else}
				{stageDetails().icon}
			{/if}
		</div>
		<div class="flex-1">
			<h3 class="text-lg font-semibold text-slate-900 dark:text-slate-100">
				{stageDetails().title}
			</h3>
			<p class="text-sm text-slate-600 dark:text-slate-300">
				{message || stageDetails().description}
			</p>
		</div>
	</div>

	<!-- Progress bar -->
	<div class="mb-3 h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
		<div
			class="h-full transition-all duration-500 ease-out {stageDetails().color === 'blue'
				? 'bg-blue-600'
				: stageDetails().color === 'purple'
					? 'bg-purple-600'
					: stageDetails().color === 'green'
						? 'bg-green-600'
						: 'bg-slate-600'}"
			style="width: {progress()}%"
		></div>
	</div>

	<!-- Attempt counter (only show when retrying) -->
	{#if stage !== 'completed' && attempt && maxAttempts}
		<p class="text-center text-xs text-slate-500 dark:text-slate-400">
			Attempt {attempt} of {maxAttempts}
		</p>
	{/if}

	<!-- Progress stages -->
	<div class="mt-4 space-y-2">
		<div class="flex items-center gap-2 text-sm">
			<div
				class="flex h-5 w-5 items-center justify-center rounded-full {stage !== 'verifying'
					? 'bg-green-500 text-white'
					: 'border-2 border-blue-500'}"
			>
				{#if stage !== 'verifying'}
					<svg
						class="h-3 w-3"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
						xmlns="http://www.w3.org/2000/svg"
					>
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="3"
							d="M5 13l4 4L19 7"
						/>
					</svg>
				{/if}
			</div>
			<span class={stage === 'verifying' ? 'font-medium' : 'text-slate-500 dark:text-slate-400'}>
				Payment received
			</span>
		</div>

		<div class="flex items-center gap-2 text-sm">
			<div
				class="flex h-5 w-5 items-center justify-center rounded-full {stage === 'completed'
					? 'bg-green-500 text-white'
					: stage === 'activating' || stage === 'checking'
						? 'border-2 border-blue-500'
						: 'border-2 border-slate-300 dark:border-slate-600'}"
			>
				{#if stage === 'completed'}
					<svg
						class="h-3 w-3"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
						xmlns="http://www.w3.org/2000/svg"
					>
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="3"
							d="M5 13l4 4L19 7"
						/>
					</svg>
				{:else if stage === 'activating' || stage === 'checking'}
					<div class="h-2 w-2 animate-spin rounded-full border border-blue-500"></div>
				{/if}
			</div>
			<span
				class={stage === 'activating' || stage === 'checking'
					? 'font-medium'
					: stage === 'completed'
						? 'text-slate-500 dark:text-slate-400'
						: 'text-slate-400 dark:text-slate-500'}
			>
				{stage === 'checking' ? 'Checking subscription status' : 'Activating subscription'}
			</span>
		</div>

		<div class="flex items-center gap-2 text-sm">
			<div
				class="flex h-5 w-5 items-center justify-center rounded-full {stage === 'completed'
					? 'bg-green-500 text-white'
					: 'border-2 border-slate-300 dark:border-slate-600'}"
			>
				{#if stage === 'completed'}
					<svg
						class="h-3 w-3"
						fill="none"
						stroke="currentColor"
						viewBox="0 0 24 24"
						xmlns="http://www.w3.org/2000/svg"
					>
						<path
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="3"
							d="M5 13l4 4L19 7"
						/>
					</svg>
				{/if}
			</div>
			<span class={stage === 'completed' ? 'font-medium' : 'text-slate-400 dark:text-slate-500'}>
				Account updated
			</span>
		</div>
	</div>

	<!-- Helper text -->
	{#if stage !== 'completed'}
		<p class="mt-4 text-center text-xs text-slate-500 dark:text-slate-400">
			This may take a few moments...
		</p>
	{/if}
</div>
