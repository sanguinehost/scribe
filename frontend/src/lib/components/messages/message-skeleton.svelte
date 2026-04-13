<script lang="ts">
	// Message skeleton component for loading states
	// Shows placeholder message bubbles while content loads
</script>

<div class="mx-auto flex w-full max-w-3xl flex-col gap-6 px-4 py-6">
	<!-- Skeleton message 1: Assistant (long) -->
	<div class="flex w-full gap-4">
		<div class="size-8 shrink-0 animate-pulse rounded-full bg-muted"></div>
		<div class="flex-1 space-y-2">
			<div class="msg-assistant-bubble rounded-xl p-4 opacity-60">
				<div class="space-y-2">
					<div class="h-4 w-4/5 animate-pulse rounded bg-muted" style="animation-delay: 0ms;"></div>
					<div class="h-4 w-full animate-pulse rounded bg-muted" style="animation-delay: 75ms;"></div>
					<div class="h-4 w-3/5 animate-pulse rounded bg-muted" style="animation-delay: 150ms;"></div>
				</div>
			</div>
		</div>
	</div>

	<!-- Skeleton message 2: User (short) -->
	<div class="flex w-full gap-4 ml-auto max-w-2xl">
		<div class="size-8 shrink-0 animate-pulse rounded-full bg-muted"></div>
		<div class="flex-1 space-y-2">
			<div class="msg-user-bubble rounded-xl p-4 opacity-60">
				<div class="space-y-2">
					<div class="h-4 w-3/4 animate-pulse rounded bg-muted" style="animation-delay: 225ms;"></div>
					<div class="h-4 w-1/2 animate-pulse rounded bg-muted" style="animation-delay: 300ms;"></div>
				</div>
			</div>
		</div>
	</div>

	<!-- Skeleton message 3: Assistant (medium) -->
	<div class="flex w-full gap-4">
		<div class="size-8 shrink-0 animate-pulse rounded-full bg-muted"></div>
		<div class="flex-1 space-y-2">
			<div class="msg-assistant-bubble rounded-xl p-4 opacity-60">
				<div class="space-y-2">
					<div class="h-4 w-full animate-pulse rounded bg-muted" style="animation-delay: 375ms;"></div>
					<div class="h-4 w-2/3 animate-pulse rounded bg-muted" style="animation-delay: 450ms;"></div>
				</div>
			</div>
		</div>
	</div>
</div>
