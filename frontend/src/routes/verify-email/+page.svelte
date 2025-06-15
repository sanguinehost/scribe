<script lang="ts">
	import type { PageData } from './$types';
	import { CheckCircle, XCircle, Loader2 } from 'lucide-svelte';
	import { Button } from '$lib/components/ui/button';
	import { goto } from '$app/navigation';

	export let data: PageData;
</script>

<div class="flex min-h-screen flex-col items-center justify-center bg-background p-4">
	<div class="w-full max-w-md rounded-lg border bg-card p-8 text-center shadow-lg">
		{#if data.status === 'loading'}
			<Loader2 class="mx-auto h-12 w-12 animate-spin text-primary" />
			<h1 class="mt-4 text-2xl font-semibold">Verifying your email...</h1>
			<p class="mt-2 text-muted-foreground">Please wait a moment.</p>
		{:else if data.status === 'success'}
			<CheckCircle class="mx-auto h-12 w-12 text-green-500" />
			<h1 class="mt-4 text-2xl font-semibold">Verification Successful!</h1>
			<p class="mt-2 text-muted-foreground">{data.message}</p>
			<a href="/signin" class="inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 ring-offset-background focus-visible:ring-ring border border-input bg-background hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2 mt-6">Go to Login</a>
		{:else if data.status === 'error'}
			<XCircle class="mx-auto h-12 w-12 text-destructive" />
			<h1 class="mt-4 text-2xl font-semibold">Verification Failed</h1>
			<p class="mt-2 text-muted-foreground">{data.message}</p>
			<a href="/signup" class="inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 ring-offset-background focus-visible:ring-ring border border-input bg-background hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2 mt-6">Return to Sign Up</a>
		{/if}
	</div>
</div>
