<script lang="ts">
	import { goto } from '$app/navigation';
	import { getIsAuthenticated, getIsLoadingAuth } from '$lib/auth.svelte';
	import { Loader } from 'lucide-svelte';

	let { children, redirectTo = '/signin' } = $props<{
		children?: any;
		redirectTo?: string;
	}>();

	// Redirect to signin if not authenticated
	$effect(() => {
		if (!getIsAuthenticated() && !getIsLoadingAuth()) {
			goto(redirectTo);
		}
	});
</script>

{#if getIsAuthenticated()}
	{@render children?.()}
{:else if getIsLoadingAuth()}
	<div class="flex h-full items-center justify-center">
		<div class="flex flex-col items-center gap-2">
			<Loader class="h-8 w-8 animate-spin text-muted-foreground" />
			<p class="text-sm text-muted-foreground">Validating session...</p>
		</div>
	</div>
{:else}
	<!-- Redirecting to signin -->
	<div class="flex h-full items-center justify-center">
		<p class="text-sm text-muted-foreground">Redirecting to sign in...</p>
	</div>
{/if}
