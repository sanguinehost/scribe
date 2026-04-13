<script lang="ts">
	import { resolve } from '$app/paths';
	import type { User } from '$lib/types';

	export let user: User | undefined = undefined;
</script>

<div data-testid="sidebar-user-nav-mock">
	{#if user?.email}
		<span>{user.email}</span>
	{/if}
	<a href={resolve("/signout")}>Sign out</a>
</div>
