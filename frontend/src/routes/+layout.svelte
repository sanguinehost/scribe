<script lang="ts">
	import '../app.pcss'; // Keep the global styles import
	import { onMount } from 'svelte';
	import { authStore } from '$lib/stores/authStore';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';

	let { children } = $props();

	// --- Authentication & Routing Logic ---
	let isAuthenticated = $state(false); // Use $state for reactivity with runes
	let isLoading = $state(true); // Start in loading state until check completes
	let currentPath = $state('');

	$effect(() => {
		// Subscribe to authStore changes
		const unsubscribe = authStore.subscribe(state => {
			isAuthenticated = state.isAuthenticated;
			isLoading = state.isLoading;
		});
		return unsubscribe; // Cleanup subscription
	});

	$effect(() => {
		// Subscribe to page path changes
		const unsubscribe = page.subscribe(p => {
			currentPath = p.url.pathname;
		});
		return unsubscribe; // Cleanup subscription
	});


	onMount(async () => {
		// Check auth status when the layout mounts on the client
		await authStore.checkAuthStatus();
		// isLoading will be updated via the subscription
	});

	// Reactive redirection logic
	$effect(() => {
		// Don't redirect while initial check is loading or if path isn't set yet
		if (isLoading || !currentPath) return;

		const protectedRoutes = ['/characters', '/chat']; // Add base paths of protected areas
		const authRoutes = ['/login', '/register'];
		const isProtectedRoute = protectedRoutes.some(route => currentPath.startsWith(route)) || currentPath === '/'; // Treat root as protected for logged-in users
		const isAuthRoute = authRoutes.includes(currentPath);

		console.log(`Routing check: Path=${currentPath}, IsAuth=${isAuthenticated}, IsLoading=${isLoading}, IsProtected=${isProtectedRoute}, IsAuthRoute=${isAuthRoute}`);


		if (!isAuthenticated && isProtectedRoute && !isAuthRoute) {
			console.log('Redirecting to /login (unauthenticated access to protected route)');
			goto('/login', { replaceState: true });
		} else if (isAuthenticated && (isAuthRoute || currentPath === '/')) {
	           // If logged in and on login/register OR on the root page, go to characters
			console.log('Redirecting to /characters (authenticated access to auth route or root)');
			goto('/characters', { replaceState: true });
		}
	});

	const handleLogout = () => {
		authStore.logout();
		// No need for explicit goto here, the reactive effect will redirect to /login
	};

</script>

{#if isLoading}
	<!-- Optional: Basic Loading Indicator -->
	<div class="flex items-center justify-center min-h-screen w-full">
		<p>Loading...</p>
	</div>
{:else}
	<!-- Main Layout -->
	<div class="flex min-h-screen bg-background text-foreground">
		<!-- Sidebar (Left Column) -->
	<aside class="w-64 flex-shrink-0 border-r border-border bg-card p-4">
		<!-- Placeholder for Sidebar Content -->
		<h2 class="text-lg font-semibold mb-4 text-card-foreground">Scribe</h2>
		<nav class="space-y-2">
			{#if isAuthenticated}
				<a href="/characters" class="block px-3 py-2 rounded-md hover:bg-muted" class:font-bold={currentPath.startsWith('/characters')}>Characters</a>
				<a href="/chat" class="block px-3 py-2 rounded-md hover:bg-muted" class:font-bold={currentPath.startsWith('/chat')}>Chat (Placeholder)</a>
				<a href="/settings" class="block px-3 py-2 rounded-md hover:bg-muted" class:font-bold={currentPath.startsWith('/settings')}>Settings (Placeholder)</a>
			{/if}
			<!-- Auth links shown when logged out -->
			{#if !isAuthenticated}
				<a href="/login" class="block px-3 py-2 rounded-md hover:bg-muted" class:font-bold={currentPath === '/login'}>Login</a>
				<a href="/register" class="block px-3 py-2 rounded-md hover:bg-muted" class:font-bold={currentPath === '/register'}>Register</a>
			{/if}
		</nav>
		<div class="mt-auto pt-4 border-t border-border">
			{#if isAuthenticated}
				<!-- User Info & Logout Button -->
				<p class="text-sm text-muted-foreground mb-2">Logged in as: {$authStore.user?.username ?? 'User'}</p>
				<button onclick={handleLogout} class="w-full px-3 py-2 rounded-md text-left text-sm text-red-500 hover:bg-muted">
					Logout
				</button>
			{:else}
				<p class="text-sm text-muted-foreground">Not logged in</p>
			{/if}
		</div>
	</aside>

	<!-- Main Content Area (Right Column) -->
	<main class="flex-1 overflow-auto p-4">
		{@render children()}
	</main>
</div>
{/if}
