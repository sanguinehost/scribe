<script lang="ts">
	import LoginForm from '$lib/components/auth/LoginForm.svelte';
</script>

<div class="container mx-auto flex h-screen items-center justify-center p-4">
	<div class="w-full max-w-md rounded-lg border bg-card p-6 shadow-sm">
		<h1 class="mb-6 text-center text-2xl font-semibold">Login</h1>
		<LoginForm />
		<p class="mt-4 text-center text-sm text-muted-foreground">
			Don't have an account? <a href="/register" class="underline hover:text-primary">Register here</a>
		</p>
	</div>
</div>