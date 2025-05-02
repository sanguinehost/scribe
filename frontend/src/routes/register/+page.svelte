<script lang="ts">
	import RegisterForm from '$lib/components/auth/RegisterForm.svelte';
</script>

<div class="container mx-auto flex h-screen items-center justify-center p-4">
	<div class="w-full max-w-md rounded-lg border bg-card p-6 shadow-sm">
		<h1 class="mb-6 text-center text-2xl font-semibold">Register</h1>
		<RegisterForm />
		<p class="mt-4 text-center text-sm text-muted-foreground">
			Already have an account? <a href="/login" class="underline hover:text-primary">Login here</a>
		</p>
	</div>
</div>