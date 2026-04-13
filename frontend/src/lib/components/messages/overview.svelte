<script lang="ts">
	import { onMount } from 'svelte';

	let mounted = $state(false);

	onMount(() => {
		// Stagger the entrance animations
		mounted = true;
	});
</script>

<div class="bg-ambient flex h-full w-full items-start justify-center overflow-y-auto p-6 pt-[12vh]">
	<div class="mx-auto flex max-w-2xl flex-col items-center gap-10 text-center">
		<!-- Animated Wordmark -->
		<div
			class="flex flex-col items-center gap-3"
			style="opacity: {mounted ? 1 : 0}; transform: translateY({mounted ? 0 : 20}px); transition: all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);"
		>
			<h1
				class="text-gradient font-heading text-6xl font-black tracking-tight sm:text-7xl md:text-8xl"
			>
				Scribe
			</h1>
			<p
				class="max-w-md text-lg font-medium text-muted-foreground"
				style="opacity: {mounted ? 1 : 0}; transform: translateY({mounted ? 0 : 10}px); transition: all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) 0.15s;"
			>
				Next-generation AI storytelling, powered by Sanguine.
			</p>
		</div>

		<!-- Quick Start Cards -->
		<div
			class="grid w-full grid-cols-1 gap-4 sm:grid-cols-3"
			style="opacity: {mounted ? 1 : 0}; transform: translateY({mounted ? 0 : 16}px); transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) 0.3s;"
		>
			<!-- Upload Character -->
			<button
				class="glass-panel group flex cursor-pointer flex-col items-center gap-3 rounded-xl p-6 transition-all duration-300 hover:scale-[1.03] hover:shadow-lg"
				onclick={() => window.dispatchEvent(new CustomEvent('overview:upload-character'))}
			>
				<div
					class="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 text-primary transition-all duration-300 group-hover:scale-110 group-hover:bg-primary/20"
				>
					<svg
						xmlns="http://www.w3.org/2000/svg"
						width="24"
						height="24"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						stroke-width="2"
						stroke-linecap="round"
						stroke-linejoin="round"
					>
						<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
						<polyline points="17 8 12 3 7 8" />
						<line x1="12" x2="12" y1="3" y2="15" />
					</svg>
				</div>
				<div class="space-y-1">
					<p class="text-sm font-semibold text-foreground">Upload Character</p>
					<p class="text-xs text-muted-foreground">Import a character card file</p>
				</div>
			</button>

			<!-- Create Persona -->
			<button
				class="glass-panel group flex cursor-pointer flex-col items-center gap-3 rounded-xl p-6 transition-all duration-300 hover:scale-[1.03] hover:shadow-lg"
				onclick={() => window.dispatchEvent(new CustomEvent('overview:create-persona'))}
			>
				<div
					class="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 text-primary transition-all duration-300 group-hover:scale-110 group-hover:bg-primary/20"
				>
					<svg
						xmlns="http://www.w3.org/2000/svg"
						width="24"
						height="24"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						stroke-width="2"
						stroke-linecap="round"
						stroke-linejoin="round"
					>
						<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
						<circle cx="12" cy="7" r="4" />
					</svg>
				</div>
				<div class="space-y-1">
					<p class="text-sm font-semibold text-foreground">Create Persona</p>
					<p class="text-xs text-muted-foreground">Define who you are in the story</p>
				</div>
			</button>

			<!-- Explore Lorebooks -->
			<button
				class="glass-panel group flex cursor-pointer flex-col items-center gap-3 rounded-xl p-6 transition-all duration-300 hover:scale-[1.03] hover:shadow-lg"
				onclick={() => window.dispatchEvent(new CustomEvent('overview:explore-lorebooks'))}
			>
				<div
					class="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 text-primary transition-all duration-300 group-hover:scale-110 group-hover:bg-primary/20"
				>
					<svg
						xmlns="http://www.w3.org/2000/svg"
						width="24"
						height="24"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						stroke-width="2"
						stroke-linecap="round"
						stroke-linejoin="round"
					>
						<path
							d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"
						/>
					</svg>
				</div>
				<div class="space-y-1">
					<p class="text-sm font-semibold text-foreground">Explore Lorebooks</p>
					<p class="text-xs text-muted-foreground">Build the fabric of your worlds</p>
				</div>
			</button>
		</div>

		<!-- Feature Pills -->
		<div
			class="flex flex-wrap justify-center gap-2"
			style="opacity: {mounted ? 1 : 0}; transform: translateY({mounted ? 0 : 12}px); transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) 0.45s;"
		>
			<span
				class="rounded-full border border-border/40 bg-muted/30 px-3 py-1 text-xs font-medium text-muted-foreground backdrop-blur-sm"
			>
				🔒 Encrypted
			</span>
			<span
				class="rounded-full border border-border/40 bg-muted/30 px-3 py-1 text-xs font-medium text-muted-foreground backdrop-blur-sm"
			>
				🧠 RAG-Powered
			</span>
			<span
				class="rounded-full border border-border/40 bg-muted/30 px-3 py-1 text-xs font-medium text-muted-foreground backdrop-blur-sm"
			>
				⚡ Streaming
			</span>
			<span
				class="rounded-full border border-border/40 bg-muted/30 px-3 py-1 text-xs font-medium text-muted-foreground backdrop-blur-sm"
			>
				🎭 Multi-Character
			</span>
		</div>

		<!-- GitHub Link -->
		<p
			class="text-xs text-muted-foreground/60"
			style="opacity: {mounted ? 1 : 0}; transition: opacity 0.5s ease 0.6s;"
		>
			Follow our progress
			<a
				class="font-medium text-muted-foreground underline underline-offset-4 transition-colors hover:text-foreground"
				href="https://github.com/sanguinehost/scribe"
				target="_blank"
			>
				on GitHub
			</a>
		</p>
	</div>
</div>
