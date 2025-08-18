<script lang="ts">
	// Removed VercelIcon and MessageIcon imports
	// Removed Button and SettingsStore imports
	import { fly } from 'svelte/transition';
	import { quintOut } from 'svelte/easing';
</script>

<div class="flex h-full w-full items-start justify-center p-6 pt-[20vh]">
	<div class="max-w-3xl">
		<div class="mx-auto flex max-w-xl flex-col gap-8 rounded-xl p-6 text-center leading-relaxed">
			<p class="flex flex-row items-center justify-center gap-4">
				<!-- Using a generic Pen Tool icon as a placeholder -->
				<svg
					xmlns="http://www.w3.org/2000/svg"
					width="32"
					height="32"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
					class="lucide lucide-pen-tool"
					><path d="m12 19 7-7 3 3-7 7-3-3z" /><path
						d="m18 13-1.5-7.5L2 2l3.5 14.5L13 18l5-5z"
					/><path d="m2 2 7.586 7.586" /><path d="m11 19-3-3" /></svg
				>
			</p>
			<p>
				Welcome to <strong>Scribe</strong>, a next-generation AI chat and storytelling interface by
				Sanguine.
			</p>
			<p>
				Scribe is designed for seamless long-term context using RAG, robust prompt engineering, and
				a modern user experience, all powered by a secure and performant Rust backend. We prioritize
				your privacy with server-side encryption of your data.
			</p>
			<p>
				Explore the future of interactive storytelling, with a commitment to user empowerment and
				open-source principles. You can follow our progress
				<!-- Adjusted to a plausible GitHub link -->
				<a
					class="font-medium underline underline-offset-4"
					href="https://github.com/sanguinehost/scribe"
					target="_blank"
				>
					on GitHub
				</a>.
			</p>

			<!-- Removed settings button div -->
		</div>
	</div>
</div>
