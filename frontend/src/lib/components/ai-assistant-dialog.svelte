<script lang="ts">
	import { Button } from './ui/button';
	import { Input } from './ui/input';
	import { Label } from './ui/label';
	import { Textarea } from './ui/textarea';
	import {
		Dialog,
		DialogContent,
		DialogDescription,
		DialogFooter,
		DialogHeader,
		DialogTitle
	} from './ui/dialog';
	import { toast } from 'svelte-sonner';
	import { Bot, Sparkles, Wand2, RefreshCw, Plus, FileText } from 'lucide-svelte';
	import { apiClient } from '$lib/api';
	import type { GenerationMode, CharacterContext } from '$lib/types';

	type Props = {
		open: boolean;
		fieldName: string;
		fieldValue: string;
		characterContext?: CharacterContext;
		onGenerated: (generatedText: string) => void;
		onOpenChange: (open: boolean) => void;
	};

	let { 
		open = $bindable(), 
		fieldName, 
		fieldValue, 
		characterContext, 
		onGenerated, 
		onOpenChange 
	}: Props = $props();

	let userInput = $state('');
	let isGenerating = $state(false);
	let selectedMode = $state<GenerationMode>('create');

	// Reset input when dialog opens/closes
	$effect(() => {
		if (open) {
			userInput = fieldValue || '';
		}
	});

	// Examples and guidance for different field types
	const fieldExamples = {
		description: {
			placeholder: "e.g., 'A mysterious detective with a troubled past'",
			example: "A seasoned detective in their 40s who works the night shift in the city's most dangerous district. They have a sharp wit, keen observational skills, and a tendency to work alone due to trust issues stemming from a betrayal by a former partner. Despite their gruff exterior, they have a strong moral compass and will go to great lengths to protect the innocent.",
			prompt: "Create a detailed character description that includes personality, background, appearance, and key traits."
		},
		personality: {
			placeholder: "e.g., 'Sarcastic but caring, distrustful but loyal'",
			example: "Cynical and sharp-tongued on the surface, but deeply compassionate underneath. Uses humor as a defense mechanism. Fiercely loyal to those who earn their trust, but takes time to open up. Has a strong sense of justice and cannot stand bullies or corruption. Often acts tough to hide vulnerability.",
			prompt: "Develop character personality traits, quirks, strengths, and flaws that make them feel real and three-dimensional."
		},
		first_mes: {
			placeholder: "e.g., 'The detective looks up from their case files'",
			example: "*The detective glances up from a stack of case files, coffee growing cold in a chipped mug. Rain patters against the precinct window as they notice you approach.* \"Another long night ahead. What brings you to my corner of this chaos?\" *They gesture to an empty chair across from their cluttered desk, eyes already assessing you with professional interest.*",
			prompt: "Create an engaging first message that establishes the scene, character voice, and invites interaction."
		},
		scenario: {
			placeholder: "e.g., 'A gritty urban police precinct during night shift'",
			example: "The setting is a busy metropolitan police precinct during the graveyard shift. The detective works in a cramped office filled with case files, evidence bags, and cold coffee. Outside, the city never sleeps - sirens wail in the distance, neon signs flicker through rain-streaked windows, and the constant hum of urban life provides a backdrop to their investigations.",
			prompt: "Establish the setting, atmosphere, and context where interactions with this character take place."
		},
		mes_example: {
			placeholder: "e.g., 'How the character typically speaks'",
			example: "{{char}}: *Leans back in chair, studying the evidence board* \"Three victims, all with the same MO. Either we've got a serial on our hands, or someone's very good at making it look that way.\"\n\n{{user}}: What's your theory?\n\n{{char}}: *Taps pen against temple* \"My gut says personal. Too clean, too methodical. This isn't random violence - someone's settling scores. Question is, what connects our vics that we haven't found yet?\" *Fixes you with an intense stare* \"And more importantly, are we looking at the killer or just getting started?\"",
			prompt: "Show how the character speaks and interacts through realistic dialogue examples."
		},
		system_prompt: {
			placeholder: "e.g., 'Instructions for AI behavior'",
			example: "You are a seasoned detective character. Maintain a professional but slightly cynical tone. Use detective/police terminology naturally. Show investigative thinking through your responses. Balance toughness with underlying compassion. Avoid being overly dramatic - keep responses grounded and realistic.",
			prompt: "Create clear instructions that guide how the AI should portray this character."
		},
		depth_prompt: {
			placeholder: "e.g., 'Always remember this character is...'",
			example: "This character carries the weight of an unsolved case involving a missing child from five years ago. It drives their determination and makes them particularly protective of vulnerable victims. They have a habit of working late into the night, often missing meals, and keep a photo of the missing child tucked in their case file as a reminder of why the work matters.",
			prompt: "Add depth with backstory, motivations, or character details that should influence all interactions."
		}
	};

	async function handleGenerate() {
		if (!userInput.trim() && selectedMode !== 'create') {
			toast.error('Please provide some text to work with');
			return;
		}

		try {
			isGenerating = true;

			if (selectedMode === 'create' || !fieldValue.trim()) {
				// Generate new content using character generation
				await generateFromScratch();
			} else {
				// Expand/enhance existing content using text expansion
				await expandExistingText();
			}
		} catch (error) {
			console.error('Error in AI generation:', error);
			toast.error('An error occurred while generating content');
		} finally {
			isGenerating = false;
		}
	}

	async function generateFromScratch() {
		const fieldInfo = fieldExamples[fieldName as keyof typeof fieldExamples];
		const prompt = userInput.trim() || `Generate a ${fieldName} for a character: ${characterContext?.name || 'new character'}`;
		
		const fullPrompt = `${fieldInfo?.prompt || `Create a ${fieldName}`}

User request: ${prompt}

${characterContext?.name ? `Character name: ${characterContext.name}` : ''}
${characterContext?.description ? `Character description: ${characterContext.description}` : ''}
${characterContext?.personality ? `Character personality: ${characterContext.personality}` : ''}
${characterContext?.scenario ? `Character scenario: ${characterContext.scenario}` : ''}

Example of good ${fieldName}:
${fieldInfo?.example || 'No example available'}

Generate a ${fieldName} that is detailed, engaging, and consistent with the character context.`;

		const result = await apiClient.generateCharacter({ prompt: fullPrompt });
		
		if (result.isOk()) {
			// The backend returns a complete character, but we only want the specific field
			const character = result.value;
			const generatedContent = extractFieldFromCharacter(character, fieldName);
			
			if (generatedContent) {
				onGenerated(generatedContent);
				toast.success(`${fieldName} generated successfully`);
				onOpenChange(false);
			} else {
				toast.error(`No ${fieldName} was generated`);
			}
		} else {
			console.error('Failed to generate character:', result.error);
			toast.error(result.error?.message || 'Failed to generate content');
		}
	}

	async function expandExistingText() {
		// Create a temporary ScribeAssistant session for text expansion
		const createSessionResult = await apiClient.createChat({
			title: `AI Assistant - ${fieldName}`,
			chat_mode: 'ScribeAssistant'
		});

		if (!createSessionResult.isOk()) {
			toast.error('Failed to create AI session');
			return;
		}

		const session = createSessionResult.value;
		const textToExpand = userInput.trim() || fieldValue;

		try {
			const expandResult = await apiClient.expandText(session.id, textToExpand);
			
			if (expandResult.isOk()) {
				onGenerated(expandResult.value.expanded_text);
				toast.success(`${fieldName} ${getModeDescription(selectedMode)} successfully`);
				onOpenChange(false);
			} else {
				console.error('Failed to expand text:', expandResult.error);
				toast.error(expandResult.error?.message || 'Failed to generate content');
			}
		} finally {
			// Clean up the temporary session
			await apiClient.deleteChat(session.id);
		}
	}

	function extractFieldFromCharacter(character: any, fieldName: string): string | null {
		// Map field names to character properties
		const fieldMap: Record<string, string> = {
			description: 'description',
			personality: 'personality',
			first_mes: 'first_mes',
			scenario: 'scenario',
			mes_example: 'mes_example',
			system_prompt: 'system_prompt',
			depth_prompt: 'depth_prompt'
		};

		const characterField = fieldMap[fieldName];
		return character[characterField] || null;
	}

	function getModeDescription(mode: GenerationMode): string {
		const descriptions = {
			create: 'generated',
			enhance: 'enhanced',
			rewrite: 'rewritten',
			expand: 'expanded'
		};
		return descriptions[mode];
	}

	function insertExample() {
		const fieldInfo = fieldExamples[fieldName as keyof typeof fieldExamples];
		if (fieldInfo?.example) {
			userInput = fieldInfo.example;
		}
	}

	// Determine available modes based on context
	let hasContent = $derived(fieldValue && fieldValue.trim().length > 0);
	let canCreate = $derived(true); // Always allow creation
	let canEnhance = $derived(hasContent);

	const modeOptions = $derived(() => {
		const options = [];
		if (canCreate) options.push({ value: 'create', label: 'Generate New', icon: Plus });
		if (canEnhance) options.push({ value: 'enhance', label: 'Enhance Existing', icon: Sparkles });
		if (canEnhance) options.push({ value: 'expand', label: 'Expand Detail', icon: Wand2 });
		if (canEnhance) options.push({ value: 'rewrite', label: 'Rewrite Fresh', icon: RefreshCw });
		return options;
	});
</script>

<Dialog bind:open onOpenChange={onOpenChange}>
	<DialogContent class="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
		<DialogHeader>
			<DialogTitle class="flex items-center gap-2">
				<Bot class="h-5 w-5" />
				AI Assistant - {fieldName}
			</DialogTitle>
			<DialogDescription>
				Use AI to generate or enhance your {fieldName}. Provide as much or as little detail as you want.
			</DialogDescription>
		</DialogHeader>

		<div class="space-y-4">
			<!-- Generation Mode Selection -->
			<div class="grid gap-2">
				<Label>Generation Mode</Label>
				<div class="flex flex-wrap gap-2">
					{#each modeOptions as mode}
						<Button
							variant={selectedMode === mode.value ? "default" : "outline"}
							size="sm"
							onclick={() => selectedMode = mode.value}
							class="flex items-center gap-1"
						>
							<svelte:component this={mode.icon} size={14} />
							{mode.label}
						</Button>
					{/each}
				</div>
			</div>

			<!-- User Input -->
			<div class="grid gap-2">
				<div class="flex items-center justify-between">
					<Label for="user-input">
						{selectedMode === 'create' ? 'Describe what you want' : 'Text to enhance'}
					</Label>
					<Button
						variant="ghost"
						size="sm"
						onclick={insertExample}
						class="text-xs"
					>
						<FileText size={12} class="mr-1" />
						Show Example
					</Button>
				</div>
				<Textarea
					id="user-input"
					bind:value={userInput}
					placeholder={fieldExamples[fieldName as keyof typeof fieldExamples]?.placeholder || `Enter your ${fieldName} content...`}
					rows={6}
					class="resize-none"
				/>
				{#if selectedMode === 'create'}
					<p class="text-sm text-muted-foreground">
						Describe what kind of {fieldName} you want. The AI will create detailed content based on your input and the character context.
					</p>
				{:else}
					<p class="text-sm text-muted-foreground">
						The AI will {getModeDescription(selectedMode).replace('ed', '')} the text above into a more detailed {fieldName}.
					</p>
				{/if}
			</div>

			<!-- Current Content Preview (if enhancing) -->
			{#if hasContent && selectedMode !== 'create'}
				<div class="grid gap-2">
					<Label>Current Content</Label>
					<div class="rounded-md bg-muted p-3 text-sm">
						{fieldValue}
					</div>
				</div>
			{/if}
		</div>

		<DialogFooter>
			<Button variant="outline" onclick={() => onOpenChange(false)} disabled={isGenerating}>
				Cancel
			</Button>
			<Button onclick={handleGenerate} disabled={isGenerating}>
				{#if isGenerating}
					<svg
						class="h-4 w-4 animate-spin mr-2"
						xmlns="http://www.w3.org/2000/svg"
						fill="none"
						viewBox="0 0 24 24"
					>
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path
							class="opacity-75"
							fill="currentColor"
							d="M4 12a8 8 0 818-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 714 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
						></path>
					</svg>
					Generating...
				{:else}
					Generate {fieldName}
				{/if}
			</Button>
		</DialogFooter>
	</DialogContent>
</Dialog>