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
	// import { RadioGroup, RadioGroupItem } from './ui/radio-group';
	import { toast } from 'svelte-sonner';
	import { Bot, Sparkles, Wand, RefreshCw, Plus, FileText, Info, Bug } from 'lucide-svelte';
	import { apiClient } from '$lib/api';
	import type { GenerationMode, CharacterContext, GenerateCharacterFieldResponse } from '$lib/types';
	import CharacterGenerationDebugModal from './character-generation-debug-modal.svelte';

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
	let selectedStyle = $state('auto');
	let isAnalyzingStyle = $state(false);
	let lastGenerationResponse = $state<GenerateCharacterFieldResponse | null>(null);
	let showDebugModal = $state(false);
	let showResults = $state(false);

	// Reset input when dialog opens/closes
	$effect(() => {
		if (open) {
			userInput = fieldValue || '';
			selectedStyle = 'auto'; // Start with auto
			
			// Async style detection if there's existing content
			if (fieldValue && fieldValue.trim().length > 20) {
				analyzeStyle(fieldValue);
			}
		} else {
			// Reset debug modal when main dialog closes
			showDebugModal = false;
			showResults = false;
		}
	});

	// Different description styles with examples and prompts
	const descriptionStyles = {
		traits: {
			name: "Character Traits",
			description: "Brief, punchy traits and physical characteristics",
			example: "Tall. Lean build. Silver hair, piercing green eyes. Former military sniper. Calm under pressure. Doesn't talk much. Prefers action over words. Methodical. Patient. Excellent marksman. Haunted by past missions. Drinks black coffee. Wears dark clothing. Struggles with close relationships. Protective of civilians. Dry sense of humor. Always alert. Sleeps light. Carries multiple knives. Efficient killer when necessary.",
			prompt: "Create a character description using short, punchy sentences. Focus on physical appearance, personality traits, relationships, and behavioral patterns. Use fragments and brief statements. Avoid flowery language or extensive narrative."
		},
		narrative: {
			name: "Narrative Description",
			description: "Story-like description with background and context",
			example: "Captain Elena Vasquez stands at the helm of her merchant vessel, weathered hands gripping the wheel as storm clouds gather on the horizon. Twenty years of sailing treacherous waters have carved lines of determination into her sun-bronzed face, while her steel-gray eyes reflect the wisdom earned through countless adventures. Once a naval officer, she abandoned her commission after witnessing corruption in the admiralty, choosing instead the uncertain freedom of independent trade. Her crew respects her fair leadership and tactical brilliance, though few know of the treasure map hidden in her cabin or the mysterious benefactor funding her expeditions.",
			prompt: "Create a narrative character description that tells a story. Include background, motivations, appearance woven into the narrative, and personality shown through context. Write in flowing paragraphs with complete sentences."
		},
		profile: {
			name: "Profile Format",
			description: "Organized data fields with biographical information and measurements",
			example: "Name: Dr. Marcus Chen\nAge: 34\nOccupation: Xenobiologist and Deep Space Explorer\nHeight: 6'1\"\nWeight: 175 lbs\nHair: Black, always slightly messy\nEyes: Dark brown behind wire-rimmed glasses\nBuild: Tall and lanky, with calloused hands from fieldwork\nPersonality: Brilliant, absent-minded, passionate about discovery, socially awkward but kind-hearted\nBackground: Born on Luna Colony, lost his parents in a mining accident at age 12. Raised by his grandfather, a renowned botanist. Devoted his life to studying alien ecosystems after discovering bioluminescent fungi on Europa. Has a pet lab rat named Newton.",
			prompt: "Create a structured character profile using organized data fields (Name:, Age:, Height:, etc.) followed by personality and background. Include specific measurements and physical attributes when relevant. Use clear field labels and consistent formatting. {{char}} refers to the character's name, {{user}} refers to the user/player."
		},
		group: {
			name: "Group Characters",
			description: "Multiple character definitions with Characters() format",
			example: "{{char}} is the crew of the starship Nebula's Edge, a ragtag team of space salvagers.\nCharacters(\"Captain Zara, Chief Engineer Bolt, Navigator Iris\")\nCaptain Zara(\"A former pirate turned legitimate salvager. Fiery red hair, cybernetic left arm, sharp tongue. Excellent pilot and negotiator. Haunted by her criminal past but fiercely loyal to her crew.\")\nChief Engineer Bolt(\"A gruff, bearded engineer who can fix anything with spare parts and determination. Missing his right leg from a reactor explosion. Drinks too much but never when on duty. Protective father figure to the crew.\")\nNavigator Iris(\"A young prodigy with enhanced neural implants for calculating hyperspace jumps. Quiet and analytical, but has moments of surprising insight. Joined the crew to escape corporate espionage charges.\")",
			prompt: "Create a group character definition starting with 'Characters()' listing all names, then define each character using their name as a function. Include detailed descriptions for each character, their relationships, and the group setting. Focus on how the characters interact as a team. {{char}} refers to the group, {{user}} refers to the player."
		},
		worldbuilding: {
			name: "World-Building/Lore",
			description: "Rich world context with character as part of larger narrative universe",
			example: "{{char}} is a Guardian of the Stellar Nexus, one of the ancient beings who maintain the cosmic balance between the seven dimensional realms. In the current age known as the Twilight Convergence, the barriers between dimensions have grown thin, allowing creatures and energies to bleed through. {{char}} serves as both protector and guide, wielding the power of stellar manipulation to seal rifts and defend inhabited worlds. The Nexus Council has tasked {{char}} with monitoring Earth, a primitive world that has unknowingly become a focal point for interdimensional instability due to humanity's rapid technological advancement.",
			prompt: "Create a world-building description that establishes the character as part of a larger fictional universe. Include world lore, power systems, historical context, and the character's role in the greater narrative. Focus on immersive world-building rather than behavioral instructions. {{char}} will be replaced with the character's name, {{user}} with the player's name."
		},
		system: {
			name: "System",
			description: "Behavioral rules and interaction guidelines for AI roleplay",
			example: "{{char}} is an adaptive survival simulation that responds to {{user}}'s choices in a post-apocalyptic wasteland. {{char}} will generate random encounters, manage resource scarcity, and track {{user}}'s health, hunger, and sanity levels. {{char}} will describe the harsh environment in vivid detail and present meaningful choices with consequences. {{char}} will never guarantee {{user}}'s safety - death is a real possibility based on poor decisions. {{char}} will maintain an atmosphere of tension and uncertainty while allowing {{user}} complete freedom to explore, fight, hide, or attempt to rebuild civilization. {{char}} will not make decisions for {{user}} or assume their actions.",
			prompt: "Create behavioral instructions for an AI character. Define what the character will and won't do, their response patterns, content boundaries, narrative perspective, and interaction rules. Can cover individual character behavior or complex system/game master mechanics. {{char}} will be replaced with the character's name, {{user}} with the player's name."
		}
	};

	// Enhanced field examples for non-description fields
	const fieldExamples = {
		description: descriptionStyles,
		personality: {
			default: {
				placeholder: "e.g., 'Sarcastic but caring, distrustful but loyal'",
				example: "Cynical and sharp-tongued on the surface, but deeply compassionate underneath. Uses humor as a defense mechanism. Fiercely loyal to those who earn their trust, but takes time to open up. Has a strong sense of justice and cannot stand bullies or corruption. Often acts tough to hide vulnerability.",
				prompt: "Develop character personality traits, quirks, strengths, and flaws that make them feel real and three-dimensional."
			}
		},
		first_mes: {
			default: {
				placeholder: "e.g., 'The detective looks up from their case files'",
				example: "*The detective glances up from a stack of case files, coffee growing cold in a chipped mug. Rain patters against the precinct window as they notice you approach.* \"Another long night ahead. What brings you to my corner of this chaos?\" *They gesture to an empty chair across from their cluttered desk, eyes already assessing you with professional interest.*",
				prompt: "Create an engaging first message that establishes the scene, character voice, and invites interaction. Use a mix of narration (in asterisks) and dialogue."
			}
		},
		scenario: {
			default: {
				placeholder: "e.g., 'A gritty urban police precinct during night shift'",
				example: "The setting is a busy metropolitan police precinct during the graveyard shift. The detective works in a cramped office filled with case files, evidence bags, and cold coffee. Outside, the city never sleeps - sirens wail in the distance, neon signs flicker through rain-streaked windows, and the constant hum of urban life provides a backdrop to their investigations.",
				prompt: "Establish the setting, atmosphere, and context where interactions with this character take place."
			}
		},
		mes_example: {
			default: {
				placeholder: "e.g., 'How the character typically speaks'",
				example: "{{char}}: *Leans back in chair, studying the evidence board* \"Three victims, all with the same MO. Either we've got a serial on our hands, or someone's very good at making it look that way.\"\n\n{{user}}: What's your theory?\n\n{{char}}: *Taps pen against temple* \"My gut says personal. Too clean, too methodical. This isn't random violence - someone's settling scores. Question is, what connects our vics that we haven't found yet?\"",
				prompt: "Show how the character speaks and interacts through realistic dialogue examples. Use {{char}} and {{user}} placeholders."
			}
		},
		system_prompt: {
			default: {
				placeholder: "e.g., 'Instructions for AI behavior'",
				example: "You are a seasoned detective character. Maintain a professional but slightly cynical tone. Use detective/police terminology naturally. Show investigative thinking through your responses. Balance toughness with underlying compassion. Avoid being overly dramatic - keep responses grounded and realistic.",
				prompt: "Create clear instructions that guide how the AI should portray this character."
			}
		},
		depth_prompt: {
			default: {
				placeholder: "e.g., 'Always remember this character is...'",
				example: "This character carries the weight of an unsolved case involving a missing child from five years ago. It drives their determination and makes them particularly protective of vulnerable victims. They have a habit of working late into the night, often missing meals, and keep a photo of the missing child tucked in their case file as a reminder of why the work matters.",
				prompt: "Add depth with backstory, motivations, or character details that should influence all interactions."
			}
		}
	};

	async function analyzeStyle(text: string) {
		if (!text || text.trim().length < 20) return;
		
		isAnalyzingStyle = true;
		try {
			const detectedStyle = await detectDescriptionStyle(text);
			selectedStyle = detectedStyle;
			if (detectedStyle !== 'auto') {
				toast.success(`AI detected style: ${descriptionStyles[detectedStyle as keyof typeof descriptionStyles]?.name || detectedStyle}`);
			}
		} catch (error) {
			console.warn('Error in style analysis:', error);
			toast.error('Failed to analyze style');
		} finally {
			isAnalyzingStyle = false;
		}
	}

	async function detectDescriptionStyle(text: string): Promise<string> {
		if (!text || text.trim().length < 20) return 'auto';
		
		try {
			// Create a temporary ScribeAssistant session for style analysis
			const createSessionResult = await apiClient.createChat({
				title: 'Style Analysis',
				chat_mode: 'ScribeAssistant'
			});

			if (!createSessionResult.isOk()) {
				console.warn('Failed to create analysis session, falling back to auto');
				return 'auto';
			}

			const session = createSessionResult.value;

			// Create a structured prompt for style analysis
			const analysisPrompt = `Analyze this character description and classify it into exactly one of these four styles. Respond with ONLY the style name, nothing else.

Available styles:
- traits: Brief, punchy traits and physical characteristics (short sentences, fragments)
- narrative: Story-like description with background and flowing prose
- worldbuilding: Rich world context with {{char}} placeholders focusing on lore and universe
- behavioral: AI behavior instructions using {{char}} and {{user}} placeholders focusing on what the AI will/won't do

Text to analyze:
"${text}"

Style classification:`;

			const expandResult = await apiClient.expandText(session.id, analysisPrompt);
			
			// Clean up the temporary session
			await apiClient.deleteChatById(session.id);

			if (expandResult.isOk()) {
				const response = expandResult.value.expanded_text.toLowerCase().trim();
				
				// Extract the style from the AI response
				if (response.includes('traits')) return 'traits';
				if (response.includes('narrative')) return 'narrative';
				if (response.includes('worldbuilding')) return 'worldbuilding';
				if (response.includes('behavioral')) return 'behavioral';
			}
		} catch (error) {
			console.warn('Error in AI style detection:', error);
		}
		
		// Fallback to auto if AI analysis fails
		return 'auto';
	}

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
		try {
			// Map frontend field names to backend field enum values
			const fieldMapping: Record<string, string> = {
				'description': 'description',
				'personality': 'personality', 
				'first_mes': 'first_mes',
				'scenario': 'scenario',
				'mes_example': 'mes_example',
				'system_prompt': 'system_prompt',
				'depth_prompt': 'depth_prompt',
				'tags': 'tags'
			};

			// Handle alternate greeting field names (alternate_greeting_1, alternate_greeting_2, etc.)
			let backendFieldName: string;
			let greetingNumber: number | null = null;
			
			if (fieldName.startsWith('alternate_greeting')) {
				backendFieldName = 'alternate_greeting';
				// Extract the number from alternate_greeting_1, alternate_greeting_2, etc.
				const match = fieldName.match(/alternate_greeting_(\d+)/);
				if (match) {
					greetingNumber = parseInt(match[1], 10);
				}
			} else {
				backendFieldName = fieldMapping[fieldName] || fieldName;
			}
			
			// Map frontend style to backend style enum values
			const styleMapping: Record<string, string> = {
				'traits': 'traits',
				'narrative': 'narrative',
				'profile': 'profile',
				'group': 'group', 
				'worldbuilding': 'worldbuilding',
				'system': 'system',
				'auto': 'auto'
			};

			const backendStyle = styleMapping[selectedStyle] || 'auto';
			
			// Build user request with context about which greeting number this is
			let userRequest: string;
			if (greetingNumber !== null) {
				userRequest = userInput.trim() || `Generate alternate greeting #${greetingNumber} for a character: ${characterContext?.name || 'new character'}. This should be different from their main greeting and any other alternate greetings.`;
			} else {
				userRequest = userInput.trim() || `Generate a ${fieldName} for a character: ${characterContext?.name || 'new character'}`;
			}
			
			// Build character context in the format expected by the backend
			const backendCharacterContext = characterContext ? {
				name: characterContext.name,
				description: characterContext.description,
				personality: characterContext.personality,
				scenario: characterContext.scenario,
				tags: characterContext.tags,
				// Include first_mes and other message fields for better context
				first_mes: characterContext.first_mes || null,
				mes_example: characterContext.mes_example || null,
				system_prompt: characterContext.system_prompt || null,
				depth_prompt: characterContext.depth_prompt || null,
				alternate_greetings: characterContext.alternate_greetings || null,
				lorebook_entries: null, // TODO: Add lorebook support
				associated_persona: null // TODO: Add persona support
			} : null;

			// Determine lorebook_id if any lorebooks are selected
			const selectedLorebookId = (characterContext?.selectedLorebooks && characterContext.selectedLorebooks.length > 0) 
				? characterContext.selectedLorebooks[0] // Use the first selected lorebook
				: null;

			// Use the dedicated character generation API endpoint
			const generateResult = await fetch('/api/characters/generate/field', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				credentials: 'include',
				body: JSON.stringify({
					field: backendFieldName,
					style: backendStyle !== 'auto' ? backendStyle : null,
					user_prompt: userRequest,
					character_context: backendCharacterContext,
					generation_options: null,
					lorebook_id: selectedLorebookId
				})
			});

			if (!generateResult.ok) {
				const errorText = await generateResult.text();
				console.error('Generation failed:', errorText);
				toast.error(`Failed to generate ${fieldName}: ${generateResult.statusText}`);
				return;
			}

			const generationResponse: GenerateCharacterFieldResponse = await generateResult.json();
			
			// Store the full response for debug access
			lastGenerationResponse = generationResponse;
			
			onGenerated(generationResponse.content);
			toast.success(`${fieldName} generated successfully - Click Debug to see details`);
			
			// Show results state instead of closing
			showResults = true;
			
		} catch (error) {
			console.error('Error in character generation:', error);
			toast.error(`Failed to generate ${fieldName}`);
		}
	}

	async function expandExistingText() {
		try {
			const textToExpand = userInput.trim() || fieldValue;
			
			// Map frontend field names to backend field enum values
			const fieldMapping: Record<string, string> = {
				'description': 'description',
				'personality': 'personality', 
				'first_mes': 'first_mes',
				'scenario': 'scenario',
				'mes_example': 'mes_example',
				'system_prompt': 'system_prompt',
				'depth_prompt': 'depth_prompt',
				'tags': 'tags'
			};

			const backendFieldName = fieldMapping[fieldName] || fieldName;

			// Determine the enhancement instructions based on mode
			let enhancementInstructions = '';
			if (selectedMode === 'enhance') {
				enhancementInstructions = `Enhance and improve this ${fieldName} while maintaining its core style and content. Add more detail, depth, and engaging elements.`;
			} else if (selectedMode === 'expand') {
				enhancementInstructions = `Expand this ${fieldName} with more detail and depth. Elaborate on existing elements and add new relevant information.`;
			} else if (selectedMode === 'rewrite') {
				enhancementInstructions = `Rewrite this ${fieldName} in a fresh way while keeping the essential information. Use different wording and structure while maintaining the core meaning.`;
			}

			// Build character context in the format expected by the backend
			const backendCharacterContext = characterContext ? {
				name: characterContext.name,
				description: characterContext.description,
				personality: characterContext.personality,
				scenario: characterContext.scenario,
				tags: characterContext.tags,
				mes_example: null,
				system_prompt: null,
				depth_prompt: null,
				alternate_greetings: null,
				lorebook_entries: null,
				associated_persona: null
			} : null;

			// Use the dedicated character enhancement API endpoint
			const enhanceResult = await fetch('/api/characters/enhance/field', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				credentials: 'include',
				body: JSON.stringify({
					field: backendFieldName,
					current_content: textToExpand,
					enhancement_instructions: enhancementInstructions,
					character_context: backendCharacterContext,
					generation_options: null
				})
			});

			if (!enhanceResult.ok) {
				const errorText = await enhanceResult.text();
				console.error('Enhancement failed:', errorText);
				toast.error(`Failed to ${selectedMode} ${fieldName}: ${enhanceResult.statusText}`);
				return;
			}

			const enhancementResponse = await enhanceResult.json();
			
			onGenerated(enhancementResponse.enhanced_content);
			toast.success(`${fieldName} ${getModeDescription(selectedMode)} successfully`);
			onOpenChange(false);
			
		} catch (error) {
			console.error('Error in character enhancement:', error);
			toast.error(`Failed to ${selectedMode} ${fieldName}`);
		}
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
		if (fieldName === 'description' && selectedStyle !== 'auto') {
			const styleInfo = descriptionStyles[selectedStyle as keyof typeof descriptionStyles];
			userInput = styleInfo.example;
		} else {
			const fieldConfig = fieldExamples[fieldName as keyof typeof fieldExamples];
			const fieldInfo = fieldConfig && 'default' in fieldConfig ? fieldConfig.default : null;
			if (fieldInfo?.example) {
				userInput = fieldInfo.example;
			}
		}
	}

	// Determine available modes based on context
	let hasContent = $derived(fieldValue && fieldValue.trim().length > 0);
	let canCreate = $derived(true); // Always allow creation
	let canEnhance = $derived(hasContent);

	const modeOptions = $derived.by(() => {
		const options = [];
		if (canCreate) options.push({ value: 'create', label: 'Generate New', icon: Plus });
		if (canEnhance) options.push({ value: 'enhance', label: 'Enhance Existing', icon: Sparkles });
		if (canEnhance) options.push({ value: 'expand', label: 'Expand Detail', icon: Wand });
		if (canEnhance) options.push({ value: 'rewrite', label: 'Rewrite Fresh', icon: RefreshCw });
		return options;
	});
</script>

<Dialog bind:open onOpenChange={onOpenChange}>
	<DialogContent class="sm:max-w-3xl max-h-[90vh] overflow-y-auto">
		<DialogHeader>
			<DialogTitle class="flex items-center gap-2">
				<Bot class="h-5 w-5" />
				AI Assistant - {fieldName}
			</DialogTitle>
			<DialogDescription>
				Use AI to generate or enhance your {fieldName}. Provide as much or as little detail as you want.
			</DialogDescription>
		</DialogHeader>

		{#if showResults}
			<!-- Results View -->
			<div class="space-y-4">
				<div class="rounded-lg border bg-green-50 dark:bg-green-900/20 p-4">
					<div class="flex items-center gap-2 text-green-700 dark:text-green-300 mb-2">
						<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
							<path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
						</svg>
						<h3 class="font-medium">Generation Complete!</h3>
					</div>
					<p class="text-sm text-green-600 dark:text-green-400">
						The {fieldName} has been generated and applied to your character. Click Debug to see detailed information about the generation process, including whether lorebook context was used.
					</p>
				</div>

				{#if lastGenerationResponse?.metadata}
					<div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
						<div class="rounded-lg border p-3">
							<div class="font-medium text-muted-foreground">Tokens Used</div>
							<div class="mt-1 text-lg font-semibold">{lastGenerationResponse.metadata.tokens_used.toLocaleString()}</div>
						</div>
						<div class="rounded-lg border p-3">
							<div class="font-medium text-muted-foreground">Generation Time</div>
							<div class="mt-1 text-lg font-semibold">{lastGenerationResponse.metadata.generation_time_ms}ms</div>
						</div>
						<div class="rounded-lg border p-3">
							<div class="font-medium text-muted-foreground">Style Applied</div>
							<div class="mt-1 text-lg font-semibold capitalize">{lastGenerationResponse.style_used}</div>
						</div>
						<div class="rounded-lg border p-3">
							<div class="font-medium text-muted-foreground">Lorebook Used</div>
							<div class="mt-1 text-lg font-semibold {lastGenerationResponse.metadata.debug_info?.lorebook_context_included ? 'text-green-600' : 'text-orange-600'}">
								{lastGenerationResponse.metadata.debug_info?.lorebook_context_included ? 'Yes' : 'No'}
							</div>
						</div>
					</div>
				{/if}

				{#if lastGenerationResponse?.metadata?.debug_info?.lorebook_context_included}
					<div class="rounded-lg border bg-blue-50 dark:bg-blue-900/20 p-4">
						<div class="flex items-center gap-2 text-blue-700 dark:text-blue-300 mb-2">
							<Info class="h-4 w-4" />
							<h4 class="font-medium">Lorebook Context Found</h4>
						</div>
						<div class="text-sm text-blue-600 dark:text-blue-400 space-y-1">
							<p><strong>Entries Retrieved:</strong> {lastGenerationResponse.metadata.debug_info.lorebook_entries_count || 0}</p>
							{#if lastGenerationResponse.metadata.debug_info.query_text_used}
								<p><strong>Query Used:</strong> "{lastGenerationResponse.metadata.debug_info.query_text_used}"</p>
							{/if}
						</div>
					</div>
				{:else if lastGenerationResponse?.metadata?.debug_info}
					<div class="rounded-lg border bg-orange-50 dark:bg-orange-900/20 p-4">
						<div class="flex items-center gap-2 text-orange-700 dark:text-orange-300 mb-2">
							<Info class="h-4 w-4" />
							<h4 class="font-medium">No Lorebook Context</h4>
						</div>
						<div class="text-sm text-orange-600 dark:text-orange-400">
							{#if lastGenerationResponse.metadata.debug_info.query_text_used}
								<p>Query was sent: "{lastGenerationResponse.metadata.debug_info.query_text_used}" but no relevant entries were found.</p>
							{:else}
								<p>No lorebook was selected or no query was performed.</p>
							{/if}
						</div>
					</div>
				{/if}
			</div>
		{:else}
			<div class="space-y-4">
			<!-- Generation Mode Selection -->
			<div class="grid gap-2">
				<Label>Generation Mode</Label>
				<div class="flex flex-wrap gap-2">
					{#each modeOptions as mode}
						<Button
							variant={selectedMode === mode.value ? "default" : "outline"}
							size="sm"
							onclick={() => selectedMode = mode.value as GenerationMode}
							class="flex items-center gap-1"
						>
							<mode.icon size={14} />
							{mode.label}
						</Button>
					{/each}
				</div>
			</div>

			<!-- Style Selection for Description Field -->
			{#if fieldName === 'description'}
				<div class="grid gap-2">
					<div class="flex items-center justify-between">
						<Label>Description Style</Label>
						{#if userInput.trim().length > 20}
							<Button
								variant="ghost"
								size="sm"
								onclick={() => analyzeStyle(userInput)}
								disabled={isAnalyzingStyle}
								class="text-xs"
							>
								{#if isAnalyzingStyle}
									<svg
										class="h-3 w-3 animate-spin mr-1"
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
									Analyzing...
								{:else}
									<Bot size={12} class="mr-1" />
									Re-analyze Style
								{/if}
							</Button>
						{/if}
					</div>
					<div class="grid gap-3">
						<div class="flex items-center space-x-2">
							<input type="radio" bind:group={selectedStyle} value="auto" id="auto" />
							<Label for="auto" class="font-normal cursor-pointer">
								Auto-detect (Let AI choose based on your input)
							</Label>
						</div>
						{#each Object.entries(descriptionStyles) as [key, style]}
							<div class="flex items-start space-x-2">
								<input type="radio" bind:group={selectedStyle} value={key} id={key} class="mt-1" />
								<Label for={key} class="font-normal cursor-pointer space-y-1">
									<div class="font-medium">{style.name}</div>
									<div class="text-sm text-muted-foreground">{style.description}</div>
								</Label>
							</div>
						{/each}
					</div>
				</div>
			{/if}

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
					placeholder={
						fieldName === 'description' && selectedStyle !== 'auto' 
							? descriptionStyles[selectedStyle as keyof typeof descriptionStyles].example.substring(0, 100) + '...'
							: (() => {
								const fieldConfig = fieldExamples[fieldName as keyof typeof fieldExamples];
								return (fieldConfig && 'default' in fieldConfig ? fieldConfig.default?.placeholder : null) || `Enter your ${fieldName} content...`;
							})()
					}
					rows={8}
					class="resize-none font-mono text-sm"
				/>
				{#if selectedMode === 'create'}
					<p class="text-sm text-muted-foreground">
						Describe what kind of {fieldName} you want. The AI will create detailed content based on your input
						{fieldName === 'description' && selectedStyle !== 'auto' ? ` in the ${descriptionStyles[selectedStyle as keyof typeof descriptionStyles].name} style` : ''}.
					</p>
				{:else}
					<p class="text-sm text-muted-foreground">
						The AI will {getModeDescription(selectedMode).replace('ed', '')} the text above into a more detailed {fieldName}.
					</p>
				{/if}
			</div>

			<!-- Style Example Preview (for descriptions) -->
			{#if fieldName === 'description' && selectedStyle !== 'auto'}
				<div class="grid gap-2">
					<div class="flex items-center gap-2">
						<Info size={16} />
						<Label>Style Example</Label>
					</div>
					<div class="rounded-md bg-muted p-3 text-sm font-mono max-h-32 overflow-y-auto">
						{descriptionStyles[selectedStyle as keyof typeof descriptionStyles].example}
					</div>
				</div>
			{/if}

			<!-- Current Content Preview (if enhancing) -->
			{#if hasContent && selectedMode !== 'create'}
				<div class="grid gap-2">
					<Label>Current Content</Label>
					<div class="rounded-md bg-muted p-3 text-sm max-h-32 overflow-y-auto">
						{fieldValue}
					</div>
				</div>
			{/if}
		</div>
		{/if}

		<DialogFooter>
			{#if showResults}
				<!-- Results Footer -->
				<div class="flex items-center justify-between w-full">
					<div class="flex gap-2">
						<Button 
							variant="outline" 
							onclick={() => showDebugModal = true}
							class="gap-2"
							title="View generation debug info"
						>
							<Bug size={14} />
							View Debug Info
						</Button>
					</div>
					<div class="flex gap-2">
						<Button 
							variant="outline" 
							onclick={() => {
								showResults = false;
								userInput = ''; // Reset input for new generation
							}}
							class="gap-2"
						>
							<RefreshCw size={14} />
							Generate Another
						</Button>
						<Button onclick={() => onOpenChange(false)}>
							Done
						</Button>
					</div>
				</div>
			{:else}
				<!-- Generation Footer -->
				<div class="flex items-center justify-between w-full">
					<div class="flex gap-2">
						<Button variant="outline" onclick={() => onOpenChange(false)} disabled={isGenerating}>
							Cancel
						</Button>
						{#if lastGenerationResponse}
							<Button 
								variant="outline" 
								size="sm"
								onclick={() => showDebugModal = true}
								class="gap-2"
								title="View generation debug info"
							>
								<Bug size={14} />
								Debug
							</Button>
						{/if}
					</div>
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
				</div>
			{/if}
		</DialogFooter>
	</DialogContent>
</Dialog>

<!-- Debug Modal -->
<CharacterGenerationDebugModal
	bind:open={showDebugModal}
	generationResponse={lastGenerationResponse}
/>