<script lang="ts">
	import { Button as ButtonComponent } from './ui/button';
	import { Input as _InputComponent } from './ui/input';
	import { Label } from './ui/label';
	import { Textarea as TextareaComponent } from './ui/textarea';
	import { Slider } from './ui/slider';
	import { Checkbox } from './ui/checkbox';
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
	import {
		Bot,
		Sparkles,
		Wand,
		RefreshCw,
		Plus,
		FileText,
		Info,
		Bug,
		Copy,
		Check
	} from 'lucide-svelte';
	import { apiClient as _apiClient } from '$lib/api';
	import type {
		GenerationMode,
		CharacterContext,
		GenerateCharacterFieldResponse,
		DescriptionStyle
	} from '$lib/types';
	import CharacterGenerationDebugModal from './character-generation-debug-modal.svelte';
	import {
		getRecommendedStyle,
		getRecommendedMaxTokens,
		isModeSupported,
		getAvailableStyles,
		sanitizeAIOutput
	} from '$lib/utils/ai-generation-helpers';

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
	let maxTokensArray = $state([2000]);
	let includeStatusBlock = $state(false);
	let isAnalyzingStyle = $state(false);
	let lastGenerationResponse = $state<GenerateCharacterFieldResponse | null>(null);
	let showDebugModal = $state(false);
	let showResults = $state(false);
	let copied = $state(false);
	let streamedContent = $state('');
	let isStreamingActive = $state(false);
	let error = $state<string | null>(null);

	// Derive maxTokens from array (sliders use arrays for multiple thumbs)
	let maxTokens = $derived(maxTokensArray[0]);
	// Approximate word count (tokens * 0.75)
	let approximateWords = $derived(Math.round(maxTokens * 0.75));

	// Status block makes sense for instruction fields AND example messages
	let showStatusBlockOption = $derived(
		fieldName === 'description' ||
			fieldName === 'system_prompt' ||
			fieldName === 'depth_prompt' ||
			fieldName === 'mes_example'
	);

	// Different handling for mes_example vs instruction fields
	let isExampleField = $derived(fieldName === 'mes_example');

	// Smart defaults: Auto-select recommended style and token limits when field changes
	$effect(() => {
		if (fieldName) {
			selectedStyle = getRecommendedStyle(fieldName);
			const recommendedTokens = getRecommendedMaxTokens(fieldName);
			maxTokensArray = [recommendedTokens];
		}
	});

	// Reset input when dialog opens/closes
	$effect(() => {
		if (open) {
			userInput = fieldValue || '';
			// Don't override smart defaults - they were set by the effect above

			// Async style detection if there's existing content (can override smart default)
			if (fieldValue && fieldValue.trim().length > 20) {
				analyzeStyle(fieldValue);
			}
		} else {
			// Reset debug modal when main dialog closes
			showDebugModal = false;
			showResults = false;
			error = null;
		}
	});

	// Different description styles with examples and prompts
	const descriptionStyles = {
		traits: {
			name: 'Character Traits',
			description: 'Brief, punchy traits and physical characteristics',
			example:
				"Tall. Lean build. Silver hair, piercing green eyes. Former military sniper. Calm under pressure. Doesn't talk much. Prefers action over words. Methodical. Patient. Excellent marksman. Haunted by past missions. Drinks black coffee. Wears dark clothing. Struggles with close relationships. Protective of civilians. Dry sense of humor. Always alert. Sleeps light. Carries multiple knives. Efficient killer when necessary.",
			prompt:
				'Create a character description using short, punchy sentences. Focus on physical appearance, personality traits, relationships, and behavioral patterns. Use fragments and brief statements. Avoid flowery language or extensive narrative.'
		},
		narrative: {
			name: 'Narrative Description',
			description: 'Story-like description with background and context',
			example:
				'Captain Elena Vasquez stands at the helm of her merchant vessel, weathered hands gripping the wheel as storm clouds gather on the horizon. Twenty years of sailing treacherous waters have carved lines of determination into her sun-bronzed face, while her steel-gray eyes reflect the wisdom earned through countless adventures. Once a naval officer, she abandoned her commission after witnessing corruption in the admiralty, choosing instead the uncertain freedom of independent trade. Her crew respects her fair leadership and tactical brilliance, though few know of the treasure map hidden in her cabin or the mysterious benefactor funding her expeditions.',
			prompt:
				'Create a narrative character description that tells a story. Include background, motivations, appearance woven into the narrative, and personality shown through context. Write in flowing paragraphs with complete sentences.'
		},
		profile: {
			name: 'Profile Format',
			description: 'Organized data fields with biographical information and measurements',
			example:
				'Name: Dr. Marcus Chen\nAge: 34\nOccupation: Xenobiologist and Deep Space Explorer\nHeight: 6\'1"\nWeight: 175 lbs\nHair: Black, always slightly messy\nEyes: Dark brown behind wire-rimmed glasses\nBuild: Tall and lanky, with calloused hands from fieldwork\nPersonality: Brilliant, absent-minded, passionate about discovery, socially awkward but kind-hearted\nBackground: Born on Luna Colony, lost his parents in a mining accident at age 12. Raised by his grandfather, a renowned botanist. Devoted his life to studying alien ecosystems after discovering bioluminescent fungi on Europa. Has a pet lab rat named Newton.',
			prompt:
				"Create a structured character profile using organized data fields (Name:, Age:, Height:, etc.) followed by personality and background. Include specific measurements and physical attributes when relevant. Use clear field labels and consistent formatting. {{char}} refers to the character's name, {{user}} refers to the user/player."
		},
		group: {
			name: 'Group Characters',
			description: 'Multiple character definitions with Characters() format',
			example:
				'{{char}} is the crew of the starship Nebula\'s Edge, a ragtag team of space salvagers.\nCharacters("Captain Zara, Chief Engineer Bolt, Navigator Iris")\nCaptain Zara("A former pirate turned legitimate salvager. Fiery red hair, cybernetic left arm, sharp tongue. Excellent pilot and negotiator. Haunted by her criminal past but fiercely loyal to her crew.")\nChief Engineer Bolt("A gruff, bearded engineer who can fix anything with spare parts and determination. Missing his right leg from a reactor explosion. Drinks too much but never when on duty. Protective father figure to the crew.")\nNavigator Iris("A young prodigy with enhanced neural implants for calculating hyperspace jumps. Quiet and analytical, but has moments of surprising insight. Joined the crew to escape corporate espionage charges.")',
			prompt:
				"Create a group character definition starting with 'Characters()' listing all names, then define each character using their name as a function. Include detailed descriptions for each character, their relationships, and the group setting. Focus on how the characters interact as a team. {{char}} refers to the group, {{user}} refers to the player."
		},
		worldbuilding: {
			name: 'World-Building/Lore',
			description: 'Rich world context with character as part of larger narrative universe',
			example:
				"{{char}} is a Guardian of the Stellar Nexus, one of the ancient beings who maintain the cosmic balance between the seven dimensional realms. In the current age known as the Twilight Convergence, the barriers between dimensions have grown thin, allowing creatures and energies to bleed through. {{char}} serves as both protector and guide, wielding the power of stellar manipulation to seal rifts and defend inhabited worlds. The Nexus Council has tasked {{char}} with monitoring Earth, a primitive world that has unknowingly become a focal point for interdimensional instability due to humanity's rapid technological advancement.",
			prompt:
				"Create a world-building description that establishes the character as part of a larger fictional universe. Include world lore, power systems, historical context, and the character's role in the greater narrative. Focus on immersive world-building rather than behavioral instructions. {{char}} will be replaced with the character's name, {{user}} with the player's name."
		},
		system: {
			name: 'System',
			description: 'Behavioral rules and interaction guidelines for AI roleplay',
			example:
				"{{char}} is an adaptive survival simulation that responds to {{user}}'s choices in a post-apocalyptic wasteland. {{char}} will generate random encounters, manage resource scarcity, and track {{user}}'s health, hunger, and sanity levels. {{char}} will describe the harsh environment in vivid detail and present meaningful choices with consequences. {{char}} will never guarantee {{user}}'s safety - death is a real possibility based on poor decisions. {{char}} will maintain an atmosphere of tension and uncertainty while allowing {{user}} complete freedom to explore, fight, hide, or attempt to rebuild civilization. {{char}} will not make decisions for {{user}} or assume their actions.",
			prompt:
				"Create behavioral instructions for an AI character. Define what the character will and won't do, their response patterns, content boundaries, narrative perspective, and interaction rules. Can cover individual character behavior or complex system/game master mechanics. {{char}} will be replaced with the character's name, {{user}} with the player's name."
		}
	};

	// Enhanced field examples for non-description fields
	const fieldExamples = {
		description: descriptionStyles,
		personality: {
			default: {
				placeholder: "e.g., 'Sarcastic but caring, distrustful but loyal'",
				example:
					'Cynical and sharp-tongued on the surface, but deeply compassionate underneath. Uses humor as a defense mechanism. Fiercely loyal to those who earn their trust, but takes time to open up. Has a strong sense of justice and cannot stand bullies or corruption. Often acts tough to hide vulnerability.',
				prompt:
					'Develop character personality traits, quirks, strengths, and flaws that make them feel real and three-dimensional.'
			}
		},
		first_mes: {
			default: {
				placeholder: "e.g., 'The detective looks up from their case files'",
				example:
					'*The detective glances up from a stack of case files, coffee growing cold in a chipped mug. Rain patters against the precinct window as they notice you approach.* "Another long night ahead. What brings you to my corner of this chaos?" *They gesture to an empty chair across from their cluttered desk, eyes already assessing you with professional interest.*',
				prompt:
					'Create an engaging first message that establishes the scene, character voice, and invites interaction. Use a mix of narration (in asterisks) and dialogue.'
			}
		},
		scenario: {
			default: {
				placeholder: "e.g., 'A gritty urban police precinct during night shift'",
				example:
					'The setting is a busy metropolitan police precinct during the graveyard shift. The detective works in a cramped office filled with case files, evidence bags, and cold coffee. Outside, the city never sleeps - sirens wail in the distance, neon signs flicker through rain-streaked windows, and the constant hum of urban life provides a backdrop to their investigations.',
				prompt:
					'Establish the setting, atmosphere, and context where interactions with this character take place.'
			}
		},
		mes_example: {
			default: {
				placeholder: "e.g., 'How the character typically speaks'",
				example:
					"{{char}}: *Leans back in chair, studying the evidence board* \"Three victims, all with the same MO. Either we've got a serial on our hands, or someone's very good at making it look that way.\"\n\n{{user}}: What's your theory?\n\n{{char}}: *Taps pen against temple* \"My gut says personal. Too clean, too methodical. This isn't random violence - someone's settling scores. Question is, what connects our vics that we haven't found yet?\"",
				prompt:
					'Show how the character speaks and interacts through realistic dialogue examples. Use {{char}} and {{user}} placeholders.'
			}
		},
		system_prompt: {
			default: {
				placeholder: "e.g., 'Instructions for AI behavior'",
				example:
					'You are a seasoned detective character. Maintain a professional but slightly cynical tone. Use detective/police terminology naturally. Show investigative thinking through your responses. Balance toughness with underlying compassion. Avoid being overly dramatic - keep responses grounded and realistic.',
				prompt: 'Create clear instructions that guide how the AI should portray this character.'
			}
		},
		depth_prompt: {
			default: {
				placeholder: "e.g., 'Always remember this character is...'",
				example:
					'This character carries the weight of an unsolved case involving a missing child from five years ago. It drives their determination and makes them particularly protective of vulnerable victims. They have a habit of working late into the night, often missing meals, and keep a photo of the missing child tucked in their case file as a reminder of why the work matters.',
				prompt:
					'Add depth with backstory, motivations, or character details that should influence all interactions.'
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
				toast.success(
					`AI detected style: ${descriptionStyles[detectedStyle as keyof typeof descriptionStyles]?.name || detectedStyle}`
				);
			}
		} catch (_error) {
			console.warn('Error in style analysis:', _error);
			toast.error('Failed to analyze style');
		} finally {
			isAnalyzingStyle = false;
		}
	}

	async function detectDescriptionStyle(text: string): Promise<string> {
		if (!text || text.trim().length < 20) return 'auto';

		try {
			// Use the new structured output endpoint for reliable style detection
			const result = await _apiClient.analyzeStyle(text);

			if (result.isOk()) {
				const analysis = result.value;

				// Map backend style to frontend style string
				// Backend returns: traits, narrative, profile, group, worldbuilding, system
				// We need to handle 'system' as 'behavioral' for backward compatibility
				const styleMap: Record<string, string> = {
					traits: 'traits',
					narrative: 'narrative',
					profile: 'profile',
					group: 'group',
					worldbuilding: 'worldbuilding',
					system: 'behavioral' // Backend "system" maps to frontend "behavioral"
				};

				return styleMap[analysis.detected_style] || analysis.detected_style;
			} else {
				console.warn('Style analysis failed:', result.error);
				return 'auto';
			}
		} catch (_error) {
			console.warn('Error in AI style detection:', _error);
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
		} catch (_error) {
			console.error('Error in AI generation:', _error);
			toast.error('An error occurred while generating content');
		} finally {
			isGenerating = false;
		}
	}

	async function generateFromScratch() {
		try {
			// Build user prompt
			let userPrompt =
				userInput.trim() ||
				`Generate a ${fieldName} for a character: ${characterContext?.name || 'new character'}`;

			// Add status block instructions if checkbox is enabled
			if (includeStatusBlock && showStatusBlockOption) {
				if (isExampleField) {
					// For mes_example: generate examples that INCLUDE status blocks
					const statusBlockExampleInstructions = `

IMPORTANT: Each conversation example should end with {{char}} displaying a status block wrapped in triple backticks (\`\`\`).

The status block should:
- Be wrapped in triple backticks (three backtick characters before and after)
- Track relevant game state (health, location, inventory, stats, objectives, etc.)
- Be contextually appropriate for this character/setting
- Update between conversation examples to show state changes

Example format for EACH conversation example:
<START>
{{char}}: "Dialogue..." *Action.*
{{user}}: "Response..."
{{char}}: "Reply..." *Action.*

\`\`\`
[Status fields here - health, location, inventory, stats, etc.]
\`\`\`

Make sure EVERY conversation example ends with a status block in triple backticks.`;
					userPrompt += statusBlockExampleInstructions;
				} else {
					// For instruction fields: generate instructions ABOUT status blocks
					const statusBlockInstructions = `

IMPORTANT: Generate instructions that tell the AI to include a status block at the end of every response.

The instructions you write MUST specify that the status block should be wrapped in triple backticks (three backtick characters: \`\`\`).

Example of what you should generate:
"{{char}} will always end each response with a status block wrapped in triple backticks. The format is:

\`\`\`
[Define specific status fields here - health, location, inventory, stats, objectives, etc.]
\`\`\`

The status block must use triple backticks for proper formatting."

Key requirements:
- Explicitly mention triple backticks in your instructions
- Define specific status fields contextually appropriate to this setting
- Specify that the block updates dynamically based on roleplay events
- The status block should be formatted consistently for easy parsing

NOTE: Since the AI cannot perform true dice rolls, if game mechanics require randomness, specify that outcomes will be narratively simulated based on stats and circumstances.

DO NOT generate an actual status block in your output - only generate the INSTRUCTIONS about how the status block should work.`;
					userPrompt += statusBlockInstructions;
				}
			}

			// Build character context - use the same format, no need to transform
			const context = characterContext
				? {
						name: characterContext.name,
						description: characterContext.description,
						personality: characterContext.personality,
						scenario: characterContext.scenario,
						first_mes: characterContext.first_mes,
						tags: characterContext.tags,
						mes_example: characterContext.mes_example,
						system_prompt: characterContext.system_prompt,
						depth_prompt: characterContext.depth_prompt,
						alternate_greetings: characterContext.alternate_greetings,
						lorebook_entries: characterContext.lorebook_entries,
						associated_persona: characterContext.associated_persona,
						selectedLorebooks: characterContext.selectedLorebooks
					}
				: undefined;

			// Use streaming API
			streamedContent = '';
			isStreamingActive = true;
			showResults = true; // Show results view immediately to display streaming

			try {
				const stream = _apiClient.generateCharacterFieldStream({
					fieldName: fieldName,
					fieldValue: undefined, // No existing content for "create" mode
					characterContext: context,
					mode: selectedMode,
					style: selectedStyle !== 'auto' ? (selectedStyle as DescriptionStyle) : undefined,
					maxTokens: maxTokens,
					userPrompt: userPrompt
				});

				// Iterate through the stream chunks
				for await (const chunk of stream) {
					// Type guard to check if this is a final response with metadata
					if ('metadata' in chunk && chunk.metadata) {
						// Final chunk with metadata - sanitize the content
						const sanitizedContent = sanitizeAIOutput(streamedContent || chunk.content);
						const generationResponse: GenerateCharacterFieldResponse = {
							content: sanitizedContent,
							style_used: selectedStyle !== 'auto' ? selectedStyle : 'auto',
							metadata: chunk.metadata
						};

						lastGenerationResponse = generationResponse;
						onGenerated(sanitizedContent);
						toast.success(`${fieldName} generated successfully - Click Debug to see details`);
					} else if ('done' in chunk && !chunk.done && chunk.content) {
						// Streaming chunk - accumulate content (raw, unsanitized during streaming)
						streamedContent += chunk.content;
					} else if ('done' in chunk && chunk.done) {
						// Final chunk without metadata (shouldn't normally happen, but handle gracefully)
						streamedContent += chunk.content;
					}
				}
			} catch (err) {
				console.error('Streaming generation failed:', err);
				error = err instanceof Error ? err.message : 'Failed to generate content';
				toast.error(`Failed to generate ${fieldName}`);
				showResults = false;
			} finally {
				isStreamingActive = false;
			}
		} catch (_error) {
			console.error('Error in character generation:', _error);
			toast.error(`Failed to generate ${fieldName}`);
		}
	}

	async function expandExistingText() {
		try {
			const textToExpand = userInput.trim() || fieldValue;

			// Determine the user prompt based on mode
			let userPrompt = '';
			if (selectedMode === 'enhance') {
				userPrompt = `Enhance and improve this ${fieldName} while maintaining its core style and content. Add more detail, depth, and engaging elements.`;
			} else if (selectedMode === 'expand') {
				userPrompt = `Expand this ${fieldName} with more detail and depth. Elaborate on existing elements and add new relevant information.`;
			} else if (selectedMode === 'rewrite') {
				userPrompt = `Rewrite this ${fieldName} in a fresh way while keeping the essential information. Use different wording and structure while maintaining the core meaning.`;
			}

			// Add status block instructions if checkbox is enabled
			if (includeStatusBlock && showStatusBlockOption) {
				if (isExampleField) {
					// For mes_example: generate examples that INCLUDE status blocks
					const statusBlockExampleInstructions = `

IMPORTANT: Each conversation example should end with {{char}} displaying a status block wrapped in triple backticks (\`\`\`).

The status block should:
- Be wrapped in triple backticks (three backtick characters before and after)
- Track relevant game state (health, location, inventory, stats, objectives, etc.)
- Be contextually appropriate for this character/setting
- Update between conversation examples to show state changes

Example format for EACH conversation example:
<START>
{{char}}: "Dialogue..." *Action.*
{{user}}: "Response..."
{{char}}: "Reply..." *Action.*

\`\`\`
[Status fields here - health, location, inventory, stats, etc.]
\`\`\`

Make sure EVERY conversation example ends with a status block in triple backticks.`;
					userPrompt += statusBlockExampleInstructions;
				} else {
					// For instruction fields: generate instructions ABOUT status blocks
					const statusBlockInstructions = `

IMPORTANT: Generate instructions that tell the AI to include a status block at the end of every response.

The instructions you write MUST specify that the status block should be wrapped in triple backticks (three backtick characters: \`\`\`).

Example of what you should generate:
"{{char}} will always end each response with a status block wrapped in triple backticks. The format is:

\`\`\`
[Define specific status fields here - health, location, inventory, stats, objectives, etc.]
\`\`\`

The status block must use triple backticks for proper formatting."

Key requirements:
- Explicitly mention triple backticks in your instructions
- Define specific status fields contextually appropriate to this setting
- Specify that the block updates dynamically based on roleplay events
- The status block should be formatted consistently for easy parsing

NOTE: Since the AI cannot perform true dice rolls, if game mechanics require randomness, specify that outcomes will be narratively simulated based on stats and circumstances.

DO NOT generate an actual status block in your output - only generate the INSTRUCTIONS about how the status block should work.`;
					userPrompt += statusBlockInstructions;
				}
			}

			// Build character context
			const context = characterContext
				? {
						name: characterContext.name,
						description: characterContext.description,
						personality: characterContext.personality,
						scenario: characterContext.scenario,
						first_mes: characterContext.first_mes,
						tags: characterContext.tags,
						mes_example: characterContext.mes_example,
						system_prompt: characterContext.system_prompt,
						depth_prompt: characterContext.depth_prompt,
						alternate_greetings: characterContext.alternate_greetings,
						lorebook_entries: characterContext.lorebook_entries,
						associated_persona: characterContext.associated_persona,
						selectedLorebooks: characterContext.selectedLorebooks
					}
				: undefined;

			// Use streaming API
			streamedContent = '';
			isStreamingActive = true;
			showResults = true; // Show results view immediately to display streaming

			try {
				const stream = _apiClient.generateCharacterFieldStream({
					fieldName: fieldName,
					fieldValue: textToExpand, // Existing content to enhance/expand/rewrite
					characterContext: context,
					mode: selectedMode,
					style: selectedStyle !== 'auto' ? (selectedStyle as DescriptionStyle) : undefined,
					maxTokens: maxTokens,
					userPrompt: userPrompt
				});

				// Iterate through the stream chunks
				for await (const chunk of stream) {
					// Type guard to check if this is a final response with metadata
					if ('metadata' in chunk && chunk.metadata) {
						// Final chunk with metadata - sanitize the content
						const sanitizedContent = sanitizeAIOutput(streamedContent || chunk.content);
						const generationResponse: GenerateCharacterFieldResponse = {
							content: sanitizedContent,
							style_used: selectedStyle !== 'auto' ? selectedStyle : 'auto',
							metadata: chunk.metadata
						};

						lastGenerationResponse = generationResponse;
						onGenerated(sanitizedContent);
						toast.success(`${fieldName} ${getModeDescription(selectedMode)} successfully`);
					} else if ('done' in chunk && !chunk.done && chunk.content) {
						// Streaming chunk - accumulate content (raw, unsanitized during streaming)
						streamedContent += chunk.content;
					} else if ('done' in chunk && chunk.done) {
						// Final chunk without metadata (shouldn't normally happen, but handle gracefully)
						streamedContent += chunk.content;
					}
				}
			} catch (err) {
				console.error('Streaming enhancement failed:', err);
				error = err instanceof Error ? err.message : 'Failed to enhance content';
				toast.error(`Failed to ${selectedMode} ${fieldName}`);
				showResults = false;
			} finally {
				isStreamingActive = false;
			}
		} catch (_error) {
			console.error('Error in character enhancement:', _error);
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

	async function copyToClipboard() {
		const content = lastGenerationResponse?.content;
		if (!content) return;

		try {
			await navigator.clipboard.writeText(content);
			copied = true;
			setTimeout(() => (copied = false), 2000);
			toast.success('Copied to clipboard!');
		} catch (_error) {
			console.error('Failed to copy:', _error);
			toast.error('Failed to copy to clipboard');
		}
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

	// Mode options with descriptions
	const allModeOptions = [
		{
			value: 'create' as GenerationMode,
			label: 'Generate New',
			description: 'Generate new content from scratch',
			icon: Plus
		},
		{
			value: 'enhance' as GenerationMode,
			label: 'Enhance Existing',
			description: 'Improve existing content',
			icon: Sparkles
		},
		{
			value: 'expand' as GenerationMode,
			label: 'Expand Detail',
			description: 'Add more detail and depth',
			icon: Wand
		},
		{
			value: 'rewrite' as GenerationMode,
			label: 'Rewrite Fresh',
			description: 'Rewrite with fresh perspective',
			icon: RefreshCw
		}
	];

	// Filter modes based on field compatibility and content availability
	let hasContent = $derived(fieldValue && fieldValue.trim().length > 0);

	const modeOptions = $derived.by(() => {
		return allModeOptions.filter((mode) => {
			// Check if mode is supported for this field
			if (!isModeSupported(fieldName, mode.value)) {
				return false;
			}

			// Create is always available
			if (mode.value === 'create') {
				return true;
			}

			// Other modes require existing content
			return hasContent;
		});
	});

	// Get available styles for this field
	const availableStyleOptions = $derived.by(() => {
		const allowedStyles = getAvailableStyles(fieldName);
		const styleLabels: Record<string, string> = {
			auto: 'Auto (recommended)',
			traits: 'Traits (comma-separated)',
			narrative: 'Narrative (flowing prose)',
			profile: 'Profile (structured)',
			group: 'Group (team dynamics)',
			worldbuilding: 'Worldbuilding (setting context)',
			system: 'System (technical)'
		};

		return allowedStyles.map((style) => ({
			value: style,
			label: styleLabels[style] || style
		}));
	});
</script>

<Dialog bind:open {onOpenChange}>
	<DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-3xl">
		<DialogHeader>
			<DialogTitle class="flex items-center gap-2">
				<Bot class="h-5 w-5" />
				AI Assistant - {fieldName}
			</DialogTitle>
			<DialogDescription>
				Use AI to generate or enhance your {fieldName}. Provide as much or as little detail as you
				want.
			</DialogDescription>
		</DialogHeader>

		{#if showResults}
			<!-- Results View -->
			<div class="space-y-4">
				{#if isStreamingActive}
					<div class="rounded-lg border bg-blue-50 p-4 dark:bg-blue-900/20">
						<div class="mb-2 flex items-center gap-2 text-blue-700 dark:text-blue-300">
							<div class="h-5 w-5 animate-pulse rounded-full bg-blue-500"></div>
							<h3 class="font-medium">Generating...</h3>
						</div>
						<p class="text-sm text-blue-600 dark:text-blue-400">
							AI is generating your {fieldName} in real-time. Watch the content appear below as it's
							being created.
						</p>
					</div>
				{:else}
					<div class="rounded-lg border bg-green-50 p-4 dark:bg-green-900/20">
						<div class="mb-2 flex items-center gap-2 text-green-700 dark:text-green-300">
							<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
								<path
									fill-rule="evenodd"
									d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
									clip-rule="evenodd"
								></path>
							</svg>
							<h3 class="font-medium">Generation Complete!</h3>
						</div>
						<p class="text-sm text-green-600 dark:text-green-400">
							The {fieldName} has been generated and applied to your character. Click Debug to see detailed
							information about the generation process, including whether lorebook context was used.
						</p>
					</div>
				{/if}

				{#if !isStreamingActive && lastGenerationResponse?.metadata}
					<div class="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
						<div class="rounded-lg border p-3">
							<div class="font-medium text-muted-foreground">Tokens Used</div>
							<div class="mt-1 text-lg font-semibold">
								{(lastGenerationResponse.metadata.tokens_used ?? 0).toLocaleString()}
							</div>
						</div>
						<div class="rounded-lg border p-3">
							<div class="font-medium text-muted-foreground">Generation Time</div>
							<div class="mt-1 text-lg font-semibold">
								{lastGenerationResponse.metadata.generation_time_ms ?? 0}ms
							</div>
						</div>
						<div class="rounded-lg border p-3">
							<div class="font-medium text-muted-foreground">Style Applied</div>
							<div class="mt-1 text-lg font-semibold capitalize">
								{lastGenerationResponse.style_used ?? 'auto'}
							</div>
						</div>
						<div class="rounded-lg border p-3">
							<div class="font-medium text-muted-foreground">Lorebook Used</div>
							<div
								class="mt-1 text-lg font-semibold {lastGenerationResponse.metadata.debug_info
									?.lorebook_context_included
									? 'text-green-600'
									: 'text-orange-600'}"
							>
								{lastGenerationResponse.metadata.debug_info?.lorebook_context_included
									? 'Yes'
									: 'No'}
							</div>
						</div>
					</div>
				{/if}

				{#if lastGenerationResponse?.metadata?.debug_info?.lorebook_context_included}
					<div class="rounded-lg border bg-blue-50 p-4 dark:bg-blue-900/20">
						<div class="mb-2 flex items-center gap-2 text-blue-700 dark:text-blue-300">
							<Info class="h-4 w-4" />
							<h4 class="font-medium">Lorebook Context Found</h4>
						</div>
						<div class="space-y-1 text-sm text-blue-600 dark:text-blue-400">
							<p>
								<strong>Entries Retrieved:</strong>
								{lastGenerationResponse.metadata.debug_info.lorebook_entries_count || 0}
							</p>
							{#if lastGenerationResponse.metadata.debug_info.query_text_used}
								<p>
									<strong>Query Used:</strong> "{lastGenerationResponse.metadata.debug_info
										.query_text_used}"
								</p>
							{/if}
						</div>
					</div>
				{:else if lastGenerationResponse?.metadata?.debug_info}
					<div class="rounded-lg border bg-orange-50 p-4 dark:bg-orange-900/20">
						<div class="mb-2 flex items-center gap-2 text-orange-700 dark:text-orange-300">
							<Info class="h-4 w-4" />
							<h4 class="font-medium">No Lorebook Context</h4>
						</div>
						<div class="text-sm text-orange-600 dark:text-orange-400">
							{#if lastGenerationResponse.metadata.debug_info.query_text_used}
								<p>
									Query was sent: "{lastGenerationResponse.metadata.debug_info.query_text_used}" but
									no relevant entries were found.
								</p>
							{:else}
								<p>No lorebook was selected or no query was performed.</p>
							{/if}
						</div>
					</div>
				{/if}

				<!-- Generated Content Display -->
				{#if isStreamingActive || lastGenerationResponse?.content}
					<div class="space-y-2">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								<Label>Generated Content</Label>
								{#if isStreamingActive}
									<div class="flex items-center gap-1 text-xs text-muted-foreground">
										<div class="h-2 w-2 animate-pulse rounded-full bg-blue-500"></div>
										Streaming...
									</div>
								{/if}
							</div>
							<ButtonComponent
								size="sm"
								variant="ghost"
								onclick={copyToClipboard}
								disabled={isStreamingActive}
							>
								{#if copied}
									<Check class="mr-1 h-4 w-4" />
									Copied
								{:else}
									<Copy class="mr-1 h-4 w-4" />
									Copy
								{/if}
							</ButtonComponent>
						</div>
						<div
							class="max-h-96 overflow-y-auto whitespace-pre-wrap rounded-md border bg-background p-4 text-sm"
						>
							{isStreamingActive ? streamedContent : lastGenerationResponse?.content || ''}
						</div>
					</div>
				{/if}
			</div>
		{:else}
			<div class="space-y-4">
				<!-- Generation Mode Selection -->
				<div class="grid gap-2">
					<Label>Generation Mode</Label>
					<div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
						{#each modeOptions as mode}
							<button
								type="button"
								class="rounded-md border-2 p-3 text-left transition-colors {selectedMode ===
								mode.value
									? 'border-primary bg-primary/10'
									: 'border-border hover:border-primary/50'}"
								onclick={() => (selectedMode = mode.value)}
							>
								<div class="flex items-center gap-2 font-semibold">
									<mode.icon size={16} />
									{mode.label}
								</div>
								<div class="mt-1 text-sm text-muted-foreground">{mode.description}</div>
							</button>
						{/each}
					</div>
				</div>

				<!-- Style Selection -->
				{#if availableStyleOptions.length > 1}
					<div class="space-y-2">
						<div class="flex items-center justify-between">
							<Label for="style">Content Style</Label>
							{#if fieldName === 'description' && userInput.trim().length > 20}
								<ButtonComponent
									variant="ghost"
									size="sm"
									onclick={() => analyzeStyle(userInput)}
									disabled={isAnalyzingStyle}
									class="text-xs"
								>
									{#if isAnalyzingStyle}
										<svg
											class="mr-1 h-3 w-3 animate-spin"
											xmlns="http://www.w3.org/2000/svg"
											fill="none"
											viewBox="0 0 24 24"
										>
											<circle
												class="opacity-25"
												cx="12"
												cy="12"
												r="10"
												stroke="currentColor"
												stroke-width="4"
											></circle>
											<path
												class="opacity-75"
												fill="currentColor"
												d="M4 12a8 8 0 0 1 8 -8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 0 1 4 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
											></path>
										</svg>
										Analyzing...
									{:else}
										<Bot size={12} class="mr-1" />
										Re-analyze Style
									{/if}
								</ButtonComponent>
							{/if}
						</div>
						<select
							id="style"
							class="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
							bind:value={selectedStyle}
						>
							{#each availableStyleOptions as styleOption (styleOption.value)}
								<option value={styleOption.value}>{styleOption.label}</option>
							{/each}
						</select>
					</div>
				{/if}

				<!-- Status Block Checkbox -->
				{#if showStatusBlockOption}
					<div class="flex items-center space-x-2">
						<Checkbox id="status-block" bind:checked={includeStatusBlock} />
						<Label
							for="status-block"
							class="cursor-pointer text-sm font-normal leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
						>
							{#if isExampleField}
								Include status blocks in conversation examples (for RPG/system cards)
							{:else}
								Include status block instructions (for RPG/system cards)
							{/if}
						</Label>
					</div>
				{/if}

				<!-- Token Slider Control -->
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<Label for="token-limit">Generation Length</Label>
						<span class="text-sm text-muted-foreground">
							{maxTokens} tokens (~{approximateWords} words)
						</span>
					</div>
					<Slider
						type="multiple"
						min={500}
						max={5000}
						step={100}
						bind:value={maxTokensArray}
						class="w-full"
					/>
					<div class="flex justify-between text-xs text-muted-foreground">
						<span>Short (500)</span>
						<span>Medium (2500)</span>
						<span>Long (5000)</span>
					</div>
				</div>

				<!-- Error Display -->
				{#if error}
					<div
						class="rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive"
					>
						{error}
					</div>
				{/if}

				<!-- User Input -->
				<div class="grid gap-2">
					<div class="flex items-center justify-between">
						<Label for="user-input">
							{selectedMode === 'create' ? 'Describe what you want' : 'Text to enhance'}
						</Label>
						<ButtonComponent variant="ghost" size="sm" onclick={insertExample} class="text-xs">
							<FileText size={12} class="mr-1" />
							Show Example
						</ButtonComponent>
					</div>
					<TextareaComponent
						id="user-input"
						bind:value={userInput}
						placeholder={fieldName === 'description' && selectedStyle !== 'auto'
							? descriptionStyles[
									selectedStyle as keyof typeof descriptionStyles
								].example.substring(0, 100) + '...'
							: (() => {
									const fieldConfig = fieldExamples[fieldName as keyof typeof fieldExamples];
									return (
										(fieldConfig && 'default' in fieldConfig
											? fieldConfig.default?.placeholder
											: null) || `Enter your ${fieldName} content...`
									);
								})()}
						rows={8}
						class="resize-none font-mono text-sm"
					/>
					{#if selectedMode === 'create'}
						<p class="text-sm text-muted-foreground">
							Describe what kind of {fieldName} you want. The AI will create detailed content based on
							your input
							{fieldName === 'description' && selectedStyle !== 'auto'
								? ` in the ${descriptionStyles[selectedStyle as keyof typeof descriptionStyles].name} style`
								: ''}.
						</p>
					{:else}
						<p class="text-sm text-muted-foreground">
							The AI will {getModeDescription(selectedMode).replace('ed', '')} the text above into a
							more detailed {fieldName}.
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
						<div class="max-h-32 overflow-y-auto rounded-md bg-muted p-3 font-mono text-sm">
							{descriptionStyles[selectedStyle as keyof typeof descriptionStyles].example}
						</div>
					</div>
				{/if}

				<!-- Current Content Preview (if enhancing) -->
				{#if hasContent && selectedMode !== 'create'}
					<div class="grid gap-2">
						<Label>Current Content</Label>
						<div class="max-h-32 overflow-y-auto rounded-md bg-muted p-3 text-sm">
							{fieldValue}
						</div>
					</div>
				{/if}

				<!-- Model Info Display -->
				<div class="rounded-md border bg-muted/30 p-3">
					<div class="flex items-center gap-2 text-xs text-muted-foreground">
						<Bot size={14} />
						<span>
							Powered by {lastGenerationResponse?.metadata?.model || 'Google Gemini AI'}
						</span>
					</div>
				</div>
			</div>
		{/if}

		<DialogFooter>
			{#if showResults}
				<!-- Results Footer -->
				<div class="flex w-full items-center justify-between">
					<div class="flex gap-2">
						<ButtonComponent
							variant="outline"
							onclick={() => (showDebugModal = true)}
							class="gap-2"
							title="View generation debug info"
						>
							<Bug size={14} />
							View Debug Info
						</ButtonComponent>
					</div>
					<div class="flex gap-2">
						<ButtonComponent
							variant="outline"
							onclick={() => {
								showResults = false;
								userInput = ''; // Reset input for new generation
								streamedContent = '';
								lastGenerationResponse = null;
								error = null;
							}}
							class="gap-2"
						>
							<RefreshCw size={14} />
							Generate Another
						</ButtonComponent>
						<ButtonComponent onclick={() => onOpenChange(false)}>Done</ButtonComponent>
					</div>
				</div>
			{:else}
				<!-- Generation Footer -->
				<div class="flex w-full items-center justify-between">
					<div class="flex gap-2">
						<ButtonComponent
							variant="outline"
							onclick={() => onOpenChange(false)}
							disabled={isGenerating}
						>
							Cancel
						</ButtonComponent>
						{#if lastGenerationResponse}
							<ButtonComponent
								variant="outline"
								size="sm"
								onclick={() => (showDebugModal = true)}
								class="gap-2"
								title="View generation debug info"
							>
								<Bug size={14} />
								Debug
							</ButtonComponent>
						{/if}
					</div>
					<ButtonComponent onclick={handleGenerate} disabled={isGenerating}>
						{#if isGenerating}
							<svg
								class="mr-2 h-4 w-4 animate-spin"
								xmlns="http://www.w3.org/2000/svg"
								fill="none"
								viewBox="0 0 24 24"
							>
								<circle
									class="opacity-25"
									cx="12"
									cy="12"
									r="10"
									stroke="currentColor"
									stroke-width="4"
								></circle>
								<path
									class="opacity-75"
									fill="currentColor"
									d="M4 12a8 8 0 0 1 8 -8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 0 1 4 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
								></path>
							</svg>
							Generating...
						{:else}
							Generate {fieldName}
						{/if}
					</ButtonComponent>
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
