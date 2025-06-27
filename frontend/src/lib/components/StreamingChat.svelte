<script lang="ts">
  import { $effect } from 'svelte';
  import { toast } from 'svelte-sonner';
  import { streamingService, type StreamingMessage } from '$lib/services/StreamingService.svelte';
  import { apiClient } from '$lib/api';
  import TypewriterMessage from './TypewriterMessage.svelte';
  import ChatHeader from './chat-header.svelte';
  import MultimodalInput from './multimodal-input.svelte';
  import type { User, ScribeCharacter, ScribeChatSession } from '$lib/types';

  // Props
  let {
    user,
    chat,
    character,
    readonly = false,
    initialChatInputValue = ""
  }: {
    user: User | undefined;
    chat: ScribeChatSession | undefined;
    character: ScribeCharacter | null | undefined;
    readonly?: boolean;
    initialChatInputValue?: string;
  } = $props();

  // Get reactive state from streaming service
  const streamingState = streamingService.getState();

  // Local component state
  let chatInput = $state(initialChatInputValue);
  let isInitialized = $state(false);

  // Derived state
  let isLoading = $derived(
    streamingState.connectionStatus === 'connecting' || 
    streamingState.connectionStatus === 'open'
  );
  
  let hasError = $derived(streamingState.currentError !== null);
  
  let lastMessage = $derived(
    streamingState.messages.length > 0 
      ? streamingState.messages[streamingState.messages.length - 1]
      : null
  );

  // Initialize with character's first message if available
  $effect(() => {
    if (!isInitialized && character?.first_mes && chat?.id) {
      const firstMessage: StreamingMessage = {
        id: `first-message-${chat.id}`,
        content: character.first_mes,
        sender: 'assistant',
        created_at: new Date().toISOString()
      };
      
      streamingService.messages = [firstMessage];
      isInitialized = true;
    }
  });

  // Cleanup on component destroy
  $effect(() => {
    return () => {
      streamingService.disconnect();
    };
  });

  // Handle connection status changes
  $effect(() => {
    const status = streamingState.connectionStatus;
    const error = streamingState.currentError;
    
    if (status === 'error' && error) {
      toast.error(error.message);
      
      // Handle auth errors
      if (error.type === 'auth' && typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('auth:session-expired'));
      }
    }
  });

  /**
   * Get current chat model from API
   */
  async function getCurrentChatModel(): Promise<string | null> {
    if (!chat?.id) return null;

    try {
      const result = await apiClient.getChatSessionSettings(chat.id);
      if (result.isOk()) {
        return result.value.model_name || null;
      }
    } catch (error) {
      console.error('Failed to get chat model:', error);
    }
    return null;
  }

  /**
   * Send a message using the streaming service
   */
  async function sendMessage(content: string): Promise<void> {
    if (!chat?.id || !user?.id || !content.trim()) {
      toast.error('Chat session or user information is missing.');
      return;
    }

    if (isLoading) {
      toast.warning('Please wait for the current message to complete.');
      return;
    }

    try {
      // Build history from current messages
      const history = streamingState.messages
        .filter(msg => !msg.loading && !msg.error)
        .map(msg => ({
          role: msg.sender === 'assistant' ? 'assistant' : 'user',
          content: msg.content
        }));

      // Get current model
      const model = await getCurrentChatModel();

      // Connect and start streaming
      await streamingService.connect({
        chatId: chat.id,
        userMessage: content.trim(),
        history,
        model: model || undefined
      });

    } catch (error) {
      console.error('Failed to send message:', error);
      toast.error('Failed to send message. Please try again.');
    }
  }

  /**
   * Handle form submission
   */
  function handleInputSubmit(e: Event): void {
    e.preventDefault();
    if (chatInput.trim() && !isLoading) {
      sendMessage(chatInput.trim());
      chatInput = '';
    }
  }

  /**
   * Stop current generation
   */
  function stopGeneration(): void {
    streamingService.disconnect();
    toast.info('Generation stopped.');
  }

  /**
   * Retry a failed message
   */
  async function retryFailedMessage(messageId: string): Promise<void> {
    if (!chat?.id) return;

    try {
      // Build history up to the failed message
      const messageIndex = streamingState.messages.findIndex(msg => msg.id === messageId);
      if (messageIndex === -1) return;

      const history = streamingState.messages
        .slice(0, messageIndex)
        .filter(msg => !msg.loading && !msg.error)
        .map(msg => ({
          role: msg.sender === 'assistant' ? 'assistant' : 'user',
          content: msg.content
        }));

      const model = await getCurrentChatModel();

      await streamingService.retryMessage(messageId, chat.id, history, model || undefined);
    } catch (error) {
      console.error('Failed to retry message:', error);
      toast.error('Failed to retry message. Please try again.');
    }
  }

  /**
   * Clear all messages
   */
  function clearMessages(): void {
    streamingService.clearMessages();
    isInitialized = false;
    toast.success('Messages cleared.');
  }

  /**
   * Get placeholder text based on current state
   */
  let placeholderText = $derived(() => {
    if (isLoading) return "Generating response...";
    if (!chat?.id) return "No active chat session";
    return "Send a message...";
  });
</script>

<div class="flex h-dvh min-w-0 flex-col bg-background">
  <!-- Chat Header -->
  <ChatHeader {user} {chat} {readonly} />

  <!-- Messages Container -->
  <div class="flex-1 overflow-y-auto px-4 py-4">
    <div class="mx-auto max-w-3xl space-y-4">
      {#each streamingState.messages as message (message.id)}
        <div class="message-wrapper">
          <!-- User Message -->
          {#if message.sender === 'user'}
            <div class="flex justify-end">
              <div class="max-w-[80%] rounded-lg bg-primary px-4 py-2 text-primary-foreground">
                <div class="whitespace-pre-wrap break-words">{message.content}</div>
                <div class="mt-1 text-xs opacity-70">
                  {new Date(message.created_at).toLocaleTimeString()}
                </div>
              </div>
            </div>
          
          <!-- Assistant Message -->
          {:else}
            <div class="flex justify-start">
              <div class="max-w-[80%] space-y-2">
                <div class="rounded-lg bg-muted px-4 py-2">
                  <!-- Character Name -->
                  {#if character?.name}
                    <div class="mb-2 text-sm font-medium text-muted-foreground">
                      {character.name}
                    </div>
                  {/if}
                  
                  <!-- Message Content with Typewriter Effect -->
                  <TypewriterMessage 
                    {message} 
                    showTypewriter={message.loading && message.content.length > 0}
                    className="text-foreground"
                  />
                  
                  <!-- Loading Indicator -->
                  {#if message.loading && message.content.length === 0}
                    <div class="flex items-center space-x-2">
                      <div class="h-2 w-2 animate-pulse rounded-full bg-muted-foreground"></div>
                      <div class="h-2 w-2 animate-pulse rounded-full bg-muted-foreground" style="animation-delay: 0.2s"></div>
                      <div class="h-2 w-2 animate-pulse rounded-full bg-muted-foreground" style="animation-delay: 0.4s"></div>
                      <span class="text-sm text-muted-foreground">Thinking...</span>
                    </div>
                  {/if}
                  
                  <!-- Error State -->
                  {#if message.error}
                    <div class="mt-2 rounded-md border border-destructive/20 bg-destructive/10 p-3">
                      <div class="flex items-start space-x-2">
                        <svg class="mt-0.5 h-4 w-4 text-destructive" fill="currentColor" viewBox="0 0 20 20">
                          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
                        </svg>
                        <div class="flex-1">
                          <p class="text-sm font-medium text-destructive">Generation failed</p>
                          <p class="text-sm text-muted-foreground">{message.error}</p>
                          {#if message.retryable}
                            <button
                              type="button"
                              onclick={() => retryFailedMessage(message.id)}
                              class="mt-2 inline-flex items-center space-x-1 text-sm text-primary hover:underline"
                            >
                              <svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                              </svg>
                              <span>Retry</span>
                            </button>
                          {/if}
                        </div>
                      </div>
                    </div>
                  {/if}
                </div>
                
                <!-- Timestamp and Token Info -->
                {#if !message.loading}
                  <div class="flex items-center justify-between text-xs text-muted-foreground">
                    <span>{new Date(message.created_at).toLocaleTimeString()}</span>
                    {#if message.prompt_tokens || message.completion_tokens}
                      <span class="font-mono">
                        {message.prompt_tokens || 0} + {message.completion_tokens || 0} tokens
                        {#if message.model_name}
                          • {message.model_name}
                        {/if}
                      </span>
                    {/if}
                  </div>
                {/if}
              </div>
            </div>
          {/if}
        </div>
      {/each}

      <!-- Connection Status -->
      {#if streamingState.connectionStatus === 'connecting'}
        <div class="flex justify-center">
          <div class="flex items-center space-x-2 rounded-lg bg-muted px-3 py-2 text-sm text-muted-foreground">
            <svg class="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Connecting...</span>
          </div>
        </div>
      {/if}
    </div>
  </div>

  <!-- Input Form -->
  {#if !readonly && chat?.id}
    <div class="border-t bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div class="mx-auto max-w-3xl px-4 py-4">
        <form onsubmit={handleInputSubmit}>
          <MultimodalInput 
            bind:value={chatInput} 
            isLoading={isLoading} 
            stopGeneration={stopGeneration} 
            chatId={chat.id}
            placeholder={placeholderText}
            onImpersonate={(response) => {
              chatInput = response;
            }}
          />
        </form>
        
        <!-- Debug Controls (Development) -->
        {#if import.meta.env.DEV}
          <div class="mt-2 flex justify-center space-x-2">
            <button
              type="button"
              onclick={clearMessages}
              class="text-xs text-muted-foreground hover:text-foreground"
            >
              Clear Messages
            </button>
            <span class="text-xs text-muted-foreground">•</span>
            <span class="text-xs font-mono text-muted-foreground">
              Status: {streamingState.connectionStatus}
            </span>
            {#if streamingState.isTyping}
              <span class="text-xs text-muted-foreground">• Typing...</span>
            {/if}
          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .message-wrapper {
    animation: slideIn 0.3s ease-out;
  }

  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateY(10px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }
</style>