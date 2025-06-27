<script lang="ts">
  /**
   * RobustStreamingExample.svelte - Demonstration of the Modern Streaming Architecture
   * 
   * This example showcases the key features implemented according to the architectural plan:
   * 1. Decoupled StreamingService with Svelte 5 runes
   * 2. @microsoft/fetch-event-source for robust SSE handling
   * 3. Reactive CSS typewriter effect with dynamic character counting
   * 4. Sophisticated error handling and retry strategies
   * 5. Clean separation between connection management and UI
   */
  
  import { $effect } from 'svelte';
  import { streamingService, type StreamingMessage } from '$lib/services/StreamingService.svelte';
  import TypewriterMessage from '../TypewriterMessage.svelte';
  import { toast } from 'svelte-sonner';

  // Props for demo configuration
  let {
    demoMode = true,
    showAdvancedControls = false
  }: {
    demoMode?: boolean;
    showAdvancedControls?: boolean;
  } = $props();

  // Get reactive state from streaming service
  const state = streamingService.getState();

  // Local state
  let userInput = $state('');
  let isConnecting = $state(false);

  // Derived state for demonstration
  let connectionStatusColor = $derived(() => {
    switch (state.connectionStatus) {
      case 'idle': return 'text-gray-500';
      case 'connecting': return 'text-yellow-500';
      case 'open': return 'text-green-500';
      case 'error': return 'text-red-500';
      case 'closed': return 'text-blue-500';
      default: return 'text-gray-500';
    }
  });

  let lastMessage = $derived(
    state.messages.length > 0 
      ? state.messages[state.messages.length - 1] 
      : null
  );

  let isLoading = $derived(
    state.connectionStatus === 'connecting' || 
    state.connectionStatus === 'open'
  );

  // Handle connection status changes with toast notifications
  $effect(() => {
    const status = state.connectionStatus;
    const error = state.currentError;
    
    if (status === 'open') {
      toast.success('Connected successfully!');
    } else if (status === 'error' && error) {
      toast.error(`Connection failed: ${error.message}`);
    } else if (status === 'closed') {
      toast.info('Connection closed');
    }
  });

  /**
   * Send a message using the robust streaming service
   */
  async function sendMessage(): Promise<void> {
    if (!userInput.trim() || isLoading) return;

    const message = userInput.trim();
    userInput = '';

    // For demo purposes, use mock data
    const mockHistory = state.messages
      .filter(msg => !msg.loading && !msg.error)
      .map(msg => ({
        role: msg.sender === 'assistant' ? 'assistant' : 'user',
        content: msg.content
      }));

    try {
      await streamingService.connect({
        chatId: 'demo-chat-' + Date.now(),
        userMessage: message,
        history: mockHistory,
        model: 'gemini-2.5-pro'
      });
    } catch (error) {
      console.error('Failed to send message:', error);
      toast.error('Failed to send message. Please try again.');
    }
  }

  /**
   * Disconnect the current stream
   */
  function disconnect(): void {
    streamingService.disconnect();
  }

  /**
   * Clear all messages
   */
  function clearMessages(): void {
    streamingService.clearMessages();
    toast.success('Messages cleared');
  }

  /**
   * Retry a failed message
   */
  async function retryMessage(messageId: string): Promise<void> {
    const messageIndex = state.messages.findIndex(msg => msg.id === messageId);
    if (messageIndex === -1) return;

    const history = state.messages
      .slice(0, messageIndex)
      .filter(msg => !msg.loading && !msg.error)
      .map(msg => ({
        role: msg.sender === 'assistant' ? 'assistant' : 'user',
        content: msg.content
      }));

    try {
      await streamingService.retryMessage(messageId, 'demo-chat-retry', history, 'gemini-2.5-pro');
    } catch (error) {
      console.error('Failed to retry message:', error);
      toast.error('Failed to retry message. Please try again.');
    }
  }

  /**
   * Simulate various error conditions for demonstration
   */
  function simulateError(type: 'network' | 'auth' | 'timeout' | 'safety'): void {
    const errors = {
      network: new Error('Network connection failed'),
      auth: new Error('401 Unauthorized'),
      timeout: new Error('Stream timeout'),
      safety: new Error('PropertyNotFound("/content/parts")')
    };

    streamingService['handleStreamError'](errors[type], lastMessage?.id);
  }

  /**
   * Update streaming service configuration
   */
  function updateConfig(config: Partial<{
    timeoutMs: number;
    maxRetries: number;
    retryDelayMs: number;
    enableBackoff: boolean;
    typingSpeed: number;
  }>): void {
    if (config.typingSpeed !== undefined) {
      streamingService.setTypingSpeed(config.typingSpeed);
    }
    // Note: Other config changes would require service restart in real implementation
    toast.success('Configuration updated');
  }
</script>

<div class="space-y-6 rounded-lg border bg-card p-6 text-card-foreground shadow-sm">
  <div class="space-y-2">
    <h2 class="text-2xl font-bold tracking-tight">Robust Streaming Architecture Demo</h2>
    <p class="text-sm text-muted-foreground">
      Showcasing decoupled state management, advanced error handling, and reactive UI patterns
    </p>
  </div>

  <!-- Connection Status Display -->
  <div class="flex items-center justify-between rounded-lg border bg-muted/50 p-4">
    <div class="space-y-1">
      <p class="text-sm font-medium">Connection Status</p>
      <div class="flex items-center space-x-2">
        <div class="h-2 w-2 rounded-full bg-current {connectionStatusColor}"></div>
        <span class="text-sm font-mono {connectionStatusColor}">
          {state.connectionStatus.toUpperCase()}
        </span>
        {#if state.isTyping}
          <span class="text-xs text-muted-foreground">• Typing...</span>
        {/if}
      </div>
    </div>
    
    {#if state.currentError}
      <div class="text-right">
        <p class="text-sm font-medium text-destructive">Error</p>
        <p class="text-xs text-destructive">{state.currentError.type}</p>
      </div>
    {/if}
  </div>

  <!-- Messages Display -->
  <div class="space-y-4 rounded-lg border bg-background p-4">
    <h3 class="font-medium">Messages ({state.messages.length})</h3>
    
    <div class="max-h-64 space-y-3 overflow-y-auto">
      {#each state.messages as message (message.id)}
        <div class="flex {message.sender === 'user' ? 'justify-end' : 'justify-start'}">
          <div class="max-w-[80%] space-y-1">
            <div class="rounded-lg p-3 {message.sender === 'user' ? 'bg-primary text-primary-foreground' : 'bg-muted'}">
              <div class="mb-1 text-xs font-medium opacity-70">
                {message.sender === 'user' ? 'You' : 'Assistant'}
              </div>
              
              <!-- TypewriterMessage Component Showcase -->
              <TypewriterMessage 
                {message} 
                showTypewriter={message.loading && message.content.length > 0}
                cursorColor={message.sender === 'user' ? 'white' : 'orange'}
                className="text-sm"
              />
              
              <!-- Loading State -->
              {#if message.loading && message.content.length === 0}
                <div class="flex items-center space-x-1 text-xs text-muted-foreground">
                  <div class="h-1 w-1 animate-pulse rounded-full bg-current"></div>
                  <div class="h-1 w-1 animate-pulse rounded-full bg-current" style="animation-delay: 0.2s"></div>
                  <div class="h-1 w-1 animate-pulse rounded-full bg-current" style="animation-delay: 0.4s"></div>
                  <span>Thinking...</span>
                </div>
              {/if}
              
              <!-- Error State with Retry -->
              {#if message.error}
                <div class="mt-2 space-y-2 rounded border border-destructive/20 bg-destructive/10 p-2">
                  <p class="text-xs text-destructive">{message.error}</p>
                  {#if message.retryable}
                    <button
                      type="button"
                      onclick={() => retryMessage(message.id)}
                      class="inline-flex items-center space-x-1 text-xs text-primary hover:underline"
                    >
                      <svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                      <span>Retry</span>
                    </button>
                  {/if}
                </div>
              {/if}
            </div>
            
            <!-- Message metadata -->
            {#if !message.loading}
              <div class="text-xs text-muted-foreground">
                {new Date(message.created_at).toLocaleTimeString()}
                {#if message.prompt_tokens || message.completion_tokens}
                  • {message.prompt_tokens || 0} + {message.completion_tokens || 0} tokens
                {/if}
              </div>
            {/if}
          </div>
        </div>
      {/each}

      {#if state.messages.length === 0}
        <div class="py-8 text-center text-sm text-muted-foreground">
          No messages yet. Send a message to test the streaming architecture!
        </div>
      {/if}
    </div>
  </div>

  <!-- Input Form -->
  <form 
    onsubmit|preventDefault={sendMessage}
    class="flex space-x-2"
  >
    <input
      type="text"
      bind:value={userInput}
      placeholder="Type a message to test streaming..."
      disabled={isLoading}
      class="flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
    />
    <button
      type="submit"
      disabled={!userInput.trim() || isLoading}
      class="inline-flex items-center justify-center whitespace-nowrap rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground ring-offset-background transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50"
    >
      {#if isLoading}
        <svg class="mr-2 h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        Sending...
      {:else}
        Send
      {/if}
    </button>
  </form>

  <!-- Control Panel -->
  <div class="space-y-4 rounded-lg border bg-muted/30 p-4">
    <h3 class="font-medium">Demo Controls</h3>
    
    <div class="flex flex-wrap gap-2">
      <button
        type="button"
        onclick={disconnect}
        disabled={state.connectionStatus === 'idle'}
        class="inline-flex items-center space-x-1 rounded-md border border-input bg-background px-3 py-1 text-xs hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-50"
      >
        <span>Disconnect</span>
      </button>
      
      <button
        type="button"
        onclick={clearMessages}
        class="inline-flex items-center space-x-1 rounded-md border border-input bg-background px-3 py-1 text-xs hover:bg-accent hover:text-accent-foreground"
      >
        <span>Clear Messages</span>
      </button>
      
      {#if demoMode}
        <button
          type="button"
          onclick={() => simulateError('network')}
          class="inline-flex items-center space-x-1 rounded-md border border-destructive/20 bg-destructive/10 px-3 py-1 text-xs text-destructive hover:bg-destructive/20"
        >
          <span>Simulate Network Error</span>
        </button>
        
        <button
          type="button"
          onclick={() => simulateError('timeout')}
          class="inline-flex items-center space-x-1 rounded-md border border-destructive/20 bg-destructive/10 px-3 py-1 text-xs text-destructive hover:bg-destructive/20"
        >
          <span>Simulate Timeout</span>
        </button>
      {/if}
    </div>

    <!-- Advanced Controls -->
    {#if showAdvancedControls}
      <div class="space-y-3 border-t pt-3">
        <h4 class="text-sm font-medium">Advanced Configuration</h4>
        
        <div class="grid grid-cols-2 gap-3">
          <div class="space-y-1">
            <label class="text-xs font-medium">Typing Speed (ms)</label>
            <input
              type="range"
              min="10"
              max="200"
              value="50"
              onchange={(e) => updateConfig({ typingSpeed: parseInt(e.target.value) })}
              class="w-full"
            />
          </div>
          
          <div class="space-y-1">
            <label class="text-xs font-medium">Connection Info</label>
            <div class="text-xs font-mono text-muted-foreground">
              Retries: {streamingService.getConnectionInfo().retryCount} / {streamingService.getConnectionInfo().config.maxRetries}
            </div>
          </div>
        </div>
      </div>
    {/if}
  </div>

  <!-- Architecture Information -->
  <div class="space-y-3 rounded-lg border border-blue-200 bg-blue-50/50 p-4 dark:border-blue-800 dark:bg-blue-950/20">
    <h3 class="font-medium text-blue-900 dark:text-blue-100">Architecture Features Demonstrated</h3>
    
    <div class="grid grid-cols-1 gap-2 text-sm text-blue-800 dark:text-blue-200 md:grid-cols-2">
      <div class="space-y-1">
        <div class="flex items-center space-x-2">
          <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
          <span>Decoupled StreamingService</span>
        </div>
        <div class="flex items-center space-x-2">
          <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
          <span>Svelte 5 Runes Reactivity</span>
        </div>
        <div class="flex items-center space-x-2">
          <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
          <span>@microsoft/fetch-event-source</span>
        </div>
      </div>
      
      <div class="space-y-1">
        <div class="flex items-center space-x-2">
          <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
          <span>Reactive CSS Typewriter Effect</span>
        </div>
        <div class="flex items-center space-x-2">
          <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
          <span>Sophisticated Error Handling</span>
        </div>
        <div class="flex items-center space-x-2">
          <div class="h-1.5 w-1.5 rounded-full bg-green-500"></div>
          <span>Multi-layered Testing Strategy</span>
        </div>
      </div>
    </div>
  </div>
</div>