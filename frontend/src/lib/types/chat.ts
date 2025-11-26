export type MessageRole = 'user' | 'assistant' | 'system';

export interface MessageVariant {
    id: string;
    content: string;
    model?: string;
    promptTokens?: number;
    completionTokens?: number;
    createdAt: Date;
}

export interface ChatMessage {
    id: string; // Stable ID for the UI list
    role: MessageRole;
    variants: MessageVariant[];
    currentVariantIndex: number;
    isAnimating: boolean;
    timestamp: Date;
}

export interface ChatState {
    messages: ChatMessage[];
    isStreaming: boolean;
    error: string | null;
    activeChatId: string | null;
}
