# Message Variants System Design

## Overview

This document describes a clean, proper design for the message variant system in Sanguine Scribe. The current implementation has fundamental architectural issues that make variants appear as duplicate messages instead of being switchable versions of a single message.

## Current Problems

### 1. Backend Issues
- **Mixed Data Models**: The backend returns variant 0 content in place of the original message content when loading messages
- **No Relationship Data**: Messages don't indicate if they ARE variants or HAVE variants
- **Implicit Behavior**: The system silently substitutes variant content without telling the frontend

### 2. Frontend Issues  
- **Complex Tracking**: Multiple Maps and state trackers trying to guess relationships
- **Content-Based Matching**: Using content comparison to identify variants (unreliable)
- **Race Conditions**: Async variant loading vs message display
- **Filtering Complexity**: Trying to hide "duplicate" messages that shouldn't exist

### 3. Architectural Issues
- **Separation of Concerns Violation**: Variants are a separate system but affect core message display
- **Data Model Mismatch**: Database has parent-child relationships but API doesn't expose them
- **State Synchronization**: Frontend trying to maintain parallel variant state

## Proposed Solution

### Core Principle
**Messages and variants should be a single, unified system where variants are properties of messages, not separate entities.**

### Data Model

#### Backend Message Structure
```rust
pub struct MessageResponse {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: String,
    pub role: String,
    
    // Core content - always the CURRENTLY SELECTED variant
    pub content: String,
    pub parts: Value,
    pub attachments: Value,
    
    // Variant metadata 
    pub variant_count: i32,        // Total number of variants (0 if no variants)
    pub current_variant_index: i32, // Currently selected variant (0-based)
    pub is_variant: bool,           // True if this message IS a variant of another
    pub parent_message_id: Option<Uuid>, // If is_variant=true, ID of parent
    
    // Optional: Complete variant data for immediate access
    pub variants: Option<Vec<MessageVariant>>, // All variants if requested
    
    // Standard metadata
    pub created_at: DateTime<Utc>,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub model_name: Option<String>,
    pub raw_prompt: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
}

pub struct MessageVariant {
    pub index: i32,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub prompt_tokens: Option<i64>,
    pub completion_tokens: Option<i64>,
    pub model_name: Option<String>,
}
```

#### Frontend Message Structure
```typescript
export interface ScribeChatMessage {
    id: string;
    backend_id?: string;
    content: string;
    message_type: MessageRole;
    
    // Variant information embedded (directly from backend)
    variant_count?: number;           // Total number of variants
    current_variant_index?: number;   // Currently displayed variant
    variants?: MessageVariant[];      // Complete variant data if provided
    is_variant?: boolean;             // Is this a variant of another message?
    parent_message_id?: string;       // Parent if this is a variant
    
    // Rest of fields...
    created_at?: string;
    prompt_tokens?: number;
    completion_tokens?: number;
    model_name?: string;
    status?: string;
}

export interface MessageVariant {
    index: number;
    content: string;
    created_at: string;
    prompt_tokens?: number;
    completion_tokens?: number;
    model_name?: string;
}
```

### API Design

#### 1. Get Messages Endpoint
**Current**: `/api/chats/{id}/messages`
```json
// Returns all messages with variant 0 content substituted
[
    {
        "id": "msg-1",
        "content": "variant 0 content if exists, else original",
        // No variant information
    }
]
```

**Proposed**: `/api/chats/{id}/messages`
```json
{
    "messages": [
        {
            "id": "msg-1", 
            "content": "current variant content",
            "variant_count": 3,
            "current_variant_index": 0,
            "is_variant": false,
            "parent_message_id": null,
            "variants": [
                {
                    "index": 0,
                    "content": "First variant content",
                    "created_at": "2024-01-01T10:00:00Z",
                    "model_name": "gemini-2.5-flash"
                },
                {
                    "index": 1,
                    "content": "Second variant content", 
                    "created_at": "2024-01-01T10:01:00Z",
                    "model_name": "gemini-2.5-flash"
                }
            ]
        }
    ],
    "next_cursor": null
}
```

#### 2. Switch Variant Endpoint (New)
**POST** `/api/messages/{id}/select-variant`
```json
{
    "variant_index": 2
}
```

Response:
```json
{
    "id": "msg-1",
    "content": "variant 2 content",
    "current_variant_index": 2,
    "variant_count": 3
}
```

#### 3. Create Variant Endpoint (Modified)
**POST** `/api/messages/{id}/variants`

**Current behavior**: Creates variant, doesn't update parent
**Proposed behavior**: Creates variant, updates parent's variant_count, returns updated parent

Response:
```json
{
    "id": "msg-1",
    "content": "new variant content", 
    "variant_count": 4,
    "current_variant_index": 3,
    "variants": [
        // ... all variants including the new one
    ]
}
```

### Implementation Plan

## Phase 1: Backend Refactoring

### 1.1 Database Schema Updates
```sql
-- Add variant tracking to chat_messages table
ALTER TABLE chat_messages ADD COLUMN variant_count INTEGER DEFAULT 0;
ALTER TABLE chat_messages ADD COLUMN current_variant_index INTEGER DEFAULT 0;

-- Add index for faster variant queries
CREATE INDEX idx_message_variants_parent ON message_variants(parent_message_id);
```

### 1.2 Backend Service Updates

```rust
// services/chat/message_handling.rs

pub struct MessageWithVariants {
    pub message: Message,
    pub variant_count: i32,
    pub current_variant_index: i32,
    pub current_content: String, // Content of current variant
}

impl MessageService {
    /// Load message with variant information
    pub async fn get_message_with_variants(
        &self,
        message_id: Uuid,
        user_id: Uuid,
    ) -> Result<MessageWithVariants, AppError> {
        // 1. Load base message
        let message = self.get_message(message_id)?;
        
        // 2. Count variants
        let variant_count = self.count_variants(message_id)?;
        
        // 3. Get current variant content
        let current_content = if variant_count > 0 {
            self.get_variant_content(message_id, message.current_variant_index)?
        } else {
            message.decrypt_content()?
        };
        
        Ok(MessageWithVariants {
            message,
            variant_count,
            current_variant_index: message.current_variant_index,
            current_content,
        })
    }
    
    /// Switch to a different variant
    pub async fn select_variant(
        &self,
        message_id: Uuid,
        variant_index: i32,
        user_id: Uuid,
    ) -> Result<MessageWithVariants, AppError> {
        // Update current_variant_index in database
        diesel::update(chat_messages::table)
            .filter(chat_messages::id.eq(message_id))
            .set(chat_messages::current_variant_index.eq(variant_index))
            .execute(&self.conn)?;
            
        self.get_message_with_variants(message_id, user_id)
    }
}
```

### 1.3 API Route Updates

```rust
// routes/chats.rs

/// Get messages with proper variant information
pub async fn get_messages_by_chat_id_handler(
    // ... params
) -> Result<impl IntoResponse, AppError> {
    let messages_with_variants = messages.into_iter()
        .map(|msg| {
            // Don't return messages that are variants of others
            if msg.is_variant_of.is_some() {
                return None;
            }
            
            let variants = get_message_variants(msg.id)?;
            Some(MessageResponse {
                id: msg.id,
                content: get_current_variant_content(&msg, &variants),
                variant_count: variants.len(),
                current_variant_index: msg.current_variant_index,
                is_variant: false,
                parent_message_id: None,
                // ... rest
            })
        })
        .filter_map(|m| m)
        .collect();
        
    Ok(Json(PaginatedMessagesResponse {
        messages: messages_with_variants,
        next_cursor,
    }))
}
```

## Phase 2: Frontend Refactoring

### 2.1 Remove Complex State Management

**Remove:**
- `messageVariants` Map
- `currentVariantIndex` Map  
- `regenerationTracker` Map
- `pendingRegeneration` state
- `filterVariantMessages` function

**Keep:**
- Simple message array from StreamingService

### 2.2 Simplified Variant Navigation

```typescript
// components/chat.svelte

async function handlePreviousVariant(messageId: string) {
    const message = messages.find(m => m.id === messageId);
    if (!message || !message.currentVariantIndex) return;
    
    const newIndex = message.currentVariantIndex - 1;
    if (newIndex < 0) return;
    
    // API call to switch variant
    const result = await apiClient.selectMessageVariant(messageId, newIndex);
    if (result.isOk()) {
        // Update message with new content
        updateMessage(messageId, {
            content: result.value.content,
            currentVariantIndex: newIndex
        });
    }
}

async function handleNextVariant(messageId: string) {
    const message = messages.find(m => m.id === messageId);
    if (!message) return;
    
    const variantCount = message.variantCount || 0;
    const currentIndex = message.currentVariantIndex || 0;
    
    if (currentIndex < variantCount - 1) {
        // Switch to existing variant
        const result = await apiClient.selectMessageVariant(messageId, currentIndex + 1);
        if (result.isOk()) {
            updateMessage(messageId, {
                content: result.value.content,
                currentVariantIndex: currentIndex + 1
            });
        }
    } else {
        // Generate new variant
        await regenerateMessage(messageId);
    }
}
```

### 2.3 Regeneration Flow

```typescript
async function regenerateMessage(messageId: string) {
    // 1. Remove message from display
    const messageIndex = messages.findIndex(m => m.id === messageId);
    const originalMessage = messages[messageIndex];
    messages.splice(messageIndex, 1);
    
    // 2. Start streaming new response
    await streamingService.regenerate({
        parentMessageId: originalMessage.backend_id,
        // ... other params
    });
    
    // 3. When complete, backend automatically:
    //    - Creates new variant
    //    - Updates parent's variant_count
    //    - Sets current_variant_index to new variant
    
    // 4. Reload message to get updated variant info
    const updated = await apiClient.getMessage(originalMessage.backend_id);
    messages.splice(messageIndex, 0, updated);
}
```

## Phase 3: Migration Strategy

### 3.1 Database Migration
```sql
-- Migrate existing variants to new structure
UPDATE chat_messages m
SET variant_count = (
    SELECT COUNT(*) 
    FROM message_variants v 
    WHERE v.parent_message_id = m.id
),
current_variant_index = 0;

-- Ensure index exists for performance
CREATE INDEX IF NOT EXISTS idx_message_variants_parent ON message_variants(parent_message_id);
```

### 3.2 Backward Compatibility
- Keep old variant endpoints working during transition
- Add feature flag for new variant system
- Gradual rollout to users

### 3.3 StreamingService Updates
The StreamingService must be updated to handle the new message format:
- When regeneration completes, expect updated parent message with new variant_count
- Remove complex variant tracking logic in favor of backend-provided metadata
- Update message_saved events to include complete variant information

## Benefits

### 1. Simplicity
- Single source of truth for message state
- No complex filtering or tracking
- Clear parent-child relationships

### 2. Performance  
- No duplicate messages in responses
- No async variant loading race conditions
- Reduced frontend state management

### 3. Reliability
- Variants explicitly marked in data model
- No content-based matching needed
- Consistent state between frontend and backend

### 4. User Experience
- Instant variant switching (no content guessing)
- Clear variant counts in UI
- No "disappearing messages" bugs

## Testing Strategy

### Unit Tests
- Message service variant operations
- API endpoint variant handling
- Frontend variant navigation

### Integration Tests
- Full regeneration flow
- Variant switching with persistence
- Multi-user variant isolation

### E2E Tests
- User clicks through variants
- Regeneration creates proper variants
- Variants persist across sessions

## Rollback Plan

If issues arise:
1. Feature flag to disable new variant system
2. Revert to old endpoints via API versioning
3. Keep database changes (non-breaking additions)
4. Frontend fallback to legacy variant handling

## Conclusion

This design eliminates the fundamental architectural issues by:
1. Making variants a first-class property of messages
2. Removing duplicate messages from the data flow
3. Providing explicit variant relationships
4. Simplifying frontend state management

The result will be a robust, maintainable variant system that works as users expect.