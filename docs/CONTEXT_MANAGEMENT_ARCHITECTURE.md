# Context Management Architecture for Sanguine Scribe

## Overview

Sanguine Scribe implements a pragmatic, three-layer context management system that balances performance, cost, and narrative coherence. Rather than complex multi-agent orchestration, we use a straightforward combination of proven techniques:

1. **Context Window Management** - Strategic truncation to preserve critical information
2. **RAG (Retrieval-Augmented Generation)** - Semantic search for relevant background knowledge  
3. **Optional Context Enrichment** - Single-agent system that enhances context when chronicles are enabled

## Core Architecture

### 1. Context Window Management

**Problem**: LLM context windows have token limits, and naive truncation destroys narrative continuity.

**Solution**: Two-layer token budget management with strategic fallback truncation:

#### Layer 1: Token Budget Management (Primary)
- **Total Budget**: 200,000 tokens (configurable per user)
- **Recent History Budget**: 150,000 tokens for conversation history
- **RAG Budget**: 50,000 tokens for retrieved context

**Implementation**: Located in `backend/src/services/chat/generation.rs`:
- Uses `HybridTokenCounter` to count tokens for each message accurately
- **Recent History Processing**: Iterates messages newest to oldest, counting tokens and stopping when budget exceeded
- **RAG Budget Calculation**: `min(rag_budget, total_limit - actual_history_tokens)`
- **Smart Allocation**: Dynamically adjusts RAG budget based on actual history token usage

#### Layer 2: Strategic Truncation (Safety Net)
- **Head Preservation**: System prompts, character definitions, persona data (always protected)
- **Tail Preservation**: Recent conversation turns (configurable via `min_tail_messages_to_preserve`)  
- **Middle Truncation**: Older conversation history less critical for immediate coherence

**Implementation**: Located in `backend/src/prompt_builder.rs` as final safety check:
- **Stage 1**: First truncates RAG context items if still over limit
- **Stage 2**: Applies strategic middle-out truncation to recent history if needed
- **Hard Limit Enforcement**: Returns error if still over limit after all truncation

**Why This Works**: Primary budget management prevents most truncation scenarios while strategic truncation provides principled fallback based on LLM attention patterns ("lost in the middle" behavior).

### 2. RAG (Retrieval-Augmented Generation)

**Problem**: Characters need access to world knowledge and history that exceeds context window limits.

**Solution**: Vector database (Qdrant) stores and retrieves relevant information:

#### Lorebook RAG
- **Storage**: User-created lorebook entries are embedded and stored in Qdrant
- **Retrieval**: User messages are used as semantic queries to find relevant lore
- **Integration**: Retrieved entries are injected into the prompt as `<lorebook_entries>`

#### Chronicle RAG (Optional)
- **Storage**: When chronicles are enabled, significant events are extracted and embedded
- **Retrieval**: Relevant past events are found through semantic similarity
- **Integration**: Retrieved events provide narrative context as `<long_term_memory>`

**Implementation**: 
- `backend/src/services/embeddings/` - Handles embedding and storage
- `backend/src/vector_db/qdrant_client.rs` - Vector database interface  
- `backend/src/services/chat/generation.rs` - RAG integration during chat generation

### 3. Optional Context Enrichment

**Problem**: Users want rich narrative experiences with automatic chronicle generation, but this should be opt-in.

**Solution**: Single-agent context enrichment system:

#### When Chronicles Are Enabled (Per-Chat Opt-In)
- **Agent**: `backend/src/services/agentic/context_enrichment_agent.rs`
- **Trigger**: Runs after each assistant response for chronicle-enabled chats
- **Function**: 
  - Analyzes conversation for narrative significance
  - Creates chronicle events when meaningful events occur
  - Optionally creates lorebook entries for new world concepts
  - All new content gets embedded for future RAG retrieval

#### When Chronicles Are Disabled
- **Behavior**: No automatic analysis or chronicle creation
- **RAG**: Still works with existing lorebook entries
- **Performance**: Minimal overhead, just basic RAG

**Implementation**:
- `backend/src/services/agentic/context_enrichment_agent.rs` - Main agent logic
- `backend/src/services/narrative_intelligence_service.rs` - Service integration
- `backend/src/services/agentic/narrative_tools.rs` - Tools for creating content

## Data Flow

### Standard Chat Flow (Chronicles Disabled)
1. User sends message
2. System performs RAG query for relevant lorebook entries
3. Prompt assembled with: system prompt + character data + RAG results + recent history
4. Strategic truncation applied if needed
5. LLM generates response

### Enhanced Chat Flow (Chronicles Enabled)  
1. User sends message
2. System performs RAG query for lorebook entries AND chronicle events
3. Prompt assembled with: system prompt + character data + RAG results + recent history
4. Strategic truncation applied if needed
5. LLM generates response
6. **Post-processing**: Context enrichment agent analyzes the conversation
7. If significant events detected, creates chronicle events and/or lorebook entries
8. New content embedded for future RAG retrieval

## Key Design Principles

### 1. Simplicity Over Complexity
- **Single agent** instead of multi-agent orchestration
- **Proven techniques** (truncation + RAG) rather than experimental approaches
- **Clear separation** between core chat and optional enrichment

### 2. User Control
- **Chronicles are opt-in** per chat session
- **Users control** when narrative processing happens
- **Graceful degradation** when enrichment is disabled

### 3. Cost Efficiency
- **Strategic truncation** prevents runaway token costs
- **RAG caching** reduces repeated embedding costs
- **Optional processing** only runs when users want it

### 4. Performance First
- **Fast core path** for basic chat functionality
- **Asynchronous enrichment** doesn't block chat responses
- **Vector search optimization** for sub-second RAG queries

## Implementation Status

### ✅ Currently Implemented
- Two-layer token budget management (200k total, 150k history, 50k RAG)
- User-configurable token budgets via settings
- Dynamic RAG budget allocation based on actual history usage
- Strategic middle-out truncation as safety net in prompt builder
- Lorebook RAG with Qdrant vector storage
- Chronicle RAG for narrative events
- Single context enrichment agent
- Per-chat chronicle opt-in system
- Encrypted content handling

### 🔄 Future Enhancements (Post-Launch)
- **Emotional RAG**: Mood-dependent memory retrieval
- **Context Compression**: Two-model pipeline for token efficiency
- **Advanced Truncation**: Smarter content preservation algorithms
- **Performance Optimization**: Faster vector search and embedding

## Technical Details

### Token Management
- **Tokenization**: Uses model-appropriate tokenizers for accurate counting
- **Budget Allocation**: Dynamic token budgets based on available context space
- **Overflow Handling**: Graceful truncation when content exceeds limits

### Vector Database (Qdrant)
- **Embedding Model**: Gemini embedding API for consistent semantic representation
- **Encryption**: All stored content encrypted with user-specific keys
- **Search**: Configurable similarity thresholds and result limits
- **Metadata**: Rich metadata for filtering and relevance scoring

### Context Enrichment Agent
- **Tools Available**: 
  - `SearchKnowledgeBaseTool` - Query existing knowledge
  - `CreateChronicleEventTool` - Record significant events
  - `CreateLorebookEntryTool` - Capture world concepts
  - `AnalyzeTextSignificanceTool` - Evaluate narrative importance
  - `UpdateLorebookEntryTool` - Modify existing entries

## Performance Characteristics

### Latency
- **Core Chat**: ~200-500ms for basic generation
- **With RAG**: +50-100ms for vector queries  
- **With Enrichment**: +1-3s for post-processing (asynchronous)

### Scalability
- **Horizontal**: Multiple Qdrant instances for vector storage
- **Vertical**: Configurable token budgets and processing limits
- **Cost Control**: Per-user opt-in prevents runaway processing costs

## Conclusion

Sanguine Scribe's context management architecture prioritizes pragmatism over complexity. By combining well-established techniques (strategic truncation + RAG) with optional intelligent enrichment, we deliver:

- **Reliable narrative coherence** through proven context management
- **Rich world knowledge** via semantic search and retrieval
- **Optional narrative intelligence** for users who want deeper experiences
- **Cost-effective operation** through smart resource allocation
- **User control** over system behavior and processing intensity

This architecture serves both casual users who want simple, fast roleplay and power users who want deep, persistent narrative experiences - all while maintaining excellent performance and reasonable operational costs.