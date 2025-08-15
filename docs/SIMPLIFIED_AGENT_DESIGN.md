# Simplified Agent Design

## Vision

Sanguine Scribe's agent system focuses on **pragmatic intelligence** rather than complex world simulation. The goal is to enhance roleplay through smart context retrieval and narrative awareness, not to build a living world.

## Core Principles

1. **Fast Responses** - Users get immediate feedback, no waiting for complex processing
2. **Smart Context Search** - Find relevant information when users reference past events
3. **Simple Chronicles** - Text summaries with keywords, not complex JSON structures
4. **Incremental Enhancement** - Start simple, add intelligence where it provides value

## Architecture

### 1. Primary Chat Flow (Immediate Response)
The primary chat flow remains fast and simple:
- User sends message → Backend processes → AI generates response → User sees response
- No blocking on chronicle extraction or complex analysis
- All enrichment happens asynchronously in the background (if using post-processing mode)

### 2. Background Context Enrichment
After sending the response, optionally process in background:
```
- Extract simple chronicle summaries from significant events
- Generate keywords for search optimization  
- Update lorebook entries if world-building elements detected
```

### 3. Smart Context Search
When users reference something not in immediate context:
```
User: "Remember when we fought the dragon?"
Agent: 
  1. Detects reference to past event
  2. Searches chronicles for "dragon" keyword
  3. Searches chat history for dragon mentions
  4. Includes relevant context in prompt
```

## Simplified Chronicle Structure

Instead of complex Ars Fabula ontology:
```rust
// OLD: Complex structure with 8+ fields
ChronicleEvent {
    actors: JsonValue,      // Complex role assignments
    causality: JsonValue,   // Event linking
    valence: JsonValue,     // Emotional impacts
    // ... many more fields
}

// NEW: Simple and searchable
ChronicleEvent {
    summary: String,        // "The party defeated the ancient dragon"
    keywords: Vec<String>,  // ["dragon", "battle", "victory"] - encrypted in DB
    timestamp: DateTime,    // When it happened in the story
    // Both summary and keywords are encrypted for security
}
```

## Implementation Approach

### Phase 1: Simplify What Exists
- Remove complex chronicle fields (causality, valence, actors)
- Simplify prompts to generate text summaries
- Keep the working tool infrastructure

### Phase 2: Add Optional Background Processing
- Implement fast response with optional background processing modes (pre-processing or post-processing)
- Add simple keyword extraction from summaries
- Keep chronicle extraction manual until proven valuable

### Phase 3: Smart Search
- Build context-aware search tool
- Query chronicles, history, and lorebooks based on user references
- Inject relevant context into prompts

## Benefits Over Complex System

| Complex System | Simplified System |
|---------------|-------------------|
| 7000+ line perception agent | < 500 line smart search |
| Complex JSON generation prone to errors | Natural text summaries |
| 10+ database tables for ECS | Single chronicle_events table |
| Difficult to debug and maintain | Clear, simple data flow |
| AI struggles with structured output | AI excels at text generation |

## Future Enhancements

Once the simple system proves valuable:
- Auto-extract chronicles for significant events only
- Implement conversation-aware lorebook updates
- Add character relationship tracking (if needed)
- Consider entity extraction (only if it adds value)

## Key Insight

The abandoned complex architecture tried to solve problems we don't have. Users want:
1. Fast, engaging responses
2. The AI to remember important events
3. Consistent world details

We can achieve all three with simple text search and summaries, without the overhead of a full entity-component system or complex event ontologies.