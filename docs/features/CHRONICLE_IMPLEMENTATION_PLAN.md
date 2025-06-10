# Scribe Chronicle: Feature Specification & Implementation Plan

## 1. Introduction & Project Goal

### 1.1. The Problem: Limited AI Memory

Currently, the Scribe AI's ability to recall past events is limited to its immediate chat history (the context window). While effective for short-term conversations, this prevents the AI from maintaining long-term narrative consistency. Key plot points, character developments, and significant world events from earlier in a long-running story can be "forgotten," leading to a degraded user experience where the narrative loses coherence over time.

### 1.2. The Solution: The Player Chronicle

The Player Chronicle is a new feature designed to give the Scribe AI a persistent, long-term memory. It functions as an intelligent, time-ordered journal that automatically logs significant events during a user's story or gameplay session.

By creating this structured memory, the AI can reference key past events long after they have fallen out of the immediate chat history, ensuring that the narrative remains consistent, characters "remember" past interactions, and the story's world feels stable and coherent.

### 1.3. Key Terminology

For clarity, here are definitions of key terms used in this document:

*   **LLM (Large Language Model):** The underlying AI engine that generates text and understands language (e.g., Gemini Pro).
*   **RAG (Retrieval-Augmented Generation):** A technique where the LLM's knowledge is augmented by retrieving relevant information from an external knowledge base (like a database) before it generates a response. This is how we give the AI access to specific lore or chronicle events.
*   **Vector Database (Qdrant):** A specialized database that stores information (text) as numerical representations called "vectors." It allows for incredibly fast and efficient "semantic search," finding text that is conceptually similar, not just text that matches keywords.

## 2. System Architecture & High-Level Flow

The Chronicle system is composed of several key components that work together:

*   **Data Storage:** A PostgreSQL database will store the chronicles and their associated events in a structured format. A Qdrant vector database will store the searchable "memories" for fast retrieval.
*   **User Interface (UI):** A new section in the Scribe web app will allow users to create, manage, and link chronicles to their chat sessions.
*   **Event Extraction Service:** An asynchronous (background) service that uses a secondary, smaller LLM to analyze conversations and automatically identify and record significant events.
*   **RAG Pipeline:** The core logic that retrieves the most relevant chronicle events in real-time to provide context to the main LLM during a conversation.

## 3. Phased Implementation Plan

We will implement the Player Chronicle in three distinct phases to manage complexity and deliver value incrementally.

### Phase 1: Foundational Infrastructure & Data Management

**Goal:** Establish the core database schema and the data processing pipeline for storing and vectorizing chronicle events.

### 3.1. Database Schema

We will create two new tables in the PostgreSQL database.

**`player_chronicles` Table:** This table defines the "journal" itself.

*   `id (UUID)`: Primary Key.
*   `user_id (UUID)`: Foreign Key to `users.id`, linking the chronicle to its owner.
*   `name (Varchar)`: A user-defined name for the story (e.g., "The Sunstone Quest").
*   `description (Text)`: An optional, longer description.
*   `created_at`, `updated_at (Timestamps)`: Standard timestamps for record management.

**`game_events` Table:** This table stores each individual "memory" or event within a chronicle.

*   `id (UUID)`: Primary Key.
*   `chronicle_id (UUID)`: Foreign Key to `player_chronicles.id`, linking the event to its chronicle.
*   `timestamp (Timestamp)`: Records when the event occurred.
*   `event_type (Varchar)`: A category for the event (e.g., "PlotTwist", "ItemAcquired").
*   `summary (Text)`: A concise, human-readable summary of the event. This is the text that will be searched.
*   `source (Varchar)`: Tracks how the event was created (e.g., 'AI_EXTRACTED', 'GAME_API', 'USER_ADDED').
*   `event_data (JSONB)`: A flexible field for storing additional structured data about the event.
*   `vector_id (UUID)`: A reference to the corresponding searchable vector in our Qdrant database.

We will also modify the `chat_sessions` table to include a nullable `player_chronicle_id (UUID)` column, allowing each chat to be associated with a specific chronicle.

### 3.2. Advanced Data Ingestion & Chunking

The `EmbeddingPipelineService` will be responsible for processing event summaries before they are stored for retrieval. This is a critical step for ensuring high-quality search results.

**Rationale:** Simply storing entire event summaries is inefficient. We need to break them down into semantically meaningful "chunks" for our vector search to be effective.

**Implementation:**

*   **Semantic Chunking:** We will use an advanced chunking strategy that analyzes the text to find natural thematic breaks. This ensures that a single "chunk" contains a complete, coherent thought, rather than being arbitrarily cut off.
*   **Small-to-Big Retrieval:** For very long events, we will create smaller, searchable chunks (the "small" part) that link back to the full event text (the "big" part). Our system will search the small chunks for relevance but provide the full context to the LLM, giving it the best of both worlds: search precision and contextual depth.

### Phase 2: Intelligent Event Extraction & Retrieval

**Goal:** Implement the AI-powered services that automatically create events and the RAG pipeline that uses them.

### 3.1. Asynchronous Event Extractor (Dual-LLM Architecture)

**Rationale:** We need to extract events from conversations without slowing down the user's chat experience. Using a separate, smaller, and faster LLM for this background task is more efficient and cost-effective than using our main, more powerful LLM.

**Implementation:**

*   **Trigger:** After the main AI sends its response to the user, a background job will be triggered if the chat is linked to a chronicle.
*   **Process:** This job sends the last few turns of the conversation to a smaller LLM (e.g., Gemini Flash or Claude 3 Haiku).
*   **Extraction:** The small LLM will be prompted specifically to identify significant events and use a function-calling tool named `record_event()`. This forces the LLM to return structured data (event type, summary), which is far more reliable than parsing plain text.
*   **Storage:** If the `record_event()` function is called, our system creates a new record in the `game_events` table and sends the summary to the `EmbeddingPipelineService` for processing and vectorization.

### 3.2. Advanced RAG Pipeline for Generation

This is where the chronicle's memory is put to use. The main generation service (`generation.rs`) will be updated to perform a multi-step retrieval process before generating a response.

**Query Transformation:**

**Rationale:** User questions are often not phrased in the same way as the information is stored. We can improve search by first transforming the query into an "ideal" answer.

**Implementation (HyDE):** We will use the main LLM to generate a hypothetical chronicle event that would perfectly answer the user's query. We then search for stored events that are semantically similar to this hypothetical event, which yields more relevant results.

**Hybrid Retrieval & Re-ranking:**

**Rationale:** Combining different search methods gives better results. We need to find events that are both semantically related (conceptual match) and contain the right keywords (exact match). We also need to ensure the results are not redundant.

**Implementation:**

*   The system will perform a Hybrid Search, using both vector search (for semantic meaning) and traditional keyword search.
*   It will initially retrieve a large number of candidate events (e.g., top 50).
*   These candidates will then be re-ranked using an algorithm called Maximal Marginal Relevance (MMR). This algorithm prioritizes events that are not only highly relevant to the query but also distinct from each other, preventing repetitive information.

**Strategic Prompt Injection:**

**Rationale:** LLMs pay more attention to information at the beginning and end of their context window (the "lost in the middle" problem).

**Implementation:** The `PromptBuilder` will intelligently assemble the final prompt for the LLM. It will place the single most relevant event from the re-ranked list at the very end of the context section to ensure it receives maximum attention from the AI.

### Phase 3: External Integration & Self-Correction (Post-MVP)

**Goal:** Expand the Chronicle system to be more robust and integrate with external game clients.

*   **Game-Driven Event API:**
    *   **Action:** Implement a secure `POST /api/chronicle/{chronicle_id}/events` endpoint.
    *   **Purpose:** This will allow authenticated game clients (like Sanguine Ascend) to directly push significant gameplay events (e.g., "Player completed the 'Whispering Caves' quest") into the chronicle. These events will be processed by the same advanced ingestion pipeline.
*   **Corrective RAG (CRAG) Elements:**
    *   **Action:** Introduce a "confidence score" for retrieved events.
    *   **Purpose:** If the system retrieves events but the relevance scores are all very low, it indicates the chronicle has no useful memory for the current query. Instead of feeding the AI irrelevant information, the system will take an alternative action, such as explicitly stating in the prompt, "The chronicle has no specific memory of this," or performing a broader search across the user's other lorebooks.

## 4. Long-Term Vision: The Future is a Knowledge Graph

Beyond this implementation, the ultimate evolution of the Chronicle system is to move from a simple log of events to a fully interconnected Knowledge Graph.

*   **Concept (GraphRAG):** We will process the chronicles and lorebooks to extract key entities (characters, locations, items) and the relationships between them. This creates a rich, queryable graph of the entire story world.
*   **Benefit:** This will allow the AI to answer incredibly complex, multi-step questions by traversing the graph (e.g., "Which characters were present at the location where the Sunstone was first discovered, and what relationship did they have to the Abyssal Heart?"). This represents the pinnacle of contextual understanding and narrative intelligence.