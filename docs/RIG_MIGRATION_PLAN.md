# Epic: Rig + Mistral.rs Migration

**Goal:** Replace the custom `rust-genai` fork with the [Rig](https://github.com/0xPlaygrounds/rig) framework for cloud providers and [Mistral.rs](https://github.com/EricLBuehler/mistral.rs) for local inference. This standardizes our AI stack, enables "Agentic" capabilities, and simplifies maintenance.

**Architecture:** Hybrid
- **Cloud:** Rig (Gemini, Anthropic, etc.)
- **Local:** Mistral.rs (Embedded via custom Rig adapter)
- **Vector DB:** Rig Native (LanceDB, Qdrant)

---

## Phase 1: Foundation & Dependencies [x]

### Task 1.1: Dependency Management [x]
- [x] **Subtask:** Update `backend/Cargo.toml`
    - Add `rig-core`, `rig-lancedb`, `rig-qdrant`.
    - Add `mistralrs-core` (and related crates).
    - Remove `genai` (eventually, keep for transition).
- [x] **Subtask:** Create `backend/src/services/ai/mod.rs` structure
    - Define `RigClient` wrapper struct.
    - Define `CompletionModel` factory.

### Task 1.2: Test Infrastructure (TDD Start) [x]
- [x] **Subtask:** Create `backend/tests/rig_integration_tests.rs`
    - Write a failing test for `RigClient::new()`.
    - Write a failing test for `RigClient::completion()`.
- [x] **Subtask:** Create `MockRigClient`
    - Implement a mock that satisfies Rig's `CompletionModel` trait for existing unit tests.

---

## Phase 2: Cloud Provider Migration (Rig) [x]

### Task 2.1: Unified Cloud Adapter Port [x]
- [x] **Subtask:** Implement `RigProvider` (as `RigClient`)
    - Map Scribe's `ChatRequest` to Rig's `CompletionRequest`.
    - Support multiple providers (Gemini, Anthropic, OpenAI) via unified Rig interface.
    - Handle "Thinking" tokens (Gemini 2.5/3, Claude 3.7).
    - **Test:** Verify reasoning capture across providers.
- [x] **Subtask:** Streaming Support
    - Implement `Stream<Item = ScribeSseEvent>` for Rig's output.
    - **Test:** Verify real-time token streaming.

### Task 2.2: LLM Abstraction & Naming Cleanup [x]
- [x] **Subtask:** Rename provider-specific variables in `generation.rs`
    - `gemini_thinking_budget` -> `thinking_budget`
    - `gemini_thinking_level` -> `thinking_level`
    - `gemini_enable_code_execution` -> `enable_code_execution`
- [x] **Subtask:** Rename provider-specific services
    - `GeminiTokenClient` -> `TokenClient`
    - `GeminiEmbeddingClient` -> `CloudEmbeddingClient`
- [x] **Subtask:** Update API request/response types to be provider-agnostic.

---

## Phase 3: Local Inference (Mistral.rs) [x]

### Task 3.1: Mistral.rs Embedding [x]
- [x] **Subtask:** Implement `MistralRsService`
    - Initialize `MistralRs` engine in a separate thread/service.
    - Handle model loading (GGUF) from `resources/models`.
- [x] **Subtask:** Create `MistralRsRigAdapter`
    - Implement `rig::completion::CompletionModel` for `MistralRsService`.
    - Map Rig requests to `mistralrs_core::Request`.
    - **Test:** Verify local inference via Rig API.

---

## Phase 4: Vector Database Abstraction [x]

### Task 4.1: Unified Vector Service [x]
- [x] **Subtask:** Replace manual LanceDB/Qdrant code with `rig-lancedb` and `rig-qdrant`
    - Abstract `backend/src/services/embeddings/` to use a unified `VectorService` trait.
    - Rename build-specific services:
        - `QdrantClientService` -> `CloudVectorService`
        - `LanceDbClient` -> `DesktopVectorService`
    - Use Rig's `VectorStore` trait for all operations.
    - **Test:** Verify RAG retrieval works with new unified impl on both Cloud and Desktop.

---

## Phase 5: Core Service Refactor [x]

### Task 5.1: Switch `ChatService` [x]
- [x] **Subtask:** Update `backend/src/services/chat/generation.rs`
    - Replace `genai::chat::*` with Rig types.
    - Use `RigClient` instead of direct `genai` calls.
- [x] **Subtask:** Update `backend/src/services/chat/types.rs`
    - Remove `genai` dependency re-exports.

### Task 5.2: Cleanup [x]
- [x] **Subtask:** Remove `genai` from `Cargo.toml`.
- [x] **Subtask:** Delete old adapter code.

---

## Phase 6: Tokenizer Migration [x]

### Task 6.1: Replace SentencePiece [x]
- [x] **Subtask:** Update `backend/Cargo.toml`
    - Remove `sentencepiece` dependency.
    - Ensure `tokenizers` is available (transitive or direct).
- [x] **Subtask:** Refactor Token Counting
    - Update `backend/src/services/tokenizer_service.rs` to use `tokenizers` crate.
    - Load `.json` tokenizers instead of `.model` (or convert if needed).
- [x] **Subtask:** Verify Pure Rust Stack
    - Confirm no C++ linking issues (remove `build.rs` hacks if any).

---

## Verification Strategy

### Automated Tests
1.  **Unit Tests:** Run `cargo test` after each subtask.
2.  **Integration Tests:** Run `backend/tests/rig_integration_tests.rs`.

### Manual Verification
1.  **Cloud Chat:** Chat with Gemini 2.5/Claude 3.7 (verify reasoning).
2.  **Local Chat:** Chat with a GGUF model (verify Mistral.rs embedding).
3.  **RAG:** Ask a question about a Lorebook entry (verify unified Vector Service).
