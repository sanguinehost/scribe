# Epic: Rig + Mistral.rs Migration

**Goal:** Replace the custom `rust-genai` fork with the [Rig](https://github.com/0xPlaygrounds/rig) framework for cloud providers and [Mistral.rs](https://github.com/EricLBuehler/mistral.rs) for local inference. This standardizes our AI stack, enables "Agentic" capabilities, and simplifies maintenance.

**Architecture:** Hybrid
- **Cloud:** Rig (Gemini, Anthropic)
- **Local:** Mistral.rs (Embedded via custom Rig adapter)
- **Vector DB:** Rig Native (LanceDB, Qdrant)

---

## Phase 1: Foundation & Dependencies

### Task 1.1: Dependency Management
- [x] **Subtask:** Update `backend/Cargo.toml`
    - Add `rig-core`, `rig-lancedb`, `rig-qdrant`.
    - Add `mistralrs-core` (and related crates).
    - Remove `genai` (eventually, keep for transition).
- [x] **Subtask:** Create `backend/src/services/ai/mod.rs` structure
    - Define `RigClient` wrapper struct.
    - Define `CompletionModel` factory.

### Task 1.2: Test Infrastructure (TDD Start)
- [x] **Subtask:** Create `backend/tests/rig_integration_tests.rs`
    - Write a failing test for `RigClient::new()`.
    - Write a failing test for `RigClient::completion()`.
- [x] **Subtask:** Create `MockRigClient`
    - Implement a mock that satisfies Rig's `CompletionModel` trait for existing unit tests.

---

## Phase 2: Cloud Provider Migration (Rig)

### Task 2.1: Gemini Adapter Port
- [x] **Subtask:** Implement `RigGeminiProvider`
    - Map Scribe's `ChatRequest` to Rig's `CompletionRequest`.
    - Handle "Thinking" tokens (Gemini 2.5/3).
    - **Test:** Verify Gemini 3 reasoning is captured.
- [x] **Subtask:** Streaming Support
    - Implement `Stream<Item = ScribeSseEvent>` for Rig's output.
    - **Test:** Verify real-time token streaming.

---

## Phase 3: Local Inference (Mistral.rs)

### Task 3.1: Mistral.rs Embedding
- [ ] **Subtask:** Implement `MistralRsService`
    - Initialize `MistralRs` engine in a separate thread/service.
    - Handle model loading (GGUF) from `resources/models`.
- [ ] **Subtask:** Create `MistralRsRigAdapter`
    - Implement `rig::completion::CompletionModel` for `MistralRsService`.
    - Map Rig requests to `mistralrs_core::Request`.
    - **Test:** Verify local inference via Rig API.

---

## Phase 4: Vector Database Migration

### Task 4.1: LanceDB Migration
- [ ] **Subtask:** Replace manual LanceDB code with `rig-lancedb`
    - Update `backend/src/services/embeddings/lancedb.rs`.
    - Use Rig's `VectorStore` trait.
    - **Test:** Verify RAG retrieval works with new impl.

### Task 4.2: Qdrant Migration
- [ ] **Subtask:** Replace `qdrant-client` usage with `rig-qdrant`
    - Update `backend/src/services/embeddings/qdrant.rs`.
    - **Test:** Verify Qdrant RAG retrieval.

---

## Phase 5: Core Service Refactor

### Task 5.1: Switch `ChatService`
- [ ] **Subtask:** Update `backend/src/services/chat/generation.rs`
    - Replace `genai::chat::*` with Rig types.
    - Use `RigClient` instead of direct `genai` calls.
- [ ] **Subtask:** Update `backend/src/services/chat/types.rs`
    - Remove `genai` dependency re-exports.

### Task 5.2: Cleanup
- [ ] **Subtask:** Remove `genai` from `Cargo.toml`.
- [ ] **Subtask:** Delete old adapter code.

---

## Phase 6: Tokenizer Migration

### Task 6.1: Replace SentencePiece
- [ ] **Subtask:** Update `backend/Cargo.toml`
    - Remove `sentencepiece` dependency.
    - Ensure `tokenizers` is available (transitive or direct).
- [ ] **Subtask:** Refactor Token Counting
    - Update `backend/src/services/tokenizer_service.rs` to use `tokenizers` crate.
    - Load `.json` tokenizers instead of `.model` (or convert if needed).
- [ ] **Subtask:** Verify Pure Rust Stack
    - Confirm no C++ linking issues (remove `build.rs` hacks if any).

---

## Verification Strategy

### Automated Tests
1.  **Unit Tests:** Run `cargo test` after each subtask.
2.  **Integration Tests:** Run `backend/tests/rig_integration_tests.rs`.

### Manual Verification
1.  **Cloud Chat:** Chat with Gemini 2.5 (verify reasoning).
2.  **Local Chat:** Chat with a GGUF model (verify Mistral.rs embedding).
3.  **RAG:** Ask a question about a Lorebook entry (verify LanceDB/Qdrant).
