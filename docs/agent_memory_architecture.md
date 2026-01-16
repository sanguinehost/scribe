# Agent Memory Architecture: Hindsight, TITANS, and MIRAS

This document outlines the theoretical foundation and architectural design for the Scribe Agent Memory System, drawing inspiration from three key technical reports: **Hindsight**, **TITANS**, and **MIRAS**.

## 1. Theoretical Foundation

### 1.1 Hindsight: Structured Long-Term Recall
**Reference**: *Hindsight: A Memory Architecture for Long-Lived AI Agents* (2025)

Hindsight introduces a multi-network memory organization designed to separate objective facts from subjective beliefs. Scribe adopts the **Four-Network Memory** model:

*   **World Network (W)**: Objective facts about the external environment.
*   **Experience Network (B)**: Biographical information and first-person experiences.
*   **Opinion Network (O)**: Subjective judgments with associated confidence scores.
*   **Observation Network (S)**: Synthesized, preference-neutral summaries of entities.

**Core Operations**:
*   **Retain**: Extracting narrative facts (Who, What, Where, When, Why) from conversational transcripts.
*   **Recall**: Multi-strategy retrieval (Semantic, Keyword, Entity Graph) fused via Reciprocal Rank Fusion (RRF).
*   **Reflect**: Reasoning over retrieved facts to form or update opinions.

### 1.2 TITANS: Test-Time Memorization
**Reference**: *Titans: Learning to Memorize at Test Time* (2024)

TITANS proposes a "Neural Long-Term Memory" that learns to memorize historical context at test time. Scribe emulates this through a **Core Memory (Neural State)**:

*   **Neural State**: A compressed, evolving summary of the character's "mind state" stored as a persistent record.
*   **Surprise-Driven Updates**: Memory updates are triggered by a "surprise metric"—the degree to which new information violates the current state's expectations.

### 1.3 MIRAS: Online Optimization Framework
**Reference**: *It’s All Connected: A Journey Through Test-Time Memorization, Attentional Bias, Retention, and Online Optimization* (2025)

MIRAS provides a formal framework for online memory optimization. Scribe utilizes its concepts for:

*   **Attentional Bias**: Prioritizing "surprising" or "significant" events for deeper reflection.
*   **Retention Regularization**: Balancing the learning of new concepts with the retention of previously learned knowledge (stability vs. plasticity).
*   **Huber-style Coping**: Implementing robust updates that handle extreme outliers (significant events) differently than routine information.

## 2. Scribe Implementation Architecture

Scribe integrates these concepts into a multi-tiered, chronicle-specific system.

### 2.1 Multi-Tiered Storage
1.  **Tier 1: Structured Facts (Hindsight)**: 5D facts extracted from every turn and stored in a vector-enabled database (`cognitive_facts`).
2.  **Tier 2: Core Memory (TITANS)**: A single, evolving "Neural State" summary per chronicle (`cognitive_core_memory`).

### 2.2 The Agentic Loop
The system operates in a two-stage agentic loop:

1.  **Extraction & Surprise (Stage 1)**:
    *   Extract 2-5 narrative facts from the current turn.
    *   Calculate a **Surprise Score** by comparing these facts to the current `Core Memory`.
    *   Identify **Significant Events** using Huber-style logic.

2.  **Conditional Reflection (Stage 2)**:
    *   If `Surprise Score > Threshold` (e.g., 0.7), trigger a **Reflect** call.
    *   The Reflect step reconciles new facts with the existing `Core Memory`, updates opinion confidence scores, and resolves background contradictions.

### 2.3 Retrieval Pipeline (TEMPR Emulation)
*   **Semantic Search**: Vector similarity on `cognitive_facts`.
*   **Keyword Search**: BM25 on fact text.
*   **State Injection**: The latest `Core Memory` is always injected into the prompt context to provide immediate "working memory" of the character's state.

## 3. Cost Efficiency and Billing
To ensure sustainability, Scribe tracks all LLM calls within the memory system:
*   **Stage 1 (Extraction)**: Always performed as part of narrative processing.
*   **Stage 2 (Reflection)**: Only performed when necessary (high surprise), minimizing expensive "deep thinking" calls.
*   **Billing**: All token usage is aggregated and reflected in the user's chronicle balance.
