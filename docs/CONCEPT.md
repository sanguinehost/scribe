# Scribe - Concept

## Vision

Scribe aims to be a next-generation AI chat and storytelling interface, building upon the strengths of existing platforms like SillyTavern while addressing key limitations, particularly around context management and long-term memory. It leverages a modern web stack (SvelteKit + Rust) for a performant and maintainable experience.

## Core Goals

1.  **Seamless Long-Term Context:** Eliminate the need for manual context management through an automated, dynamic context system (initially RAG-based). Enable multi-session stories and transitions without memory loss.
2.  **Robust Prompt Engineering:** Provide powerful, flexible, and portable control over prompt construction, inheriting the best aspects of SillyTavern's system prompt, jailbreak, and character field integration.
3.  **Modern User Experience:** Offer a clean, reactive, and performant UI built with SvelteKit.
4.  **Extensibility:** Architect the backend (Rust) and frontend for future expansion, including support for various local and remote AI models.
5.  **Compatibility:** Maintain compatibility with the standard V2 character card format for easy adoption.
6.  **Testability & Maintainability:** Employ Test-Driven Development (TDD) principles and a clear separation of concerns between frontend, backend, and data layers.

## Key Differentiating Features (MVP Focus)

*   **Dynamic RAG Context:** Automatically embed and retrieve relevant past conversation snippets/summaries/facts to augment the prompt context, overcoming traditional context window limitations.
*   **Database-Backed:** Utilize PostgreSQL for structured data (chats, characters, users) and Qdrant for vector storage, providing a more robust foundation than file-based systems.
*   **Rust Backend:** Ensure performance, type safety, and reliability for core logic and API interactions.

## Target Audience

Users engaged in long-form AI roleplaying, storytelling, or chat who are currently limited by context window sizes or frustrated by manual context management in existing tools.