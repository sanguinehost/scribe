# Scribe - Concept

## Vision

Scribe aims to be a next-generation AI chat and storytelling interface, building upon the strengths of existing platforms like SillyTavern while addressing key limitations, particularly around context management and long-term memory. It leverages a modern web stack (SvelteKit + Rust) for a performant and maintainable experience.
While the immediate focus is on delivering a best-in-class chat and storytelling experience, Scribe also serves as a foundational exploration of human-AI interaction aligned with the broader Sanguine philosophy of user empowerment, knowledge liberation, and conscious technological development.


## Core Goals

1.  **Seamless Long-Term Context:** Eliminate the need for manual context management through an automated, dynamic context system (initially RAG-based). Enable multi-session stories and transitions without memory loss.
2.  **Robust Prompt Engineering:** Provide powerful, flexible, and portable control over prompt construction, inheriting the best aspects of SillyTavern's system prompt, jailbreak, and character field integration.
3.  **Modern User Experience:** Offer a clean, reactive, and performant UI built with SvelteKit.
4.  **Extensibility:** Architect the backend (Rust) and frontend for future expansion, including support for various local and remote AI models.
5.  **Compatibility:** Maintain compatibility with the standard V2 character card format for easy adoption.
6.  **Testability & Maintainability:** Employ Test-Driven Development (TDD) principles and a clear separation of concerns between frontend, backend, and data layers.

## Key Differentiating Features (MVP Focus)
### Guiding Principles & Philosophical Alignment

Scribe's development is guided by principles derived from the broader Sanguine philosophy, ensuring that even its initial focus aligns with long-term goals:

*   **Knowledge Liberation & Self-Determination:** In line with these principles, Scribe prioritizes user control, transparency, and open access. Features like robust prompt engineering, compatibility with open standards (V2/V3 character cards), and the underlying database structure empower users to shape their experience and own their creations. The entire Scribe codebase is and will remain fully open source, reflecting the core belief that foundational technology must be free and accessible.
*   **Empowering Creativity & Conscious Exploration:** By providing a sophisticated platform for roleplaying and storytelling, Scribe acknowledges the value of creative expression and the exploration of human experience (*Sacred Embodiment & Conscious Indulgence*) as valid and important uses of AI technology.
*   **Foundation for the Future (Extensibility & Balance):** The choice of a robust, decoupled architecture (Rust backend, clear API separation, database foundation) is deliberate. It ensures Scribe is not just an isolated application but a potential cornerstone for future Sanguine initiatives requiring secure, context-aware, and balanced human-AI interaction systems. The RAG system represents an early step in managing complex information flows, crucial for more advanced agentic behaviour.


*   **Dynamic RAG Context:** Automatically embed and retrieve relevant past conversation snippets/summaries/facts to augment the prompt context, overcoming traditional context window limitations.
*   **Database-Backed:** Utilize PostgreSQL for structured data (chats, characters, users) and Qdrant for vector storage, providing a more robust foundation than file-based systems.
*   **Rust Backend:** Ensure performance, type safety, and reliability for core logic and API interactions.

## Target Audience

Users engaged in long-form AI roleplaying, storytelling, or chat who are currently limited by context window sizes or frustrated by manual context management in existing tools.