# Sanguine Scribe - Technical Concept

## Vision

Sanguine Scribe is a high-performance character-based AI roleplaying platform designed for interactive character conversations and AI-driven game dialogues. Building upon the strengths of existing tools like SillyTavern while addressing their key limitations, Scribe focuses on fast, reactive character AI with intelligent context management and **uncompromising user privacy**.

**Privacy-Focused Architecture:** Scribe implements server-side encryption where user data is encrypted with keys derived from user passwords. Your character data and chat history are protected on our servers, though AI processing requires sending chat messages to external APIs like Google's Gemini for generation and embeddings.

The platform combines a modern Rust backend with a reactive SvelteKit frontend to deliver a professional-grade solution for character-based roleplaying, with architecture specifically designed to power future AI-driven game dialogue systems including RPGs, dating simulators, and immersive interactive experiences.


## Core Goals

1.  **Server-Side Data Protection:** Client-side key derivation with server-side encryption protects your stored data, though AI processing requires external API calls
2.  **Fast, Reactive Character AI:** Lightning-fast responses with background context enrichment to enable real-time character conversations suitable for game dialogue systems
3.  **Intelligent Context Management:** Automated, RAG-based context system that eliminates manual memory management while maintaining character consistency across long conversations
4.  **Character-Focused Architecture:** Optimized for character-based interactions with support for V2/V3 character cards, personas, and seamless migration from SillyTavern/Character.AI
5.  **Game-Ready Performance:** Built for future AI-driven game dialogue integration - RPGs, dating sims, interactive fiction, and immersive character experiences
6.  **Modern Tech Stack:** Type-safe Rust backend with PostgreSQL and Qdrant vector database, paired with reactive SvelteKit frontend for optimal performance
7.  **Self-Hostable Platform:** Complete open-source solution competing with Character.AI while offering self-hosting capabilities and true data ownership

## Key Technical Features

*   **Server-Side Encryption:** Client-side password-derived keys with server-side data encryption protect stored data (note: AI processing requires external API calls)
*   **Character-Aware Context System:** RAG-based automatic retrieval of relevant character interactions, personality traits, and relationship history to maintain character consistency
*   **Dual Database Architecture:** PostgreSQL for structured character and conversation data with ACID compliance, and Qdrant vector database for semantic search of character memories and context
*   **High-Performance Backend:** Rust implementation ensures zero-cost abstractions, memory safety, and high concurrency suitable for real-time game dialogue systems
*   **Chronicle System:** Automatic extraction and indexing of character interactions and relationship developments for intelligent character continuity
*   **Game Integration Architecture:** Designed for future RPG, dating sim, and interactive fiction integration with EventSource::GameApi hooks and scalable event processing
*   **Game-Ready Deployment:** Single binary architecture designed for both self-hosted installations and integration into game development pipelines

### Design Principles

Scribe's development follows established software engineering principles:

*   **Privacy-Focused Design:** Scribe implements server-side encryption where user data is encrypted with password-derived keys. Your stored character data and chat history are protected, though AI processing requires sending messages to external APIs like Gemini.
*   **Open Source & User Control:** Complete transparency with MIT licensing, compatibility with open standards (V2/V3 character cards), and full database schema access. Users maintain complete control over their data and creative workflow.
*   **Character Roleplay Focus:** Designed specifically for character-based AI roleplay, competing with Character.AI while providing self-hosting capabilities and the performance architecture needed for future game integration.
*   **Game-Ready Extensibility:** The decoupled architecture (Rust backend with clear API boundaries, PostgreSQL + Qdrant dual database design) is specifically designed to integrate into game engines for RPGs, dating simulators, and interactive fiction. The RAG system and event processing architecture scales from personal roleplay to professional game development workflows.

## Target Audience

- **Privacy-Conscious Roleplayers:** Users requiring server-side data encryption and data ownership (understanding AI processing limitations)
- **Character Roleplay Enthusiasts:** Users seeking fast, reactive character-based AI conversations with consistent personality and memory
- **SillyTavern Migrants:** Users wanting a more streamlined, production-ready alternative with automatic context management and better performance
- **Character.AI Refugees:** Users frustrated by limitations, censorship, or lack of control who want self-hostable character AI with full data ownership
- **Game Developers:** Studios and indie developers interested in integrating AI-driven character dialogue systems into RPGs, dating sims, and interactive fiction
- **Technical Self-Hosters:** Users who prefer running their own character AI infrastructure with complete data sovereignty
- **Future Game Integrators:** Developers planning AI-powered NPCs, dating simulation mechanics, or interactive fiction systems