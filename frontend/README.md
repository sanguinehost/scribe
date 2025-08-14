# Sanguine Scribe Frontend

Privacy-first, modern frontend for Sanguine Scribe's character AI platform, built with SvelteKit, TypeScript, and Tailwind CSS.

## Features

- **Privacy-Focused Design**: Client-side password handling and secure key derivation for server-side encryption (AI processing requires external API calls)
- **Modern Stack**: Svelte 5 with Runes, SvelteKit, TypeScript, Tailwind CSS
- **Component Library**: shadcn-svelte for beautiful, accessible UI components
- **Real-time Updates**: Server-Sent Events for live chat and chronicle updates with encrypted data handling
- **Game-Ready UI**: Architecture designed for future game integration (RPGs, dating sims, interactive fiction)
- **Type Safety**: Full TypeScript coverage with strict mode and encrypted data types
- **Responsive Design**: Mobile-first approach with Tailwind CSS
- **Comprehensive Testing**: Vitest with Testing Library including privacy and security validation

## Prerequisites

- **Node.js 18+** (LTS recommended)
- **pnpm** package manager (preferred over npm/yarn)
- **Backend API** running (see [backend README](../backend/README.md))

## Quick Start

### 1. Install Dependencies

```bash
cd frontend
pnpm install
```

### 2. Configure Environment

Copy and edit the environment file:

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# API Configuration
PUBLIC_API_URL=https://api.your-domain.com
# For development, use:
# PUBLIC_API_URL=http://localhost:8080

# Optional: Analytics
PUBLIC_VERCEL_ANALYTICS_ID=your-analytics-id
```

### 3. Development Server

```bash
# Start development server with hot reload
pnpm run dev

# Open browser automatically  
pnpm run dev --open
```

The frontend will be available at `http://localhost:5173`

### 4. Build for Production

```bash
# Create production build
pnpm run build

# Preview production build locally
pnpm run preview
```

## Development

### Project Structure

```
src/
├── lib/
│   ├── api/           # API client and types
│   ├── components/    # Reusable Svelte components
│   │   ├── ui/        # shadcn-svelte components
│   │   ├── messages/  # Chat message components
│   │   ├── lorebooks/ # Knowledge base components
│   │   └── ...        # Feature-specific components
│   ├── hooks/         # Custom Svelte hooks
│   ├── stores/        # Svelte stores for state management
│   ├── types.ts       # TypeScript type definitions
│   └── utils/         # Utility functions
├── routes/            # SvelteKit routes (pages)
└── app.html          # HTML template
```

### Key Components

- **Secure Authentication**: Client-side password handling with secure key derivation for server-side encryption
- **Chat Interface**: Real-time messaging with typing indicators and encrypted message handling
- **Character Management**: V2/V3 character card support with encrypted character data
- **Chronicle System**: Automatic narrative history tracking with privacy-preserving event storage
- **Lorebook Editor**: Rich knowledge base management with encrypted content
- **Game-Ready Architecture**: UI components designed for future RPG/dating sim game integration
- **Settings Panel**: User preferences and chat configuration with privacy controls

### Development Commands

```bash
# Development
pnpm run dev            # Start dev server
pnpm run dev --host     # Expose on network

# Building
pnpm run build          # Production build
pnpm run preview        # Preview build locally

# Quality
pnpm run check          # TypeScript checking
pnpm run check --watch  # Watch mode type checking
pnpm run lint           # ESLint
pnpm run format         # Prettier formatting

# Testing  
pnpm run test           # Run tests
pnpm run test:ui        # Tests with UI
pnpm run test:coverage  # Coverage report
```

### Code Quality

```bash
# Format code
pnpm run format

# Lint code
pnpm run lint

# Type checking
pnpm run check

# All quality checks
pnpm run format && pnpm run lint && pnpm run check
```

## Testing

### Unit & Component Tests

```bash
# Run all tests
pnpm run test

# Watch mode
pnpm run test --watch

# Specific test file
pnpm run test -- chat-header.test.ts

# Coverage report
pnpm run test:coverage
```

### Testing Structure

- **Component Tests**: Using `@testing-library/svelte`
- **Unit Tests**: Pure function testing with Vitest
- **Mock Services**: API mocking for isolated testing

Example test:

```typescript
import { render, screen } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import ChatHeader from './chat-header.svelte';

test('displays character name', () => {
  render(ChatHeader, {
    props: { character: { name: 'Test Character' } }
  });
  
  expect(screen.getByText('Test Character')).toBeInTheDocument();
});
```

## Deployment

### Vercel (Recommended)

```bash
# Install Vercel CLI
pnpm install -g vercel

# Deploy
vercel

# Production deployment
vercel --prod
```

### Custom Server

```bash
# Build static files
pnpm run build

# The built app is in the `build/` directory
# Serve with any static file server
```

### Docker

```bash
# Build image
docker build -t sanguine-scribe-frontend .

# Run container
docker run -p 3000:3000 sanguine-scribe-frontend
```

### Environment Variables

For production, set these environment variables:

```bash
# Required: API endpoint
PUBLIC_API_URL=https://api.your-domain.com

# Optional: Analytics
PUBLIC_VERCEL_ANALYTICS_ID=your-analytics-id

# Optional: Error tracking
PUBLIC_SENTRY_DSN=your-sentry-dsn
```

## Component Library

We use [shadcn-svelte](https://shadcn-svelte.com/) for our component system.

### Adding New Components

```bash
# Add a new component
pnpm dlx shadcn-svelte@latest add button

# Add multiple components
pnpm dlx shadcn-svelte@latest add dialog card badge
```

### Custom Components

Create reusable components in `src/lib/components/`:

```svelte
<!-- src/lib/components/my-component.svelte -->
<script lang="ts">
  interface Props {
    title: string;
    optional?: boolean;
  }
  
  let { title, optional = false }: Props = $props();
</script>

<div class="p-4 border rounded">
  <h2 class="text-xl font-bold">{title}</h2>
  {#if optional}
    <p>Optional content</p>
  {/if}
</div>
```

## State Management

We use Svelte 5 runes and stores for state management:

```typescript
// Global state with stores
import { writable } from 'svelte/store';

export const selectedCharacter = writable(null);

// Component state with runes
let count = $state(0);
let doubled = $derived(count * 2);

// Effects
$effect(() => {
  console.log('Count changed:', count);
});
```

## API Integration

The API client is in `src/lib/api/index.ts`:

```typescript
import { apiClient } from '$lib/api';

// Fetch characters
const characters = await apiClient.get('/characters');

// Send message
await apiClient.post('/chats/123/messages', {
  content: 'Hello world'
});
```

## Styling

We use Tailwind CSS with custom configuration:

```typescript
// tailwind.config.ts
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  theme: {
    extend: {
      colors: {
        // Custom colors
      }
    }
  }
};
```

### CSS Classes

```svelte
<!-- Use Tailwind utilities -->
<button class="bg-blue-500 hover:bg-blue-600 px-4 py-2 rounded text-white">
  Click me
</button>

<!-- Custom component styles -->
<div class="chat-bubble">
  Content
</div>

<style>
  .chat-bubble {
    @apply bg-gray-100 rounded-lg p-3;
  }
</style>
```

## Troubleshooting

### Build Issues

```bash
# Clear all caches
rm -rf node_modules .svelte-kit
pnpm install

# Check Node version
node --version  # Should be 18+

# Verify dependencies
pnpm audit
```

### Type Errors

```bash
# Run type checking
pnpm run check

# Generate types
pnpm run sync  # For SvelteKit sync
```

### Runtime Issues

- **API Connection**: Verify `PUBLIC_API_URL` in environment and HTTPS configuration
- **CORS Errors**: Ensure backend allows frontend origin and handles encrypted data properly
- **SSR Issues**: Check for browser-only code in server context, especially crypto operations
- **Privacy Issues**: Verify client-side key derivation and secure credential handling

### Performance

```bash
# Analyze bundle
pnpm run build --analyze

# Check lighthouse scores
pnpm dlx @unlighthouse/cli --site http://localhost:5173
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development guidelines.

### Code Standards

- **Privacy & Security**: Never log, store, or expose sensitive data (passwords, keys, encrypted content)
- **TypeScript**: Use strict typing (avoid `any`) with special attention to encrypted data types
- **ESLint & Prettier**: Follow configuration for consistent, secure code
- **Testing**: Write tests for components and utilities, including privacy/security validation
- **Accessibility**: Use semantic HTML and ARIA attributes for inclusive design
- **Svelte 5**: Follow runes patterns for reactive state management
- **Game-Ready**: Design components with future game engine integration in mind

### Pull Request Checklist

- [ ] Tests pass (`pnpm test`)
- [ ] Types check (`pnpm check`) 
- [ ] Code is formatted (`pnpm format`)
- [ ] No lint errors (`pnpm lint`)
- [ ] Components are accessible
- [ ] Mobile responsive

## License

MIT License - see [LICENSE](../LICENSE) file for details.