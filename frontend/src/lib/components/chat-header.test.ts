import { render, cleanup } from '@testing-library/svelte';
import { describe, it, expect, afterEach, vi, beforeEach } from 'vitest';
import ChatHeader from './chat-header.svelte';
import type { ScribeChatSession } from '$lib/types';

// --- Mocks ---

// --- Hoisted Mocks for Svelte 5 Compatibility ---

const HoistedMockVisibilitySelector = vi.hoisted(() => {
	class MockedVisibilitySelectorComponentInternal {
		element: HTMLDivElement;
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		constructor({
			target,
			props
		}: {
			target: Element;
			props: { chat?: ScribeChatSession; class?: string };
		}) {
			this.element = document.createElement('div');
			this.element.setAttribute('data-testid', 'visibility-selector-mock');
			target.appendChild(this.element);
		}
		$set() {
			/* no-op */
		}
		$destroy() {
			if (this.element.parentNode) {
				this.element.parentNode.removeChild(this.element);
			}
		}
	}
	return { MockedVisibilitySelectorComponentInternal };
});

// Mock for SidebarToggle (auto-mocked by __mocks__ directory)
vi.mock('./sidebar-toggle.svelte');

// Mock for SidebarUserNav (auto-mocked by __mocks__ directory)
vi.mock('./sidebar-user-nav.svelte');

// Mock for ModelSelector (auto-mocked, will be a vi.fn())
vi.mock('./model-selector.svelte');

// Mock for VisibilitySelector
vi.mock('./visibility-selector.svelte', () => ({
	default: HoistedMockVisibilitySelector.MockedVisibilitySelectorComponentInternal,
	__esModule: true
}));

// Mock SvelteKit's $app/navigation
vi.mock('$app/navigation', () => ({
	goto: vi.fn()
}));

// Mock for useSidebar
vi.mock('./ui/sidebar', () => ({
	useSidebar: vi.fn(() => ({
		open: false // Default mock value
		// Add other properties or methods if needed by the component
	}))
}));

// Mock for Tooltip components (auto-mocked by __mocks__ directory)
vi.mock('./ui/tooltip');

// --- Test Suite ---

describe('ChatHeader.svelte', () => {
	let ModelSelector: ReturnType<typeof vi.fn>;

	beforeEach(async () => {
		const modelSelectorModule = await import('./model-selector.svelte');
		ModelSelector = modelSelectorModule.default as ReturnType<typeof vi.fn>;
		ModelSelector.mockClear();
	});

	afterEach(() => {
		cleanup();
		vi.clearAllMocks();
	});

	const mockChat: ScribeChatSession | undefined = undefined;

	it('renders ModelSelector when not readonly', () => {
		render(ChatHeader, { props: { user: undefined, chat: mockChat, readonly: false } });
		expect(ModelSelector).toHaveBeenCalledTimes(1);
	});

	it('does not render ModelSelector when readonly', () => {
		render(ChatHeader, { props: { user: undefined, chat: mockChat, readonly: true } });
		expect(ModelSelector).not.toHaveBeenCalled();
	});
});
