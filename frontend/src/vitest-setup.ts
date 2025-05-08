import '@testing-library/jest-dom';

// Mock window.matchMedia for jsdom
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false, // Default to not matching
    media: query,
    onchange: null,
    addListener: vi.fn(), // Deprecated but sometimes used
    removeListener: vi.fn(), // Deprecated but sometimes used
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
}); 