import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import '@testing-library/jest-dom';
import TypewriterMessage from './TypewriterMessage.svelte';
import type { StreamingMessage } from '$lib/services/StreamingService';

describe('TypewriterMessage', () => {
  let mockMessage: StreamingMessage;

  beforeEach(() => {
    mockMessage = {
      id: 'test-message-1',
      content: 'Hello, this is a test message!',
      sender: 'assistant',
      created_at: new Date().toISOString(),
      loading: false
    };
  });

  describe('Basic Rendering', () => {
    it('should render message content', () => {
      render(TypewriterMessage, {
        props: {
          message: mockMessage
        }
      });

      expect(screen.getByText('Hello, this is a test message!')).toBeInTheDocument();
    });

    it('should apply custom className', () => {
      const { container } = render(TypewriterMessage, {
        props: {
          message: mockMessage,
          className: 'custom-class'
        }
      });

      const messageElement = container.querySelector('.message-content');
      expect(messageElement).toHaveClass('custom-class');
    });

    it('should render without typewriter effect by default', () => {
      const { container } = render(TypewriterMessage, {
        props: {
          message: mockMessage
        }
      });

      const messageElement = container.querySelector('.message-content');
      expect(messageElement).not.toHaveClass('typewriter');
    });
  });

  describe('Typewriter Effect', () => {
    it('should apply typewriter effect when conditions are met', () => {
      const loadingMessage: StreamingMessage = {
        ...mockMessage,
        loading: true,
        sender: 'assistant'
      };

      const { container } = render(TypewriterMessage, {
        props: {
          message: loadingMessage,
          showTypewriter: true
        }
      });

      const messageElement = container.querySelector('.message-content');
      expect(messageElement).toHaveClass('typewriter');
    });

    it('should not apply typewriter effect for user messages', () => {
      const userMessage: StreamingMessage = {
        ...mockMessage,
        sender: 'user',
        loading: true
      };

      const { container } = render(TypewriterMessage, {
        props: {
          message: userMessage,
          showTypewriter: true
        }
      });

      const messageElement = container.querySelector('.message-content');
      expect(messageElement).not.toHaveClass('typewriter');
    });

    it('should not apply typewriter effect when not loading', () => {
      const completedMessage: StreamingMessage = {
        ...mockMessage,
        loading: false,
        sender: 'assistant'
      };

      const { container } = render(TypewriterMessage, {
        props: {
          message: completedMessage,
          showTypewriter: true
        }
      });

      const messageElement = container.querySelector('.message-content');
      expect(messageElement).not.toHaveClass('typewriter');
    });

    it('should not apply typewriter effect when content is empty', () => {
      const emptyMessage: StreamingMessage = {
        ...mockMessage,
        content: '',
        loading: true,
        sender: 'assistant'
      };

      const { container } = render(TypewriterMessage, {
        props: {
          message: emptyMessage,
          showTypewriter: true
        }
      });

      const messageElement = container.querySelector('.message-content');
      expect(messageElement).not.toHaveClass('typewriter');
    });
  });

  describe('CSS Custom Properties', () => {
    it('should set character count CSS variable', () => {
      const { container } = render(TypewriterMessage, {
        props: {
          message: mockMessage
        }
      });

      const messageElement = container.querySelector('.message-content') as HTMLElement;
      const charCount = messageElement.style.getPropertyValue('--char-count');
      expect(charCount).toBe(String(mockMessage.content.length));
    });

    it('should apply custom cursor color', () => {
      const { container } = render(TypewriterMessage, {
        props: {
          message: mockMessage,
          cursorColor: 'blue'
        }
      });

      const messageElement = container.querySelector('.message-content') as HTMLElement;
      const cursorColor = messageElement.style.getPropertyValue('--cursor-color');
      expect(cursorColor).toBe('blue');
    });

    it('should apply custom animation duration', () => {
      const { container } = render(TypewriterMessage, {
        props: {
          message: mockMessage,
          animationDuration: '3s'
        }
      });

      const messageElement = container.querySelector('.message-content') as HTMLElement;
      const duration = messageElement.style.getPropertyValue('--animation-duration');
      expect(duration).toBe('3s');
    });

    it('should update character count when content changes', async () => {
      const { component, container } = render(TypewriterMessage, {
        props: {
          message: mockMessage
        }
      });

      const messageElement = container.querySelector('.message-content') as HTMLElement;
      
      // Initial character count
      expect(messageElement.style.getPropertyValue('--char-count')).toBe('29');

      // Update message content
      const updatedMessage: StreamingMessage = {
        ...mockMessage,
        content: 'Short message'
      };

      await component.$set({ message: updatedMessage });

      // Should update character count
      expect(messageElement.style.getPropertyValue('--char-count')).toBe('13');
    });
  });

  describe('Content Formatting', () => {
    it('should preserve whitespace and line breaks', () => {
      const messageWithBreaks: StreamingMessage = {
        ...mockMessage,
        content: 'Line 1\nLine 2\n\nLine 4'
      };

      const { container } = render(TypewriterMessage, {
        props: {
          message: messageWithBreaks
        }
      });

      const messageElement = container.querySelector('.message-content');
      expect(messageElement).toHaveTextContent('Line 1\nLine 2\n\nLine 4');
    });

    it('should handle long words correctly', () => {
      const messageWithLongWord: StreamingMessage = {
        ...mockMessage,
        content: 'This is a supercalifragilisticexpialidocious word that should wrap properly'
      };

      render(TypewriterMessage, {
        props: {
          message: messageWithLongWord
        }
      });

      // Should render without issues
      expect(screen.getByText(/supercalifragilisticexpialidocious/)).toBeInTheDocument();
    });
  });

  describe('Responsive Behavior', () => {
    it('should apply correct CSS classes for responsive design', () => {
      const { container } = render(TypewriterMessage, {
        props: {
          message: {
            ...mockMessage,
            loading: true,
            sender: 'assistant'
          },
          showTypewriter: true
        }
      });

      const messageElement = container.querySelector('.message-content.typewriter');
      expect(messageElement).toBeInTheDocument();
      
      // Check if CSS is properly applied (this is mostly tested by the CSS itself)
      const computedStyle = window.getComputedStyle(messageElement!);
      expect(computedStyle.fontFamily).toContain('monospace');
    });
  });

  describe('Performance', () => {
    it('should handle very long messages efficiently', () => {
      const longContent = 'A'.repeat(10000); // Very long message
      const longMessage: StreamingMessage = {
        ...mockMessage,
        content: longContent
      };

      const startTime = performance.now();
      
      render(TypewriterMessage, {
        props: {
          message: longMessage
        }
      });

      const endTime = performance.now();
      const renderTime = endTime - startTime;

      // Should render quickly even with long content
      expect(renderTime).toBeLessThan(100); // Less than 100ms
      expect(screen.getByText(longContent)).toBeInTheDocument();
    });

    it('should update efficiently when content changes', async () => {
      const { component } = render(TypewriterMessage, {
        props: {
          message: mockMessage
        }
      });

      const startTime = performance.now();

      // Simulate multiple rapid updates
      for (let i = 0; i < 50; i++) {
        const updatedMessage: StreamingMessage = {
          ...mockMessage,
          content: mockMessage.content + i
        };
        await component.$set({ message: updatedMessage });
      }

      const endTime = performance.now();
      const updateTime = endTime - startTime;

      // Should handle rapid updates efficiently
      expect(updateTime).toBeLessThan(500); // Less than 500ms for 50 updates
    });
  });

  describe('Accessibility', () => {
    it('should be accessible to screen readers', () => {
      render(TypewriterMessage, {
        props: {
          message: mockMessage
        }
      });

      const messageElement = screen.getByText(mockMessage.content);
      
      // Should be readable by screen readers
      expect(messageElement).toBeVisible();
      expect(messageElement).toHaveTextContent(mockMessage.content);
    });

    it('should handle empty content gracefully', () => {
      const emptyMessage: StreamingMessage = {
        ...mockMessage,
        content: ''
      };

      render(TypewriterMessage, {
        props: {
          message: emptyMessage
        }
      });

      // Should render without errors
      const messageElement = screen.getByText('', { selector: '.message-content' });
      expect(messageElement).toBeInTheDocument();
    });
  });
});