// Quick test to verify the chat fix
import { streamingService } from './services/StreamingService.js';

console.log('Testing StreamingService reactivity...');

// Test 1: Check if messages array is reactive
console.log('Initial messages count:', streamingService.messages.length);

// Test 2: Add some test messages
const testMessages = [
  {
    id: 'test-1',
    content: 'Hello world',
    sender: 'user',
    created_at: new Date().toISOString(),
    loading: false
  },
  {
    id: 'test-2', 
    content: 'Hi there!',
    sender: 'assistant',
    created_at: new Date().toISOString(),
    loading: false
  }
];

// Clear and populate using our new method
streamingService.clearMessages();
for (const message of testMessages) {
  streamingService.messages.push(message);
}

console.log('After adding test messages:', streamingService.messages.length);
console.log('Test messages:', streamingService.messages);

// Test 3: Clear messages
streamingService.clearMessages();
console.log('After clearing:', streamingService.messages.length);

console.log('StreamingService reactivity test complete!');