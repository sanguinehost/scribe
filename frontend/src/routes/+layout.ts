// Disable SSR for Tauri desktop app
// This is REQUIRED per Tauri + SvelteKit documentation:
// https://v2.tauri.app/develop/sveltekit/#disable-ssr
//
// Tauri apps run entirely in the browser context with no Node.js server,
// so server-side rendering cannot work. All data loading must happen
// client-side via API calls to the Rust backend.
export const ssr = false;

// Disable prerendering to run in SPA mode
// Prerendering would fail for dynamic routes (e.g., /chat/[chatId])
// SPA mode works better for Tauri as everything loads client-side
export const prerender = false;
